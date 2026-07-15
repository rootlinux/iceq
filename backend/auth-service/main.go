// Command auth-service is the IceQ authentication and identity
// HTTP service. It owns user registration, login (with rate
// limiting), refresh-token rotation, and logout. It speaks JSON
// over HTTP/1.1 on the port specified by PORT (default 8080)
// and is the only writer to the users and refresh_tokens tables.
//
// Process shape:
//
//	HTTP request
//	  └─ chi router
//	       ├─ POST /api/auth/register    → handlers.Register
//	       ├─ POST /api/auth/login       → handlers.Login
//	       ├─ POST /api/auth/refresh     → handlers.Refresh
//	       ├─ POST /api/auth/logout      → handlers.Logout
//	       │                              (behind middleware.BearerAuth)
//	       └─ GET  /api/auth/health      → handlers.Health
//
// On SIGINT / SIGTERM the process runs a 10-second graceful
// shutdown: in-flight requests are given time to complete, the
// HTTP server stops accepting new connections, and the Postgres
// + Redis pools are closed.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"strings"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/iceq/iceq/auth-service/handlers"
	"github.com/iceq/iceq/auth-service/models"
	"github.com/iceq/iceq/shared/db"
	"github.com/iceq/iceq/shared/jwt"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/iceq/iceq/shared/natsclient"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// ----------------------------------------------------------------------------
// Build-time info. VERSION is overridable at build time via
//   go build -ldflags "-X main.VERSION=$(git rev-parse --short HEAD)"
// and the linker substitutes it into the binary. The default
// "dev" lets local builds run without ceremony.
// ----------------------------------------------------------------------------

var VERSION = "dev"

// ----------------------------------------------------------------------------
// Configuration. Everything the process needs is pulled from
// environment variables in loadConfig(); defaults match the
// docker-compose.yml service hostnames so a developer can
// `go run .` inside the iceq-net network and have DNS resolve.
// ----------------------------------------------------------------------------

type config struct {
	Port            string
	PostgresDSN     string
	RedisAddr       string
	RedisPassword   string
	NATSURL         string
	ScyllaHosts     string
	ScyllaKeyspace  string
	JWTSecret       string
	AllowedOrigins  string
	ShutdownTimeout time.Duration
}

func loadConfig() config {
	return config{
		Port:            envOr("PORT", "8080"),
		PostgresDSN:     envOr("ICEQ_PG_DSN", "postgres://postgres:postgres@postgres:5432/iceq?sslmode=disable"),
		RedisAddr:       envOr("ICEQ_REDIS_ADDR", "redis:6379"),
		RedisPassword:   envOr("ICEQ_REDIS_PASSWORD", ""),
		NATSURL:         envOr("ICEQ_NATS_URL", "nats://nats:4222"),
		ScyllaHosts:     envOr("ICEQ_SCYLLA_HOSTS", "scylla:9042"),
		ScyllaKeyspace:  envOr("ICEQ_SCYLLA_KEYSPACE", "iceq"),
		JWTSecret:       envOr("ICEQ_JWT_SECRET", ""),
		AllowedOrigins:  envOr("ICEQ_ALLOWED_ORIGINS", "https://localhost"),
		ShutdownTimeout: 10 * time.Second,
	}
}

func envOr(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return fallback
}

// ----------------------------------------------------------------------------
// main. We do the wiring once here and inject the resulting
// clients into the handlers. The handlers themselves are pure
// functions of their dependencies, which makes them easy to
// unit-test against fixtures.
// ----------------------------------------------------------------------------

func main() {
	cfg := loadConfig()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)

	if cfg.JWTSecret == "" {
		// Refuse to start with an empty signing secret. An
		// empty HMAC key is "no signature" and would silently
		// break the entire auth pipeline.
		log.Fatalf("ICEQ_JWT_SECRET is not set; refusing to start")
	}

	// 30 s ceiling for the whole bootstrap. Each factory has
	// its own tighter internal timeout, but a total budget
	// here ensures we don't hang on a dependency that won't
	// come up.
	bootCtx, bootCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer bootCancel()

	// --- Postgres pool ------------------------------------------------
	pgPool, err := db.NewPostgresPool(db.Config{
		PostgresDSN: cfg.PostgresDSN,
	})
	if err != nil {
		log.Fatalf("postgres: %v", err)
	}
	defer pgPool.Close()
	if err := pgPool.Ping(bootCtx); err != nil {
		log.Fatalf("postgres ping: %v", err)
	}
	log.Printf("[auth-service] postgres: connected")

	// --- Redis client --------------------------------------------------
	rdb, err := db.NewRedisClient(db.Config{
		RedisAddr:     cfg.RedisAddr,
		RedisPassword: cfg.RedisPassword,
	})
	if err != nil {
		log.Fatalf("redis: %v", err)
	}
	defer func() { _ = rdb.Close() }()
	log.Printf("[auth-service] redis: connected to %s", cfg.RedisAddr)

	// Panic wipe must be able to remove ciphertext rows. Fail startup if the
	// dependency is unavailable instead of silently shipping a partial wipe.
	scyllaSession, err := db.NewScyllaSession(db.Config{ScyllaHosts: cfg.ScyllaHosts, ScyllaKeyspace: cfg.ScyllaKeyspace})
	if err != nil {
		log.Fatalf("scylla: %v", err)
	}
	defer scyllaSession.Close()
	messageStore, err := handlers.NewScyllaMessageStore(scyllaSession)
	if err != nil {
		log.Fatalf("scylla message store: %v", err)
	}
	panicWipeDeps := newPanicWipeDeps(pgPool, rdb, messageStore)

	// --- JWT manager ---------------------------------------------------
	// F-2 / F-5 (JWT assessment): NewManager now requires the pg
	// pool because the per-user session_epoch check in Verify
	// reads from `users.session_epoch`. The constructor also
	// refuses to construct a Manager with a weak secret, so a
	// crash here with "ICEQ_JWT_SECRET is too weak" means the
	// operator needs to regenerate the secret with
	// `openssl rand -hex 32`.
	mgr, err := jwt.NewManager(cfg.JWTSecret, rdb, pgPool)
	if err != nil {
		log.Fatalf("jwt manager: %v", err)
	}

	// --- NATS bus -------------------------------------------------------
	// Step 10: the auth-service now publishes `notification.<uin>`
	// envelopes on the bus (contact-request, group-invite). The
	// web client subscribes to these subjects to surface a
	// toast. We connect to the same NATS cluster the rest of
	// the services use; if the cluster is unreachable we
	// log.Fatal — auth-service without a bus would silently
	// drop contact-request notifications, which is a
	// user-visible bug.
	bus, err := natsclient.NewClient(cfg.NATSURL, "auth-service")
	if err != nil {
		log.Fatalf("nats: %v", err)
	}
	log.Printf("[auth-service] nats: connected to %s", cfg.NATSURL)

	// --- Router --------------------------------------------------------
	r := chi.NewRouter()

	// chi's bundled middlewares. Order matters: RealIP must
	// run before RequestID so the request ID embeds the real
	// client IP, and Recoverer wraps everything so a panic
	// in a handler becomes a 500 rather than a process crash.
	r.Use(chimw.RealIP)
	r.Use(chimw.RequestID)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(30 * time.Second))
	r.Use(chimw.RequestSize(1 << 20)) // 1 MiB max body
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   strings.Split(cfg.AllowedOrigins, ","),
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", middleware.CSRFHeaderName},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Routes. We mount the four auth endpoints under the
	// /api/auth prefix and the unauthenticated /health on the
	// same prefix for symmetry.
	r.Route("/api/auth", func(r chi.Router) {
		csrfMW := middleware.RequireCSRF
		authMW := middleware.NewBearerAuth(middleware.BearerAuthConfig{Manager: mgr})
		rate := func(action string, limit int64, window time.Duration) func(http.Handler) http.Handler {
			return middleware.NewAuthenticatedRateLimit(middleware.AuthenticatedRateLimitConfig{Redis: rdb, Action: action, Limit: limit, Window: window})
		}
		r.Post("/register", handlers.NewRegisterHandler(handlers.RegisterDeps{
			Pool:            pgPool,
			Manager:         mgr,
			Redis:           rdb,
			RateLimitSecret: []byte(cfg.JWTSecret),
		}))
		r.Post("/login", handlers.NewLoginHandler(handlers.LoginDeps{
			Pool:            pgPool,
			Redis:           rdb,
			Manager:         mgr,
			RateLimitSecret: []byte(cfg.JWTSecret),
			// Wipe is the optional panic-wipe deps. nil
			// here would disable the feature entirely;
			// passing the populated struct below enables
			// it. The Scylla field is nil at step 3
			// because no message-service is wired yet;
			// step 4 (or whenever the message-service
			// lands) will fill it in.
			Wipe: &panicWipeDeps,
		}))
		r.With(csrfMW).Post("/refresh", handlers.NewRefreshHandler(handlers.RefreshDeps{
			Pool:    pgPool,
			Manager: mgr,
			Limiter: handlers.NewRedisRefreshRateLimiter(rdb),
		}))
		// Logout is the only endpoint that REQUIRES the
		// access token. The BearerAuth middleware reads the
		// header, verifies the token, and injects the UIN
		// into the request context.
		r.With(authMW, rate("auth:logout", 10, time.Minute), csrfMW).Post("/logout", handlers.NewLogoutHandler(handlers.LogoutDeps{
			Pool:    pgPool,
			Manager: mgr,
		}))
		// Security settings (panic-wipe configuration).
		// Both endpoints are behind BearerAuth: the user's
		// UIN is the primary key, and only the
		// authenticated user can read or write their own
		// row.
		r.With(authMW, rate("auth:settings:read", 60, time.Minute)).Get("/settings", handlers.NewGetSettingsHandler(handlers.SettingsDeps{
			Pool: pgPool,
		}))
		r.With(authMW, rate("auth:settings:write", 10, time.Minute), csrfMW).Put("/settings", handlers.NewPutSettingsHandler(handlers.SettingsDeps{
			Pool: pgPool,
		}))
		r.With(authMW, rate("auth:me", 60, time.Minute)).Get("/me", handlers.NewMeHandler(handlers.MeDeps{
			Pool: pgPool,
		}))
		r.With(authMW, rate("auth:panic-wipe", 3, time.Hour), csrfMW).Post("/panic-wipe", handlers.NewManualPanicWipeHandler(handlers.ManualPanicWipeDeps{
			PanicWipeDeps: panicWipeDeps,
		}))
		r.Get("/health", newHealthHandler(pgPool, rdb, VERSION))
	})

	// --- /api/contacts (Step 10) --------------------------------------
	// Mounted as a separate top-level route group because the
	// resource is logically independent from /api/auth. Every
	// route here is behind BearerAuth — the user's UIN always
	// comes from the verified JWT, never from the request body.
	contactsDeps := handlers.ContactsDeps{
		Pool: pgPool,
		Bus:  bus,
	}
	authMW := middleware.NewBearerAuth(middleware.BearerAuthConfig{Manager: mgr})
	contactRate := func(action string, limit int64) func(http.Handler) http.Handler {
		return middleware.NewAuthenticatedRateLimit(middleware.AuthenticatedRateLimitConfig{Redis: rdb, Action: action, Limit: limit, Window: time.Minute})
	}
	r.Route("/api/contacts", func(r chi.Router) {
		r.With(authMW, contactRate("contacts:list", 60)).Get("/", handlers.NewListContactsHandler(contactsDeps))
		r.With(authMW, contactRate("contacts:add", 30), middleware.RequireCSRF).Post("/", handlers.NewAddContactHandler(contactsDeps))
		r.With(authMW, contactRate("contacts:accept", 30), middleware.RequireCSRF).Put("/{target_uin}/accept", handlers.NewAcceptContactHandler(contactsDeps))
		r.With(authMW, contactRate("contacts:block", 30), middleware.RequireCSRF).Put("/{target_uin}/block", handlers.NewBlockContactHandler(contactsDeps))
		r.With(authMW, contactRate("contacts:remove", 30), middleware.RequireCSRF).Delete("/{target_uin}", handlers.NewRemoveContactHandler(contactsDeps))
	})

	// --- HTTP server + graceful shutdown -------------------------------
	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Run the server in a goroutine so the main goroutine
	// can block on the signal channel.
	serverErr := make(chan error, 1)
	go func() {
		log.Printf("[auth-service] listening on :%s (version=%s)", cfg.Port, VERSION)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
		close(serverErr)
	}()

	// Wait for either a fatal server error or a shutdown
	// signal. Whichever arrives first wins.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		if err != nil {
			log.Fatalf("http server: %v", err)
		}
	case sig := <-stop:
		log.Printf("[auth-service] received %s; starting graceful shutdown (timeout=%s)", sig, cfg.ShutdownTimeout)
	}

	// Graceful shutdown. Shutdown blocks until in-flight
	// requests finish or the context expires, whichever
	// comes first. The 10 s budget is the user-facing
	// contract from the spec.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[auth-service] graceful shutdown failed: %v", err)
	} else {
		log.Printf("[auth-service] http server stopped cleanly")
	}
	// Drain the NATS bus after the HTTP server is fully stopped
	// so no in-flight publish is interrupted mid-flight. Drain()
	// is best-effort; an error here is logged but does not
	// block process exit.
	if err := bus.Drain(); err != nil {
		log.Printf("[auth-service] nats drain failed: %v", err)
	}
	log.Printf("[auth-service] bye")
}

func newPanicWipeDeps(pool *pgxpool.Pool, redisClient *redis.Client, store handlers.MessageStore) handlers.PanicWipeDeps {
	return handlers.PanicWipeDeps{Pool: pool, Redis: redisClient, Scylla: store}
}

// ----------------------------------------------------------------------------
// Health handler. Pings Postgres + Redis with a short deadline
// and reports per-dependency status. 200 means both deps are
// reachable; 503 means at least one is degraded. We never 500
// here — a partial outage is observable but not fatal to the
// response shape.
// ----------------------------------------------------------------------------

func newHealthHandler(pg *pgxpool.Pool, rdb *redis.Client, version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		status := models.HealthResponse{
			Status:       "ok",
			Service:      "auth-service",
			Version:      version,
			Time:         time.Now().UTC(),
			Dependencies: map[string]string{},
		}

		if err := pg.Ping(ctx); err != nil {
			status.Status = "degraded"
			status.Dependencies["postgres"] = err.Error()
		} else {
			status.Dependencies["postgres"] = "ok"
		}
		if err := rdb.Ping(ctx).Err(); err != nil {
			status.Status = "degraded"
			status.Dependencies["redis"] = err.Error()
		} else {
			status.Dependencies["redis"] = "ok"
		}

		code := http.StatusOK
		if status.Status != "ok" {
			code = http.StatusServiceUnavailable
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(status)
	}
}
