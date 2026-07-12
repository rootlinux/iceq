// Command key-service is the IceQ Signal Protocol key distribution
// HTTP service. It owns the prekey_bundles and one_time_prekeys
// tables; clients talk to it to upload their own bundle and to
// fetch a peer's bundle as the first step of an X3DH handshake.
//
// Process shape:
//
//	HTTP request
//	  └─ chi router
//	       ├─ GET  /api/keys/bundle/{uin}        → handlers.GetBundle   (no auth)
//	       ├─ POST /api/keys/bundle              → handlers.PostBundle   (BearerAuth)
//	       ├─ POST /api/keys/prekeys             → handlers.AddPrekeys   (BearerAuth)
//	       └─ GET  /api/keys/prekeys/count       → handlers.CountPrekeys (BearerAuth)
//
// The X3DH protocol requires Alice to fetch Bob's bundle BEFORE
// they share a session — that is why GET /bundle is the one
// endpoint that is NOT behind BearerAuth. Every other route
// requires the caller to be authenticated, and the authenticated
// UIN is the only UIN any handler will ever act on (cross-tenant
// access is impossible by construction).
//
// On SIGINT / SIGTERM the process runs a 10-second graceful
// shutdown: in-flight requests are given time to complete, the
// HTTP server stops accepting new connections, and the Postgres
// pool is closed.
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

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/iceq/iceq/key-service/handlers"
	"github.com/iceq/iceq/key-service/models"
	"github.com/iceq/iceq/key-service/store"
	"github.com/iceq/iceq/shared/db"
	"github.com/iceq/iceq/shared/jwt"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// ----------------------------------------------------------------------------
// Build-time info. VERSION is overridable at build time via
//   go build -ldflags "-X main.VERSION=$(git rev-parse --short HEAD)"
// and the linker substitutes it into the binary.
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
	JWTSecret       string
	ShutdownTimeout time.Duration
}

func loadConfig() config {
	return config{
		Port:            envOr("PORT", "8081"),
		RedisAddr:       envOr("ICEQ_REDIS_ADDR", "redis:6379"),
		RedisPassword:   envOr("ICEQ_REDIS_PASSWORD", ""),
		JWTSecret:       envOr("ICEQ_JWT_SECRET", ""),
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
		// Refuse to start with an empty signing secret.
		// An empty HMAC key is "no signature" and would
		// silently break the entire auth pipeline.
		log.Fatalf("ICEQ_JWT_SECRET is not set; refusing to start")
	}

	// 30 s ceiling for the whole bootstrap. Each factory
	// has its own tighter internal timeout, but a total
	// budget here ensures we don't hang on a dependency
	// that won't come up.
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
	log.Printf("[key-service] postgres: connected")

	// --- Redis client (needed for the JWT blocklist) -------------------
	rdb, err := db.NewRedisClient(db.Config{
		RedisAddr:     cfg.RedisAddr,
		RedisPassword: cfg.RedisPassword,
	})
	if err != nil {
		log.Fatalf("redis: %v", err)
	}
	defer func() { _ = rdb.Close() }()
	log.Printf("[key-service] redis: connected to %s", cfg.RedisAddr)

	// --- JWT manager ---------------------------------------------------
	mgr, err := jwt.NewManager(cfg.JWTSecret, rdb, pgPool)
	if err != nil {
		log.Fatalf("jwt manager: %v", err)
	}

	// --- Keystore + handlers ------------------------------------------
	ks := store.NewKeystore(pgPool)

	bundleDeps := handlers.BundleDeps{Keystore: ks}
	prekeyDeps := handlers.PrekeyDeps{Keystore: ks}

	// --- Router --------------------------------------------------------
	r := chi.NewRouter()

	// chi's bundled middlewares. Order matters: RealIP
	// must run before RequestID so the request ID embeds
	// the real client IP, and Recoverer wraps everything
	// so a panic in a handler becomes a 500 rather than a
	// process crash.
	r.Use(chimw.RealIP)
	r.Use(chimw.RequestID)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(30 * time.Second))
	r.Use(chimw.RequestSize(1 << 20)) // 1 MiB max body

	// Routes. /api/keys/bundle/{uin} is the ONE endpoint
	// that doesn't require BearerAuth — Alice needs to
	// fetch Bob's keys before any shared session exists.
	// Every other route is gated.
	r.Route("/api/keys", func(r chi.Router) {
		r.Get("/bundle/{uin}", handlers.NewGetBundleHandler(bundleDeps))

		// Authenticated bundle upload: client uploads its
		// OWN bundle. The BearerAuth middleware injects
		// the authenticated UIN; the handler uses that,
		// never a UIN from the URL.
		r.With(middleware.NewBearerAuth(middleware.BearerAuthConfig{
			Manager: mgr,
		})).Post("/bundle", handlers.NewPostBundleHandler(bundleDeps, fetchRegisteredIdentityKey(pgPool)))

		// Authenticated prekey management.
		r.With(middleware.NewBearerAuth(middleware.BearerAuthConfig{
			Manager: mgr,
		})).Post("/prekeys", handlers.NewAddPrekeysHandler(prekeyDeps))

		r.With(middleware.NewBearerAuth(middleware.BearerAuthConfig{
			Manager: mgr,
		})).Get("/prekeys/count", handlers.NewCountPrekeysHandler(prekeyDeps))

		// Health: unauthenticated by design (k8s liveness
		// probes don't carry credentials).
		r.Get("/health", newHealthHandler(pgPool, rdb, VERSION))
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
		log.Printf("[key-service] listening on :%s (version=%s)", cfg.Port, VERSION)
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
		log.Printf("[key-service] received %s; starting graceful shutdown (timeout=%s)", sig, cfg.ShutdownTimeout)
	}

	// Graceful shutdown. Shutdown blocks until in-flight
	// requests finish or the context expires, whichever
	// comes first.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[key-service] graceful shutdown failed: %v", err)
	} else {
		log.Printf("[key-service] http server stopped cleanly")
	}
	log.Printf("[key-service] bye")
}

// ----------------------------------------------------------------------------
// Health handler. Pings Postgres + Redis with a short deadline
// and reports per-dependency status. 200 means both deps are
// reachable; 503 means at least one is degraded.
// ----------------------------------------------------------------------------

func newHealthHandler(pg *pgxpool.Pool, rdb *redis.Client, version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		status := models.KeyServiceHealth{
			Status:       "ok",
			Service:      "key-service",
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

// ----------------------------------------------------------------------------
// Identity-key consistency check.
//
// POST /api/keys/bundle must verify that the identity_key the
// client is uploading matches the one on file at registration
// (the auth-service stores the registration-time key in
// users.identity_key). This is a single SELECT — the handler
// injects it as a closure to keep the keystore ignorant of
// users-table access.
// ----------------------------------------------------------------------------

// fetchRegisteredIdentityKey returns a closure that SELECTs
// users.identity_key for the given UIN. Returning "" means the
// row is missing or the column is empty (which is itself a
// pre-E2EE row that should be treated as "no registered
// key" — the handler will then accept any uploaded key and
// the next step's "registered vs uploaded" comparison is a
// no-op).
func fetchRegisteredIdentityKey(pg *pgxpool.Pool) func(ctx context.Context, uin int64) (string, error) {
	const q = `SELECT identity_key FROM users WHERE uin = $1`
	return func(ctx context.Context, uin int64) (string, error) {
		var key string
		if err := pg.QueryRow(ctx, q, uin).Scan(&key); err != nil {
			return "", err
		}
		return key, nil
	}
}
