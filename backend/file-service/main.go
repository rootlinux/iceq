// Command file-service is the IceQ file-transfer service.
// It mints pre-signed MinIO URLs for file uploads,
// downloads, and avatar updates. The service NEVER sees
// the file bytes themselves — the client PUTs / GETs
// directly against MinIO using the signed URL, so the
// file-service's bandwidth cost is zero and the bytes
// can never be logged, inspected, or transformed by
// this process.
//
// Privacy contract
// ----------------
//
//  1. The original client-supplied name is dropped on
//     the floor. The minio wrapper accepts a name
//     field on the request struct for wire-shape
//     compatibility only — it is never persisted,
//     logged, or included in object keys. Object keys
//     for files are random UUIDs; for avatars,
//     "avatars/<uin>".
//
//  2. UINs appear in object keys only for the avatar
//     bucket (deterministic overwrite). They NEVER
//     appear in any log line, error response, or
//     object key for general file uploads.
//
//  3. The service has no NATS subscribers, no
//     message-storage tables, no access to ciphertext
//     from chat. The only state is a single
//     *minio.Client. A failure of this service does
//     not affect chat delivery or message persistence.
//
// Process shape:
//
//	HTTP request
//	  └─ chi router
//	       ├─ POST /api/files/upload-url         (auth) → handlers.UploadURL
//	       ├─ POST /api/files/download-url       (auth) → handlers.DownloadURL
//	       ├─ POST /api/files/avatar-upload-url  (auth) → handlers.AvatarUploadURL
//	       └─ GET  /health                       (open) → readiness
//
// On SIGINT / SIGTERM the process runs a 10-second graceful
// shutdown: in-flight requests are given time to complete,
// the HTTP server stops accepting new connections, and the
// MinIO client is GC'd via the defer chain.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/iceq/iceq/file-service/handlers"
	"github.com/iceq/iceq/file-service/minio"
	"github.com/iceq/iceq/shared/db"
	"github.com/iceq/iceq/shared/jwt"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/redis/go-redis/v9"
)

// ----------------------------------------------------------------------------
// Build-time info. VERSION is overridable at build time via
//   go build -ldflags "-X main.VERSION=$(git rev-parse --short HEAD)"
// and the linker substitutes it.
// ----------------------------------------------------------------------------

var VERSION = "dev"

// ----------------------------------------------------------------------------
// Configuration. Pulled from environment variables; defaults
// match the docker-compose service hostnames so a developer
// can `go run .` inside the iceq-net network and have DNS
// resolve.
// ----------------------------------------------------------------------------

type config struct {
	Port            string
	MinioEndpoint   string
	MinioAccessKey  string
	MinioSecretKey  string
	MinioUseSSL     bool
	PostgresDSN     string
	JWTSecret       string
	RedisAddr       string
	RedisPassword   string
	ShutdownTimeout time.Duration
}

func loadConfig() config {
	return config{
		Port:            envOr("PORT", "8080"),
		MinioEndpoint:   envOr("ICEQ_MINIO_ENDPOINT", "minio:9000"),
		MinioAccessKey:  envFirst([]string{"ICEQ_MINIO_ACCESS_KEY", "MINIO_ROOT_USER"}, "minio"),
		MinioSecretKey:  envFirst([]string{"ICEQ_MINIO_SECRET_KEY", "MINIO_ROOT_PASSWORD"}, "minio12345"),
		MinioUseSSL:     envBool("ICEQ_MINIO_USE_SSL", false),
		PostgresDSN:     envOr("ICEQ_PG_DSN", "postgres://postgres:postgres@postgres:5432/iceq?sslmode=disable"),
		JWTSecret:       envOr("ICEQ_JWT_SECRET", ""),
		RedisAddr:       envOr("ICEQ_REDIS_ADDR", "redis:6379"),
		RedisPassword:   envOr("ICEQ_REDIS_PASSWORD", ""),
		ShutdownTimeout: 10 * time.Second,
	}
}

func envOr(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return fallback
}

func envFirst(names []string, fallback string) string {
	for _, name := range names {
		if v, ok := os.LookupEnv(name); ok && v != "" {
			return v
		}
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	if v, ok := os.LookupEnv(name); ok {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return fallback
}

// ----------------------------------------------------------------------------
// main. Wires every dependency once, then starts the HTTP
// server. The MinIO client is constructed first so a
// connectivity failure is a fatal startup error, not a
// per-request surprise.
// ----------------------------------------------------------------------------

func main() {
	cfg := loadConfig()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)

	if cfg.JWTSecret == "" {
		log.Fatalf("ICEQ_JWT_SECRET is not set; refusing to start")
	}

	// 30 s ceiling for the whole bootstrap. Most of
	// this is the MinIO probe; if MinIO isn't ready
	// within 30 s, something is fundamentally wrong
	// and the supervisor will restart us.
	bootCtx, bootCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer bootCancel()

	// --- Redis client (needed for the JWT blocklist) ---
	rdb, err := db.NewRedisClient(db.Config{
		RedisAddr:     cfg.RedisAddr,
		RedisPassword: cfg.RedisPassword,
	})
	if err != nil {
		log.Fatalf("redis: %v", err)
	}
	defer func() { _ = rdb.Close() }()
	log.Printf("[file-service] redis: connected to %s", cfg.RedisAddr)

	// --- Postgres pool (needed for the JWT session_epoch check) ---
	// F-5 (JWT assessment): Verify on every authenticated
	// request now reads `users.session_epoch` for the
	// authenticated user. The file-service itself has no
	// other need for Postgres, but the JWT layer does, so we
	// open a pool at boot. Ping fails fast if Postgres is
	// down so we don't get request-timeouts on a misconfigured
	// network path.
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
	log.Printf("[file-service] postgres: connected")

	// --- MinIO client ---
	// New() also does a BucketExists probe; a
	// misconfigured endpoint fails fast here
	// rather than on the first request.
	mc, err := minio.New(bootCtx, minio.Config{
		Endpoint:  cfg.MinioEndpoint,
		AccessKey: cfg.MinioAccessKey,
		SecretKey: cfg.MinioSecretKey,
		UseSSL:    cfg.MinioUseSSL,
	})
	if err != nil {
		log.Fatalf("minio: %v", err)
	}
	log.Printf("[file-service] minio: connected to %s ssl=%v", cfg.MinioEndpoint, cfg.MinioUseSSL)

	// --- JWT manager ---
	mgr, err := jwt.NewManager(cfg.JWTSecret, rdb, pgPool)
	if err != nil {
		log.Fatalf("jwt manager: %v", err)
	}

	// --- HTTP router ---
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(30 * time.Second))
	r.Use(chimw.RequestSize(512)) // 512 B: service only receives metadata, never file bytes
	// No chi.RealIP — the file-service is a backend and
	// MUST NOT log the client's IP. chi's RealIP would
	// rewrite RemoteAddr to the X-Forwarded-For value,
	// which we then must not log; easier to just leave
	// the default.

	// Body-size cap. The pre-signed URL is tiny
	// (~200 bytes); the actual file bytes never touch
	// this process. A 64 KiB cap is generous.
	//
	// chi.Heartbeat is intentionally NOT used here:
	// the file-service's own /health handler returns
	// a JSON body with per-dep status, and a chi
	// Heartbeat short-circuit would shadow it.
	// chi.AllowContentType is not used here — the
	// file-service's own handlers read JSON, and a
	// 415 from chi for non-JSON would shadow the
	// 415 we want to emit for a disallowed content
	// type in the request body.

	h := handlers.New(mc, pgPool)

	// /api/files/* requires BearerAuth. The
	// middleware injects the verified UIN into the
	// request context; the handlers read it back
	// with middleware.GetUIN.
	r.Route("/api/files", func(r chi.Router) {
		r.Use(middleware.NewBearerAuth(middleware.BearerAuthConfig{
			Manager: mgr,
		}))

		rate := func(action string, limit int64) func(http.Handler) http.Handler {
			return middleware.NewAuthenticatedRateLimit(middleware.AuthenticatedRateLimitConfig{Redis: rdb, Action: action, Limit: limit, Window: time.Minute})
		}
		r.With(rate("files:upload", 30)).Post("/upload-url", h.UploadURL)
		r.With(rate("files:download", 60)).Post("/download-url", h.DownloadURL)
		r.With(rate("files:avatar-upload", 10)).Post("/avatar-upload-url", h.AvatarUploadURL)
		r.With(rate("files:grant", 30)).Post("/grants", h.Grant)
		r.With(rate("files:grant:revoke", 30)).Delete("/grants", h.RevokeGrant)
	})

	// /health is unauthenticated. Caddy / k8s liveness
	// probes don't carry credentials.
	r.Get("/health", newHealthHandler(rdb, VERSION))

	// --- HTTP server + graceful shutdown ---
	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		log.Printf("[file-service] listening on :%s (version=%s)", cfg.Port, VERSION)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
		close(serverErr)
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		if err != nil {
			log.Fatalf("http server: %v", err)
		}
	case sig := <-stop:
		log.Printf("[file-service] received %s; starting graceful shutdown (timeout=%s)", sig, cfg.ShutdownTimeout)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[file-service] graceful shutdown failed: %v", err)
	} else {
		log.Printf("[file-service] http server stopped cleanly")
	}
	log.Printf("[file-service] bye")
}

// ----------------------------------------------------------------------------
// Health handler. Pings Redis with a 2-second deadline
// and reports per-dep status. 200 means Redis is
// reachable; 503 means it's degraded. MinIO is not
// re-pinged on every /health call — the boot probe
// already proved the endpoint is reachable, and
// re-probing on every healthcheck would burn a
// request to MinIO for every k8s liveness probe
// (typically 1 Hz). If MinIO goes down, the
// presign-UPDATE handlers will return 500 and the
// kubelet will mark the pod NotReady via the
// readiness probe — which is the right behavior.
// ----------------------------------------------------------------------------

// healthResponse is the JSON shape returned by /health.
// Stable across versions; clients (and the smoke test)
// can decode it directly.
type healthResponse struct {
	Service      string            `json:"service"`
	Version      string            `json:"version"`
	Time         time.Time         `json:"time"`
	Status       string            `json:"status"`
	Dependencies map[string]string `json:"dependencies"`
}

func newHealthHandler(rdb *redis.Client, version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		out := healthResponse{
			Service:      "file-service",
			Version:      version,
			Time:         time.Now().UTC(),
			Status:       "ok",
			Dependencies: map[string]string{},
		}
		allOK := true

		if err := rdb.Ping(ctx).Err(); err != nil {
			out.Dependencies["redis"] = "degraded"
			allOK = false
		} else {
			out.Dependencies["redis"] = "ok"
		}

		if !allOK {
			out.Status = "degraded"
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(out)
	}
}
