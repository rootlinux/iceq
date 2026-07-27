// Command ws-gateway is the IceQ WebSocket gateway. It is the
// real-time transport for chat: every connected client gets a
// WebSocket here, every chat envelope is JSON-encoded and
// routed to a NATS subject, every inbound NATS message is
// fanned out to the recipient's local connections (or queued
// in Redis for offline users).
//
// The gateway is a *transport router* — it does not store
// ciphertext, does not perform key exchange, does not inspect
// the contents of an envelope. Its only responsibilities are:
//
//  1. Authenticate the connection (JWT, access token type).
//  2. Enforce the per-message wipe check (panic-wipe
//     blocklist).
//  3. Rate-limit inbound messages.
//  4. Publish on the right NATS subject.
//  5. Deliver inbound NATS messages to the right local
//     connection (or queue them if the user is offline).
//
// Process shape:
//
//	HTTP request (upgrade)
//	  └─ chi router
//	       ├─ GET  /ws       → client.ServeHTTP  (the WebSocket)
//	       ├─ GET  /health   → 200 OK
//	       └─ NATS subscribers (msg.direct.*, msg.group.*)
//
// On SIGINT / SIGTERM the process runs a 15-second graceful
// shutdown: stop accepting new WS upgrades, drain the NATS
// connection, exit.
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
	"github.com/iceq/iceq/shared/db"
	"github.com/iceq/iceq/shared/jwt"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/iceq/iceq/shared/natsclient"
	"github.com/iceq/iceq/ws-gateway/client"
	"github.com/iceq/iceq/ws-gateway/hub"
	"github.com/iceq/iceq/ws-gateway/router"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
)

// VERSION is overridable at build time via
//
//	go build -ldflags "-X main.VERSION=$(git rev-parse --short HEAD)"
var VERSION = "dev"

// ----------------------------------------------------------------------------
// Configuration. Everything the process needs is pulled from
// environment variables in loadConfig(). Defaults match the
// docker-compose service hostnames so a developer can `go run .`
// inside the iceq-net network and have DNS resolve.
// ----------------------------------------------------------------------------

type config struct {
	Port            string
	NATSURL         string
	RedisAddr       string
	RedisPassword   string
	JWTSecret       string
	PostgresDSN     string
	ShutdownTimeout time.Duration
}

func loadConfig() config {
	return config{
		Port:            envOr("PORT", "8082"),
		NATSURL:         envOr("ICEQ_NATS_URL", "nats://nats:4222"),
		RedisAddr:       envOr("ICEQ_REDIS_ADDR", "redis:6379"),
		RedisPassword:   envOr("ICEQ_REDIS_PASSWORD", ""),
		JWTSecret:       envOr("ICEQ_JWT_SECRET", ""),
		PostgresDSN:     envOr("ICEQ_PG_DSN", "postgres://postgres:postgres@postgres:5432/iceq?sslmode=disable"),
		ShutdownTimeout: 15 * time.Second,
	}
}

func envOr(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return fallback
}

// ----------------------------------------------------------------------------
// main. Wire every dependency once, then start the HTTP server
// and the NATS subscribers. The subscribers start BEFORE the
// HTTP server so an inbound NATS message that arrives
// milliseconds after main() returns already has a Hub to land
// in.
// ----------------------------------------------------------------------------

func main() {
	cfg := loadConfig()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)

	if cfg.JWTSecret == "" {
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
	log.Printf("[ws-gateway] postgres: connected")

	// --- Redis client --------------------------------------------------
	rdb, err := db.NewRedisClient(db.Config{
		RedisAddr:     cfg.RedisAddr,
		RedisPassword: cfg.RedisPassword,
	})
	if err != nil {
		log.Fatalf("redis: %v", err)
	}
	defer func() { _ = rdb.Close() }()
	log.Printf("[ws-gateway] redis: connected to %s", cfg.RedisAddr)

	// --- NATS ---------------------------------------------------------
	nc, err := natsclient.NewClient(cfg.NATSURL, "ws-gateway")
	if err != nil {
		log.Fatalf("nats: %v", err)
	}
	defer func() { _ = nc.Drain() }()
	log.Printf("[ws-gateway] nats: connected to %s", cfg.NATSURL)

	// --- JWT manager ---------------------------------------------------
	// The ws-gateway does not WRITE to session_epoch, but its
	// Verify path READS it on every WebSocket auth frame, so
	// the pool has to be in scope at construction time.
	mgr, err := jwt.NewManager(cfg.JWTSecret, rdb, pgPool)
	if err != nil {
		log.Fatalf("jwt manager: %v", err)
	}

	// --- Hub -----------------------------------------------------------
	h := hub.New(rdb)
	pollStore := router.NewRedisPollStore(rdb)
	acceptanceStore := router.NewRecipientAcceptanceStore(rdb)
	js, err := nc.Conn().JetStream()
	if err != nil {
		log.Fatalf("jetstream context: %v", err)
	}
	deliveryCtx, stopDelivery := context.WithCancel(context.Background())
	if err := startDeliveryConsumer(deliveryCtx, js, acceptanceStore, h, nc); err != nil {
		stopDelivery()
		log.Fatalf("durable delivery consumer: %v", err)
	}

	// Wire Core NATS subscribers for real-time fanout. Without these,
	// msg.direct.*, msg.group.*, and notification.* are dead letters —
	// the auth-service's publish to notification.<uin> reaches nobody,
	// and contact requests/acceptances are invisible until manual reload.
	if err := startNATSSubscribers(nc, h, pgPool); err != nil {
		log.Fatalf("nats subscribers: %v", err)
	}

	// --- Shared client deps (passed to every WebSocket) ---------------
	deps := client.Deps{
		NATS:                nc,
		Hub:                 h,
		Redis:               rdb,
		Manager:             mgr,
		PG:                  pgPool,
		Dispatch:            router.Dispatch,
		RecipientQueueAcker: acceptanceStore,
		WakeAccepted: func(ctx context.Context, uin int64) error {
			return replayAccepted(ctx, acceptanceStore, h, uin)
		},
		ConnectRateLimiter: middleware.NewAuthenticatedRateLimiter(middleware.AuthenticatedRateLimitConfig{
			Redis: rdb, Action: "ws:connect", Limit: 20, Window: time.Minute,
		}),
		FrameRateLimiter: middleware.NewAuthenticatedRateLimiter(middleware.AuthenticatedRateLimitConfig{
			Redis: rdb, Action: "ws:frame", Limit: 30, Window: time.Minute, Timeout: 200 * time.Millisecond,
		}),
	}

	// --- HTTP server ---------------------------------------------------
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.Recoverer)
	r.Use(chimw.RequestSize(1 << 20)) // 1 MiB max body
	// No chi.RealIP — the gateway is a transport router and
	// MUST NOT log the client's IP.

	// /ws: no Timeout — WebSocket connections are long-lived.
	r.Get("/ws", func(w http.ResponseWriter, req *http.Request) {
		client.ServeHTTP(deps, w, req)
	})
	authMW := middleware.NewBearerAuth(middleware.BearerAuthConfig{Manager: mgr})
	pollRate := middleware.NewAuthenticatedRateLimit(middleware.AuthenticatedRateLimitConfig{
		Redis: rdb, Action: "transport:poll", Limit: 120, Window: time.Minute, Timeout: 200 * time.Millisecond,
	})
	// Timeout exceeds MaxPollWait slightly so JSON serialization can finish;
	// request cancellation propagates through Redis XREAD.
	r.With(authMW, pollRate, chimw.Timeout(30*time.Second)).Get("/api/transport/poll", router.NewPollHandler(pollStore).ServeHTTP)
	sendRate := middleware.NewAuthenticatedRateLimit(middleware.AuthenticatedRateLimitConfig{
		Redis: rdb, Action: "transport:send", Limit: 30, Window: time.Minute, Timeout: 200 * time.Millisecond,
	})
	r.With(authMW, sendRate, chimw.Timeout(10*time.Second)).Post("/api/transport/send", router.NewSendHandler(router.SendDeps{
		Ingester: nc, Groups: router.NewPGGroupSendAuthorizer(pgPool),
	}).ServeHTTP)
	// /health: standard 30 s timeout (short-lived probe).
	r.With(chimw.Timeout(30*time.Second)).Get("/health", newHealthHandler(pgPool, rdb, nc, js, VERSION))

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		// The HTTP server is only carrying the WS upgrade
		// and /health; long-lived connections are
		// WebSocket frames which the nhooyr library
		// manages internally. We keep Read/Write timeouts
		// modest so a stale connection doesn't pin a
		// goroutine past 60s.
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Run the server in a goroutine so the main goroutine
	// can block on the signal channel.
	serverErr := make(chan error, 1)
	go func() {
		log.Printf("[ws-gateway] listening on :%s (version=%s)", cfg.Port, VERSION)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
		close(serverErr)
	}()

	// Wait for either a fatal server error or a shutdown
	// signal.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		if err != nil {
			log.Fatalf("http server: %v", err)
		}
	case sig := <-stop:
		log.Printf("[ws-gateway] received %s; starting graceful shutdown (timeout=%s)", sig, cfg.ShutdownTimeout)
	}

	// Graceful shutdown. Shutdown blocks until in-flight
	// requests finish or the context expires. WebSocket
	// connections are NOT closed by Shutdown — nhooyr's
	// library keeps the connection open until the client
	// or the read-loop closes it. The 15 s timeout is the
	// upper bound for HTTP request draining; WS
	// connections are not part of the count.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	stopDelivery()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[ws-gateway] graceful shutdown failed: %v", err)
	}
	log.Printf("[ws-gateway] bye")
}

// ----------------------------------------------------------------------------
// NATS subscribers. Each subscription handler is a small
// closure over the hub; the spec's two subjects are covered
// (msg.direct.*, msg.group.*).
//
// presence-service is the canonical handler for the
// canonical "X's status changed" subject; ws-gateway only
// consumes the downstream "presence.notify.{uin}" subjects,
// and that subscription is per-connection (see
// client.presenceNotifyHandler). acks flow directly back to
// the sender through the router with no NATS round trip, so
// the gateway has nothing to do on those subjects either.
// ----------------------------------------------------------------------------

// startNATSSubscribers subscribes to every NATS subject the
// gateway cares about and returns the first error. All
// subscriptions live for the lifetime of the process; the
// returned *natsclient.Client's Drain handles the teardown
// during shutdown.
func startNATSSubscribers(nc *natsclient.Client, h *hub.Hub, pg *pgxpool.Pool) error {
	// 1. msg.direct.* — fan out to the recipient's local
	//    connection(s), or enqueue if offline.
	if _, err := nc.Subscribe("msg.direct.*", func(m *natsMsg) {
		// Subject is "msg.direct.<uin>". Parse the
		// trailing token. The wildcard is a single
		// token so a non-numeric tail won't match
		// unless we have a non-numeric recipient,
		// which we don't.
		uin, ok := parseTailUIN(m.Subject, "msg.direct.")
		if !ok {
			return
		}
		// Send. Hub.Send handles the offline-enqueue
		// path automatically.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := h.Send(ctx, uin, m.Data); err != nil {
			log.Printf("[ws-gateway] direct fanout: %v", err)
		}
	}); err != nil {
		return err
	}

	// 2. msg.group.* — fan out to every member of the
	//    group. Membership is in PG; the handler queries
	//    once per inbound message and uses Hub.Broadcast.
	if _, err := nc.Subscribe("msg.group.*", func(m *natsMsg) {
		groupID, ok := parseTail(m.Subject, "msg.group.")
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// SELECT uin FROM group_members WHERE group_id = $1
		const q = `SELECT uin FROM group_members WHERE group_id = $1`
		rows, err := pg.Query(ctx, q, groupID)
		if err != nil {
			log.Printf("[ws-gateway] group members: %v", err)
			return
		}
		defer rows.Close()
		var uins []int64
		for rows.Next() {
			var u int64
			if err := rows.Scan(&u); err == nil {
				uins = append(uins, u)
			}
		}
		if err := rows.Err(); err != nil {
			log.Printf("[ws-gateway] group members iter: %v", err)
			return
		}
		h.Broadcast(ctx, uins, m.Data)
	}); err != nil {
		return err
	}

	// 3. notification.* — server-originated user-visible events (contact
	//    requests, group invites; see NotificationKind* in
	//    shared/models/envelope.go). Without this subscription the
	//    auth-service's publish to notification.<uin> is a dead end: the
	//    recipient only learns about the pending row on their next manual
	//    GET /api/contacts or /api/groups poll. Hub.Send gives us the same
	//    live-delivery + bounded offline-queue semantics as msg.direct.
	if _, err := nc.Subscribe("notification.*", func(m *natsMsg) {
		uin, ok := parseTailUIN(m.Subject, "notification.")
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := h.Send(ctx, uin, m.Data); err != nil {
			log.Printf("[ws-gateway] notification fanout: %v", err)
		}
	}); err != nil {
		return err
	}

	return nil
}

// ----------------------------------------------------------------------------
// Small helpers. parseTail / parseTailUIN split the trailing
// token of a NATS subject; natsMsg is a thin alias for the
// upstream type so the closures above read like prose.
// ----------------------------------------------------------------------------

// natsMsg is a re-alias of the upstream nats.Msg so the
// handler signatures in startNATSSubscribers read like
// documentation rather than noise.
type natsMsg = nats.Msg

// parseTail returns the token after a subject prefix.
// Returns ("", false) if the subject is shorter than the
// prefix; in that case the handler drops the message.
func parseTail(subject, prefix string) (string, bool) {
	if len(subject) <= len(prefix) {
		return "", false
	}
	return subject[len(prefix):], true
}

// parseTailUIN is parseTail specialized to int64. We do NOT
// use a wildcard split because the upstream nats library
// already only delivers a single subject (msg.direct.* is a
// single-token wildcard).
func parseTailUIN(subject, prefix string) (int64, bool) {
	s, ok := parseTail(subject, prefix)
	if !ok {
		return 0, false
	}
	uin, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return uin, true
}

// ----------------------------------------------------------------------------
// Health handler. Pings PG + Redis + NATS; reports status.
// 200 means all three are reachable; 503 means at least one
// is degraded.
// ----------------------------------------------------------------------------

func newHealthHandler(pg *pgxpool.Pool, rdb *redis.Client, nc *natsclient.Client, js nats.JetStreamContext, version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		out := map[string]any{
			"service":      "ws-gateway",
			"version":      version,
			"time":         time.Now().UTC(),
			"dependencies": map[string]string{},
		}
		deps := out["dependencies"].(map[string]string)
		allOK := true
		if err := pg.Ping(ctx); err != nil {
			deps["postgres"] = "degraded"
			allOK = false
		} else {
			deps["postgres"] = "ok"
		}
		if err := rdb.Ping(ctx).Err(); err != nil {
			deps["redis"] = "degraded"
			allOK = false
		} else {
			deps["redis"] = "ok"
		}
		if !nc.IsConnected() {
			deps["nats"] = "degraded"
			allOK = false
		} else {
			deps["nats"] = "ok"
		}
		if js == nil {
			deps["jetstream_consumer"] = "degraded"
			allOK = false
		} else if _, err := js.ConsumerInfo(deliveryStreamName, deliveryConsumerDurable, nats.Context(ctx)); err != nil {
			deps["jetstream_consumer"] = "degraded"
			allOK = false
		} else {
			deps["jetstream_consumer"] = "ok"
		}
		status := "ok"
		code := http.StatusOK
		if !allOK {
			status = "degraded"
			code = http.StatusServiceUnavailable
		}
		out["status"] = status

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(out)
	}
}
