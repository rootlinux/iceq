// Command presence-service is the IceQ presence aggregator. It
// owns the canonical "is user X online right now" record in
// Redis, accepts presence-change events from the rest of the
// platform on the presence.update NATS subject, and fans the
// change out to every accepted contact of the user whose
// presence changed.
//
// Process shape:
//
//	HTTP request (internal-only — Docker network)
//	  └─ chi router
//	       ├─ GET  /health                        → readiness
//	       ├─ GET  /api/presence/{uin}            → single user's record
//	       └─ POST /api/presence/bulk             → batch record
//
//	NATS subscribers
//	  ├─ presence.update           → store + fan out to contacts
//	  └─ presence.query.{uin}      → answer a peer's query
//
// On SIGINT / SIGTERM the process runs a 10-second graceful
// shutdown: the HTTP server stops accepting new connections,
// in-flight requests finish, NATS drains, and the Postgres + Redis
// pools are closed.
//
// Privacy contract: this service is the only place in IceQ that
// knows "what is user X's status right now" as a per-record
// fact. We never log a UIN next to a status, never log an IP, and
// never log a user-agent. A failed publish gets a log line with
// the subject and the error string — not the message body.
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
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/iceq/iceq/presence-service/store"
	"github.com/iceq/iceq/shared/db"
	"github.com/iceq/iceq/shared/jwt"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/iceq/iceq/shared/models"
	"github.com/iceq/iceq/shared/natsclient"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// ----------------------------------------------------------------------------
// Build-time info. Mirrors the auth-service / ws-gateway pattern:
//   go build -ldflags "-X main.VERSION=$(git rev-parse --short HEAD)"
// substitutes the linker-set variable. "dev" lets local builds run.
// ----------------------------------------------------------------------------

var VERSION = "dev"

// ----------------------------------------------------------------------------
// Configuration. Pulled from environment variables; defaults match
// the docker-compose service hostnames so a `go run .` inside the
// iceq-net network resolves DNS correctly.
// ----------------------------------------------------------------------------

type config struct {
	Port            string
	NATSURL         string
	RedisAddr       string
	RedisPassword   string
	PostgresDSN     string
	JWTSecret       string
	ShutdownTimeout time.Duration
}

func loadConfig() config {
	return config{
		Port:            envOr("PORT", "8080"),
		NATSURL:         envOr("ICEQ_NATS_URL", "nats://nats:4222"),
		RedisAddr:       envOr("ICEQ_REDIS_ADDR", "redis:6379"),
		RedisPassword:   envOr("ICEQ_REDIS_PASSWORD", ""),
		PostgresDSN:     envOr("ICEQ_PG_DSN", "postgres://postgres:postgres@postgres:5432/iceq?sslmode=disable"),
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
// main. Wires up the dependencies, registers the NATS subscribers,
// and starts the HTTP server. The shutdown sequence below is the
// single place that knows about ordering: NATS drain first (so
// we don't receive new presence.update events mid-shutdown), then
// the HTTP server, then the storage pools.
// ----------------------------------------------------------------------------

func main() {
	cfg := loadConfig()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
	if cfg.JWTSecret == "" {
		log.Fatalf("ICEQ_JWT_SECRET is not set; refusing to start")
	}

	// 30 s ceiling for the whole bootstrap. Each factory has
	// its own tighter internal timeout, but a total budget
	// here ensures we don't hang on a dependency that won't
	// come up.
	bootCtx, bootCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer bootCancel()

	// --- Postgres pool ------------------------------------------------
	// Used for the contact-fan-out query in the presence.update
	// handler. We don't keep a long-lived connection here
	// beyond the pool's idle baseline; the query is bounded
	// (5 s timeout inside the handler) so a missing PG
	// surfaces as a logged error rather than a hung request.
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
	log.Printf("[presence-service] postgres: connected")

	// --- Redis client --------------------------------------------------
	// The presence hash lives here. The store wraps the
	// client; main only sees the wrapper.
	rdb, err := db.NewRedisClient(db.Config{
		RedisAddr:     cfg.RedisAddr,
		RedisPassword: cfg.RedisPassword,
	})
	if err != nil {
		log.Fatalf("redis: %v", err)
	}
	defer func() { _ = rdb.Close() }()
	log.Printf("[presence-service] redis: connected to %s", cfg.RedisAddr)

	presenceStore := store.New(rdb)
	mgr, err := jwt.NewManager(cfg.JWTSecret, rdb, pgPool)
	if err != nil {
		log.Fatalf("jwt manager: %v", err)
	}

	// --- NATS bus ------------------------------------------------------
	// Connect first; if NATS is down, the service is useless
	// (we'd silently drop presence.update events) so we
	// fail-fast rather than start in a degraded mode.
	bus, err := natsclient.NewClient(cfg.NATSURL, "presence-service")
	if err != nil {
		log.Fatalf("nats: %v", err)
	}
	log.Printf("[presence-service] nats: connected to %s", cfg.NATSURL)

	// Register the two NATS subscribers. The fan-out handler
	// owns the contact lookup; the query handler is a thin
	// request/reply.
	if err := startNATSSubscribers(bus, presenceStore, pgPool); err != nil {
		log.Fatalf("nats subscribe: %v", err)
	}

	// --- HTTP router ---------------------------------------------------
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(30 * time.Second))
	r.Use(chimw.RequestSize(1 << 20)) // 1 MiB max body

	// /health is unauthenticated. Presence reads require an access
	// token and enforce self-or-accepted-contact authorization.
	r.Get("/health", newHealthHandler(presenceStore, pgPool, bus, VERSION))
	r.Route("/api/presence", func(r chi.Router) {
		r.Use(middleware.NewBearerAuth(middleware.BearerAuthConfig{Manager: mgr}))
		r.Get("/{uin}", newGetPresenceHandler(presenceStore, pgPool))
		r.Post("/bulk", newGetBulkPresenceHandler(presenceStore, pgPool))
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

	serverErr := make(chan error, 1)
	go func() {
		log.Printf("[presence-service] listening on :%s (version=%s)", cfg.Port, VERSION)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
		close(serverErr)
	}()

	// Wait for a fatal server error or a shutdown signal.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		if err != nil {
			log.Fatalf("http server: %v", err)
		}
	case sig := <-stop:
		log.Printf("[presence-service] received %s; starting graceful shutdown (timeout=%s)", sig, cfg.ShutdownTimeout)
	}

	// Graceful shutdown. The ordering is intentional: stop
	// the HTTP server first (no more queries from internal
	// services), then drain NATS (let any in-flight handler
	// finish), then close the storage pools via the deferred
	// Close() calls.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[presence-service] graceful shutdown failed: %v", err)
	} else {
		log.Printf("[presence-service] http server stopped cleanly")
	}
	if err := bus.Drain(); err != nil {
		log.Printf("[presence-service] nats drain failed: %v", err)
	} else {
		log.Printf("[presence-service] nats drained")
	}
	log.Printf("[presence-service] bye")
}

// ----------------------------------------------------------------------------
// NATS subscribers. The two topics we care about are
// `presence.update` (the canonical "X's status changed" event
// from the ws-gateway or anywhere else) and `presence.query.{uin}`
// (a peer's on-demand lookup).
// ----------------------------------------------------------------------------

// startNATSSubscribers wires the two NATS subscriptions. Errors
// at subscribe-time are fatal: a service that thinks it has
// listeners but actually has none is worse than a service that
// crashes and restarts.
//
// `bus` is the natsclient wrapper, `ps` is the store layer,
// `pg` is the pool used for the contact-fan-out query.
func startNATSSubscribers(bus *natsclient.Client, ps *store.PresenceStore, pg *pgxpool.Pool) error {
	// 1. presence.update — the canonical event source. The
	//    payload envelope is the same Envelope the
	//    ws-gateway publishes; we unmarshal once into the
	//    shared model and then act on the PresencePayload
	//    inside.
	if _, err := bus.Subscribe("presence.update", func(m *nats.Msg) {
		handlePresenceUpdate(bus, ps, pg, m.Data)
	}); err != nil {
		return err
	}

	// 2. presence.query.{uin} — request/reply. The publisher
	//    subscribes to presence.response.{uin} before
	//    sending the query; we just publish on the
	//    response subject derived from the inbound subject.
	//
	//    The query is also answered by the HTTP route
	//    /api/presence/{uin}; the NATS path is the
	//    in-bus alternative that avoids a TCP hop back to
	//    the ws-gateway when a peer's already-registered
	//    handler is on the same process.
	if _, err := bus.Subscribe("presence.query.*", func(m *nats.Msg) {
		handlePresenceQuery(bus, ps, m.Subject, m.Data)
	}); err != nil {
		return err
	}

	return nil
}

// handlePresenceUpdate is the fan-out handler. It is the only
// piece of business logic in this file: store the new status,
// look up the user's accepted contacts, and publish a notify
// envelope to each contact's subject.
//
// Privacy: the log lines here intentionally do NOT include the
// UIN, the status, or the contact list. We log only that the
// handler ran and whether the publish succeeded. The presence
// state is recoverable from the store, so a leaked log line
// would only help an attacker, not the operator.
func handlePresenceUpdate(bus *natsclient.Client, ps *store.PresenceStore, pg *pgxpool.Pool, data []byte) {
	// Unwrap the envelope first. A malformed envelope
	// (the bus is shared, any publisher can spam it) is
	// dropped silently.
	var env models.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return
	}
	var p models.PresencePayload
	if err := json.Unmarshal(env.Payload, &p); err != nil {
		return
	}
	if p.UIN == 0 {
		return
	}
	if !store.IsValidStatus(p.Status) {
		// Publisher bug — do not pollute the keyspace.
		return
	}

	// 1. Persist the new status. SetStatus picks the right
	//    TTL based on the status string; we don't need to
	//    branch here.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := ps.SetStatus(ctx, p.UIN, p.Status); err != nil {
		// Log the error but don't crash the handler —
		// the next heartbeat from the same user will
		// re-write the key.
		log.Printf("[presence-service] set status: %v", err)
		return
	}

	// 2. Look up who should be notified. The query is
	//    "who has me as an accepted contact?" — that is
	//    the set of users who have added me to their
	//    contact list and whose request I have accepted.
	//    Those are the watchers of MY presence.
	const q = `SELECT owner_uin FROM contacts WHERE target_uin = $1 AND status = 'accepted'`
	rows, err := pg.Query(ctx, q, p.UIN)
	if err != nil {
		log.Printf("[presence-service] contact lookup: %v", err)
		return
	}
	defer rows.Close()
	var watchers []int64
	for rows.Next() {
		var u int64
		if err := rows.Scan(&u); err == nil {
			watchers = append(watchers, u)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("[presence-service] contact rows: %v", err)
		return
	}

	// 3. Build the per-watcher notify envelope. We build
	//    it once and reuse the bytes for every publish —
	//    the watcher-specific subject is the only thing
	//    that changes.
	notifyEnv, err := models.NewEnvelope(models.EnvelopeTypePresence, models.PresencePayload{
		UIN:    p.UIN,
		Status: p.Status,
		TS:     time.Now().UTC().UnixMilli(),
	})
	if err != nil {
		log.Printf("[presence-service] marshal notify: %v", err)
		return
	}
	notifyBytes, err := json.Marshal(notifyEnv)
	if err != nil {
		log.Printf("[presence-service] marshal notify: %v", err)
		return
	}

	// 4. Fan out. Per-publish error is logged but does
	//    not abort the loop — one bad subscriber
	//    shouldn't hide the change from the rest.
	for _, watcher := range watchers {
		subject := "presence.notify." + strconv.FormatInt(watcher, 10)
		if err := bus.Publish(subject, notifyBytes); err != nil {
			log.Printf("[presence-service] notify publish: %v", err)
		}
	}
}

// handlePresenceQuery answers a single peer's
// presence.query.{uin} request with a presence.response.{uin}
// reply. The request body is empty; the subject encodes the
// querier's identity (used to derive the response subject).
//
// The handler is best-effort: a failed store read logs and
// drops. A failed publish is logged too; the requester will
// time out and (presumably) retry via the HTTP path.
func handlePresenceQuery(bus *natsclient.Client, ps *store.PresenceStore, subject string, _ []byte) {
	// Subject looks like "presence.query.1234"; we want
	// the trailing UIN so we can answer the right user.
	uinStr, ok := subjectTail(subject, "presence.query.")
	if !ok {
		return
	}
	uin, err := strconv.ParseInt(uinStr, 10, 64)
	if err != nil || uin == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	state, err := ps.GetPresence(ctx, uin)
	if err != nil {
		log.Printf("[presence-service] query read: %v", err)
		return
	}

	respEnv, err := models.NewEnvelope(models.EnvelopeTypePresence, models.PresencePayload{
		UIN:    uin,
		Status: state.Status,
		TS:     state.LastSeen,
	})
	if err != nil {
		return
	}
	respBytes, err := json.Marshal(respEnv)
	if err != nil {
		return
	}
	respSubject := "presence.response." + uinStr
	if err := bus.Publish(respSubject, respBytes); err != nil {
		log.Printf("[presence-service] query reply: %v", err)
	}
}

// subjectTail returns the substring of `subject` that follows
// `prefix`, and a bool indicating whether the prefix was
// present. Returns ("", false) for subjects that do not have
// the prefix, which the handler uses to drop malformed input.
func subjectTail(subject, prefix string) (string, bool) {
	if !strings.HasPrefix(subject, prefix) {
		return "", false
	}
	return subject[len(prefix):], true
}

// ----------------------------------------------------------------------------
// HTTP handlers.
// ----------------------------------------------------------------------------

type presenceReader interface {
	GetPresence(context.Context, int64) (*store.PresenceState, error)
	GetBulkPresence(context.Context, []int64) (map[int64]*store.PresenceState, error)
}

type contactChecker interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

const acceptedContactQuery = `
	SELECT EXISTS (
		SELECT 1 FROM contacts
		WHERE owner_uin = $1 AND target_uin = $2 AND status = 'accepted'
	)`

func mayReadPresence(ctx context.Context, contacts contactChecker, actorUIN, targetUIN int64) (bool, error) {
	if actorUIN == targetUIN {
		return true, nil
	}
	var accepted bool
	if err := contacts.QueryRow(ctx, acceptedContactQuery, actorUIN, targetUIN).Scan(&accepted); err != nil {
		return false, err
	}
	return accepted, nil
}

// newGetPresenceHandler serves GET /api/presence/{uin}.
//
// BearerAuth supplies the actor UIN. The actor may read their own
// record or an accepted contact's record. Unrelated and nonexistent
// targets share the same 404 response to avoid account enumeration.
func newGetPresenceHandler(ps presenceReader, contacts contactChecker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actorUIN, ok := middleware.GetUIN(r.Context())
		if !ok || actorUIN <= 0 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		uinStr := chi.URLParam(r, "uin")
		uin, err := strconv.ParseInt(uinStr, 10, 64)
		if err != nil || uin <= 0 {
			http.Error(w, "invalid uin", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		allowed, err := mayReadPresence(ctx, contacts, actorUIN, uin)
		if err != nil {
			http.Error(w, "authorization error", http.StatusInternalServerError)
			return
		}
		if !allowed {
			http.Error(w, "presence not found", http.StatusNotFound)
			return
		}
		state, err := ps.GetPresence(ctx, uin)
		if err != nil {
			http.Error(w, "store error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(state)
	}
}

// newGetBulkPresenceHandler serves POST /api/presence/bulk with
// a JSON body of the form {"uins": [int, int, ...]}.
//
// The response is a JSON object keyed by UIN-as-string with
// PresenceState values; missing keys are still present in the
// response (offline sentinel) so the client can iterate the
// input list without nil-checking the response.
//
// The body is bounded: we cap the input at 500 UINs to keep
// the Redis pipeline within a sane round-trip cost. A larger
// request is rejected with 413.
func newGetBulkPresenceHandler(ps presenceReader, contacts contactChecker) http.HandlerFunc {
	const maxBulk = 500
	return func(w http.ResponseWriter, r *http.Request) {
		actorUIN, ok := middleware.GetUIN(r.Context())
		if !ok || actorUIN <= 0 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct {
			UINs []int64 `json:"uins"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if len(req.UINs) == 0 {
			// Empty input is not an error; return an
			// empty map (not null) for a stable
			// client-side shape.
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = w.Write([]byte("{}"))
			return
		}
		if len(req.UINs) > maxBulk {
			http.Error(w, "too many uins", http.StatusRequestEntityTooLarge)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		authorized := make([]int64, 0, len(req.UINs))
		seen := make(map[int64]struct{}, len(req.UINs))
		for _, targetUIN := range req.UINs {
			if targetUIN <= 0 {
				continue
			}
			if _, duplicate := seen[targetUIN]; duplicate {
				continue
			}
			seen[targetUIN] = struct{}{}
			allowed, err := mayReadPresence(ctx, contacts, actorUIN, targetUIN)
			if err != nil {
				http.Error(w, "authorization error", http.StatusInternalServerError)
				return
			}
			if allowed {
				authorized = append(authorized, targetUIN)
			}
		}
		states, err := ps.GetBulkPresence(ctx, authorized)
		if err != nil {
			http.Error(w, "store error", http.StatusInternalServerError)
			return
		}
		// Marshal as a string-keyed map so JSON output
		// has stable shape regardless of int64
		// serialization quirks across clients.
		out := make(map[string]*store.PresenceState, len(states))
		for k, v := range states {
			out[strconv.FormatInt(k, 10)] = v
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(out)
	}
}

// newHealthHandler pings every dependency with a 2-second
// deadline and reports per-dep status. The 200 vs 503 choice
// is the same as the auth-service: 200 when everything is
// reachable, 503 when at least one is degraded.
func newHealthHandler(ps *store.PresenceStore, pg *pgxpool.Pool, bus *natsclient.Client, version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		deps := map[string]string{}

		// Redis: a HGETALL on a key we know exists
		// (the store itself writes one for any user who
		// has ever been online). A simpler PING would do,
		// but a PING succeeds even on a read-only
		// replica; HGETALL exercises the same code path
		// the bulk handler uses.
		if _, err := ps.GetPresence(ctx, 0); err != nil {
			deps["redis"] = err.Error()
		} else {
			deps["redis"] = "ok"
		}

		if err := pg.Ping(ctx); err != nil {
			deps["postgres"] = err.Error()
		} else {
			deps["postgres"] = "ok"
		}

		if !bus.IsConnected() {
			deps["nats"] = "not connected"
		} else {
			deps["nats"] = "ok"
		}

		status := "ok"
		code := http.StatusOK
		for _, v := range deps {
			if v != "ok" {
				status = "degraded"
				code = http.StatusServiceUnavailable
				break
			}
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":       status,
			"service":      "presence-service",
			"version":      version,
			"time":         time.Now().UTC(),
			"dependencies": deps,
		})
	}
}
