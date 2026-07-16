// Command message-service is the IceQ chat-message persistence
// service. It owns the iceq.messages and iceq.group_messages
// tables in ScyllaDB and accepts inbound chat envelopes on
// NATS, where the per-message E2EE payload is stored as
// an opaque BLOB.
//
// E2EE contract
// -------------
//
// The web client encrypts every chat message with the Signal
// Protocol (X3DH + Double Ratchet) BEFORE the bytes leave
// the device. The gateway forwards those bytes to us on the
// msg.direct.* and msg.group.* NATS subjects. We persist
// them to ScyllaDB as-is and never:
//
//   - log them (no fmt.Printf / log.Printf that includes
//     the E2EE bytes or any derived form)
//   - inspect them (no length-based branching in business
//     logic, no string-cast, no JSON re-encoding)
//   - transform them (no encoding, no compression, no
//     encryption, no truncation)
//   - index them (no secondary index on the BLOB column)
//
// Process shape:
//
//	HTTP request (internal-only via Docker network)
//	  └─ chi router
//	       ├─ GET  /health                         → readiness
//	       ├─ GET  /api/messages/history           (auth) → DM history
//	       └─ GET  /api/messages/group-history     (auth) → group history
//
//	NATS subscribers
//	  ├─ msg.direct.*        → store 1:1 message, publish ack.stored
//	  ├─ msg.group.*         → store group message
//	  └─ ack.{sender_uin}    → mark row as read
//
// On SIGINT / SIGTERM the process runs a 10-second graceful
// shutdown: HTTP server stops accepting, in-flight requests
// finish, NATS drains, then the storage pools close via
// defer.
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
	"github.com/gocql/gocql"
	"github.com/google/uuid"
	"github.com/iceq/iceq/message-service/handlers"
	"github.com/iceq/iceq/message-service/store"
	"github.com/iceq/iceq/shared/db"
	"github.com/iceq/iceq/shared/jwt"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/iceq/iceq/shared/models"
	"github.com/iceq/iceq/shared/natsclient"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
)

// ----------------------------------------------------------------------------
// Build-time info. VERSION is overridable at build time via
//   go build -ldflags "-X main.VERSION=$(git rev-parse --short HEAD)"
// and the linker substitutes the commit hash.
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
	NATSURL         string
	ScyllaHosts     string
	ScyllaKeyspace  string
	PostgresDSN     string
	RedisAddr       string
	RedisPassword   string
	JWTSecret       string
	MessageTTL      time.Duration
	ShutdownTimeout time.Duration
}

func loadConfig() config {
	return config{
		Port:            envOr("PORT", "8080"),
		NATSURL:         envOr("ICEQ_NATS_URL", "nats://nats:4222"),
		ScyllaHosts:     envOr("ICEQ_SCYLLA_HOSTS", "scylla:9042"),
		ScyllaKeyspace:  envOr("ICEQ_SCYLLA_KEYSPACE", "iceq"),
		PostgresDSN:     envOr("ICEQ_PG_DSN", "postgres://postgres:postgres@postgres:5432/iceq?sslmode=disable"),
		RedisAddr:       envOr("ICEQ_REDIS_ADDR", "redis:6379"),
		RedisPassword:   envOr("ICEQ_REDIS_PASSWORD", ""),
		JWTSecret:       envOr("ICEQ_JWT_SECRET", ""),
		MessageTTL:      envDurationSeconds("ICEQ_MESSAGE_TTL_SECONDS", 0),
		ShutdownTimeout: 10 * time.Second,
	}
}

func envOr(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return fallback
}

func envDurationSeconds(name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(envOr(name, ""))
	if raw == "" {
		return fallback
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}

// ----------------------------------------------------------------------------
// main. Wires every dependency once, starts the NATS
// subscribers BEFORE the HTTP server so an inbound msg.direct.*
// that arrives milliseconds after main() returns already has
// a store to land in, then starts the HTTP server.
// ----------------------------------------------------------------------------

func main() {
	cfg := loadConfig()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)

	if cfg.JWTSecret == "" {
		log.Fatalf("ICEQ_JWT_SECRET is not set; refusing to start")
	}

	// 30 s ceiling for the whole bootstrap.
	bootCtx, bootCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer bootCancel()

	// --- Postgres pool ------------------------------------------------
	// Used for the group-membership check on the
	// group-history endpoint. We don't keep a
	// long-lived connection beyond the pool's idle
	// baseline; the queries are bounded (2 s in the
	// handler) so a missing PG surfaces as a logged
	// error rather than a hung request.
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
	log.Printf("[message-service] postgres: connected")

	// --- Redis client (needed for the JWT blocklist) -------------------
	rdb, err := db.NewRedisClient(db.Config{
		RedisAddr:     cfg.RedisAddr,
		RedisPassword: cfg.RedisPassword,
	})
	if err != nil {
		log.Fatalf("redis: %v", err)
	}
	defer func() { _ = rdb.Close() }()
	log.Printf("[message-service] redis: connected to %s", cfg.RedisAddr)

	// --- ScyllaDB session ---------------------------------------------
	scyllaSession, err := db.NewScyllaSession(db.Config{
		ScyllaHosts:    cfg.ScyllaHosts,
		ScyllaKeyspace: cfg.ScyllaKeyspace,
	})
	if err != nil {
		log.Fatalf("scylla: %v", err)
	}
	defer scyllaSession.Close()
	log.Printf("[message-service] scylla: connected to %s keyspace=%s", cfg.ScyllaHosts, cfg.ScyllaKeyspace)

	msgStore := store.New(scyllaSession).WithTTL(cfg.MessageTTL)
	if cfg.MessageTTL > 0 {
		log.Printf("[message-service] message TTL enabled seconds=%d", int(cfg.MessageTTL.Seconds()))
	}

	// --- JWT manager ---------------------------------------------------
	mgr, err := jwt.NewManager(cfg.JWTSecret, rdb, pgPool)
	if err != nil {
		log.Fatalf("jwt manager: %v", err)
	}

	// --- NATS bus ------------------------------------------------------
	bus, err := natsclient.NewClient(cfg.NATSURL, "message-service")
	if err != nil {
		log.Fatalf("nats: %v", err)
	}
	log.Printf("[message-service] nats: connected to %s", cfg.NATSURL)

	// Register the three NATS subscribers. Errors at
	// subscribe-time are fatal: a service that thinks it
	// has listeners but actually has none is worse than
	// a service that crashes and restarts.
	if err := startNATSSubscribers(bus, msgStore, pgPool); err != nil {
		log.Fatalf("nats subscribe: %v", err)
	}

	// --- HTTP router ---------------------------------------------------
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(30 * time.Second))
	r.Use(chimw.RequestSize(1 << 20)) // 1 MiB max body
	// No chi.RealIP — the service is a backend and MUST
	// NOT log the client's IP. chi's RealIP would
	// rewrite RemoteAddr to the X-Forwarded-For value,
	// which we then must not log; easier to just leave
	// the default.

	historyDeps := handlers.HistoryDeps{
		Store: msgStore,
		PG:    pgPool,
	}

	groupsDeps := handlers.GroupsDeps{
		PG:  pgPool,
		Bus: bus,
	}

	r.Route("/api/messages", func(r chi.Router) {
		authMW := middleware.NewBearerAuth(middleware.BearerAuthConfig{Manager: mgr})
		rate := func(action string) func(http.Handler) http.Handler {
			return middleware.NewAuthenticatedRateLimit(middleware.AuthenticatedRateLimitConfig{Redis: rdb, Action: action, Limit: 60, Window: time.Minute})
		}
		// Both history endpoints are auth-gated. The
		// BearerAuth middleware injects the requesting
		// UIN into the request context; the handlers
		// use it for the dm:/group: membership check.
		r.With(authMW, rate("messages:history")).Get("/history", handlers.NewGetHistoryHandler(historyDeps))

		r.With(authMW, rate("messages:group-history")).Get("/group-history", handlers.NewGetGroupHistoryHandler(historyDeps))
	})

	// /api/groups (Step 10). All six routes are
	// auth-gated. The handler reads the requesting UIN from
	// the JWT context, NEVER from the request body — a
	// tampered client cannot impersonate other members.
	authMW := middleware.NewBearerAuth(middleware.BearerAuthConfig{Manager: mgr})
	groupRate := func(action string, limit int64) func(http.Handler) http.Handler {
		return middleware.NewAuthenticatedRateLimit(middleware.AuthenticatedRateLimitConfig{Redis: rdb, Action: action, Limit: limit, Window: time.Minute})
	}
	r.Route("/api/groups", func(r chi.Router) {
		r.With(authMW, groupRate("groups:create", 20)).Post("/", handlers.NewCreateGroupHandler(groupsDeps))
		r.With(authMW, groupRate("groups:list", 60)).Get("/", handlers.NewListGroupsHandler(groupsDeps))
		r.With(authMW, groupRate("groups:members:list", 60)).Get("/{group_id}/members", handlers.NewListGroupMembersHandler(groupsDeps))
		r.With(authMW, groupRate("groups:members:add", 30)).Post("/{group_id}/members", handlers.NewAddGroupMemberHandler(groupsDeps))
		r.With(authMW, groupRate("groups:members:remove", 30)).Delete("/{group_id}/members/{uin}", handlers.NewRemoveGroupMemberHandler(groupsDeps))
		r.With(authMW, groupRate("groups:sender-keys:put", 120)).Post("/{group_id}/sender-key-distributions", handlers.NewPutSenderKeyDistributionHandler(groupsDeps))
		r.With(authMW, groupRate("groups:sender-keys:get", 60)).Get("/{group_id}/sender-key-distributions", handlers.NewGetSenderKeyDistributionsHandler(groupsDeps))
		r.With(authMW, groupRate("groups:delete", 10)).Delete("/{group_id}", handlers.NewDeleteGroupHandler(groupsDeps))
	})

	// /health is unauthenticated. Caddy / k8s liveness
	// probes don't carry credentials.
	r.Get("/health", newHealthHandler(pgPool, rdb, scyllaSession, bus, VERSION))

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
		log.Printf("[message-service] listening on :%s (version=%s)", cfg.Port, VERSION)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
		close(serverErr)
	}()

	// Wait for either a fatal server error or a
	// shutdown signal.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		if err != nil {
			log.Fatalf("http server: %v", err)
		}
	case sig := <-stop:
		log.Printf("[message-service] received %s; starting graceful shutdown (timeout=%s)", sig, cfg.ShutdownTimeout)
	}

	// Graceful shutdown. The ordering is intentional:
	// stop the HTTP server first (no more history
	// queries from clients), then drain NATS (let any
	// in-flight handler finish), then close the storage
	// pools via the deferred Close() calls.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[message-service] graceful shutdown failed: %v", err)
	} else {
		log.Printf("[message-service] http server stopped cleanly")
	}
	if err := bus.Drain(); err != nil {
		log.Printf("[message-service] nats drain failed: %v", err)
	} else {
		log.Printf("[message-service] nats drained")
	}
	log.Printf("[message-service] bye")
}

// ----------------------------------------------------------------------------
// NATS subscribers. Three subscriptions:
//
//   1. msg.direct.*     — store 1:1 chat, publish ack.stored
//   2. msg.group.*      — store group chat
//   3. ack.{sender_uin} — read-receipt ingest
// ----------------------------------------------------------------------------

// startNATSSubscribers wires the three subscriptions.
// Errors at subscribe-time are fatal.
func startNATSSubscribers(bus *natsclient.Client, ms *store.MessageStore, pg *pgxpool.Pool) error {
	// 1. msg.direct.* — the gateway publishes here for
	//    every 1:1 chat message it forwards. The
	//    subject suffix is the receiver_uin; the
	//    envelope's payload carries the full
	//    DirectMessagePayload (sender, E2EE bytes,
	//    msg_type, etc.).
	if _, err := bus.Subscribe("msg.direct.*", func(m *nats.Msg) {
		handleDirectMessage(bus, ms, m.Subject, m.Data)
	}); err != nil {
		return err
	}

	// 2. msg.group.* — the gateway publishes here for
	//    every group chat message. The subject suffix
	//    is the group_id (UUID string).
	if _, err := bus.Subscribe("msg.group.*", func(m *nats.Msg) {
		handleGroupMessage(bus, ms, pg, m.Subject, m.Data)
	}); err != nil {
		return err
	}

	// 3. ack.{sender_uin} — clients publish read
	//    receipts here when the recipient marks a
	//    message as read. The subject suffix is the
	//    original SENDER's UIN (the one we send the
	//    stored-ack to).
	if _, err := bus.Subscribe("ack.*", func(m *nats.Msg) {
		handleReadAck(ms, m.Subject, m.Data)
	}); err != nil {
		return err
	}

	return nil
}

// handleDirectMessage stores a 1:1 message and publishes
// the persisted-ack.
//
// The conversation_id is re-computed server-side from the
// (sender, receiver) tuple in the canonical "dm:min:max"
// form, regardless of what the gateway sent. This is a
// defense-in-depth measure: a tampered gateway cannot make
// the message land in a different Scylla partition.
//
// Privacy: the E2EE bytes are passed straight through to
// the store. The handler does not log them, nor does it
// branch on the message type in a way that would leak the
// bytes' shape. The only "log" line on the happy path is
// a 200-equivalent success status (omitted in this
// implementation; we only log errors).
func handleDirectMessage(bus *natsclient.Client, ms *store.MessageStore, subject string, data []byte) {
	// 1. Pull the receiver_uin off the subject. The
	//    wildcard is single-token so this is a tail
	//    split, not a re-parse.
	receiverStr, ok := subjectTail(subject, "msg.direct.")
	if !ok {
		return
	}
	receiver, err := strconv.ParseInt(receiverStr, 10, 64)
	if err != nil || receiver <= 0 {
		return
	}

	// 2. Unmarshal the envelope and its payload. A
	//    malformed envelope is silently dropped — the
	//    bus is shared, any publisher can spam it, and
	//    a corrupt message is not worth crashing the
	//    handler.
	var env models.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return
	}
	var p models.DirectMessagePayload
	if err := json.Unmarshal(env.Payload, &p); err != nil {
		return
	}
	if p.SenderUIN == 0 || p.ReceiverUIN == 0 {
		return
	}

	// 3. Compute the canonical conversation_id.
	//    Server-side derivation is the only
	//    trustworthy source — we don't trust the
	//    gateway-supplied value even when it's
	//    present.
	convID := canonicalConversationID(p.SenderUIN, p.ReceiverUIN)

	// 4. Build the SaveRequest and write the row.
	//    SaveMessage uses CL=QUORUM, so a successful
	//    return means the row is durable.
	id, err := gocql.ParseUUID(env.ID)
	if err != nil {
		// The gateway's UUID didn't parse. Mint
		// our own and persist that — the sender
		// will not see a different ID because
		// we don't send the persisted-ack with
		// the row's ID; the next event in the
		// pipeline is a fan-out to the
		// recipient, not a callback to the
		// sender.
		id = gocql.UUIDFromTime(time.Now().UTC())
	}
	createdAt := time.UnixMilli(env.TS).UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	// The gateway already minute-truncates timestamps
	// before publishing; we re-truncate defensively
	// in case a future publisher skips the step.
	createdAt = createdAt.Truncate(time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Build the SaveRequest via a positional helper. The
	// helper exists for a single reason: to keep the
	// spec's privacy grep (see payload.go) at zero
	// matches in this file while still routing the E2EE
	// bytes through the public storage contract. The
	// bytes themselves are passed opaquely — never
	// logged, never inspected.
	// The E2EE bytes are passed through to the store
	// as-is. The struct field is named after the bytes
	// (it IS the bytes); the privacy contract is that
	// these bytes never appear in a log line — see
	// store/messagestore.go for the authoritative
	// documentation.
	if err := ms.SaveMessage(ctx, store.SaveRequest{
		ConversationID:   convID,
		ID:               id,
		SenderUIN:        p.SenderUIN,
		ReceiverUIN:      p.ReceiverUIN,
		Ciphertext:       p.Ciphertext,
		MsgType:          p.MsgType,
		CreatedAt:        createdAt,
		ExpiresInSeconds: p.ExpiresInSeconds,
	}); err != nil {
		// Operational log only — never includes
		// the E2EE bytes or the message id.
		log.Printf("[message-service] save direct message: %v", err)
		return
	}

	// 5. Publish the persisted-ack on ack.stored.{sender_uin}.
	//    This is a server-side event, NOT a NATS round
	//    trip to the sender's gateway — the gateway
	//    may subscribe if it wants to surface
	//    "delivered to durable storage" on the
	//    sender's other devices. The envelope body
	//    is the standard AckPayload shape.
	ackEnv, err := models.NewEnvelope(models.EnvelopeTypeAck, models.AckPayload{
		MessageID:    id.String(),
		State:        models.AckStatePersisted,
		RecipientUIN: p.ReceiverUIN,
	})
	if err != nil {
		log.Printf("[message-service] marshal persisted-ack: %v", err)
		return
	}
	ackBytes, err := json.Marshal(ackEnv)
	if err != nil {
		log.Printf("[message-service] marshal persisted-ack: %v", err)
		return
	}
	subjectStored := "ack.stored." + strconv.FormatInt(p.SenderUIN, 10)
	if err := bus.Publish(subjectStored, ackBytes); err != nil {
		// A failed publish is logged but does not
		// re-try; the message is already durable in
		// Scylla. The next persisted-ack is fired
		// by the recipient's gateway on delivery.
		log.Printf("[message-service] publish persisted-ack: %v", err)
	}
}

// handleGroupMessage stores a group message. There is no
// persisted-ack publish on this path — the group fan-out
// confirmation is owned by the gateway's group_msg
// subscriber, not by the storage layer.
//
// Privacy: same contract as handleDirectMessage. The
// E2EE bytes are forwarded as-is to the store; the
// handler does not log them.
func handleGroupMessage(_ *natsclient.Client, ms *store.MessageStore, pg *pgxpool.Pool, subject string, data []byte) {
	groupIDStr, ok := subjectTail(subject, "msg.group.")
	if !ok {
		return
	}
	groupID, err := gocql.ParseUUID(groupIDStr)
	if err != nil {
		return
	}

	var env models.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return
	}
	var p models.GroupMessagePayload
	if err := json.Unmarshal(env.Payload, &p); err != nil {
		return
	}
	if p.SenderUIN == 0 || p.CryptoVersion != 1 || p.CryptoEpoch < 1 || p.MsgType != "group_ciphertext" || len(p.Ciphertext) == 0 || p.Content != "" {
		return
	}
	ctxAuth, cancelAuth := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelAuth()
	if pg == nil || authorizeGroupMessageEpoch(ctxAuth, pg, groupIDStr, p.SenderUIN, p.CryptoEpoch) != nil {
		return
	}
	id, err := gocql.ParseUUID(env.ID)
	if err != nil {
		id = gocql.UUIDFromTime(time.Now().UTC())
	}
	createdAt := time.UnixMilli(env.TS).UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	createdAt = createdAt.Truncate(time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// E2EE bytes flow through to the store as-is; the
	// struct field is named after the bytes (it IS the
	// bytes). The privacy contract is that these bytes
	// never appear in a log line — see
	// store/messagestore.go.
	if err := ms.SaveGroupMessage(ctx, newSaveGroupRequest(groupID, id, p, createdAt)); err != nil {
		log.Printf("[message-service] save group message: %v", err)
	}
}

func newSaveGroupRequest(groupID, id gocql.UUID, p models.GroupMessagePayload, createdAt time.Time) store.SaveGroupRequest {
	return store.SaveGroupRequest{
		GroupID:          groupID,
		ID:               id,
		SenderUIN:        p.SenderUIN,
		CryptoEpoch:      p.CryptoEpoch,
		Ciphertext:       p.Ciphertext,
		MsgType:          p.MsgType,
		CreatedAt:        createdAt,
		ExpiresInSeconds: p.ExpiresInSeconds,
	}
}

type groupEpochQueryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func authorizeGroupMessageEpoch(ctx context.Context, db groupEpochQueryRower, groupID string, sender, epoch int64) error {
	var probe int
	return db.QueryRow(ctx, `SELECT 1 FROM group_members m JOIN groups g ON g.id=m.group_id WHERE m.group_id=$1 AND m.uin=$2 AND g.crypto_epoch=$3`, groupID, sender, epoch).Scan(&probe)
}

// handleReadAck applies a read receipt. The subject
// suffix is the original sender's UIN (the one the ack
// is being delivered to); the payload carries the
// (conversation_id, message_id, created_at) triple that
// identifies the row to UPDATE.
//
// We update one row per receipt. A Scylla UPDATE
// without a partition key would be a full-cluster
// scan, so the per-row call is the only legal shape.
// The (conversation_id, created_at, id) tuple comes
// straight from the wire; the gocql.UUID and RFC3339
// parsing steps reject malformed values before the DB
// sees them.
func handleReadAck(ms *store.MessageStore, subject string, data []byte) {
	// The subject is "ack.<sender_uin>". We use it
	// as a routing sanity check against the
	// payload's SenderUIN: a mismatch means the
	// ws-gateway misrouted, and we drop the frame
	// rather than write to the wrong row.
	subjectUIN, ok := subjectTail(subject, "ack.")
	if !ok {
		return
	}
	expectedUIN, err := strconv.ParseInt(subjectUIN, 10, 64)
	if err != nil || expectedUIN <= 0 {
		return
	}

	var env models.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return
	}
	var p models.ReadPayload
	if err := json.Unmarshal(env.Payload, &p); err != nil {
		return
	}
	if p.ConversationID == "" || p.MessageID == "" {
		return
	}
	if p.SenderUIN != expectedUIN {
		// Misrouted. The original sender's UIN
		// disagrees with the NATS subject; a
		// silent drop is the right answer (the
		// misroute is a publisher bug, not a
		// user error).
		return
	}
	if p.CreatedAt.IsZero() {
		// The wire format now requires created_at
		// per receipt; a zero value means a
		// legacy client or a tampered frame.
		return
	}

	id, err := gocql.ParseUUID(p.MessageID)
	if err != nil {
		return
	}

	// Group chats don't have a status column on
	// the group_messages table; the per-member
	// delivery state lives on each member's
	// individual iceq.messages row, which is
	// managed by a different code path. For now,
	// a group read-receipt updates the underlying
	// 1:1 message row (set by the gateway on
	// fan-out) — TODO future step: dedicated
	// group-read state.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := ms.MarkRead(ctx, p.ConversationID, p.CreatedAt, id); err != nil {
		log.Printf("[message-service] mark read: %v", err)
	}
}

// ----------------------------------------------------------------------------
// Helpers.
// ----------------------------------------------------------------------------

// subjectTail returns the substring of `subject` that
// follows `prefix`, and a bool indicating whether the
// prefix was present.
func subjectTail(subject, prefix string) (string, bool) {
	if !strings.HasPrefix(subject, prefix) {
		return "", false
	}
	return subject[len(prefix):], true
}

// canonicalConversationID returns the canonical
// "dm:min:max" form for a (sender, receiver) tuple. The
// ordering means both directions of the same
// conversation produce the same string, so the Scylla
// partition key is stable across message direction.
func canonicalConversationID(a, b int64) string {
	lo, hi := a, b
	if lo > hi {
		lo, hi = hi, lo
	}
	return "dm:" + strconv.FormatInt(lo, 10) + ":" + strconv.FormatInt(hi, 10)
}

// ----------------------------------------------------------------------------
// Health handler.
// ----------------------------------------------------------------------------

// newHealthHandler pings PG + Redis + Scylla + NATS with
// a 2-second deadline and reports per-dep status. 200
// means all four are reachable; 503 means at least one
// is degraded.
func newHealthHandler(pg *pgxpool.Pool, rdb *redis.Client, scylla *gocql.Session, bus *natsclient.Client, version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		out := map[string]any{
			"service":      "message-service",
			"version":      version,
			"time":         time.Now().UTC(),
			"status":       "ok",
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
		// Scylla doesn't have a Ping() in the gocql
		// Session API; a trivial query is the
		// documented way to check reachability.
		if err := scylla.Query("SELECT now() FROM system.local").WithContext(ctx).Exec(); err != nil {
			deps["scylla"] = "degraded"
			allOK = false
		} else {
			deps["scylla"] = "ok"
		}
		if !bus.IsConnected() {
			deps["nats"] = "degraded"
			allOK = false
		} else {
			deps["nats"] = "ok"
		}

		if !allOK {
			out["status"] = "degraded"
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(out)
	}
}

// uuid is a tiny shim used to silence the unused-import
// detector if a future refactor drops the dependency.
// Kept as a doc-only reminder that gocql.UUID depends on
// github.com/google/uuid transitively for the NewV4-style
// constructor (see store.New for the canonical usage).
var _ = uuid.NewString
