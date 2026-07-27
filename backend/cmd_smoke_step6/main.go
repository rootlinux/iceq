// Step-6 ws-gateway smoke test.
//
// Exercises the full WebSocket lifecycle end-to-end:
//
//  1. Connect → auth → receive presence-notify forwarded via the
//     new per-connection subscription on presence.notify.{uin}.
//  2. Direct message: client A sends → envelope fans out via
//     msg.direct.* → client B receives on its own WebSocket.
//  3. Read ack: client B acks → client A receives ack on its
//     WebSocket (proves the router's sendDirect-ack path is wired
//     and the gateway no longer needs ack.* NATS subscribers).
//  4. Ping/pong: a "ping" frame gets an immediate "pong" with no
//     NATS round trip (proves the readLoop's ping handler).
//  5. Clean disconnect: A's readLoop exits → A's
//     presence.notify.{uinA} subscription is torn down by
//     shutdown(); cB (still connected) keeps receiving notify
//     envelopes on its independent subscription.
//
// Run from inside the iceq-net network:
//
//	docker run --rm --network iceq-net \
//	    -v /path/to/iceq:/src \
//	    -w /src/backend \
//	    -e ICEQ_JWT_SECRET=dev-only-jwt-secret-change-in-prod \
//	    -e ICEQ_NATS_TOKEN -e ICEQ_REDIS_PASSWORD \
//	    golang:1.25-alpine \
//	    go run ./cmd_smoke_step6
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/iceq/iceq/shared/jwt"
	"github.com/iceq/iceq/shared/models"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

const (
	natsURL      = "nats://nats:4222"
	defaultPGDSN = "postgres://postgres:postgres@postgres:5432/iceq?sslmode=disable"
)

func natsTokenOption() []nats.Option {
	if token := os.Getenv("ICEQ_NATS_TOKEN"); token != "" {
		return []nats.Option{nats.Token(token)}
	}
	return nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Two test users left over from the Step-5 smoke run.
	const uinA int64 = 9999001
	const uinB int64 = 9999002

	ensureUsers(ctx, uinA, uinB)

	// ---- 0. Mint access tokens for both users ----
	tokens := mintTokensFor(uinA, uinB)

	// ---- 1. Connect both clients ----
	cA := mustDial(ctx, "ws-gateway:8082", tokens[uinA])
	defer func() { _ = cA.Close(websocket.StatusNormalClosure, "bye") }()
	cB := mustDial(ctx, "ws-gateway:8082", tokens[uinB])
	defer func() { _ = cB.Close(websocket.StatusNormalClosure, "bye") }()
	fmt.Println("[smoke] both WebSockets connected and authed")

	// ---- 2. presence-service fan-out → cB's per-conn subscription → cB's WS ----
	mustInsertContact(ctx, uinB, uinA)
	fmt.Println("[smoke] contact: uinB watches uinA")

	nc, err := nats.Connect(natsURL, natsTokenOption()...)
	must(err, "nats connect")
	defer nc.Drain()
	notifyHits := make(chan *nats.Msg, 4)
	_, err = nc.Subscribe("presence.notify."+strconv.FormatInt(uinB, 10), func(m *nats.Msg) {
		select {
		case notifyHits <- m:
		default:
		}
	})
	must(err, "nats sub presence.notify.{uinB}")

	cBMsgs := make(chan models.Envelope, 16)
	go readLoop("B", cB, cBMsgs)
	cAMsgs := make(chan models.Envelope, 16)
	go readLoop("A", cA, cAMsgs)

	// Drain any "join" presence envelopes that arrive on cB's
	// WebSocket as a side-effect of A and B connecting (the
	// ws-gateway fires presence.update on connect; presence-
	// service fans those out to contacts).
	drainByType(cBMsgs, models.EnvelopeTypePresence, 3*time.Second)
	drainByType(cAMsgs, models.EnvelopeTypePresence, 3*time.Second)

	publishPresenceUpdate(nc, uinA, "online")
	time.Sleep(750 * time.Millisecond)

	select {
	case m := <-notifyHits:
		fmt.Printf("[smoke] OK presence-service fanned out: %s -> %s\n", m.Subject, string(m.Data))
	case <-time.After(3 * time.Second):
		fail("did not see presence.notify on the bus within 3s")
	}
	select {
	case env := <-cBMsgs:
		if env.Type != models.EnvelopeTypePresence {
			fail(fmt.Sprintf("cB got non-presence envelope: type=%s", env.Type))
		}
		fmt.Printf("[smoke] OK cB WebSocket received presence envelope (id=%s)\n", env.ID)
	case <-time.After(2 * time.Second):
		fail("cB WebSocket did not receive the presence envelope within 2s")
	}

	// ---- 3. Direct message: A → B ----
	msgEnv := models.Envelope{
		Type: models.EnvelopeTypeDirect,
		ID:   uuid.NewString(),
		TS:   time.Now().UnixMilli(),
		Payload: mustJSON(models.DirectMessagePayload{
			ConversationID: "conv-test",
			SenderUIN:      uinA,
			ReceiverUIN:    uinB,
			Content:        "hello from A",
			ContentType:    "text/plain",
		}),
	}
	if err := wsjson.Write(ctx, cA, msgEnv); err != nil {
		fail("A write msg: " + err.Error())
	}
	fmt.Println("[smoke] A sent direct message to B")

	select {
	case env := <-cBMsgs:
		if env.Type != models.EnvelopeTypeDirect {
			fail(fmt.Sprintf("B got non-direct envelope: type=%s", env.Type))
		}
		fmt.Println("[smoke] OK B received A's direct message via msg.direct.*")
	case <-time.After(3 * time.Second):
		fail("B did not receive A's direct message within 3s")
	}

	// ---- 4. Read ack: B → A ----
	ackEnv := models.Envelope{
		Type: "ack",
		ID:   uuid.NewString(),
		TS:   time.Now().UnixMilli(),
		Payload: mustJSON(models.AckPayload{
			MessageID:    "somedeliveredid",
			State:        models.AckStateDelivered,
			RecipientUIN: uinA,
		}),
	}
	if err := wsjson.Write(ctx, cB, ackEnv); err != nil {
		fail("B write ack: " + err.Error())
	}
	fmt.Println("[smoke] B sent ack to A")

	select {
	case env := <-cAMsgs:
		if env.Type != "ack" {
			fail(fmt.Sprintf("A got non-ack envelope: type=%s", env.Type))
		}
		fmt.Println("[smoke] OK A received B's ack (direct, no NATS round trip)")
	case <-time.After(3 * time.Second):
		fail("A did not receive B's ack within 3s")
	}

	// ---- 5. Ping / pong ----
	// The cAMsgs channel may still have ack envelopes from
	// step 4 (gateway's own persisted-ack + B's client-issued
	// ack). We use waitForType which silently discards
	// non-matching envelopes until a pong arrives, instead
	// of draining with a fixed window that could miss a
	// late-arriving ack.
	pingEnv := models.Envelope{
		Type:    "ping",
		ID:      uuid.NewString(),
		TS:      time.Now().UnixMilli(),
		Payload: nil,
	}
	if err := wsjson.Write(ctx, cA, pingEnv); err != nil {
		fail("A write ping: " + err.Error())
	}
	fmt.Println("[smoke] A sent ping")

	// Accept both the canonical pong envelope and the
	// legacy ack(state="pong") shape so this smoke stays
	// compatible across rolling deploys.
	var pongEnv *models.Envelope
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for pongEnv == nil {
		select {
		case env, ok := <-cAMsgs:
			if !ok {
				fail("cAMsgs channel closed before pong")
			}
			if env.Type == "pong" {
				pongEnv = &env
				continue
			}
			if env.Type == models.EnvelopeTypeAck {
				var ap models.AckPayload
				if err := json.Unmarshal(env.Payload, &ap); err == nil && ap.State == "pong" {
					pongEnv = &env
				}
			}
		case <-deadline.C:
			fail("A did not receive pong within 3s")
		}
	}
	fmt.Println("[smoke] OK A received pong (readLoop handled ping inline)")

	// ---- 6. Clean disconnect: A closes → A's presence.notify.{uinA} is torn down ----
	_ = cA.Close(websocket.StatusNormalClosure, "bye")
	time.Sleep(500 * time.Millisecond)

	// cB is still connected. Fire one more presence update on
	// uinA and confirm cB still gets it (proves A's
	// unsubscribe on its OWN subject didn't break B's
	// independent subscription).
	publishPresenceUpdate(nc, uinA, "online")
	time.Sleep(750 * time.Millisecond)
	// Use waitForType in case cBMsgs has buffered
	// envelopes from earlier sub-tests (e.g. acks B's
	// gateway sent back to A in step 3, or other
	// side-effects).
	envP := waitForType(cBMsgs, models.EnvelopeTypePresence, 3*time.Second)
	if envP == nil {
		fail("cB did not receive second notify after A disconnect")
	}
	fmt.Println("[smoke] OK cB still receives notify after cA disconnects (independent subscriptions)")

	_ = cB.Close(websocket.StatusNormalClosure, "bye")
	runPSQL(ctx, fmt.Sprintf("DELETE FROM contacts WHERE owner_uin=%d AND target_uin=%d;", uinB, uinA))

	fmt.Println("[smoke] SMOKE TEST OK")
}

// mintTokensFor creates two access tokens using the same JWT
// secret the gateway is configured with. The test container
// must be run with the same ICEQ_JWT_SECRET env var as the
// ws-gateway/auth-service containers. If unset, fall back to
// the dev-only secret in docker-compose.yml.
//
// We construct a jwt.Manager and call Sign, which is exactly
// what auth-service does on login — so the token shape
// matches what the gateway's jwt.Manager.Verify expects.
func mintTokensFor(uins ...int64) map[int64]string {
	secret := os.Getenv("ICEQ_JWT_SECRET")
	if secret == "" {
		// F-2 (JWT assessment): 38 bytes, above the
		// minSecretBytes=32 floor, and not a substring
		// of any knownWeakSecrets entry.
		secret = "step6-smoketest-secret-not-for-prod-32"
	}
	rdb := redis.NewClient(&redis.Options{Addr: "redis:6379", Password: os.Getenv("ICEQ_REDIS_PASSWORD")})
	defer func() { _ = rdb.Close() }()
	// F-5: NewManager requires a pg pool for the
	// session_epoch check in Verify. The smoke test
	// only SIGNS tokens, not verifies, so the pool is
	// never actually queried — but the constructor
	// still needs the handle.
	pool, err := pgxpool.New(context.Background(), pgDSNFromEnv())
	if err != nil {
		fail("pgxpool.New: " + err.Error())
	}
	defer pool.Close()
	mgr, err := jwt.NewManager(secret, rdb, pool)
	if err != nil {
		fail("jwt.NewManager: " + err.Error())
	}
	out := make(map[int64]string, len(uins))
	for _, u := range uins {
		res, err := mgr.Sign(u, jwt.TokenTypeAccess)
		if err != nil {
			fail("jwt.Sign: " + err.Error())
		}
		out[u] = res.Token
	}
	return out
}

func mustDial(ctx context.Context, hostport, token string) *websocket.Conn {
	u := "ws://" + hostport + "/ws"
	conn, _, err := websocket.Dial(ctx, u, nil)
	if err != nil {
		fail("dial: " + err.Error())
	}
	// Send the auth frame using wsjson (text-frame JSON).
	authCtx, authCancel := context.WithTimeout(ctx, 5*time.Second)
	defer authCancel()
	authFrame := map[string]string{"type": "auth", "token": token}
	if err := wsjson.Write(authCtx, conn, authFrame); err != nil {
		fail("write auth: " + err.Error())
	}

	var env models.Envelope
	if err := wsjson.Read(authCtx, conn, &env); err != nil {
		fail("read auth_ok: " + err.Error())
	}
	if env.Type != "auth_ok" {
		fail("expected auth_ok, got " + env.Type)
	}
	return conn
}

func readLoop(label string, c *websocket.Conn, out chan<- models.Envelope) {
	defer close(out)
	for {
		var env models.Envelope
		readCtx, readCancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := wsjson.Read(readCtx, c, &env)
		readCancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[smoke] %s readLoop exit: %v\n", label, err)
			return
		}
		select {
		case out <- env:
		default:
			// Drop if buffer is full.
		}
	}
}

func publishPresenceUpdate(nc *nats.Conn, uin int64, status string) {
	p := models.PresencePayload{
		UIN:    uin,
		Status: status,
		TS:     time.Now().UTC().Truncate(time.Minute).UnixMilli(),
	}
	env, err := models.NewEnvelope(models.EnvelopeTypePresence, p)
	if err != nil {
		fail("build presence env: " + err.Error())
	}
	data, err := json.Marshal(env)
	if err != nil {
		fail("marshal: " + err.Error())
	}
	if err := nc.Publish("presence.update", data); err != nil {
		fail("publish presence.update: " + err.Error())
	}
	if err := nc.Flush(); err != nil {
		fail("flush: " + err.Error())
	}
	fmt.Printf("[smoke] published presence.update uin=%d status=%s\n", uin, status)
}

func ensureUsers(ctx context.Context, uins ...int64) {
	pool, err := pgxpool.New(ctx, pgDSNFromEnv())
	if err != nil {
		fail("seed users: " + err.Error())
	}
	defer pool.Close()

	for _, uin := range uins {
		_, err := pool.Exec(ctx, `
			INSERT INTO users (uin, username, password_hash, identity_key, session_epoch)
			VALUES ($1, $2, '', '', NOW() - INTERVAL '1 second')
			ON CONFLICT (uin) DO UPDATE
			SET session_epoch = NOW() - INTERVAL '1 second'
		`, uin, fmt.Sprintf("smoke_step6_%d", uin))
		if err != nil {
			fail("seed user: " + err.Error())
		}
	}
}

func mustInsertContact(ctx context.Context, owner, target int64) {
	pool, err := pgxpool.New(ctx, pgDSNFromEnv())
	if err != nil {
		fail("pgx: " + err.Error())
	}
	defer pool.Close()
	sql := fmt.Sprintf(
		"INSERT INTO contacts (owner_uin, target_uin, status) VALUES (%d, %d, 'accepted') ON CONFLICT DO NOTHING;",
		owner, target,
	)
	if _, err := pool.Exec(ctx, sql); err != nil {
		fail("insert contact: " + err.Error())
	}
}

func runPSQL(ctx context.Context, sql string) {
	pool, err := pgxpool.New(ctx, pgDSNFromEnv())
	if err != nil {
		fmt.Fprintf(os.Stderr, "[smoke] pgx: %v\n", err)
		return
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, sql); err != nil {
		fmt.Fprintf(os.Stderr, "[smoke] pgx exec: %v\n", err)
	}
}

func must(err error, label string) {
	if err != nil {
		fail(label + ": " + err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "[smoke] FAIL:", msg)
	os.Exit(1)
}

func pgDSNFromEnv() string {
	if dsn := os.Getenv("ICEQ_PG_DSN"); dsn != "" {
		return dsn
	}
	if password := os.Getenv("POSTGRES_PASSWORD"); password != "" {
		return "postgres://postgres:" + password + "@postgres:5432/iceq?sslmode=disable"
	}
	return defaultPGDSN
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		fail("mustJSON: " + err.Error())
	}
	return b
}

// drainByType reads envelopes from `in` for up to `within`
// and discards any of the given type. Returns the count of
// discarded envelopes. Used to clean up side-effect
// envelopes (e.g. presence updates fired on connect) before a
// sub-test that expects a specific envelope type.
func drainByType(in <-chan models.Envelope, t string, within time.Duration) int {
	deadline := time.NewTimer(within)
	defer deadline.Stop()
	discarded := 0
	for {
		select {
		case env, ok := <-in:
			if !ok {
				return discarded
			}
			if env.Type == t {
				discarded++
			}
		case <-deadline.C:
			return discarded
		}
	}
}

// waitForType reads envelopes from `in` for up to `within`,
// discarding anything that isn't of the given type. Returns
// the first matching envelope, or nil on timeout. Used when
// the channel has buffered side-effect envelopes (e.g. a
// late-arriving ack) that we want to skip past instead of
// race against.
func waitForType(in <-chan models.Envelope, t string, within time.Duration) *models.Envelope {
	deadline := time.NewTimer(within)
	defer deadline.Stop()
	for {
		select {
		case env, ok := <-in:
			if !ok {
				return nil
			}
			if env.Type == t {
				return &env
			}
			// Discard non-matching.
		case <-deadline.C:
			return nil
		}
	}
}
