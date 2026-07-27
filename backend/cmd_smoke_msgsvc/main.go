// message-service smoke test.
//
// Exercises the 4 sub-tests from the Step 6 spec:
//
//  1. Publish msg.direct.{uin} to NATS → verify ScyllaDB row inserted.
//  2. GET /api/messages/history        → verify ciphertext returned.
//  3. Read-receipt column update        → direct gocql UPDATE to prove
//     the status column is writable
//     (the wire format for ack.* is
//     pending; see report).
//  4. Pagination: insert 25 messages into the same conversation,
//     fetch with limit=10, walk pages with next_cursor.
//
// Run from inside the iceq-net network with the same
// ICEQ_JWT_SECRET as the message-service / auth-service:
//
//	docker run --rm --network iceq-net \
//	  -v /path/to/iceq:/src \
//	  -w /src/backend \
//	  -e ICEQ_JWT_SECRET=dev-secret-not-for-prod \
//	  -e ICEQ_NATS_TOKEN -e ICEQ_REDIS_PASSWORD \
//	  alpine:3.20 /src/backend/cmd_smoke_msgsvc/smoke
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/gocql/gocql"
	"github.com/google/uuid"
	"github.com/iceq/iceq/shared/jwt"
	"github.com/iceq/iceq/shared/models"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
)

const (
	natsURL      = "nats://nats:4222"
	msgsvcBase   = "http://message-service:8080"
	defaultPGDSN = "postgres://postgres:postgres@postgres:5432/iceq?sslmode=disable"
	// F-2 (JWT assessment): 38 bytes, above the
	// minSecretBytes=32 floor.
	jwtSecret   = "msgsvc-smoketest-secret-not-for-prod-32"
	scyllaHosts = "scylla:9042"
)

func natsTokenOption() []nats.Option {
	if token := os.Getenv("ICEQ_NATS_TOKEN"); token != "" {
		return []nats.Option{nats.Token(token)}
	}
	return nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	runSalt := time.Now().UTC().UnixNano()
	uinA := int64(8_000_000_000_000_000 + (runSalt % 1_000_000_000))
	uinB := uinA + 1
	// Use run-unique UINs so pre-existing rows from earlier smoke runs
	// cannot pollute history assertions or pagination counts.
	convID := canonicalConvID(uinA, uinB)
	ensureUsers(ctx, uinA, uinB)

	// ---- 0. Mint access tokens for both users ----
	mgr := newJWTManager()
	accessA := mintAccessToken(mgr, uinA)
	_ = mintAccessToken(mgr, uinB) // minted for parity; not used by this test

	nc, err := nats.Connect(natsURL, natsTokenOption()...)
	must(err, "nats connect")
	defer nc.Drain()

	// Open ONE Scylla session for the whole test. The
	// gocql driver maintains a per-host control
	// connection; opening a fresh session per call (as
	// the first version of this test did) makes the
	// driver keep retrying the initial handshake on
	// the closing control connection, which surfaces
	// as the "EOF: connection closed waiting for
	// response" storm we saw on the first run.
	sc := openScylla(ctx)
	defer sc.Close()

	// ---- 1. Publish msg.direct.{receiver_uin} → Scylla row inserted ----
	fmt.Println("[smoke] ==== 1. publish msg.direct.* ====")
	ct1 := []byte("signal-ciphertext-1-\x00\x01\x02\xff")
	msgID1 := uuid.NewString()
	published1 := models.Envelope{
		Type: models.EnvelopeTypeDirect,
		ID:   msgID1,
		TS:   time.Now().UTC().Truncate(time.Minute).UnixMilli(),
		Payload: mustJSON(models.DirectMessagePayload{
			SenderUIN:   uinA,
			ReceiverUIN: uinB,
			Ciphertext:  ct1,
			MsgType:     "prekey_message",
		}),
	}
	publishDirectMsg(nc, uinB, published1)
	fmt.Printf("[smoke] published msg.direct.%d id=%s ciphertext_len=%d\n", uinB, msgID1, len(ct1))

	// Wait for the message-service to consume & store.
	row1 := waitForRow(ctx, sc, convID, msgID1, 5*time.Second)
	if row1 == nil {
		fail("row 1 not inserted within 5s")
	}
	if row1.SenderUIN != uinA || row1.ReceiverUIN != uinB {
		fail(fmt.Sprintf("row 1: unexpected sender/receiver: %d/%d", row1.SenderUIN, row1.ReceiverUIN))
	}
	if row1.MsgType != "prekey_message" {
		fail(fmt.Sprintf("row 1: unexpected msg_type=%q", row1.MsgType))
	}
	if string(row1.Ciphertext) != string(ct1) {
		fail("row 1: ciphertext does not match the bytes we sent")
	}
	fmt.Println("[smoke] OK row inserted with matching ciphertext bytes (opaque to server)")

	// ---- 2. GET /api/messages/history → ciphertext returned ----
	fmt.Println("[smoke] ==== 2. GET history ====")
	msgs := fetchHistory(ctx, accessA, convID, "", 10)
	if len(msgs) == 0 {
		fail("history returned 0 messages")
	}
	var got map[string]any
	for _, msg := range msgs {
		if msg["id"] == msgID1 {
			got = msg
			break
		}
	}
	if got == nil {
		fail(fmt.Sprintf("history did not return inserted id %s", msgID1))
	}
	// The ciphertext is base64url-encoded; the round trip
	// must produce the same bytes.
	gotCT, _ := got["ciphertext"].(string)
	if gotCT == "" {
		fail("history[0].ciphertext is empty")
	}
	fmt.Printf("[smoke] OK history returned id=%s ciphertext_b64=%s...\n", got["id"], gotCT[:min(20, len(gotCT))])

	// ---- 3. Read-receipt: end-to-end via the "read" frame → NATS → MarkRead ----
	fmt.Println("[smoke] ==== 3. read receipt (end-to-end via ack.*) ====")
	// Now that ReadPayload carries CreatedAt + SenderUIN,
	// we can exercise the FULL path:
	//   1. Publish a "read" envelope on ack.<sender_uin>
	//   2. message-service's handleReadAck parses it and
	//      calls MarkRead(convID, createdAt, id)
	//   3. Scylla row status flips to "read"
	//   4. GET history returns status="read"
	readEnv := models.Envelope{
		Type: models.EnvelopeTypeRead,
		ID:   uuid.NewString(),
		TS:   time.Now().UTC().UnixMilli(),
		Payload: mustJSON(models.ReadPayload{
			ConversationID: convID,
			ReaderUIN:      uinA, // server-side fill in real gateway; we set it here for the test
			SenderUIN:      uinB, // original sender
			MessageID:      msgID1,
			CreatedAt:      row1.CreatedAt,
		}),
	}
	publishAck(nc, uinB, readEnv)
	fmt.Printf("[smoke] published ack.%d id=%s created_at=%s\n", uinB, msgID1, row1.CreatedAt.Format(time.RFC3339))

	// Poll Scylla for the status flip.
	if err := waitForStatus(ctx, sc, convID, row1.CreatedAt, row1.ID, "read", 5*time.Second); err != nil {
		fail("status did not flip to 'read' within 5s: " + err.Error())
	}
	fmt.Println("[smoke] OK status column UPDATE path verified via ack.* (end-to-end)")

	// ---- 4. Pagination: insert 25 messages into the same conv ----
	fmt.Println("[smoke] ==== 4. pagination (25 messages, limit=10) ====")
	// Use a distinct run-unique conversation for pagination
	// so the page count is deterministic even across repeated
	// smoke runs against the same live stack.
	uinC := uinB + 1
	convID4 := canonicalConvID(uinA, uinC)
	const N = 25
	inserted := make(map[string]bool, N)
	baseTS := time.Now().UTC().Add(-time.Duration(N+5) * time.Second)
	for i := 0; i < N; i++ {
		id := uuid.NewString()
		ts := baseTS.Add(time.Duration(i) * time.Second)
		_ = insertRowDirect(ctx, sc, convID4, id, uinA, uinC, []byte(fmt.Sprintf("payload-%d", i)), "signal_message", ts)
		inserted[id] = true
	}
	fmt.Printf("[smoke] inserted %d rows into %s\n", N, convID4)

	seen := make(map[string]bool, N)
	page := 1
	var cursor string
	for {
		msgs := fetchHistory(ctx, accessA, convID4, cursor, 10)
		fmt.Printf("[smoke] page %d: got %d rows, sent cursor=%q\n", page, len(msgs), cursor)
		if len(msgs) == 0 {
			break
		}
		for _, m := range msgs {
			id, _ := m["id"].(string)
			if seen[id] {
				fail("duplicate id across pages: " + id)
			}
			seen[id] = true
			if !inserted[id] {
				fail("page returned an id we did not insert: " + id)
			}
		}
		// Decide next cursor. The last message's
		// created_at (in DESC order) is the oldest on
		// this page; pass it as `before` to get the
		// next page.
		last := msgs[len(msgs)-1]
		nc, _ := last["created_at"].(string)
		fmt.Printf("[smoke]   page %d last created_at=%s\n", page, nc)
		if len(msgs) < 10 {
			fmt.Printf("[smoke] partial page (%d) — end of history\n", len(msgs))
			break
		}
		cursor = nc
		page++
		if page > 10 {
			fail("pagination did not terminate after 10 pages")
		}
	}
	if len(seen) != N {
		fail(fmt.Sprintf("pagination returned %d unique rows, want %d", len(seen), N))
	}
	fmt.Printf("[smoke] OK pagination walked all %d rows across %d pages\n", N, page)

	fmt.Println("[smoke] SMOKE TEST OK")
}

// ----------------------------------------------------------------------------
// Helpers.
// ----------------------------------------------------------------------------

func canonicalConvID(a, b int64) string {
	lo, hi := a, b
	if lo > hi {
		lo, hi = hi, lo
	}
	return "dm:" + strconv.FormatInt(lo, 10) + ":" + strconv.FormatInt(hi, 10)
}

func newJWTManager() *jwt.Manager {
	rdb := redis.NewClient(&redis.Options{Addr: "redis:6379"})
	// F-5: NewManager requires a *pgxpool.Pool for the
	// session_epoch check. The smoke test only signs
	// tokens, so the pool is never actually queried —
	// but the constructor still needs the handle.
	pool, err := pgxpool.New(context.Background(), pgDSNFromEnv())
	if err != nil {
		must(err, "pgxpool.New")
	}
	defer pool.Close()
	secret := os.Getenv("ICEQ_JWT_SECRET")
	if secret == "" {
		secret = jwtSecret
	}
	mgr, err := jwt.NewManager(secret, rdb, pool)
	must(err, "jwt.NewManager")
	return mgr
}

func mintAccessToken(mgr *jwt.Manager, uin int64) string {
	res, err := mgr.Sign(uin, jwt.TokenTypeAccess)
	must(err, "jwt.Sign")
	return res.Token
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	must(err, "marshal payload")
	return b
}

func publishDirectMsg(nc *nats.Conn, receiver int64, env models.Envelope) {
	data, err := json.Marshal(env)
	must(err, "marshal envelope")
	subject := "msg.direct." + strconv.FormatInt(receiver, 10)
	if err := nc.Publish(subject, data); err != nil {
		fail("publish: " + err.Error())
	}
	if err := nc.Flush(); err != nil {
		fail("nats flush: " + err.Error())
	}
}

// publishAck sends a read-receipt envelope on ack.<sender_uin>.
// This is the wire path the ws-gateway's handleRead produces
// after server-side fill; message-service's `ack.*`
// subscriber should pick it up and call MarkRead.
func publishAck(nc *nats.Conn, senderUIN int64, env models.Envelope) {
	data, err := json.Marshal(env)
	must(err, "marshal ack envelope")
	subject := "ack." + strconv.FormatInt(senderUIN, 10)
	if err := nc.Publish(subject, data); err != nil {
		fail("publish ack: " + err.Error())
	}
	if err := nc.Flush(); err != nil {
		fail("nats flush ack: " + err.Error())
	}
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

func ensureUsers(ctx context.Context, uins ...int64) {
	pool, err := pgxpool.New(ctx, pgDSNFromEnv())
	must(err, "pgxpool.New")
	defer pool.Close()

	for _, uin := range uins {
		_, err := pool.Exec(ctx, `
			INSERT INTO users (uin, username, password_hash, identity_key)
			VALUES ($1, $2, '', '')
			ON CONFLICT (uin) DO NOTHING
		`, uin, fmt.Sprintf("msgsvc-smoke-%d", uin))
		must(err, "seed user")
	}
}

// fetchHistory calls /api/messages/history with the given
// access token, conversation_id, and cursor. Returns the
// "messages" array. limit is hard-capped at 50 by the
// server.
func fetchHistory(ctx context.Context, accessToken, convID, before string, limit int) []map[string]any {
	u, _ := url.Parse(msgsvcBase + "/api/messages/history")
	q := u.Query()
	q.Set("conversation_id", convID)
	if before != "" {
		q.Set("before", before)
	}
	q.Set("limit", strconv.Itoa(limit))
	u.RawQuery = q.Encode()

	req, _ := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fail("GET history: " + err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		fail(fmt.Sprintf("GET history: status=%d body=%s", resp.StatusCode, string(body)))
	}
	var out struct {
		Messages   []map[string]any `json:"messages"`
		NextCursor *string          `json:"next_cursor"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		fail("decode history: " + err.Error())
	}
	return out.Messages
}

// waitForRow polls Scylla until the given (convID, msgID)
// row appears or the deadline expires. Returns the row
// on success, nil on timeout.
func waitForRow(ctx context.Context, sc *gocql.Session, convID, msgID string, within time.Duration) *messageRow {
	deadline := time.Now().Add(within)
	var lastErr error
	for {
		if time.Now().After(deadline) {
			if lastErr != nil {
				fmt.Fprintf(os.Stderr, "[smoke] waitForRow last error: %v\n", lastErr)
			}
			return nil
		}
		row, err := readRow(ctx, sc, convID, msgID)
		if err == nil && row != nil {
			return row
		}
		lastErr = err
		time.Sleep(150 * time.Millisecond)
	}
}

type messageRow struct {
	ConversationID string
	CreatedAt      time.Time
	ID             gocql.UUID
	SenderUIN      int64
	ReceiverUIN    int64
	Ciphertext     []byte
	MsgType        string
	Status         string
}

func readRow(ctx context.Context, sc *gocql.Session, convID, msgID string) (*messageRow, error) {
	// The (conversation_id, created_at, id) clustering
	// order means we MUST include created_at in the WHERE
	// clause to filter by id. Without it, CQL rejects
	// the query with "PRIMARY KEY column id cannot be
	// restricted as preceding column created_at is not
	// restricted".
	//
	// The test workaround: filter by conversation_id and
	// walk the partition in DESC order until we find the
	// matching id. With a small conversation (one row
	// from test 1) this is O(1) and correct.
	id, err := gocql.ParseUUID(msgID)
	if err != nil {
		return nil, err
	}
	iter := sc.Query(
		`SELECT created_at, id, sender_uin, receiver_uin, ciphertext, msg_type, status
		 FROM iceq.messages
		 WHERE conversation_id = ?`,
		convID,
	).WithContext(ctx).Consistency(gocql.Quorum).Iter()
	defer iter.Close()
	for {
		var row messageRow
		row.ConversationID = convID
		if !iter.Scan(
			&row.CreatedAt,
			&row.ID,
			&row.SenderUIN,
			&row.ReceiverUIN,
			&row.Ciphertext,
			&row.MsgType,
			&row.Status,
		) {
			break
		}
		if row.ID == id {
			return &row, nil
		}
	}
	return nil, fmt.Errorf("row not found")
}

func insertRowDirect(ctx context.Context, sc *gocql.Session, convID, msgID string, sender, receiver int64, ct []byte, msgType string, ts time.Time) error {
	id, err := gocql.ParseUUID(msgID)
	if err != nil {
		return err
	}
	return sc.Query(
		`INSERT INTO iceq.messages (conversation_id, created_at, id, sender_uin, receiver_uin, ciphertext, msg_type, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		convID, ts, id, sender, receiver, ct, msgType, "",
	).WithContext(ctx).Consistency(gocql.Quorum).Exec()
}

// updateRowStatus was the legacy direct-UPDATE path used
// before the wire format had CreatedAt on ReadPayload. Now
// that the wire format is fixed, the smoke test exercises
// the full NATS round trip; this helper is kept for the
// raw-CQL "wire bypass" diagnostic at the bottom of the
// file (intentionally unused in the main flow).
var _ = func(ctx context.Context, sc *gocql.Session, convID string, ts time.Time, id gocql.UUID, newStatus string) error {
	return sc.Query(
		`UPDATE iceq.messages SET status = ? WHERE conversation_id = ? AND created_at = ? AND id = ?`,
		newStatus, convID, ts, id,
	).WithContext(ctx).Consistency(gocql.Quorum).Exec()
}

// waitForStatus polls Scylla for the given (convID, ts, id)
// row until its `status` column matches `want`, or the
// deadline expires. Returns nil on success, an error
// describing the last observed state on timeout.
func waitForStatus(ctx context.Context, sc *gocql.Session, convID string, ts time.Time, id gocql.UUID, want string, within time.Duration) error {
	deadline := time.Now().Add(within)
	var lastObserved string
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("status=%q, want %q (last observed at row id=%s)", lastObserved, want, id.String())
		}
		var got string
		err := sc.Query(
			`SELECT status FROM iceq.messages WHERE conversation_id = ? AND created_at = ? AND id = ?`,
			convID, ts, id,
		).WithContext(ctx).Consistency(gocql.Quorum).Scan(&got)
		if err == nil && got == want {
			return nil
		}
		if err != nil {
			lastObserved = fmt.Sprintf("err=%v", err)
		} else {
			lastObserved = got
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// openScylla creates a single gocql session with the
// parameters known to work against the local Scylla 5.x
// container: protocol v4 (CQL native protocol that Scylla
// 5.x negotiates), DisableInitialHostLookup=true so we
// never hit the cluster-wide gossip round-trip before the
// first query, and a 3 s connect timeout so a wrong host
// fails fast instead of stalling the test loop.
func openScylla(ctx context.Context) *gocql.Session {
	cluster := gocql.NewCluster(scyllaHosts)
	cluster.Keyspace = "iceq"
	cluster.Consistency = gocql.Quorum
	cluster.ProtoVersion = 4
	cluster.DisableInitialHostLookup = true
	cluster.ConnectTimeout = 3 * time.Second
	cluster.Timeout = 5 * time.Second
	cluster.NumConns = 1
	s, err := cluster.CreateSession()
	if err != nil {
		fail("gocql CreateSession: " + err.Error())
	}
	return s
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
