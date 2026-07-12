// Step 2 smoke test — exercises every public function of the
// backend/shared packages against the live Step 1 infrastructure.
//
// This is not a unit test. It is a runtime integration check that
// the Step 2 code can talk to the Step 1 services, sign and verify
// a real JWT, build a real envelope, and open a real NATS
// subscription. Run with:
//
//	cd iceq/backend && go run ./cmd/smoketest
//
// Exit code 0 = all green. Any non-zero exit is a Step 2 regression
// that must be fixed before moving to Step 3.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/iceq/iceq/shared/db"
	"github.com/iceq/iceq/shared/jwt"
	"github.com/iceq/iceq/shared/models"
	"github.com/iceq/iceq/shared/natsclient"
	"github.com/nats-io/nats.go"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("[smoketest] FAIL: %v", err)
	}
	log.Printf("[smoketest] OK: all Step 2 packages work end-to-end against live infra")
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Postgres pool — verify the pool is alive and the
	// users table (from the Step 1 init) is reachable.
	log.Printf("[1/6] postgres: dialing")
	pgPool, err := db.NewPostgresPool(db.Config{
		PostgresDSN: envOr("ICEQ_PG_DSN", "postgres://postgres:postgres@localhost:5432/iceq?sslmode=disable"),
	})
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer pgPool.Close()
	var n int
	if err := pgPool.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&n); err != nil {
		return fmt.Errorf("postgres users count: %w", err)
	}
	log.Printf("[1/6] postgres: users count = %d", n)
	if _, err := pgPool.Exec(ctx, `
		INSERT INTO users (uin, username, password_hash, identity_key)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (uin) DO NOTHING
	`, int64(42), "smoketest_uin_42", "", ""); err != nil {
		return fmt.Errorf("postgres seed user 42: %w", err)
	}

	// 2. Scylla session — verify CreateSession succeeded and
	// the iceq keyspace's messages table is queryable.
	log.Printf("[2/6] scylla: dialing")
	sc, err := db.NewScyllaSession(db.Config{
		ScyllaHosts:    envOr("ICEQ_SCYLLA_HOSTS", "localhost:9042"),
		ScyllaKeyspace: envOr("ICEQ_SCYLLA_KEYSPACE", "iceq"),
	})
	if err != nil {
		return fmt.Errorf("scylla: %w", err)
	}
	defer sc.Close()
	var msgCount int
	if err := sc.Query("SELECT count(*) FROM iceq.messages").Scan(&msgCount); err != nil {
		return fmt.Errorf("scylla messages count: %w", err)
	}
	log.Printf("[2/6] scylla: messages count = %d", msgCount)

	// 3. Redis client — verify the client is alive and the
	// blocklist namespace is empty (no tokens revoked yet).
	log.Printf("[3/6] redis: dialing")
	rdb, err := db.NewRedisClient(db.Config{
		RedisAddr:     envOr("ICEQ_REDIS_ADDR", "localhost:6379"),
		RedisPassword: envOr("ICEQ_REDIS_PASSWORD", ""),
	})
	if err != nil {
		return fmt.Errorf("redis: %w", err)
	}
	defer rdb.Close()
	keys, err := rdb.Keys(ctx, "jwt:revoked:*").Result()
	if err != nil {
		return fmt.Errorf("redis keys: %w", err)
	}
	log.Printf("[3/6] redis: %d revoked tokens in blocklist", len(keys))

	// 4. JWT — sign an access token, verify it, revoke it,
	// confirm verify now rejects it.
	log.Printf("[4/6] jwt: sign + verify + revoke round trip")
	// F-2 (JWT assessment): the test secret must satisfy the
	// same length floor as production. "smoketest-secret-
	// not-for-prod-padding" is 42 bytes — comfortably above
	// minSecretBytes=32. We pad with a recognisable suffix so
	// a `grep` against the binary or a log line immediately
	// shows this is a fixture and not a leaked production key.
	mgr, err := jwt.NewManager("smoketest-secret-not-for-prod-padding", rdb, pgPool)
	if err != nil {
		return fmt.Errorf("jwt new manager: %w", err)
	}

	access, err := mgr.Sign(42, jwt.TokenTypeAccess)
	if err != nil {
		return fmt.Errorf("jwt sign access: %w", err)
	}
	refresh, err := mgr.Sign(42, jwt.TokenTypeRefresh)
	if err != nil {
		return fmt.Errorf("jwt sign refresh: %w", err)
	}

	claims, err := mgr.Verify(ctx, access.Token, jwt.TokenTypeAccess)
	if err != nil {
		return fmt.Errorf("jwt verify access: %w", err)
	}
	if claims.UIN != 42 {
		return fmt.Errorf("jwt claim UIN mismatch: got %d want 42", claims.UIN)
	}
	log.Printf("[4/6] jwt: access token verified, uin=%d jti=%s", claims.UIN, claims.JTI)

	if _, err := mgr.Verify(ctx, access.Token, jwt.TokenTypeRefresh); err == nil {
		return fmt.Errorf("jwt type discrimination failed: access token accepted as refresh")
	}
	log.Printf("[4/6] jwt: type discriminator rejects cross-type use")

	if err := mgr.Revoke(ctx, access.Token); err != nil {
		return fmt.Errorf("jwt revoke: %w", err)
	}
	if _, err := mgr.Verify(ctx, access.Token, jwt.TokenTypeAccess); err == nil {
		return fmt.Errorf("jwt revoke failed: revoked token still verifies")
	}
	log.Printf("[4/6] jwt: revoked token now rejected (blocklist OK)")

	if _, err := mgr.Verify(ctx, refresh.Token, jwt.TokenTypeRefresh); err != nil {
		return fmt.Errorf("jwt: non-revoked refresh token unexpectedly rejected: %w", err)
	}
	log.Printf("[4/6] jwt: untouched refresh token still verifies")

	// 5. Envelope — build a direct-message envelope, JSON-round
	// trip it, unmarshal the payload into the right struct.
	log.Printf("[5/6] models: envelope round trip")
	env, err := models.NewEnvelope(models.EnvelopeTypeDirect, models.DirectMessagePayload{
		ConversationID: "12:42",
		SenderUIN:      42,
		ReceiverUIN:    1007,
		Content:        "hello",
		ContentType:    models.ContentTypeText,
	})
	if err != nil {
		return fmt.Errorf("envelope new: %w", err)
	}
	wire, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("envelope marshal: %w", err)
	}
	var back models.Envelope
	if err := json.Unmarshal(wire, &back); err != nil {
		return fmt.Errorf("envelope unmarshal: %w", err)
	}
	var dm models.DirectMessagePayload
	if err := json.Unmarshal(back.Payload, &dm); err != nil {
		return fmt.Errorf("envelope payload unmarshal: %w", err)
	}
	if dm.ReceiverUIN != 1007 || dm.Content != "hello" {
		return fmt.Errorf("envelope payload mismatch: %+v", dm)
	}
	log.Printf("[5/6] models: envelope id=%s ts=%d payload=%s", back.ID, back.TS, string(back.Payload))

	// 6. NATS — connect, publish a message, subscribe, confirm
	// the message is delivered.
	log.Printf("[6/6] nats: publish + subscribe round trip")
	nc, err := natsclient.NewClient(envOr("ICEQ_NATS_URL", "nats://localhost:4222"), "smoketest")
	if err != nil {
		return fmt.Errorf("nats connect: %w", err)
	}
	defer nc.Drain()

	subject := "iceq.smoketest"
	got := make(chan []byte, 1)
	sub, err := nc.Subscribe(subject, func(m *nats.Msg) {
		got <- m.Data
	})
	if err != nil {
		return fmt.Errorf("nats subscribe: %w", err)
	}
	defer sub.Unsubscribe()

	if err := nc.Publish(subject, []byte("ping")); err != nil {
		return fmt.Errorf("nats publish: %w", err)
	}

	select {
	case data := <-got:
		if string(data) != "ping" {
			return fmt.Errorf("nats: got %q want ping", string(data))
		}
		log.Printf("[6/6] nats: published and received %q on %s", data, subject)
	case <-time.After(3 * time.Second):
		return fmt.Errorf("nats: timed out waiting for published message")
	}

	return nil
}

func envOr(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return fallback
}
