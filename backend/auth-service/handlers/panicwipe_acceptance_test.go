//go:build integration
// +build integration

// Package handlers — mandatory five-storage acceptance test for panic wipe.
//
// This test gate is CLOSED by default. Normal `go test ./...` does NOT run
// acceptance tests — use the integration build tag:
//
//	ICEQ_ACCEPTANCE=1 \
//	ICEQ_ACCEPTANCE_PG_URL="postgres://postgres:postgres@localhost:5434/iceq?sslmode=disable" \
//	ICEQ_ACCEPTANCE_REDIS_ADDR="localhost:6380" \
//	ICEQ_ACCEPTANCE_SCYLLA_HOSTS="localhost:9043" \
//	ICEQ_ACCEPTANCE_NATS_URL="nats://localhost:4223" \
//	ICEQ_ACCEPTANCE_MINIO_ENDPOINT="localhost:9002" \
//	ICEQ_ACCEPTANCE_MINIO_ACCESS_KEY="minioadmin" \
//	ICEQ_ACCEPTANCE_MINIO_SECRET_KEY="minioadmin" \
//	go test -count=1 -race -tags=integration -run TestAcceptanceFullStack -v ./auth-service/handlers/
//
// ALL five storage layers (PostgreSQL, Redis, Scylla, NATS JetStream, MinIO)
// are MANDATORY. The test FAILS if any connection variable is unset or any
// service is unreachable — no silent skipping, no localhost defaults that
// risk touching the production iceq-* Compose project.
//
// The disposable acceptance stack is an isolated Compose project with
// separate volumes, network, and port mappings:
//
//	docker compose -f deploy/docker-compose.acceptance.yml up -d
//	docker compose -f deploy/docker-compose.acceptance.yml down -v
package handlers

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gocql/gocql"
	"github.com/iceq/iceq/message-service/store"
	"github.com/iceq/iceq/shared/jwt"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
)

// ---------------------------------------------------------------------------
// Acceptance gate — fail closed
// ---------------------------------------------------------------------------

func requireAcceptanceEnv(t *testing.T) {
	t.Helper()
	if os.Getenv("ICEQ_ACCEPTANCE") != "1" {
		t.Fatalf("ICEQ_ACCEPTANCE=1 is required to run acceptance tests. " +
			"Set it to explicitly opt in to the destructive five-storage acceptance harness.")
	}
}

// ---------------------------------------------------------------------------
// Mandatory connection helpers — no defaults that could hit production
// ---------------------------------------------------------------------------

func acceptancePGURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("ICEQ_ACCEPTANCE_PG_URL")
	if u == "" {
		t.Fatal("ICEQ_ACCEPTANCE_PG_URL is required (e.g. postgres://postgres:postgres@localhost:5434/iceq?sslmode=disable)")
	}
	return u
}

func acceptanceRedisAddr(t *testing.T) string {
	t.Helper()
	a := os.Getenv("ICEQ_ACCEPTANCE_REDIS_ADDR")
	if a == "" {
		t.Fatal("ICEQ_ACCEPTANCE_REDIS_ADDR is required (e.g. localhost:6380)")
	}
	return a
}

func acceptanceScyllaHosts(t *testing.T) []string {
	t.Helper()
	h := os.Getenv("ICEQ_ACCEPTANCE_SCYLLA_HOSTS")
	if h == "" {
		t.Fatal("ICEQ_ACCEPTANCE_SCYLLA_HOSTS is required (e.g. localhost:9043)")
	}
	return strings.Split(h, ",")
}

func acceptanceNATSURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("ICEQ_ACCEPTANCE_NATS_URL")
	if u == "" {
		t.Fatal("ICEQ_ACCEPTANCE_NATS_URL is required (e.g. nats://localhost:4223)")
	}
	return u
}

func acceptanceMinioEndpoint(t *testing.T) string {
	t.Helper()
	e := os.Getenv("ICEQ_ACCEPTANCE_MINIO_ENDPOINT")
	if e == "" {
		t.Fatal("ICEQ_ACCEPTANCE_MINIO_ENDPOINT is required (e.g. localhost:9002)")
	}
	return e
}

func acceptanceMinioAccessKey(t *testing.T) string {
	t.Helper()
	k := os.Getenv("ICEQ_ACCEPTANCE_MINIO_ACCESS_KEY")
	if k == "" {
		t.Fatal("ICEQ_ACCEPTANCE_MINIO_ACCESS_KEY is required (e.g. minioadmin)")
	}
	return k
}

func acceptanceMinioSecretKey(t *testing.T) string {
	t.Helper()
	k := os.Getenv("ICEQ_ACCEPTANCE_MINIO_SECRET_KEY")
	if k == "" {
		t.Fatal("ICEQ_ACCEPTANCE_MINIO_SECRET_KEY is required (e.g. minioadmin)")
	}
	return k
}

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const (
	acceptanceTestUIN    = int64(90000001)
	acceptanceControlUIN = int64(90000002)
	acceptanceTestBucket = "iceq-files"
	acceptanceTestRegion = "us-east-1"
)

// ---------------------------------------------------------------------------
// Production storage adapters
// ---------------------------------------------------------------------------

// productionMinioCleaner wraps a real *minio.Client with the same semantics
// as file-service/minio.MinioClient.DeleteUserObjects — exact keys only,
// no ListObjects, deterministic avatar path, NoSuchKey on avatar is non-fatal.
type productionMinioCleaner struct {
	client *minio.Client
}

func (c *productionMinioCleaner) DeleteUserObjects(ctx context.Context, uin int64, fileKeys []string) error {
	for _, key := range fileKeys {
		if key == "" {
			continue
		}
		if err := c.client.RemoveObject(ctx, acceptanceTestBucket, key, minio.RemoveObjectOptions{}); err != nil {
			return fmt.Errorf("delete file object %s: %w", key, err)
		}
	}
	// Delete the deterministic avatar key. NoSuchKey is not an error.
	avatarKey := fmt.Sprintf("avatars/%d", uin)
	if err := c.client.RemoveObject(ctx, "iceq-avatars", avatarKey, minio.RemoveObjectOptions{}); err != nil {
		if !strings.Contains(err.Error(), "The specified key does not exist") {
			return fmt.Errorf("delete avatar: %w", err)
		}
	}
	return nil
}

func (c *productionMinioCleaner) DeleteUserGrants(ctx context.Context, uin int64) error {
	return nil // Grants live in PG, deleted inside the PanicWipe transaction.
}

// productionNATSCleaner wraps a real *nats.Conn to purge per-user JetStream
// subjects. Same contract as natsclient.Client.PurgeUserStreams.
type productionNATSCleaner struct {
	nc *nats.Conn
}

func (c *productionNATSCleaner) PurgeUserStreams(ctx context.Context, uin int64) error {
	js, err := c.nc.JetStream()
	if err != nil {
		return fmt.Errorf("jetstream unavailable: %w", err)
	}
	directSubject := fmt.Sprintf("msg.direct.%d", uin)
	err = js.PurgeStream("ICEQ_DELIVERY", nats.Context(ctx), &nats.StreamPurgeRequest{
		Subject: directSubject,
	})
	if err != nil && err != nats.ErrNoStreamResponse {
		return fmt.Errorf("purge user stream %q: %w", directSubject, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Schema bootstrap — apply real migrations
// ---------------------------------------------------------------------------

var pgMigrationFiles = []string{
	"001_session_epoch.sql",
	"002_prekey_bundle_registration_id.sql",
	"003_contacts_requested_by.sql",
	"005_wiped_accounts.sql",
	"006_file_object_owners.sql",
	"007_file_object_grants.sql",
	"008_group_crypto_epoch.sql",
	"009_sender_key_distribution_inbox.sql",
	"014_panic_wipe_pin.sql",
	"015_wipe_public_key.sql",
	"016_wipe_jobs.sql",
}

func applyAcceptanceSchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Match the production fresh-volume bootstrap order: the base schema is
	// created by postgres-init.sql before any numbered migration runs. Guard the
	// bootstrap so the acceptance test remains safe to re-run against its
	// disposable database without re-creating the sequence and base tables.
	var usersTable *string
	if err := pool.QueryRow(ctx, `SELECT to_regclass('public.users')::text`).Scan(&usersTable); err != nil {
		t.Fatalf("inspect PG base schema: %v", err)
	}
	if usersTable == nil {
		basePath := "../../../deploy/init/postgres-init.sql"
		baseRaw, err := os.ReadFile(basePath)
		if err != nil {
			t.Fatalf("read PG base schema %s: %v", basePath, err)
		}
		if _, err := pool.Exec(ctx, string(baseRaw)); err != nil {
			t.Fatalf("apply PG base schema %s: %v", basePath, err)
		}
	}

	// Apply real migration files from the deploy/init/migrations directory.
	// Execute each file as one PostgreSQL script so dollar-quoted DO blocks are
	// preserved exactly as production runs them.
	migrationDir := "../../../deploy/init/migrations"
	for _, filename := range pgMigrationFiles {
		path := migrationDir + "/" + filename
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read PG migration %s: %v", path, err)
		}
		if _, err := pool.Exec(ctx, string(raw)); err != nil {
			t.Fatalf("apply PG migration %s: %v", filename, err)
		}
	}
	t.Log("acceptance schema created from real migration files")

	// Clean leftover rows from previous runs.
	for _, table := range []string{
		"file_object_grants", "file_objects", "group_members",
		"contacts", "wipe_jobs", "wiped_accounts", "one_time_prekeys",
		"prekey_bundles", "refresh_tokens", "user_security_settings",
		"sender_key_distributions", "groups", "users",
	} {
		pool.Exec(ctx, `DELETE FROM `+table)
	}
}

// splitSQLStatements splits raw SQL text by semicolons, strips blank lines and
// -- comments, and returns non-empty statements. It is intentionally simple —
// production migration files do not contain semicolons inside string literals
// or multi-line functions.
func splitSQLStatements(raw string) []string {
	var stmts []string
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}
		stmts = append(stmts, trimmed)
	}
	joined := strings.Join(stmts, " ")
	var result []string
	for _, s := range strings.Split(joined, ";") {
		s = strings.TrimSpace(s)
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}

func applyScyllaSchema(t *testing.T, session *gocql.Session) {
	t.Helper()
	ctx := context.Background()

	// Apply base schema first (creates messages, group_messages tables).
	basePath := "../../../deploy/init/scylla-init.cql"
	baseRaw, err := os.ReadFile(basePath)
	if err != nil {
		t.Fatalf("read Scylla base schema: %v", err)
	}
	applyCQLStatements(t, session, ctx, string(baseRaw), "scylla-init.cql")

	cqlFiles := []string{
		"004_panic_wipe_message_indexes.cql",
		"010_group_message_crypto_epoch.cql",
		"011_disappearing_messages.cql",
		"012_durable_message_ingest.cql",
		"013_group_recipient_snapshot.cql",
		"017_user_erasure_indexes.cql",
		// 018 ALTERs message_ingest (created by 012) to add
		// recipient_set_sanitized -- must be applied here or every query
		// touching that column fails with "undefined column" against this
		// test's Scylla instance, exactly the silently-missing-migration
		// scenario this fixture exists to catch.
		"018_message_ingest_recipient_sanitized.cql",
	}

	migrationDir := "../../../deploy/init/migrations"
	for _, f := range cqlFiles {
		path := migrationDir + "/" + f
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read CQL migration %s: %v", path, err)
		}
		applyCQLStatements(t, session, ctx, string(raw), f)
	}

	// Clean leftover rows.
	for _, table := range []string{
		"message_deletion_index", "group_message_deletion_index",
		"messages", "group_messages",
		"message_ingest", "message_ingest_erasure_index",
		"message_outbox", "message_outbox_erasure_index",
		"group_message_outbox", "group_message_outbox_erasure_index",
	} {
		session.Query(`TRUNCATE ` + table).WithContext(ctx).Exec()
	}
}

// applyCQLStatements strips -- comments, splits on ;, and executes each
// non-empty CQL statement. "already exist" errors are treated as idempotent.
func applyCQLStatements(t *testing.T, session *gocql.Session, ctx context.Context, raw, label string) {
	t.Helper()
	var stripped []string
	for _, line := range strings.Split(raw, "\n") {
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		stripped = append(stripped, trimmed)
	}
	cleanCQL := strings.Join(stripped, " ")

	for _, stmt := range strings.Split(cleanCQL, ";") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if err := session.Query(stmt).WithContext(ctx).Exec(); err != nil {
			le := strings.ToLower(err.Error())
			if strings.Contains(le, "already exist") || strings.Contains(le, "existing keyspace") ||
				strings.Contains(le, "already existing") || strings.Contains(le, "conflicts with an existing column") {
				continue
			}
			t.Fatalf("apply CQL %s: %v\n%s", label, err, stmt)
		}
	}
	t.Logf("applied CQL: %s", label)

	// Clean leftover rows.
	for _, table := range []string{
		"message_deletion_index", "group_message_deletion_index",
		"messages", "group_messages",
		"message_ingest", "message_ingest_erasure_index",
		"message_outbox", "message_outbox_erasure_index",
		"group_message_outbox", "group_message_outbox_erasure_index",
	} {
		session.Query(`TRUNCATE ` + table).WithContext(ctx).Exec()
	}
}

// scyllaSeedKeys holds the primary keys of rows seeded for a single user so
// the verification pass can query exact rows without ALLOW FILTERING.
type scyllaSeedKeys struct {
	fileObjectKeys []string

	convID          string
	directCreatedAt time.Time
	msgID           gocql.UUID

	grpID          gocql.UUID
	groupCreatedAt time.Time
	grpMsgID       gocql.UUID

	ingestClientID  string
	outboxBucket    int8
	grpOutboxBucket int8

	// Recipient-only fixture: the wiped user is only a recipient, not sender.
	recipientOnlyGrpOutboxBucket int8
	recipientOnlyGrpCreatedAt    time.Time
	recipientOnlyGrpMsgID        gocql.UUID

	// Group message_ingest recipient fixture: the wiped user is a recipient
	// (not sender) of a durable ingest receipt that also has a surviving
	// recipient. Exercises message_ingest's own role-aware sanitization,
	// distinct from group_message_outbox above.
	groupIngestSenderUIN   int64
	groupIngestClientID    string
	groupIngestSurvivorUIN int64
}

func seedAcceptanceUserFullStack(t *testing.T, pool *pgxpool.Pool, rdb *redis.Client,
	session *gocql.Session, nc *nats.Conn, minioClient *minio.Client,
	uin int64, label string) scyllaSeedKeys {

	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s := itoa(uin)

	// --- PostgreSQL ---
	// Production foreign keys require every contact, grant and group owner to
	// be a real user. Seed deterministic auxiliary users before relationships.
	for _, fixtureUIN := range []int64{uin, uin + 100, uin + 200, acceptanceControlUIN} {
		if _, err := pool.Exec(ctx, `INSERT INTO users (uin, username, password_hash, identity_key)
			VALUES ($1, $2, '$2a$10$placeholder', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=')
			ON CONFLICT (uin) DO NOTHING`, fixtureUIN, "acceptance_"+itoa(fixtureUIN)); err != nil {
			t.Fatalf("[%s] seed user %d: %v", label, fixtureUIN, err)
		}
	}

	// Contacts.
	for _, target := range []int64{uin + 100, uin + 200} {
		if _, err := pool.Exec(ctx, `INSERT INTO contacts (owner_uin, target_uin, requested_by_uin, status)
			VALUES ($1, $2, $1, 'accepted') ON CONFLICT DO NOTHING`, uin, target); err != nil {
			t.Fatalf("[%s] seed contacts: %v", label, err)
		}
	}

	// Group memberships.
	var pgGroupID string
	if err := pool.QueryRow(ctx, `INSERT INTO groups (name, owner_uin)
		VALUES ($1, $2) RETURNING id::text`, "acceptance-group-"+s, uin).Scan(&pgGroupID); err != nil {
		t.Fatalf("[%s] seed group: %v", label, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO group_members (group_id, uin, role)
		VALUES ($1::uuid, $2, 'admin') ON CONFLICT DO NOTHING`, pgGroupID, uin); err != nil {
		t.Fatalf("[%s] seed group_members: %v", label, err)
	}

	// File objects + MinIO objects. Production object keys are UUIDs and the
	// grant row carries the same object key plus owner/grantee UINs.
	fileObjectKeys := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		objectUUID, err := gocql.RandomUUID()
		if err != nil {
			t.Fatalf("[%s] generate file object key: %v", label, err)
		}
		objKey := objectUUID.String()
		if _, err := pool.Exec(ctx,
			`INSERT INTO file_objects (object_key, owner_uin) VALUES ($1::uuid, $2)`,
			objKey, uin); err != nil {
			t.Fatalf("[%s] seed file object: %v", label, err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO file_object_grants (object_key, owner_uin, grantee_uin)
			VALUES ($1::uuid, $2, $3) ON CONFLICT DO NOTHING`, objKey, uin, uin+100); err != nil {
			t.Fatalf("[%s] seed file_object_grants: %v", label, err)
		}
		fileObjectKeys = append(fileObjectKeys, objKey)

		// MinIO: upload test object.
		payload := []byte("encrypted-payload-" + label + "-" + objKey)
		_, err = minioClient.PutObject(ctx, acceptanceTestBucket, objKey,
			bytes.NewReader(payload), int64(len(payload)), minio.PutObjectOptions{})
		if err != nil {
			t.Fatalf("[%s] seed minio object %s: %v", label, objKey, err)
		}
	}

	// Avatar.
	avatarKey := fmt.Sprintf("avatars/%d", uin)
	if _, err := minioClient.PutObject(ctx, "iceq-avatars", avatarKey,
		bytes.NewReader([]byte("fake-avatar-"+label)), 0, minio.PutObjectOptions{}); err != nil {
		t.Fatalf("[%s] seed avatar: %v", label, err)
	}

	// --- Redis ---
	for _, key := range []string{
		"presence:" + s,
		"undelivered:" + s,
		"poll:stream:" + s,
		"poll:cursors:" + s,
		"poll:cursor-order:" + s,
		"login_attempts:" + s,
		"jwt:blocklist:wipe:" + s,
	} {
		if err := rdb.Set(ctx, key, "1", 7*24*time.Hour).Err(); err != nil {
			t.Fatalf("[%s] seed redis key %s: %v", label, key, err)
		}
	}
	// Hash-tag poll keys.
	if err := rdb.Set(ctx, "poll:{"+s+"}:sequence", "1", 0).Err(); err != nil {
		t.Fatalf("[%s] seed redis poll sequence: %v", label, err)
	}
	if err := rdb.Set(ctx, "poll:{"+s+"}:seen:abc123", "1", 0).Err(); err != nil {
		t.Fatalf("[%s] seed redis poll seen: %v", label, err)
	}

	// --- Scylla ---
	// Use a single createdAt per message to eliminate the false positive
	// where the deletion index and ciphertext row have different timestamps.
	directCreatedAt := time.Now().Truncate(time.Millisecond)
	msgID, err := gocql.RandomUUID()
	if err != nil {
		t.Fatalf("[%s] generate msgID: %v", label, err)
	}
	convID := "conv-" + label
	if err := session.Query(`INSERT INTO message_deletion_index (uin, conversation_id, created_at, id)
		VALUES (?, ?, ?, ?)`, uin, convID, directCreatedAt, msgID).WithContext(ctx).Exec(); err != nil {
		t.Fatalf("[%s] seed message_deletion_index: %v", label, err)
	}
	if err := session.Query(`INSERT INTO messages (conversation_id, created_at, id, sender_uin, receiver_uin, ciphertext, msg_type, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, convID, directCreatedAt, msgID, uin, uin+100, []byte("test-ciphertext-"+label), "signal_message", "").WithContext(ctx).Exec(); err != nil {
		t.Fatalf("[%s] seed messages: %v", label, err)
	}

	// Seed message_ingest receipt + erasure index.
	ingestClientID := "acceptance-client-" + label
	if err := session.Query(`INSERT INTO message_ingest (sender_uin, client_id, message_kind, receiver_uin, conversation_id, envelope, envelope_hash, message_id, created_at, state, owner_token, lease_until)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		uin, ingestClientID, "direct", uin+100, convID, []byte("env"), []byte("hash12345678901234567890123456789012"), msgID, directCreatedAt, "stored", msgID, directCreatedAt,
	).WithContext(ctx).Exec(); err != nil {
		t.Fatalf("[%s] seed message_ingest: %v", label, err)
	}
	if err := session.Query(`INSERT INTO message_ingest_erasure_index (uin, sender_uin, client_id)
		VALUES (?, ?, ?)`, uin, uin, ingestClientID).WithContext(ctx).Exec(); err != nil {
		t.Fatalf("[%s] seed message_ingest_erasure_index: %v", label, err)
	}

	// Seed direct outbox + erasure index (sender entry).
	outboxBucket := int8(msgID[0] & 15)
	if err := session.Query(`INSERT INTO message_outbox (bucket, created_at, message_id, receiver_uin, sender_uin, client_id, conversation_id, envelope, envelope_hash, state)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		outboxBucket, directCreatedAt, msgID, uin+100, uin, ingestClientID, convID, []byte("env"), []byte("hash12345678901234567890123456789012"), "pending",
	).WithContext(ctx).Exec(); err != nil {
		t.Fatalf("[%s] seed message_outbox: %v", label, err)
	}
	if err := session.Query(`INSERT INTO message_outbox_erasure_index (uin, bucket, created_at, message_id)
		VALUES (?, ?, ?, ?)`, uin, outboxBucket, directCreatedAt, msgID).WithContext(ctx).Exec(); err != nil {
		t.Fatalf("[%s] seed message_outbox_erasure_index: %v", label, err)
	}

	// Seed group message deletion index + group_messages.
	groupCreatedAt := time.Now().Truncate(time.Millisecond)
	grpMsgID, err := gocql.RandomUUID()
	if err != nil {
		t.Fatalf("[%s] generate grpMsgID: %v", label, err)
	}
	grpID, err := gocql.RandomUUID()
	if err != nil {
		t.Fatalf("[%s] generate grpID: %v", label, err)
	}
	if err := session.Query(`INSERT INTO group_message_deletion_index (uin, group_id, created_at, id)
		VALUES (?, ?, ?, ?)`, uin, grpID, groupCreatedAt, grpMsgID).WithContext(ctx).Exec(); err != nil {
		t.Fatalf("[%s] seed group_message_deletion_index: %v", label, err)
	}
	if err := session.Query(`INSERT INTO group_messages (group_id, created_at, id, sender_uin, crypto_epoch, ciphertext, msg_type)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, grpID, groupCreatedAt, grpMsgID, uin, 1, []byte("test-group-ciphertext-"+label), "signal_message").WithContext(ctx).Exec(); err != nil {
		t.Fatalf("[%s] seed group_messages: %v", label, err)
	}

	// Seed group outbox + erasure index (sender entry).
	// Recipient erasure index entries are added in a second group outbox
	// row seeded below for the recipient-only fixture.
	grpOutboxBucket := int8(grpMsgID[0] & 15)
	if err := session.Query(`INSERT INTO group_message_outbox (bucket, created_at, message_id, group_id, sender_uin, client_id, crypto_epoch, recipient_uins, envelope, envelope_hash, state)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		grpOutboxBucket, groupCreatedAt, grpMsgID, grpID, uin, ingestClientID+"-group", 1, []int64{uin + 100}, []byte("env"), []byte("hash12345678901234567890123456789012"), "pending",
	).WithContext(ctx).Exec(); err != nil {
		t.Fatalf("[%s] seed group_message_outbox: %v", label, err)
	}
	if err := session.Query(`INSERT INTO group_message_outbox_erasure_index (uin, bucket, created_at, message_id, role)
		VALUES (?, ?, ?, ?, ?)`, uin, grpOutboxBucket, groupCreatedAt, grpMsgID, "sender").WithContext(ctx).Exec(); err != nil {
		t.Fatalf("[%s] seed group_message_outbox_erasure_index (sender): %v", label, err)
	}
	// Also index the recipient so erasure-index coverage includes
	// recipient entries.
	if err := session.Query(`INSERT INTO group_message_outbox_erasure_index (uin, bucket, created_at, message_id, role)
		VALUES (?, ?, ?, ?, ?)`, uin+100, grpOutboxBucket, groupCreatedAt, grpMsgID, "recipient").WithContext(ctx).Exec(); err != nil {
		t.Fatalf("[%s] seed group_message_outbox_erasure_index (recipient): %v", label, err)
	}

	// Seed a second group outbox row where this user is ONLY a recipient,
	// not the sender. The sender is the control user (for test user) or
	// the test user + offset (for control user).
	recipientGrpMsgID, err := gocql.RandomUUID()
	if err != nil {
		t.Fatalf("[%s] generate recipient-only grpMsgID: %v", label, err)
	}
	recipientGrpID, err := gocql.RandomUUID()
	if err != nil {
		t.Fatalf("[%s] generate recipient-only grpID: %v", label, err)
	}
	recipientGrpCreatedAt := time.Now().Truncate(time.Millisecond)
	recipientGrpOutboxBucket := int8(recipientGrpMsgID[0] & 15)

	// The sender for this group outbox is the control user (for test user)
	// or test user + 200 (for control user). The test user is a recipient.
	senderForRecipientFixture := acceptanceControlUIN
	if uin == acceptanceControlUIN {
		senderForRecipientFixture = acceptanceTestUIN + 200
	}

	if err := session.Query(`INSERT INTO group_message_outbox (bucket, created_at, message_id, group_id, sender_uin, client_id, crypto_epoch, recipient_uins, envelope, envelope_hash, state)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		recipientGrpOutboxBucket, recipientGrpCreatedAt, recipientGrpMsgID, recipientGrpID,
		senderForRecipientFixture, "acceptance-client-"+label+"-recipient-only", 1,
		[]int64{uin, acceptanceControlUIN},
		[]byte("env"), []byte("hash12345678901234567890123456789012"), "pending",
	).WithContext(ctx).Exec(); err != nil {
		t.Fatalf("[%s] seed recipient-only group_message_outbox: %v", label, err)
	}
	// Index sender.
	if err := session.Query(`INSERT INTO group_message_outbox_erasure_index (uin, bucket, created_at, message_id, role)
		VALUES (?, ?, ?, ?, ?)`, senderForRecipientFixture, recipientGrpOutboxBucket, recipientGrpCreatedAt, recipientGrpMsgID, "sender").WithContext(ctx).Exec(); err != nil {
		t.Fatalf("[%s] seed recipient-only erasure index (sender): %v", label, err)
	}
	// Index this user as recipient.
	if err := session.Query(`INSERT INTO group_message_outbox_erasure_index (uin, bucket, created_at, message_id, role)
		VALUES (?, ?, ?, ?, ?)`, uin, recipientGrpOutboxBucket, recipientGrpCreatedAt, recipientGrpMsgID, "recipient").WithContext(ctx).Exec(); err != nil {
		t.Fatalf("[%s] seed recipient-only erasure index (recipient %d): %v", label, uin, err)
	}
	// Index the control user as recipient too (shared row).
	if err := session.Query(`INSERT INTO group_message_outbox_erasure_index (uin, bucket, created_at, message_id, role)
		VALUES (?, ?, ?, ?, ?)`, acceptanceControlUIN, recipientGrpOutboxBucket, recipientGrpCreatedAt, recipientGrpMsgID, "recipient").WithContext(ctx).Exec(); err != nil {
		t.Fatalf("[%s] seed recipient-only erasure index (recipient control): %v", label, err)
	}

	// Seed a group message_ingest receipt where this user is a RECIPIENT
	// (not sender), alongside another recipient who must survive the wipe.
	// Mirrors the recipient-only group_message_outbox fixture above but
	// exercises message_ingest's own role-aware sanitization path
	// (recipient_uins reduced in place, recipient_set_sanitized marker set,
	// row NOT deleted since the sender is untouched and a recipient remains).
	groupIngestSenderUIN := acceptanceControlUIN
	if uin == acceptanceControlUIN {
		groupIngestSenderUIN = acceptanceTestUIN + 200
	}
	groupIngestSurvivorUIN := uin + 100
	groupIngestClientID := "acceptance-client-" + label + "-group-ingest"
	groupIngestMsgID, err := gocql.RandomUUID()
	if err != nil {
		t.Fatalf("[%s] generate group ingest msgID: %v", label, err)
	}
	groupIngestGroupID, err := gocql.RandomUUID()
	if err != nil {
		t.Fatalf("[%s] generate group ingest groupID: %v", label, err)
	}
	groupIngestCreatedAt := time.Now().Truncate(time.Millisecond)
	if err := session.Query(`INSERT INTO message_ingest
		(sender_uin, client_id, message_kind, group_id, crypto_epoch, recipient_uins, envelope, envelope_hash, message_id, created_at, state, owner_token, lease_until)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		groupIngestSenderUIN, groupIngestClientID, "group", groupIngestGroupID, int64(1),
		[]int64{uin, groupIngestSurvivorUIN}, []byte("env"), []byte("hash12345678901234567890123456789012"),
		groupIngestMsgID, groupIngestCreatedAt, "stored", groupIngestMsgID, groupIngestCreatedAt,
	).WithContext(ctx).Exec(); err != nil {
		t.Fatalf("[%s] seed group message_ingest: %v", label, err)
	}
	// Index every uin that appears in this receipt, mirroring Claim()'s
	// erasureIndexUINs: sender, the wiped recipient, and the survivor.
	for _, indexUIN := range []int64{groupIngestSenderUIN, uin, groupIngestSurvivorUIN} {
		if err := session.Query(`INSERT INTO message_ingest_erasure_index (uin, sender_uin, client_id)
			VALUES (?, ?, ?)`, indexUIN, groupIngestSenderUIN, groupIngestClientID).WithContext(ctx).Exec(); err != nil {
			t.Fatalf("[%s] seed group ingest erasure index (uin %d): %v", label, indexUIN, err)
		}
	}

	// --- NATS JetStream ---
	js, err := nc.JetStream()
	if err != nil {
		t.Fatalf("[%s] jetstream: %v", label, err)
	}
	// Ensure the delivery stream exists.
	if _, err := js.AddStream(&nats.StreamConfig{
		Name:     "ICEQ_DELIVERY",
		Subjects: []string{"msg.direct.>"},
	}); err != nil {
		t.Fatalf("[%s] jetstream add stream: %v", label, err)
	}
	// Publish test messages synchronously and wait for JetStream
	// acknowledgement. Any publish error fails the test — silent
	// NATS failures must not mask missing data.
	_, err = js.Publish(fmt.Sprintf("msg.direct.%d", uin), []byte("test-direct-"+label), nats.Context(ctx))
	if err != nil {
		t.Fatalf("[%s] nats publish: %v", label, err)
	}

	t.Logf("[%s] seeded across all 5 storage layers", label)
	return scyllaSeedKeys{
		fileObjectKeys:               fileObjectKeys,
		convID:                       convID,
		directCreatedAt:              directCreatedAt,
		msgID:                        msgID,
		grpID:                        grpID,
		groupCreatedAt:               groupCreatedAt,
		grpMsgID:                     grpMsgID,
		ingestClientID:               ingestClientID,
		outboxBucket:                 outboxBucket,
		grpOutboxBucket:              grpOutboxBucket,
		recipientOnlyGrpOutboxBucket: recipientGrpOutboxBucket,
		recipientOnlyGrpCreatedAt:    recipientGrpCreatedAt,
		recipientOnlyGrpMsgID:        recipientGrpMsgID,
		groupIngestSenderUIN:         groupIngestSenderUIN,
		groupIngestClientID:          groupIngestClientID,
		groupIngestSurvivorUIN:       groupIngestSurvivorUIN,
	}
}

// ---------------------------------------------------------------------------
// Pre-wipe verification — prove every seeded row exists before any deletion
// ---------------------------------------------------------------------------

// verifySeededFootprintFullStack confirms that every expected test-user and
// control-user row, key, object, and message actually exists before the panic
// wipe executes. The test must never interpret a failed seed operation as
// successful deletion. This function MUST run after seeding and BEFORE any
// wipe is attempted.
func verifySeededFootprintFullStack(t *testing.T, pool *pgxpool.Pool, rdb *redis.Client,
	session *gocql.Session, nc *nats.Conn, minioClient *minio.Client,
	uin int64, label string, keys scyllaSeedKeys, isControl bool) {

	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s := itoa(uin)

	// --- PostgreSQL: verify expected rows exist ---
	pgChecks := []struct {
		table, where string
		args         []any
	}{
		{"users", "uin = $1", []any{uin}},
		{"contacts", "owner_uin = $1", []any{uin}},
		{"group_members", "uin = $1", []any{uin}},
		{"file_objects", "owner_uin = $1", []any{uin}},
	}
	for _, c := range pgChecks {
		var count int
		if err := pool.QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE %s`, c.table, c.where), c.args...).Scan(&count); err != nil {
			t.Fatalf("[%s] pre-wipe verify %s: %v", label, c.table, err)
		}
		if count == 0 {
			t.Fatalf("[%s] pre-wipe verify: %s has 0 rows — seed did not persist", label, c.table)
		}
	}

	// --- Redis: verify expected keys exist ---
	redisKeys := []string{
		"presence:" + s,
		"undelivered:" + s,
		"poll:stream:" + s,
		"poll:cursors:" + s,
		"poll:cursor-order:" + s,
	}
	for _, key := range redisKeys {
		exists, err := rdb.Exists(ctx, key).Result()
		if err != nil {
			t.Fatalf("[%s] pre-wipe verify redis %s: %v", label, key, err)
		}
		if exists == 0 {
			t.Fatalf("[%s] pre-wipe verify: redis key %s missing — seed did not persist", label, key)
		}
	}

	// --- Scylla: verify exact rows exist ---
	var scyllaCount int
	iter := session.Query(`SELECT COUNT(*) FROM message_deletion_index WHERE uin = ?`, uin).WithContext(ctx).Iter()
	iter.Scan(&scyllaCount)
	if err := iter.Close(); err != nil {
		t.Fatalf("[%s] pre-wipe verify message_deletion_index iter close: %v", label, err)
	}
	if scyllaCount == 0 {
		t.Fatalf("[%s] pre-wipe verify: message_deletion_index has 0 rows for uin=%d", label, uin)
	}

	// Verify exact messages row.
	var msgCount int
	iter = session.Query(`SELECT COUNT(*) FROM messages WHERE conversation_id = ? AND created_at = ? AND id = ?`,
		keys.convID, keys.directCreatedAt, keys.msgID).WithContext(ctx).Iter()
	iter.Scan(&msgCount)
	if err := iter.Close(); err != nil {
		t.Fatalf("[%s] pre-wipe verify messages iter close: %v", label, err)
	}
	if msgCount == 0 {
		t.Fatalf("[%s] pre-wipe verify: messages row missing for conv=%s", label, keys.convID)
	}

	// Verify message_ingest erasure index.
	var ingestIdxCount int
	iter = session.Query(`SELECT COUNT(*) FROM message_ingest_erasure_index WHERE uin = ?`, uin).WithContext(ctx).Iter()
	iter.Scan(&ingestIdxCount)
	if err := iter.Close(); err != nil {
		t.Fatalf("[%s] pre-wipe verify ingest erasure index iter close: %v", label, err)
	}
	if ingestIdxCount == 0 {
		t.Fatalf("[%s] pre-wipe verify: message_ingest_erasure_index has 0 rows for uin=%d", label, uin)
	}

	// Verify message_outbox erasure index.
	var outboxIdxCount int
	iter = session.Query(`SELECT COUNT(*) FROM message_outbox_erasure_index WHERE uin = ?`, uin).WithContext(ctx).Iter()
	iter.Scan(&outboxIdxCount)
	if err := iter.Close(); err != nil {
		t.Fatalf("[%s] pre-wipe verify outbox erasure index iter close: %v", label, err)
	}
	if outboxIdxCount == 0 {
		t.Fatalf("[%s] pre-wipe verify: message_outbox_erasure_index has 0 rows for uin=%d", label, uin)
	}

	// Verify group_message_outbox erasure index.
	var grpOutboxIdxCount int
	iter = session.Query(`SELECT COUNT(*) FROM group_message_outbox_erasure_index WHERE uin = ?`, uin).WithContext(ctx).Iter()
	iter.Scan(&grpOutboxIdxCount)
	if err := iter.Close(); err != nil {
		t.Fatalf("[%s] pre-wipe verify group outbox erasure index iter close: %v", label, err)
	}
	if grpOutboxIdxCount == 0 {
		t.Fatalf("[%s] pre-wipe verify: group_message_outbox_erasure_index has 0 rows for uin=%d", label, uin)
	}

	// Verify the group message_ingest recipient fixture exists with both
	// recipients still present, unsanitized.
	var preWipeGroupIngestRecipients []int64
	var preWipeGroupIngestSanitized bool
	iter = session.Query(`SELECT recipient_uins, recipient_set_sanitized FROM message_ingest WHERE sender_uin = ? AND client_id = ?`,
		keys.groupIngestSenderUIN, keys.groupIngestClientID).WithContext(ctx).Iter()
	iter.Scan(&preWipeGroupIngestRecipients, &preWipeGroupIngestSanitized)
	if err := iter.Close(); err != nil {
		t.Fatalf("[%s] pre-wipe verify group ingest iter close: %v", label, err)
	}
	if len(preWipeGroupIngestRecipients) != 2 {
		t.Fatalf("[%s] pre-wipe verify: group message_ingest recipient_uins = %v, want 2 entries", label, preWipeGroupIngestRecipients)
	}
	if preWipeGroupIngestSanitized {
		t.Fatalf("[%s] pre-wipe verify: group message_ingest recipient_set_sanitized already true before any wipe ran", label)
	}

	// --- NATS: verify message exists ---
	js, err := nc.JetStream()
	if err != nil {
		t.Fatalf("[%s] pre-wipe verify NATS JetStream unavailable: %v", label, err)
	}
	sub, err := js.SubscribeSync(fmt.Sprintf("msg.direct.%d", uin), nats.Context(ctx))
	if err != nil {
		t.Fatalf("[%s] pre-wipe verify NATS subscribe: %v", label, err)
	}
	msg, err := sub.NextMsg(2 * time.Second)
	sub.Unsubscribe()
	if err != nil || msg == nil {
		t.Fatalf("[%s] pre-wipe verify: NATS message missing for msg.direct.%d — seed did not persist", label, uin)
	}

	// --- MinIO: verify objects exist ---
	for _, objectKey := range keys.fileObjectKeys {
		if _, err := minioClient.StatObject(ctx, acceptanceTestBucket, objectKey, minio.StatObjectOptions{}); err != nil {
			t.Fatalf("[%s] pre-wipe verify: MinIO object missing at %s: %v", label, objectKey, err)
		}
	}

	// Verify avatar exists.
	avatarKey := fmt.Sprintf("avatars/%d", uin)
	if _, err := minioClient.StatObject(ctx, "iceq-avatars", avatarKey, minio.StatObjectOptions{}); err != nil {
		t.Fatalf("[%s] pre-wipe verify: MinIO avatar missing at %s — seed did not persist", label, avatarKey)
	}

	t.Logf("[%s] pre-wipe verification passed — all 5 storage layers confirmed seeded", label)
}

// ---------------------------------------------------------------------------
// Verification helpers — every storage layer, every key
// ---------------------------------------------------------------------------

func verifyZeroFootprintFullStack(t *testing.T, pool *pgxpool.Pool, rdb *redis.Client,
	session *gocql.Session, nc *nats.Conn, minioClient *minio.Client,
	uin int64, label string, keys scyllaSeedKeys) {

	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s := itoa(uin)

	// --- PostgreSQL: zero rows for this UIN ---
	checks := []struct {
		table, where string
	}{
		{"users", "uin = $1"},
		{"wiped_accounts", "uin = $1"},
		{"wipe_jobs", "uin = $1"},
		{"contacts", "owner_uin = $1 OR target_uin = $1"},
		{"group_members", "uin = $1"},
		{"file_objects", "owner_uin = $1"},
		{"file_object_grants", "owner_uin = $1 OR grantee_uin = $1"},
		{"one_time_prekeys", "uin = $1"},
		{"prekey_bundles", "uin = $1"},
		{"refresh_tokens", "uin = $1"},
		{"user_security_settings", "uin = $1"},
	}
	for _, c := range checks {
		var count int
		pool.QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE %s`, c.table, c.where), uin).Scan(&count)
		if count != 0 {
			t.Errorf("[%s] %s row count = %d, want 0", label, c.table, count)
		}
	}

	// --- Redis: zero user-scoped keys ---
	for _, key := range []string{
		"presence:" + s,
		"undelivered:" + s,
		"poll:stream:" + s,
		"poll:cursors:" + s,
		"poll:cursor-order:" + s,
		"login_attempts:" + s,
		// Blocklist key MUST be verified — the worker deletes it after
		// final PG erasure.
		"jwt:blocklist:wipe:" + s,
	} {
		exists, err := rdb.Exists(ctx, key).Result()
		if err != nil {
			t.Errorf("[%s] redis exists %s: %v", label, key, err)
		} else if exists != 0 {
			t.Errorf("[%s] redis key %s still exists", label, key)
		}
	}
	// Hash-tag poll keys.
	for _, pattern := range []string{
		"poll:{" + s + "}:*",
		"poll:{" + s + "}",
	} {
		keys, _, _ := rdb.Scan(ctx, 0, pattern, 100).Result()
		if len(keys) > 0 {
			t.Errorf("[%s] redis scan pattern %s returned %d keys: %v", label, pattern, len(keys), keys)
		}
	}

	// --- Scylla: zero user rows in all tables ---
	// Deletion indexes.
	for _, tc := range []struct{ table, where string }{
		{"message_deletion_index", "uin = ?"},
		{"group_message_deletion_index", "uin = ?"},
		{"message_ingest_erasure_index", "uin = ?"},
		{"message_outbox_erasure_index", "uin = ?"},
		{"group_message_outbox_erasure_index", "uin = ?"},
	} {
		var count int
		iter := session.Query(`SELECT COUNT(*) FROM `+tc.table+` WHERE `+tc.where, uin).WithContext(ctx).Iter()
		iter.Scan(&count)
		if err := iter.Close(); err != nil {
			t.Errorf("[%s] %s iter close: %v", label, tc.table, err)
		}
		if count != 0 {
			t.Errorf("[%s] %s row count = %d, want 0", label, tc.table, count)
		}
	}

	// Verify the exact messages row is gone (not just the index).
	// Use the exact primary key — no ALLOW FILTERING, no full scan.
	var msgCount int
	iter := session.Query(`SELECT COUNT(*) FROM messages WHERE conversation_id = ? AND created_at = ? AND id = ?`, keys.convID, keys.directCreatedAt, keys.msgID).WithContext(ctx).Iter()
	iter.Scan(&msgCount)
	if err := iter.Close(); err != nil {
		t.Errorf("[%s] messages iter close: %v", label, err)
	}
	if msgCount != 0 {
		t.Errorf("[%s] messages ciphertext row still exists (conv=%s, created_at=%v, id=%s)", label, keys.convID, keys.directCreatedAt, keys.msgID)
	}

	// Verify the exact group_messages row is gone.
	var grpCount int
	iter = session.Query(`SELECT COUNT(*) FROM group_messages WHERE group_id = ? AND created_at = ? AND id = ?`, keys.grpID, keys.groupCreatedAt, keys.grpMsgID).WithContext(ctx).Iter()
	iter.Scan(&grpCount)
	if err := iter.Close(); err != nil {
		t.Errorf("[%s] group_messages iter close: %v", label, err)
	}
	if grpCount != 0 {
		t.Errorf("[%s] group_messages ciphertext row still exists (group=%s, created_at=%v, id=%s)", label, keys.grpID, keys.groupCreatedAt, keys.grpMsgID)
	}

	// Verify ingest receipt is gone (exact PK).
	var ingestCount int
	iter = session.Query(`SELECT COUNT(*) FROM message_ingest WHERE sender_uin = ? AND client_id = ?`, uin, keys.ingestClientID).WithContext(ctx).Iter()
	iter.Scan(&ingestCount)
	if err := iter.Close(); err != nil {
		t.Errorf("[%s] message_ingest iter close: %v", label, err)
	}
	if ingestCount != 0 {
		t.Errorf("[%s] message_ingest row still exists for sender_uin=%d client_id=%s", label, uin, keys.ingestClientID)
	}

	// Verify direct outbox is gone (exact PK).
	var outboxCount int
	iter = session.Query(`SELECT COUNT(*) FROM message_outbox WHERE bucket = ? AND created_at = ? AND message_id = ?`, keys.outboxBucket, keys.directCreatedAt, keys.msgID).WithContext(ctx).Iter()
	iter.Scan(&outboxCount)
	if err := iter.Close(); err != nil {
		t.Errorf("[%s] message_outbox iter close: %v", label, err)
	}
	if outboxCount != 0 {
		t.Errorf("[%s] message_outbox row still exists (bucket=%d)", label, keys.outboxBucket)
	}

	// Verify group outbox is gone (exact PK).
	var grpOutboxCount int
	iter = session.Query(`SELECT COUNT(*) FROM group_message_outbox WHERE bucket = ? AND created_at = ? AND message_id = ?`, keys.grpOutboxBucket, keys.groupCreatedAt, keys.grpMsgID).WithContext(ctx).Iter()
	iter.Scan(&grpOutboxCount)
	if err := iter.Close(); err != nil {
		t.Errorf("[%s] group_message_outbox iter close: %v", label, err)
	}
	if grpOutboxCount != 0 {
		t.Errorf("[%s] group_message_outbox row still exists (bucket=%d)", label, keys.grpOutboxBucket)
	}

	// Verify the recipient-only group outbox: the shared row must still
	// exist (remaining control recipients), but the test UIN must NOT be
	// in recipient_uins.
	var recipientUINs []int64
	iter = session.Query(`SELECT recipient_uins FROM group_message_outbox WHERE bucket = ? AND created_at = ? AND message_id = ?`,
		keys.recipientOnlyGrpOutboxBucket, keys.recipientOnlyGrpCreatedAt, keys.recipientOnlyGrpMsgID).WithContext(ctx).Iter()
	iter.Scan(&recipientUINs)
	if err := iter.Close(); err != nil {
		t.Errorf("[%s] recipient-only group outbox iter close: %v", label, err)
	}
	for _, r := range recipientUINs {
		if r == uin {
			t.Errorf("[%s] recipient-only group outbox still contains wiped UIN %d in recipient_uins", label, uin)
		}
	}
	// The shared row must still exist because the control user is also a
	// recipient — the wipe must not delete a row that still has valid
	// recipients.
	if len(recipientUINs) == 0 {
		t.Errorf("[%s] recipient-only group outbox row was incorrectly deleted — control recipients still need it", label)
	}

	// Verify the group message_ingest recipient fixture: the shared receipt
	// must still exist (the sender was not wiped and a recipient survives),
	// the wiped UIN must be gone from recipient_uins, the surviving
	// recipient must remain, and recipient_set_sanitized must be set. This
	// is message_ingest's own role-aware sanitization path — distinct from
	// (and previously entirely untested against) the group_message_outbox
	// check above.
	var groupIngestRecipients []int64
	var groupIngestSanitized bool
	iter = session.Query(`SELECT recipient_uins, recipient_set_sanitized FROM message_ingest WHERE sender_uin = ? AND client_id = ?`,
		keys.groupIngestSenderUIN, keys.groupIngestClientID).WithContext(ctx).Iter()
	iter.Scan(&groupIngestRecipients, &groupIngestSanitized)
	if err := iter.Close(); err != nil {
		t.Errorf("[%s] group ingest iter close: %v", label, err)
	}
	for _, r := range groupIngestRecipients {
		if r == uin {
			t.Errorf("[%s] group message_ingest still contains wiped UIN %d in recipient_uins", label, uin)
		}
	}
	foundSurvivor := false
	for _, r := range groupIngestRecipients {
		if r == keys.groupIngestSurvivorUIN {
			foundSurvivor = true
		}
	}
	if !foundSurvivor {
		t.Errorf("[%s] group message_ingest row lost surviving recipient %d — recipient_uins = %v", label, keys.groupIngestSurvivorUIN, groupIngestRecipients)
	}
	if len(groupIngestRecipients) == 0 {
		t.Errorf("[%s] group message_ingest row was incorrectly emptied or deleted — surviving recipient %d still needs it", label, keys.groupIngestSurvivorUIN)
	}
	if !groupIngestSanitized {
		t.Errorf("[%s] group message_ingest recipient_set_sanitized = false, want true after recipient removal", label)
	}

	// --- NATS: no messages for this user's subject ---
	js, err := nc.JetStream()
	if err != nil {
		t.Errorf("[%s] NATS JetStream unavailable during verification: %v", label, err)
	} else {
		directSubject := fmt.Sprintf("msg.direct.%d", uin)
		// Try to read a message — if the stream is empty for this subject,
		// we should get ErrNoMessage or timeout.
		sub, subErr := js.SubscribeSync(directSubject, nats.Context(ctx))
		if subErr != nil {
			t.Errorf("[%s] NATS subscribe error: %v", label, subErr)
		} else {
			msg, msgErr := sub.NextMsg(2 * time.Second)
			sub.Unsubscribe()
			if msgErr == nil && msg != nil {
				t.Errorf("[%s] NATS message still exists on subject %s: %s", label, directSubject, string(msg.Data))
			}
		}
	}

	// --- MinIO: zero objects for this user ---
	for _, objectKey := range keys.fileObjectKeys {
		if _, err := minioClient.StatObject(ctx, acceptanceTestBucket, objectKey, minio.StatObjectOptions{}); err == nil {
			t.Errorf("[%s] MinIO object still exists: %s", label, objectKey)
		}
	}
	// Avatar.
	avatarKey := fmt.Sprintf("avatars/%d", uin)
	_, err = minioClient.StatObject(ctx, "iceq-avatars", avatarKey, minio.StatObjectOptions{})
	if err == nil {
		t.Errorf("[%s] MinIO avatar still exists: %s", label, avatarKey)
	}

	t.Logf("[%s] zero footprint verified across all 5 storage layers", label)
}

func verifyControlUnchangedFullStack(t *testing.T, pool *pgxpool.Pool, rdb *redis.Client,
	session *gocql.Session, nc *nats.Conn, minioClient *minio.Client, keys scyllaSeedKeys) {

	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s := itoa(acceptanceControlUIN)

	// PG: control user must still exist.
	var userCount int
	pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE uin = $1`, acceptanceControlUIN).Scan(&userCount)
	if userCount != 1 {
		t.Errorf("control user row count = %d, want 1", userCount)
	}

	// PG: control user contacts intact.
	var contactCount int
	pool.QueryRow(ctx, `SELECT COUNT(*) FROM contacts WHERE owner_uin = $1 OR target_uin = $1`, acceptanceControlUIN).Scan(&contactCount)
	if contactCount < 1 {
		t.Errorf("control user contacts count = %d, want >= 1", contactCount)
	}

	// Redis: control user keys intact.
	exists, err := rdb.Exists(ctx, "presence:"+s).Result()
	if err != nil || exists == 0 {
		t.Errorf("control user Redis keys missing: exists=%d err=%v", exists, err)
	}

	// Scylla: control user deletion/erasure indexes intact.
	for _, tc := range []struct{ table, where string }{
		{"message_deletion_index", "uin = ?"},
		{"message_ingest_erasure_index", "uin = ?"},
		{"message_outbox_erasure_index", "uin = ?"},
		{"group_message_outbox_erasure_index", "uin = ?"},
	} {
		var scyllaCount int
		iter := session.Query(`SELECT COUNT(*) FROM `+tc.table+` WHERE `+tc.where, acceptanceControlUIN).WithContext(ctx).Iter()
		iter.Scan(&scyllaCount)
		if err := iter.Close(); err != nil {
			t.Errorf("control user Scylla %s iter close: %v", tc.table, err)
		}
		if scyllaCount < 1 {
			t.Errorf("control user Scylla %s rows = %d, want >= 1", tc.table, scyllaCount)
		}
	}

	// NATS: control user messages intact.
	js, err := nc.JetStream()
	if err != nil {
		t.Errorf("control user NATS JetStream unavailable: %v", err)
	} else {
		sub, subErr := js.SubscribeSync(fmt.Sprintf("msg.direct.%d", acceptanceControlUIN), nats.Context(ctx))
		if subErr != nil {
			t.Errorf("control user NATS subscribe error: %v", subErr)
		} else {
			msg, msgErr := sub.NextMsg(2 * time.Second)
			sub.Unsubscribe()
			if msgErr != nil || msg == nil {
				t.Errorf("control user NATS messages missing or unreachable")
			}
		}
	}

	// MinIO: control user objects intact.
	for _, objectKey := range keys.fileObjectKeys {
		if _, err := minioClient.StatObject(ctx, acceptanceTestBucket, objectKey, minio.StatObjectOptions{}); err != nil {
			t.Errorf("control user MinIO object missing (%s): %v", objectKey, err)
		}
	}

	t.Log("control account data unchanged across all 5 storage layers")
}

// ---------------------------------------------------------------------------
// Authenticated test helpers — exercise the real auth middleware boundary
// ---------------------------------------------------------------------------

// newAcceptanceJWTManager creates a jwt.Manager suitable for acceptance tests.
// It uses a fixed 32-byte secret and the real Redis + PG backends so BearerAuth
// exercises the full token verification path (signature → blocklist check →
// wiped_accounts check → session_epoch check).
func newAcceptanceJWTManager(t *testing.T, rdb *redis.Client, pool *pgxpool.Pool) *jwt.Manager {
	t.Helper()
	secret := "acceptance-test-secret-32-bytes!!" // exactly 32 bytes
	mgr, err := jwt.NewManager(secret, rdb, pool)
	if err != nil {
		t.Fatalf("create acceptance JWT manager: %v", err)
	}
	return mgr
}

// signAcceptanceAccessToken generates a real JWT access token for the given UIN.
func signAcceptanceAccessToken(t *testing.T, mgr *jwt.Manager, uin int64) string {
	t.Helper()
	result, err := mgr.Sign(uin, jwt.TokenTypeAccess)
	if err != nil {
		t.Fatalf("sign access token for uin %d: %v", uin, err)
	}
	return result.Token
}

// newAcceptanceAuthRouter creates a chi router with the real BearerAuth and CSRF
// middleware, mounting the panic-wipe challenge and manual panic-wipe handlers.
// This exercises the exact middleware stack used in production.
func newAcceptanceAuthRouter(t *testing.T, mgr *jwt.Manager, challengeHandler, wipeHandler http.HandlerFunc) http.Handler {
	t.Helper()
	r := chi.NewRouter()

	authMW := middleware.NewBearerAuth(middleware.BearerAuthConfig{Manager: mgr})
	csrfMW := middleware.RequireCSRF

	r.Route("/api/auth", func(r chi.Router) {
		r.With(authMW).Post("/panic-wipe-challenge", challengeHandler)
		r.With(authMW, csrfMW).Post("/panic-wipe", wipeHandler)
	})
	return r
}

// ---------------------------------------------------------------------------
// Full-stack acceptance test
// ---------------------------------------------------------------------------

func TestAcceptanceFullStack(t *testing.T) {
	requireAcceptanceEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// ---- Connect to ALL five storage layers (mandatory) -------------------
	// PostgreSQL
	pgPool, err := pgxpool.New(ctx, acceptancePGURL(t))
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	defer pgPool.Close()
	applyAcceptanceSchema(t, pgPool)

	// Redis
	rdb := redis.NewClient(&redis.Options{Addr: acceptanceRedisAddr(t), Password: os.Getenv("ICEQ_ACCEPTANCE_REDIS_PASSWORD")})
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Fatalf("Redis unreachable at %s: %v — all 5 storage layers are mandatory", acceptanceRedisAddr(t), err)
	}
	defer rdb.Close()
	rdb.FlushDB(ctx)

	// Scylla
	scyllaHosts := acceptanceScyllaHosts(t)

	// Create keyspace if it doesn't exist.
	bootstrapCluster := gocql.NewCluster(scyllaHosts...)
	bootstrapCluster.Timeout = 10 * time.Second
	bootstrapCluster.ConnectTimeout = 10 * time.Second
	bootstrapSession, err := bootstrapCluster.CreateSession()
	if err != nil {
		t.Fatalf("Scylla unreachable at %v: %v — all 5 storage layers are mandatory", scyllaHosts, err)
	}
	if err := bootstrapSession.Query(`CREATE KEYSPACE IF NOT EXISTS iceq WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1}`).WithContext(ctx).Exec(); err != nil {
		bootstrapSession.Close()
		t.Fatalf("Scylla keyspace creation failed: %v — all 5 storage layers are mandatory", err)
	}
	bootstrapSession.Close()

	// Connect with the iceq keyspace.
	scyllaCluster := gocql.NewCluster(scyllaHosts...)
	scyllaCluster.Keyspace = "iceq"
	scyllaCluster.Consistency = gocql.LocalQuorum
	scyllaCluster.Timeout = 10 * time.Second
	scyllaCluster.ConnectTimeout = 10 * time.Second
	scyllaSession, err := scyllaCluster.CreateSession()
	if err != nil {
		t.Fatalf("Scylla unreachable at %v: %v — all 5 storage layers are mandatory", scyllaHosts, err)
	}
	defer scyllaSession.Close()
	applyScyllaSchema(t, scyllaSession)

	// NATS
		nc, err := nats.Connect(acceptanceNATSURL(t), nats.Token(os.Getenv("ICEQ_ACCEPTANCE_NATS_TOKEN")))
	if err != nil {
		t.Fatalf("NATS unreachable at %s: %v — all 5 storage layers are mandatory", acceptanceNATSURL(t), err)
	}
	defer nc.Close()
	js, err := nc.JetStream()
	if err != nil {
		t.Fatalf("NATS JetStream unavailable: %v — JetStream is mandatory", err)
	}
	// Ensure ICEQ_DELIVERY stream.
	js.AddStream(&nats.StreamConfig{
		Name:     "ICEQ_DELIVERY",
		Subjects: []string{"msg.direct.>"},
	})

	// MinIO
	minioClient, err := minio.New(acceptanceMinioEndpoint(t), &minio.Options{
		Creds:  credentials.NewStaticV4(acceptanceMinioAccessKey(t), acceptanceMinioSecretKey(t), ""),
		Secure: false,
	})
	if err != nil {
		t.Fatalf("MinIO unreachable at %s: %v — all 5 storage layers are mandatory", acceptanceMinioEndpoint(t), err)
	}
	// Ensure buckets.
	for _, bucket := range []string{acceptanceTestBucket, "iceq-avatars"} {
		exists, err := minioClient.BucketExists(ctx, bucket)
		if err != nil {
			t.Fatalf("MinIO bucket check %s failed: %v", bucket, err)
		}
		if !exists {
			if err := minioClient.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: acceptanceTestRegion}); err != nil {
				t.Fatalf("MinIO bucket creation %s failed: %v", bucket, err)
			}
		}
	}

	// ---- Seed data across all 5 layers ------------------------------------
	t.Log("seeding test user across all 5 storage layers...")
	testKeys := seedAcceptanceUserFullStack(t, pgPool, rdb, scyllaSession, nc, minioClient, acceptanceTestUIN, "test")
	t.Log("seeding control user across all 5 storage layers...")
	controlKeys := seedAcceptanceUserFullStack(t, pgPool, rdb, scyllaSession, nc, minioClient, acceptanceControlUIN, "control")

	// ---- Pre-wipe verification: prove every seeded row exists --------------
	t.Log("verifying seeded test user footprint across all 5 storage layers...")
	verifySeededFootprintFullStack(t, pgPool, rdb, scyllaSession, nc, minioClient, acceptanceTestUIN, "test", testKeys, false)
	t.Log("verifying seeded control user footprint across all 5 storage layers...")
	verifySeededFootprintFullStack(t, pgPool, rdb, scyllaSession, nc, minioClient, acceptanceControlUIN, "control", controlKeys, true)

	// ---- Authenticated challenge-signature flow ---------------------------
	// Exercise the real authentication boundary: JWT issuance, BearerAuth
	// middleware, CSRF protection, and actual route registrations. The UIN
	// is NEVER injected directly into the request context for the full
	// acceptance path — the middleware stack resolves it from the token.
	//
	// 1. Generate an Ed25519 key pair for the test user.
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	// Insert the wipe public key into user_security_settings.
	if _, err := pgPool.Exec(ctx, `INSERT INTO user_security_settings (uin, wipe_public_key) VALUES ($1, $2) ON CONFLICT (uin) DO UPDATE SET wipe_public_key = $2`, acceptanceTestUIN, pubKeyB64); err != nil {
		t.Fatalf("insert wipe public key: %v", err)
	}

	// 2. Create a real JWT Manager and sign an access token for the test
	//    user. The token goes through the full BearerAuth verification
	//    path: signature → blocklist → wiped_accounts → session_epoch.
	jwtMgr := newAcceptanceJWTManager(t, rdb, pgPool)
	accessToken := signAcceptanceAccessToken(t, jwtMgr, acceptanceTestUIN)

	// 3. Build handlers with real production dependencies (the same ones
	//    main.go wires).
	challengeHandler := NewWipeChallengeHandler(WipeChallengeDeps{Redis: rdb})
	wipeDeps := ManualPanicWipeDeps{
		PanicWipeDeps: PanicWipeDeps{
			Pool:   pgPool,
			Redis:  rdb,
			Scylla: nil, // Scylla cleanup is handled by the worker
			NATS:   nil, // NATS cleanup is handled by the worker
			Minio:  nil, // MinIO cleanup is handled by the worker
		},
		ChallengeSignatureDeps: &ChallengeSignatureDeps{
			Pool:                pgPool,
			LookupWipePublicKey: NewLookupWipePublicKey(pgPool),
			Redis:               rdb,
		},
	}
	wipeHandler := NewManualPanicWipeHandler(wipeDeps)

	// 4. Create a chi router with the real BearerAuth and CSRF middleware
	//    and start an httptest server. Every request goes through the
	//    exact same middleware stack used in production.
	authRouter := newAcceptanceAuthRouter(t, jwtMgr, challengeHandler, wipeHandler)
	authServer := httptest.NewServer(authRouter)
	defer authServer.Close()

	// 5. Request a single-use wipe challenge through the real router.
	//    GET is exempt from CSRF check, but BearerAuth still runs.
	challengeReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, authServer.URL+"/api/auth/panic-wipe-challenge", nil)
	challengeReq.Header.Set("Authorization", "Bearer "+accessToken)
	challengeResp, err := http.DefaultClient.Do(challengeReq)
	if err != nil {
		t.Fatalf("challenge HTTP request failed: %v", err)
	}
	defer challengeResp.Body.Close()
	if challengeResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(challengeResp.Body)
		t.Fatalf("challenge request failed: status=%d body=%s", challengeResp.StatusCode, string(body))
	}
	var chalResp wipeChallengeResponse
	if err := json.NewDecoder(challengeResp.Body).Decode(&chalResp); err != nil {
		t.Fatalf("parse challenge response: %v", err)
	}
	t.Logf("challenge obtained via authenticated boundary: id=%s", chalResp.ChallengeID)

	// 6. Sign the canonical challenge with the private key.
	challengeBytes, err := base64.StdEncoding.DecodeString(chalResp.Challenge)
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	signature := ed25519.Sign(privKey, challengeBytes)
	sigB64 := base64.StdEncoding.EncodeToString(signature)

	// 7. Submit the authenticated manual panic-wipe through the real
	//    router. The POST method requires both the Bearer token AND the
	//    X-IceQ-CSRF: 1 header (enforced by RequireCSRF middleware).
	wipeBody, _ := json.Marshal(manualPanicWipeRequest{
		ChallengeID: chalResp.ChallengeID,
		Signature:   sigB64,
	})
	wipeReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, authServer.URL+"/api/auth/panic-wipe", bytes.NewReader(wipeBody))
	wipeReq.Header.Set("Authorization", "Bearer "+accessToken)
	wipeReq.Header.Set("Content-Type", "application/json")
	wipeReq.Header.Set(middleware.CSRFHeaderName, middleware.CSRFHeaderValue)
	wipeResp, err := http.DefaultClient.Do(wipeReq)
	if err != nil {
		t.Fatalf("panic wipe HTTP request failed: %v", err)
	}
	defer wipeResp.Body.Close()
	if wipeResp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(wipeResp.Body)
		t.Fatalf("panic wipe request failed: status=%d body=%s", wipeResp.StatusCode, string(body))
	}
	t.Logf("panic wipe handler returned %d via authenticated boundary", wipeResp.StatusCode)

	// 8. Verify challenge is single-use consumed. A second wipe attempt
	//    with the same challenge must be rejected.
	wipeReq2, _ := http.NewRequestWithContext(ctx, http.MethodPost, authServer.URL+"/api/auth/panic-wipe", bytes.NewReader(wipeBody))
	wipeReq2.Header.Set("Authorization", "Bearer "+accessToken)
	wipeReq2.Header.Set("Content-Type", "application/json")
	wipeReq2.Header.Set(middleware.CSRFHeaderName, middleware.CSRFHeaderValue)
	wipeResp2, err := http.DefaultClient.Do(wipeReq2)
	if err != nil {
		t.Fatalf("second wipe HTTP request failed: %v", err)
	}
	defer wipeResp2.Body.Close()
	if wipeResp2.StatusCode == http.StatusAccepted {
		t.Fatal("second wipe attempt with same challenge must be rejected — single-use challenge was not consumed")
	}
	t.Logf("challenge single-use enforced: second attempt returned %d", wipeResp2.StatusCode)

	// Extract job ID for the worker.
	var jobID int64
	pgPool.QueryRow(ctx, `SELECT id FROM wipe_jobs WHERE uin = $1 ORDER BY id DESC LIMIT 1`, acceptanceTestUIN).Scan(&jobID)
	t.Logf("PanicWipe created job %d via authenticated handler", jobID)

	// ---- Run wipe worker to completion with ALL production cleaners -------
	workerIDBytes := make([]byte, 8)
	rand.Read(workerIDBytes)
	workerID := "acceptance-" + hex.EncodeToString(workerIDBytes)

	scyllaStore, err := NewScyllaMessageStore(scyllaSession)
	if err != nil {
		t.Fatalf("create Scylla store: %v", err)
	}

	runner := &WipeJobRunner{
		Pool:         pgPool,
		Scylla:       scyllaStore,
		NATS:         &productionNATSCleaner{nc: nc},
		Minio:        &productionMinioCleaner{client: minioClient},
		Redis:        NewRedisWipeCleaner(rdb),
		LeaseTimeout: 30 * time.Second,
		WorkerID:     workerID,
	}

	t.Log("running wipe worker processOneJob with all 5 production cleaners...")
	workerCtx, workerCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer workerCancel()

	deadline := time.Now().Add(60 * time.Second)
	for attempt := 1; ; attempt++ {
		runner.processOneJob(workerCtx)

		var jobCount int
		pgPool.QueryRow(ctx, `SELECT COUNT(*) FROM wipe_jobs WHERE id = $1`, jobID).Scan(&jobCount)
		if jobCount == 0 {
			t.Logf("job %d completed on attempt %d", jobID, attempt)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %d did not complete within 60s", jobID)
		}
		t.Logf("job %d still pending after attempt %d", jobID, attempt)
		time.Sleep(2 * time.Second)
	}

	// ---- Verify -----------------------------------------------------------
	// Primary verification: wiped user
	t.Log("verifying wiped user zero footprint across all 5 storage layers...")
	verifyZeroFootprintFullStack(t, pgPool, rdb, scyllaSession, nc, minioClient, acceptanceTestUIN, "wiped", testKeys)

	// Cross-account isolation: control user
	t.Log("verifying control user unchanged across all 5 storage layers...")
	verifyControlUnchangedFullStack(t, pgPool, rdb, scyllaSession, nc, minioClient, controlKeys)
}

// TestAcceptanceGroupRecipientWipeTTLBehavior exercises, against a real
// Scylla instance, the two TTL-loss defects found and fixed while verifying
// Task #12 (one pre-existing in group_message_outbox, one newly-introduced
// risk in message_ingest's recipient sanitization): recipient removal must
// preserve the row's remaining TTL, repeated cleanup must not extend it,
// and a row already past its own expiry must never be resurrected with a
// fresh one. It also proves a sender retry after sanitization does not
// recreate the wiped uin's message_ingest_erasure_index entry, using the
// real production Claim() implementation, not a re-derivation of it.
// pollUntil polls fn at interval until it returns true, or until deadline
// (measured from start) has elapsed -- whichever comes first. It returns
// the actual elapsed time at that point and whether fn returned true.
// Bounded polling records the real observed transition time instead of
// gambling that a single fixed sleep duration lands on the right side of
// it, which is what made the original fixed-sleep version of the TTL
// acceptance test flaky under scheduler/CI load: a blind time.Sleep can
// wake up later than intended, but never earlier, so a single read after
// it proves nothing about when the transition actually happened.
func pollUntil(start time.Time, deadline, interval time.Duration, fn func() bool) (elapsed time.Duration, becameTrue bool) {
	for {
		elapsed = time.Since(start)
		if fn() {
			return elapsed, true
		}
		if elapsed >= deadline {
			return elapsed, false
		}
		time.Sleep(interval)
	}
}

func TestAcceptanceGroupRecipientWipeTTLBehavior(t *testing.T) {
	requireAcceptanceEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	scyllaHosts := acceptanceScyllaHosts(t)
	bootstrapCluster := gocql.NewCluster(scyllaHosts...)
	bootstrapCluster.Timeout = 10 * time.Second
	bootstrapCluster.ConnectTimeout = 10 * time.Second
	bootstrapSession, err := bootstrapCluster.CreateSession()
	if err != nil {
		t.Fatalf("Scylla unreachable at %v: %v", scyllaHosts, err)
	}
	if err := bootstrapSession.Query(`CREATE KEYSPACE IF NOT EXISTS iceq WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1}`).WithContext(ctx).Exec(); err != nil {
		bootstrapSession.Close()
		t.Fatalf("Scylla keyspace creation failed: %v", err)
	}
	bootstrapSession.Close()

	scyllaCluster := gocql.NewCluster(scyllaHosts...)
	scyllaCluster.Keyspace = "iceq"
	scyllaCluster.Consistency = gocql.LocalQuorum
	scyllaCluster.Timeout = 10 * time.Second
	scyllaCluster.ConnectTimeout = 10 * time.Second
	session, err := scyllaCluster.CreateSession()
	if err != nil {
		t.Fatalf("Scylla unreachable at %v: %v", scyllaHosts, err)
	}
	defer session.Close()
	applyScyllaSchema(t, session)

	msgStore, err := NewScyllaMessageStore(session)
	if err != nil {
		t.Fatalf("create Scylla store: %v", err)
	}

	const (
		wipedUIN    = int64(910001)
		survivorUIN = int64(910002)
		senderUIN   = int64(910003)
	)

	t.Run("group_message_outbox recipient removal preserves TTL and does not extend on repeat", func(t *testing.T) {
		// Scylla's TTL() function rejects non-frozen collection columns
		// ("TTL expects an atomic column") -- recipient_uins is a
		// LIST<BIGINT> and cannot be TTL-introspected directly, and
		// group_message_outbox has no atomic sibling column touched in the
		// same UPDATE to use as a proxy (unlike message_ingest's
		// recipient_set_sanitized, checked in the subtest below). So this
		// proves TTL preservation behaviorally, against real wall-clock
		// expiry, with a short real TTL: the row must still be alive well
		// before the original TTL elapses (proving it wasn't dropped to
		// ~0), and must be gone shortly after the ORIGINAL TTL would have
		// elapsed even though cleanup ran twice in between (proving
		// neither call reset it to permanent or extended it with a fresh
		// duration).
		const (
			originalTTL  = 8 // seconds
			pollInterval = 200 * time.Millisecond
			// Polling for "still alive" stops here, this far short of the
			// original TTL -- the row must still be alive at that point,
			// proving neither cleanup call truncated the TTL toward zero.
			aliveThroughMargin = 2 * time.Second
			// How far past the original TTL the row may still be observed
			// before we conclude a cleanup call silently made it permanent
			// or extended it. Generous enough to absorb Docker/CI scheduling
			// jitter, tight enough to still catch a real defect.
			expiryMargin = 5 * time.Second
		)
		bucket := int8(5)
		createdAt := time.Now().UTC().Truncate(time.Millisecond)
		start := time.Now()
		msgID, err := gocql.RandomUUID()
		if err != nil {
			t.Fatal(err)
		}
		groupID, err := gocql.RandomUUID()
		if err != nil {
			t.Fatal(err)
		}
		expiresAt := createdAt.Add(originalTTL * time.Second)
		if err := session.Query(`INSERT INTO group_message_outbox
			(bucket, created_at, message_id, group_id, sender_uin, client_id, crypto_epoch, recipient_uins, envelope, envelope_hash, state, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) USING TTL ?`,
			bucket, createdAt, msgID, groupID, senderUIN, "ttl-check-client", 1,
			[]int64{wipedUIN, survivorUIN}, []byte("env"), []byte("hash12345678901234567890123456789012"), "pending", expiresAt, originalTTL,
		).WithContext(ctx).Exec(); err != nil {
			t.Fatalf("seed group_message_outbox: %v", err)
		}
		reindex := func() {
			if err := session.Query(`INSERT INTO group_message_outbox_erasure_index (uin, bucket, created_at, message_id, role) VALUES (?, ?, ?, ?, ?) USING TTL ?`,
				wipedUIN, bucket, createdAt, msgID, "recipient", originalTTL).WithContext(ctx).Exec(); err != nil {
				t.Fatalf("seed erasure index: %v", err)
			}
		}
		reindex()

		readRow := func() (bool, []int64) {
			var recipients []int64
			iter := session.Query(`SELECT recipient_uins FROM group_message_outbox WHERE bucket = ? AND created_at = ? AND message_id = ?`, bucket, createdAt, msgID).WithContext(ctx).Iter()
			found := iter.Scan(&recipients)
			if err := iter.Close(); err != nil {
				t.Fatalf("read row: %v", err)
			}
			return found, recipients
		}

		if err := msgStore.DeleteUserGroupMessages(ctx, wipedUIN); err != nil {
			t.Fatalf("first cleanup: %v", err)
		}
		found, recipients := readRow()
		if !found {
			t.Fatal("row gone immediately after first cleanup -- TTL must not be dropped near-zero")
		}
		if len(recipients) != 1 || recipients[0] != survivorUIN {
			t.Fatalf("recipient_uins after first cleanup = %v, want [%d]", recipients, survivorUIN)
		}

		// Poll (instead of sleeping for a fixed duration and reading once)
		// until either the row disappears or we reach a deadline safely
		// short of the original TTL. Disappearing before that deadline
		// means a cleanup call truncated the TTL toward zero instead of
		// preserving it; this alone doesn't prove the opposite mistake
		// (TTL left permanent) -- that's checked below, after a repeat
		// cleanup, with its own bounded poll.
		aliveDeadline := originalTTL*time.Second - aliveThroughMargin
		earlyElapsed, wentAwayEarly := pollUntil(start, aliveDeadline, pollInterval, func() bool {
			found, _ := readRow()
			return !found
		})
		if wentAwayEarly {
			t.Fatalf("row expired early, %s after start (original TTL was %ds; expected alive until at least %s after start) -- TTL was truncated, not preserved; start=%s observedGoneAt=%s",
				earlyElapsed, originalTTL, aliveDeadline, start.Format(time.RFC3339Nano), start.Add(earlyElapsed).Format(time.RFC3339Nano))
		}

		// Repeat: a second wipe pass (retry after a crash, or a second
		// recipient of the same message wiped separately) must not reset
		// or extend the TTL.
		reindex()
		if err := msgStore.DeleteUserGroupMessages(ctx, wipedUIN); err != nil {
			t.Fatalf("second (repeated) cleanup: %v", err)
		}
		found, recipients = readRow()
		if !found {
			t.Fatal("row gone immediately after repeated cleanup")
		}
		if len(recipients) != 1 || recipients[0] != survivorUIN {
			t.Fatalf("recipient_uins after repeated cleanup = %v, want [%d]", recipients, survivorUIN)
		}

		// Poll until the row is actually gone, bounded by the original TTL
		// plus expiryMargin, even though cleanup ran twice since the row was
		// seeded. Because the previous poll already proved the row survived
		// until aliveDeadline, any success here is sufficient proof neither
		// cleanup call reset or extended the TTL past that margin -- and if
		// it never happens, the failure carries exact timestamps and the
		// last-read row state instead of a single accusatory snapshot.
		expiryDeadline := originalTTL*time.Second + expiryMargin
		finalElapsed, becameGone := pollUntil(start, expiryDeadline, pollInterval, func() bool {
			found, _ := readRow()
			return !found
		})
		if !becameGone {
			stillFound, stillRecipients := readRow()
			t.Fatalf("row still alive %s after start, past its original %ds TTL plus %s margin (deadline %s after start) -- a cleanup call silently made it permanent or extended its TTL; start=%s now=%s deadlineAt=%s found=%v recipients=%v",
				finalElapsed, originalTTL, expiryMargin, expiryDeadline,
				start.Format(time.RFC3339Nano), time.Now().Format(time.RFC3339Nano), start.Add(expiryDeadline).Format(time.RFC3339Nano),
				stillFound, stillRecipients)
		}
	})

	t.Run("group_message_outbox already-expired row is left untouched, never resurrected", func(t *testing.T) {
		bucket := int8(6)
		createdAt := time.Now().UTC().Truncate(time.Millisecond)
		msgID, err := gocql.RandomUUID()
		if err != nil {
			t.Fatal(err)
		}
		groupID, err := gocql.RandomUUID()
		if err != nil {
			t.Fatal(err)
		}
		// The STORED expires_at value is in the past, but the row itself
		// carries a long real CQL TTL so it stays queryable during this
		// test -- deliberately exercising the "remaining <= 0" defensive
		// branch without racing real wall-clock expiry.
		staleExpiresAt := createdAt.Add(-time.Hour)
		if err := session.Query(`INSERT INTO group_message_outbox
			(bucket, created_at, message_id, group_id, sender_uin, client_id, crypto_epoch, recipient_uins, envelope, envelope_hash, state, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) USING TTL 3600`,
			bucket, createdAt, msgID, groupID, senderUIN, "ttl-stale-client", 1,
			[]int64{wipedUIN, survivorUIN}, []byte("env"), []byte("hash12345678901234567890123456789012"), "pending", staleExpiresAt,
		).WithContext(ctx).Exec(); err != nil {
			t.Fatalf("seed stale group_message_outbox: %v", err)
		}
		if err := session.Query(`INSERT INTO group_message_outbox_erasure_index (uin, bucket, created_at, message_id, role) VALUES (?, ?, ?, ?, ?) USING TTL 3600`,
			wipedUIN, bucket, createdAt, msgID, "recipient").WithContext(ctx).Exec(); err != nil {
			t.Fatalf("seed erasure index: %v", err)
		}

		if err := msgStore.DeleteUserGroupMessages(ctx, wipedUIN); err != nil {
			t.Fatalf("cleanup of already-expired row: %v", err)
		}

		// The row must be left exactly as seeded (skip, don't mutate) --
		// the wiped uin is still allowed to be present here: the whole
		// point of skipping is that this row is about to disappear via its
		// own already-past expiry anyway, so mutating it (and risking a
		// fresh/permanent TTL landing on it) is both unnecessary and
		// risky. This directly proves the "remaining <= 0 -> skip" branch
		// ran, without needing TTL() (which Scylla rejects for the
		// non-frozen recipient_uins collection -- see the sibling subtest
		// above for why the other two properties are proven via real
		// wall-clock expiry instead).
		var recipients []int64
		iter := session.Query(`SELECT recipient_uins FROM group_message_outbox WHERE bucket = ? AND created_at = ? AND message_id = ?`, bucket, createdAt, msgID).WithContext(ctx).Iter()
		iter.Scan(&recipients)
		if err := iter.Close(); err != nil {
			t.Fatalf("read row: %v", err)
		}
		found := false
		for _, r := range recipients {
			if r == wipedUIN {
				found = true
			}
		}
		if !found {
			t.Fatal("expected the already-expired row to be left untouched (wiped uin still present) -- cleanup must skip mutation, not remove it via a different path")
		}
	})

	t.Run("message_ingest recipient removal preserves TTL and a sender retry does not recreate the erasure index", func(t *testing.T) {
		clientID := "ttl-ingest-client"
		groupID, err := gocql.RandomUUID()
		if err != nil {
			t.Fatal(err)
		}
		createdAt := time.Now().UTC().Truncate(time.Millisecond)
		expiresAt := createdAt.Add(time.Hour)
		envelope := []byte("ttl-check-envelope")
		hash := sha256.Sum256(envelope)
		msgID, err := gocql.RandomUUID()
		if err != nil {
			t.Fatal(err)
		}
		if err := session.Query(`INSERT INTO message_ingest
			(sender_uin, client_id, message_kind, group_id, crypto_epoch, recipient_uins, envelope, envelope_hash, message_id, created_at, expires_at, state, owner_token, lease_until)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) USING TTL 3600`,
			senderUIN, clientID, "group", groupID, int64(1), []int64{wipedUIN, survivorUIN},
			envelope, hash[:], msgID, createdAt, expiresAt, "stored", msgID, createdAt,
		).WithContext(ctx).Exec(); err != nil {
			t.Fatalf("seed message_ingest: %v", err)
		}
		for _, indexUIN := range []int64{senderUIN, wipedUIN, survivorUIN} {
			if err := session.Query(`INSERT INTO message_ingest_erasure_index (uin, sender_uin, client_id) VALUES (?, ?, ?) USING TTL 3600`,
				indexUIN, senderUIN, clientID).WithContext(ctx).Exec(); err != nil {
				t.Fatalf("seed erasure index (uin %d): %v", indexUIN, err)
			}
		}

		// recipient_set_sanitized is an atomic boolean written in the SAME
		// UPDATE statement as recipient_uins (see sanitizeIngestReceipt),
		// so unlike recipient_uins itself (a non-frozen LIST, which
		// Scylla's TTL() function rejects -- see the group_message_outbox
		// subtests above), its TTL is a valid, directly queryable proxy
		// for the TTL actually applied to that same write.
		readState := func() (int, []int64, bool) {
			var ttl int
			var recipients []int64
			var sanitized bool
			iter := session.Query(`SELECT TTL(recipient_set_sanitized), recipient_uins, recipient_set_sanitized FROM message_ingest WHERE sender_uin = ? AND client_id = ?`, senderUIN, clientID).WithContext(ctx).Iter()
			iter.Scan(&ttl, &recipients, &sanitized)
			if err := iter.Close(); err != nil {
				t.Fatalf("read state: %v", err)
			}
			return ttl, recipients, sanitized
		}
		countErasureIndex := func(uin int64) int {
			var count int
			iter := session.Query(`SELECT COUNT(*) FROM message_ingest_erasure_index WHERE uin = ?`, uin).WithContext(ctx).Iter()
			iter.Scan(&count)
			if err := iter.Close(); err != nil {
				t.Fatalf("count erasure index: %v", err)
			}
			return count
		}

		// Before any wipe, recipient_set_sanitized was never written (NULL
		// -- its TTL is meaningless until the first sanitization sets it).
		_, _, preSanitized := readState()
		if preSanitized {
			t.Fatal("recipient_set_sanitized = true before any wipe ran")
		}

		if err := msgStore.DeleteUserMessages(ctx, wipedUIN); err != nil {
			t.Fatalf("cleanup: %v", err)
		}
		firstTTL, firstRecipients, firstSanitized := readState()
		if firstTTL <= 0 || firstTTL > 3600 {
			t.Fatalf("TTL(recipient_set_sanitized) after cleanup = %d, want in (0, 3600] -- must remain expiring, not become permanent", firstTTL)
		}
		if !firstSanitized {
			t.Fatal("recipient_set_sanitized = false after wipe, want true")
		}
		for _, r := range firstRecipients {
			if r == wipedUIN {
				t.Fatal("wiped uin still in recipient_uins after cleanup")
			}
		}
		if countErasureIndex(wipedUIN) != 0 {
			t.Fatalf("message_ingest_erasure_index still has entries for the wiped uin after cleanup")
		}

		// Simulate the SENDER retrying the original send with its stale,
		// pre-wipe recipient list, using the real production Claim()
		// implementation (not a re-derivation of it) -- proving the retry
		// is idempotent and does not recreate the wiped uin's index entry.
		backend := store.NewScyllaIngestBackend(session)
		proposed := store.IngestRecord{
			Key:           store.IngestKey{SenderUIN: senderUIN, ClientID: clientID},
			Kind:          store.IngestKindGroup,
			GroupID:       groupID,
			CryptoEpoch:   1,
			RecipientUINs: []int64{wipedUIN, survivorUIN}, // sender's stale, pre-wipe list
			Envelope:      envelope,
			EnvelopeHash:  hash,
		}
		record, disposition, err := backend.Claim(ctx, proposed, time.Now().UTC())
		if err != nil {
			t.Fatalf("retry Claim() against sanitized row: %v", err)
		}
		if disposition != store.ClaimCommitted {
			t.Fatalf("retry disposition = %v, want ClaimCommitted (idempotent, already stored)", disposition)
		}
		if len(record.RecipientUINs) != 1 || record.RecipientUINs[0] != survivorUIN {
			t.Fatalf("Claim() returned recipients %v, want only the sanitized survivor [%d]", record.RecipientUINs, survivorUIN)
		}

		if countErasureIndex(wipedUIN) != 0 {
			t.Fatal("sender retry recreated the wiped uin's erasure-index entry -- indexes must never be recreated by a retry")
		}
		secondTTL, _, _ := readState()
		if secondTTL > firstTTL {
			t.Fatalf("Claim() retry extended TTL: first=%d second=%d", firstTTL, secondTTL)
		}
	})
}
