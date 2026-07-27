//go:build integration
// +build integration

// Package handlers — focused acceptance test for wipe-key rotation against
// a real PostgreSQL + Redis, complementing the fake-backed unit tests in
// panicwipe_handler_test.go (which cannot reach the actual qUpdateWipePublicKey
// write: *pgxpool.Pool is used as a concrete type throughout this package, so
// there is nothing to inject a fake for, matching every other Pool-typed dep
// in this package). Needs only Postgres and Redis, not the full five-storage
// stack panicwipe_acceptance_test.go requires:
//
//	ICEQ_ACCEPTANCE=1 \
//	ICEQ_ACCEPTANCE_PG_URL="postgres://postgres:postgres@localhost:5434/iceq?sslmode=disable" \
//	ICEQ_ACCEPTANCE_REDIS_ADDR="localhost:6380" \
//	go test -count=1 -race -tags=integration -run TestAcceptanceWipeKeyRotation -v ./auth-service/handlers/
package handlers

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/iceq/iceq/shared/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

const acceptanceRotationUIN = int64(90001001)

// TestAcceptanceWipeKeyRotationSucceedsWithValidSignature is required test
// (c) of the panic-wipe-key retry-safety fix: a genuinely different key,
// submitted with a valid signature from the currently-enrolled key, must
// still complete a real rotation end to end (204, and the row actually
// updated) — proving the compare-before-rotate check added ahead of the
// signature requirement does not weaken real rotations, only the exact
// idempotent-resubmit case it targets.
func TestAcceptanceWipeKeyRotationSucceedsWithValidSignature(t *testing.T) {
	requireAcceptanceEnv(t)
	ctx := context.Background()

	pgPool, err := pgxpool.New(ctx, acceptancePGURL(t))
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	defer pgPool.Close()

	rdb := redis.NewClient(&redis.Options{Addr: acceptanceRedisAddr(t)})
	defer func() { _ = rdb.Close() }()

	if _, err := pgPool.Exec(ctx, `INSERT INTO users (uin, username, password_hash, identity_key)
		VALUES ($1, $2, '$2a$10$placeholder', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=')
		ON CONFLICT (uin) DO NOTHING`, acceptanceRotationUIN, fmt.Sprintf("acceptance_rotation_%d", acceptanceRotationUIN)); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pgPool.Exec(context.Background(), `DELETE FROM user_security_settings WHERE uin = $1`, acceptanceRotationUIN)
		_, _ = pgPool.Exec(context.Background(), `DELETE FROM users WHERE uin = $1`, acceptanceRotationUIN)
	})

	oldPub, oldPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate old key: %v", err)
	}
	oldPubB64 := base64.StdEncoding.EncodeToString(oldPub)
	if _, err := pgPool.Exec(ctx, `INSERT INTO user_security_settings (uin, wipe_public_key)
		VALUES ($1, $2) ON CONFLICT (uin) DO UPDATE SET wipe_public_key = $2`, acceptanceRotationUIN, oldPubB64); err != nil {
		t.Fatalf("seed existing wipe key: %v", err)
	}

	newPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate new key: %v", err)
	}
	newPubB64 := base64.StdEncoding.EncodeToString(newPub)

	// Request a real single-use challenge through the real handler, then
	// sign the domain-separated rotation payload with the OLD key, exactly
	// as the client does.
	challengeHandler := NewWipeChallengeHandler(WipeChallengeDeps{Redis: rdb})
	challengeReq := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe-challenge", nil)
	challengeReq = challengeReq.WithContext(middleware.WithUIN(challengeReq.Context(), acceptanceRotationUIN))
	challengeRR := httptest.NewRecorder()
	challengeHandler.ServeHTTP(challengeRR, challengeReq)
	if challengeRR.Code != http.StatusOK {
		t.Fatalf("challenge status = %d, want 200; body=%s", challengeRR.Code, challengeRR.Body.String())
	}
	var challenge wipeChallengeResponse
	if err := json.Unmarshal(challengeRR.Body.Bytes(), &challenge); err != nil {
		t.Fatalf("decode challenge response: %v", err)
	}

	rotationPayload := fmt.Sprintf("iceq-wipe-key-rotation-v1|%d|%s|%s|%s",
		acceptanceRotationUIN, challenge.ChallengeID, challenge.Challenge, newPubB64)
	sig := ed25519.Sign(oldPriv, []byte(rotationPayload))

	setHandler := NewSetWipePublicKeyHandler(SetWipePublicKeyDeps{
		Pool:                pgPool,
		Redis:               rdb,
		LookupWipePublicKey: NewLookupWipePublicKey(pgPool),
		LookupPasswordHash:  NewLookupPasswordHash(pgPool),
	})
	body := fmt.Sprintf(`{"public_key":"%s","challenge_id":"%s","signature":"%s"}`,
		newPubB64, challenge.ChallengeID, base64.StdEncoding.EncodeToString(sig))
	setReq := httptest.NewRequest(http.MethodPut, "/api/auth/panic-wipe-public-key", strings.NewReader(body))
	setReq = setReq.WithContext(middleware.WithUIN(setReq.Context(), acceptanceRotationUIN))
	setRR := httptest.NewRecorder()
	setHandler.ServeHTTP(setRR, setReq)

	if setRR.Code != http.StatusNoContent {
		t.Fatalf("rotation status = %d, want 204; body=%s", setRR.Code, setRR.Body.String())
	}

	var storedKey string
	if err := pgPool.QueryRow(ctx, `SELECT wipe_public_key FROM user_security_settings WHERE uin = $1`, acceptanceRotationUIN).Scan(&storedKey); err != nil {
		t.Fatalf("query rotated key: %v", err)
	}
	if storedKey != newPubB64 {
		t.Fatalf("stored wipe_public_key = %q, want the new key %q — rotation did not persist", storedKey, newPubB64)
	}
}

// TestAcceptanceWipeKeyIdempotentResubmitDoesNotRotate proves the
// compare-before-rotate check's 409 short-circuit really does return before
// touching Redis or Postgres: resubmitting the SAME key with NO challenge or
// signature must succeed as a no-op against a real database, leaving the
// enrolled key unchanged, rather than requiring proof of a rotation that
// never needed to happen.
func TestAcceptanceWipeKeyIdempotentResubmitDoesNotRotate(t *testing.T) {
	requireAcceptanceEnv(t)
	ctx := context.Background()

	pgPool, err := pgxpool.New(ctx, acceptancePGURL(t))
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	defer pgPool.Close()

	rdb := redis.NewClient(&redis.Options{Addr: acceptanceRedisAddr(t)})
	defer func() { _ = rdb.Close() }()

	const uin = acceptanceRotationUIN + 1
	if _, err := pgPool.Exec(ctx, `INSERT INTO users (uin, username, password_hash, identity_key)
		VALUES ($1, $2, '$2a$10$placeholder', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=')
		ON CONFLICT (uin) DO NOTHING`, uin, fmt.Sprintf("acceptance_resubmit_%d", uin)); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pgPool.Exec(context.Background(), `DELETE FROM user_security_settings WHERE uin = $1`, uin)
		_, _ = pgPool.Exec(context.Background(), `DELETE FROM users WHERE uin = $1`, uin)
	})

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	if _, err := pgPool.Exec(ctx, `INSERT INTO user_security_settings (uin, wipe_public_key)
		VALUES ($1, $2) ON CONFLICT (uin) DO UPDATE SET wipe_public_key = $2`, uin, pubB64); err != nil {
		t.Fatalf("seed existing wipe key: %v", err)
	}

	setHandler := NewSetWipePublicKeyHandler(SetWipePublicKeyDeps{
		Pool:                pgPool,
		Redis:               rdb,
		LookupWipePublicKey: NewLookupWipePublicKey(pgPool),
		LookupPasswordHash:  NewLookupPasswordHash(pgPool),
	})
	body := fmt.Sprintf(`{"public_key":"%s"}`, pubB64)
	req := httptest.NewRequest(http.MethodPut, "/api/auth/panic-wipe-public-key", strings.NewReader(body))
	req = req.WithContext(middleware.WithUIN(req.Context(), uin))
	rr := httptest.NewRecorder()
	setHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("idempotent resubmit status = %d, want 409; body=%s", rr.Code, rr.Body.String())
	}

	var storedKey string
	if err := pgPool.QueryRow(ctx, `SELECT wipe_public_key FROM user_security_settings WHERE uin = $1`, uin).Scan(&storedKey); err != nil {
		t.Fatalf("query key: %v", err)
	}
	if storedKey != pubB64 {
		t.Fatalf("stored wipe_public_key changed to %q, want unchanged %q", storedKey, pubB64)
	}
}
