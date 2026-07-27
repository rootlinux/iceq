package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/iceq/iceq/shared/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

func cryptoTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("ICEQ_TEST_PG_URL")
	if url == "" {
		url = os.Getenv("ICEQ_PG_DSN")
	}
	if url == "" {
		t.Skip("ICEQ_TEST_PG_URL or ICEQ_PG_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Skipf("PostgreSQL not available: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("PostgreSQL ping failed: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestCryptoBinding_Unauthenticated_Returns_401(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/auth/crypto-binding", nil)
	rr := httptest.NewRecorder()
	handler := NewCryptoBindingHandler(CryptoBindingDeps{})
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCryptoBinding_Authenticated_Returns_IdentityKey(t *testing.T) {
	pool := cryptoTestPool(t)

	// Insert a test user with a known identity_key
	const testIdentityKey = "cb-test-identity-key-001"

	// Clean up after
	ctx := context.Background()
	_, err := pool.Exec(ctx, `DELETE FROM contacts WHERE owner_uin IN (SELECT uin FROM users WHERE username = 'cb_test_user_1') OR target_uin IN (SELECT uin FROM users WHERE username = 'cb_test_user_1')`)
	if err == nil {
		_, _ = pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE uin IN (SELECT uin FROM users WHERE username = 'cb_test_user_1')`)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE username = 'cb_test_user_1'`)
	}

	var uin int64
	err = pool.QueryRow(ctx,
		`INSERT INTO users (username, email, password_hash, identity_key) VALUES ($1, NULL, $2, $3) RETURNING uin`,
		"cb_test_user_1", "$argon2id$test_hash_not_real", testIdentityKey,
	).Scan(&uin)
	if err != nil {
		t.Fatalf("insert test user: %v", err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE uin = $1`, uin)
		_, _ = pool.Exec(ctx, `DELETE FROM contacts WHERE owner_uin = $1 OR target_uin = $1`, uin)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE uin = $1`, uin)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/auth/crypto-binding", nil)
	req = req.WithContext(middleware.WithUIN(context.Background(), uin))

	rr := httptest.NewRecorder()
	handler := NewCryptoBindingHandler(CryptoBindingDeps{Pool: pool})
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp CryptoBindingResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.UIN != uin {
		t.Errorf("expected uin %d, got %d", uin, resp.UIN)
	}
	if resp.IdentityKey != testIdentityKey {
		t.Errorf("expected identity_key %q, got %q", testIdentityKey, resp.IdentityKey)
	}
}

func TestCryptoBinding_User_Not_Found_Returns_404(t *testing.T) {
	pool := cryptoTestPool(t)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/crypto-binding", nil)
	req = req.WithContext(middleware.WithUIN(context.Background(), 99999999))

	rr := httptest.NewRecorder()
	handler := NewCryptoBindingHandler(CryptoBindingDeps{Pool: pool})
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}
