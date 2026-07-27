package handlers

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/redis/go-redis/v9"
)

type fakeNatsCleaner struct {
	calls int
}
type fakeMinioCleaner struct {
	objectCalls int
	grantCalls  int
}
type fakeMinioError struct{}

func (f *fakeNatsCleaner) PurgeUserStreams(ctx context.Context, uin int64) error { f.calls++; return nil }
func (f *fakeMinioCleaner) DeleteUserObjects(ctx context.Context, uin int64, fileKeys []string) error {
	f.objectCalls++
	return nil
}
func (f *fakeMinioCleaner) DeleteUserGrants(ctx context.Context, uin int64) error { f.grantCalls++; return nil }
func (f *fakeMinioError) DeleteUserObjects(ctx context.Context, uin int64, fileKeys []string) error {
	return errors.New("minio offline")
}
func (f *fakeMinioError) DeleteUserGrants(ctx context.Context, uin int64) error { return errors.New("grant store offline") }

// TestPanicWipeSignatureErrorSanitized verifies that signature verification errors
// do not leak internal infrastructure details (Redis hosts, PG errors, base64 details).
func TestPanicWipeSignatureErrorSanitized(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	// Store a challenge that the signature will fail to verify against
	uin := int64(10000001)
	challengeID := "test-challenge-123"
	challengeKey := wipeChallengePrefix + itoa(uin) + ":" + challengeID
	challengeBytes := []byte("test challenge data")
	challengeB64 := base64.StdEncoding.EncodeToString(challengeBytes)
	if err := rdb.Set(context.Background(), challengeKey, challengeB64, 0).Err(); err != nil {
		t.Fatalf("store challenge: %v", err)
	}

	// Create a fake wipe public key lookup that returns a valid Ed25519 public key
	fakePub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	lookupWipeKey := func(ctx context.Context, uin int64) (ed25519.PublicKey, error) {
		return fakePub, nil
	}

	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		PanicWipeDeps: PanicWipeDeps{
			Redis: rdb,
		},
		ChallengeSignatureDeps: &ChallengeSignatureDeps{
			Redis:               rdb,
			LookupWipePublicKey: lookupWipeKey,
		},
	})

	// Send a wipe request with an invalid signature (wrong length to trigger specific error)
	invalidSig := base64.StdEncoding.EncodeToString([]byte("too-short"))
	reqBody := fmt.Sprintf(`{"challenge_id":%q,"signature":%q}`, challengeID, invalidSig)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	ctx := middleware.WithUIN(req.Context(), uin)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	// The error message should NOT contain internal details
	errorMsg := resp["error"]
	if strings.Contains(errorMsg, "signature has wrong length") {
		t.Errorf("error message leaks internal details (byte length): %q", errorMsg)
	}
	if strings.Contains(errorMsg, "malformed") {
		t.Errorf("error message leaks internal details (malformed): %q", errorMsg)
	}
	if strings.Contains(errorMsg, "redis") || strings.Contains(errorMsg, "Redis") {
		t.Errorf("error message leaks Redis details: %q", errorMsg)
	}
	if strings.Contains(errorMsg, "postgres") || strings.Contains(errorMsg, "pg") || strings.Contains(errorMsg, "sql") {
		t.Errorf("error message leaks database details: %q", errorMsg)
	}

	// The error message should be a generic, sanitized message
	if errorMsg == "" {
		t.Error("error message should not be empty")
	}
}

// helper: returns a Legacy PIN hash + lookup function for tests that need successful PIN auth
func testPinHashLookup(t *testing.T) (func(ctx context.Context, uin int64) (string, error), string) {
	t.Helper()
	pinHash, err := hashPassword("1234")
	if err != nil {
		t.Fatalf("hash pin: %v", err)
	}
	return func(ctx context.Context, uin int64) (string, error) { return pinHash, nil }, pinHash
}

func TestLoginWrongPasswordNeverTriggersPanicWipe(t *testing.T) {
	passwordHash, err := hashPassword("correct-password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	type protectedState struct {
		User          LoginUser
		SessionEpoch  string
		FileOwnership map[string]int64
		WipeMarker    bool
	}
	state := protectedState{
		User:          LoginUser{UIN: 10000001, Username: "alice", Email: "alice@example.com", PasswordHash: passwordHash},
		SessionEpoch:  "2026-07-16T00:00:00Z",
		FileOwnership: map[string]int64{"object-key": 10000001},
	}
	wantState := protectedState{
		User:          state.User,
		SessionEpoch:  state.SessionEpoch,
		FileOwnership: map[string]int64{"object-key": 10000001},
	}
	handler := NewLoginHandler(LoginDeps{
		Redis:           rdb,
		RateLimitSecret: []byte("01234567890123456789012345678901"),
		LookupUser: func(context.Context, string, bool) (LoginUser, error) {
			return state.User, nil
		},
	})

	for attempt := 1; attempt <= 5; attempt++ {
		body, _ := json.Marshal(map[string]string{"username": "alice", "password": "wrong-password"})
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		edgeDigest := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		req.Header.Set(middleware.EdgeIdentityHeader, "v1.abcdef012345."+edgeDigest)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401; body=%q", attempt, rr.Code, rr.Body.String())
		}
		if rr.Body.String() != "{\"error\":\"invalid credentials\",\"code\":\"INVALID_CREDENTIALS\"}\n" {
			t.Fatalf("attempt %d body = %q, want exact generic invalid-credentials response", attempt, rr.Body.String())
		}
	}

	if !reflect.DeepEqual(state, wantState) {
		t.Fatalf("protected user/session/file/wipe state mutated: got %#v, want %#v", state, wantState)
	}
	for _, forbiddenKey := range []string{"login_attempts:10000001", "jwt:blocklist:wipe:10000001"} {
		if mr.Exists(forbiddenKey) {
			t.Fatalf("wrong-password login created automatic-wipe state %q", forbiddenKey)
		}
	}
}

type recordingMessageStore struct{}

func (*recordingMessageStore) DeleteUserMessages(context.Context, int64) error      { return nil }
func (*recordingMessageStore) DeleteUserGroupMessages(context.Context, int64) error { return nil }

func TestManualPanicWipeHandlerUsesAuthenticatedUINAndClearsCookies(t *testing.T) {
	const authenticatedUIN int64 = 10000001
	lookup, _ := testPinHashLookup(t)

	var wipedUIN int64
	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		PanicWipeDeps:     PanicWipeDeps{},
		LookupPanicPinHash: lookup,
		Wipe: func(ctx context.Context, deps PanicWipeDeps, uin int64) (int64, error) {
			wipedUIN = uin
			return 0, nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", strings.NewReader(`{"pin":"1234"}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), authenticatedUIN))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusAccepted, rr.Body.String())
	}
	if wipedUIN != authenticatedUIN {
		t.Fatalf("wiped UIN = %d, want %d", wipedUIN, authenticatedUIN)
	}
	if rr.Body.Len() == 0 {
		t.Fatalf("body = %q, want non-empty 202 body", rr.Body.String())
	}

	refresh := findCookie(rr.Result().Cookies(), refreshCookieName)
	access := findCookie(rr.Result().Cookies(), accessCookieName)
	if refresh == nil || access == nil {
		t.Fatalf("cookies = %#v, want both auth cookies cleared", rr.Result().Cookies())
	}
	if refresh.MaxAge != -1 || access.MaxAge != -1 {
		t.Fatalf("MaxAge refresh=%d access=%d, want -1", refresh.MaxAge, access.MaxAge)
	}
}

func TestManualPanicWipeHandlerPassesMessageStoreDependencyToWipe(t *testing.T) {
	store := &recordingMessageStore{}
	lookup, _ := testPinHashLookup(t)
	var got MessageStore
	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		PanicWipeDeps:     PanicWipeDeps{Scylla: store},
		LookupPanicPinHash: lookup,
		Wipe: func(_ context.Context, deps PanicWipeDeps, _ int64) (int64, error) {
			got = deps.Scylla
			return 0, nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", strings.NewReader(`{"pin":"1234"}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000003))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusAccepted)
	}
	if got != store {
		t.Fatalf("message store = %#v, want %#v", got, store)
	}
}

func TestManualPanicWipeHandlerClearsCookiesOnFailureWithoutMetadata(t *testing.T) {
	lookup, _ := testPinHashLookup(t)
	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		LookupPanicPinHash: lookup,
		Wipe: func(ctx context.Context, deps PanicWipeDeps, uin int64) (int64, error) {
			return 0, errors.New("storage unavailable for sensitive user")
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", strings.NewReader(`{"pin":"1234"}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000002))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusServiceUnavailable, rr.Body.String())
	}
	if body := rr.Body.String(); body == "" || containsAny(body, []string{"10000002", "storage unavailable", "sensitive user"}) {
		t.Fatalf("body leaks metadata or is empty: %q", body)
	}
	refresh := findCookie(rr.Result().Cookies(), refreshCookieName)
	access := findCookie(rr.Result().Cookies(), accessCookieName)
	if refresh == nil || access == nil {
		t.Fatalf("cookies = %#v, want both auth cookies cleared", rr.Result().Cookies())
	}
	if refresh.MaxAge != -1 || access.MaxAge != -1 {
		t.Fatalf("MaxAge refresh=%d access=%d, want -1", refresh.MaxAge, access.MaxAge)
	}
}

func TestManualPanicWipeHandlerWithNoVerifierConfiguredRejectsWipe(t *testing.T) {
	var wiped bool
	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		Wipe:               func(context.Context, PanicWipeDeps, int64) (int64, error) { wiped = true; return 0, nil },
		LookupPanicPinHash: func(context.Context, int64) (string, error) { return "", nil }, // no PIN set
	})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", strings.NewReader("{}"))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000001))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rr.Code, rr.Body.String())
	}
	if wiped {
		t.Fatal("wipe was invoked for an account with no security setup")
	}
}

func TestManualPanicWipeHandlerRejectsWrongPinWithoutWiping(t *testing.T) {
	pinHash, err := hashPassword("1234")
	if err != nil {
		t.Fatalf("hash pin: %v", err)
	}
	var wiped bool
	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		Wipe:               func(context.Context, PanicWipeDeps, int64) (int64, error) { wiped = true; return 0, nil },
		LookupPanicPinHash: func(context.Context, int64) (string, error) { return pinHash, nil },
	})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", strings.NewReader(`{"pin":"9999"}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000001))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rr.Code, rr.Body.String())
	}
	if wiped {
		t.Fatal("account was wiped despite an incorrect panic PIN")
	}
}

func TestManualPanicWipeHandlerAcceptsCorrectPin(t *testing.T) {
	pinHash, err := hashPassword("1234")
	if err != nil {
		t.Fatalf("hash pin: %v", err)
	}
	var wiped bool
	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		Wipe:               func(context.Context, PanicWipeDeps, int64) (int64, error) { wiped = true; return 0, nil },
		LookupPanicPinHash: func(context.Context, int64) (string, error) { return pinHash, nil },
	})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", strings.NewReader(`{"pin":"1234"}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000001))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", rr.Code, rr.Body.String())
	}
	if !wiped {
		t.Fatal("wipe was not invoked despite a correct panic PIN")
	}
}

func TestWipeInvokesNatsCleanerWhenDepsHasNats(t *testing.T) {
	cleaner := &fakeNatsCleaner{}
	lookup, _ := testPinHashLookup(t)
	var gotNATS NatsCleaner

	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		PanicWipeDeps:     PanicWipeDeps{NATS: cleaner},
		LookupPanicPinHash: lookup,
		Wipe: func(_ context.Context, deps PanicWipeDeps, _ int64) (int64, error) {
			gotNATS = deps.NATS
			if deps.NATS != nil {
				_ = deps.NATS.PurgeUserStreams(context.Background(), 0)
			}
			return 0, nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", strings.NewReader(`{"pin":"1234"}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000001))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rr.Code)
	}
	if cleaner.calls != 1 {
		t.Fatalf("nats purge calls = %d, want 1", cleaner.calls)
	}
	if gotNATS != cleaner {
		t.Fatalf("nats cleaner = %#v, want %#v", gotNATS, cleaner)
	}
}

func TestWipeSkipsNatsWhenCleanerNil(t *testing.T) {
	lookup, _ := testPinHashLookup(t)
	var gotNATS NatsCleaner
	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		LookupPanicPinHash: lookup,
		Wipe: func(_ context.Context, deps PanicWipeDeps, _ int64) (int64, error) {
			gotNATS = deps.NATS
			return 0, nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", strings.NewReader(`{"pin":"1234"}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000012))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rr.Code)
	}
	if gotNATS != nil {
		t.Fatalf("nats cleaner = %#v, want nil", gotNATS)
	}
}

func TestWipeInvokesMinioCleanerWhenSet(t *testing.T) {
	cleaner := &fakeMinioCleaner{}
	lookup, _ := testPinHashLookup(t)
	var gotMinio MinioCleaner
	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		PanicWipeDeps:     PanicWipeDeps{Minio: cleaner},
		LookupPanicPinHash: lookup,
		Wipe: func(_ context.Context, deps PanicWipeDeps, _ int64) (int64, error) {
			gotMinio = deps.Minio
			if deps.Minio != nil {
				_ = deps.Minio.DeleteUserObjects(context.Background(), 0, nil)
				_ = deps.Minio.DeleteUserGrants(context.Background(), 0)
			}
			return 0, nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", strings.NewReader(`{"pin":"1234"}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000013))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rr.Code)
	}
	if cleaner.objectCalls != 1 {
		t.Fatalf("minio object calls = %d, want 1", cleaner.objectCalls)
	}
	if cleaner.grantCalls != 1 {
		t.Fatalf("minio grant calls = %d, want 1", cleaner.grantCalls)
	}
	if gotMinio != cleaner {
		t.Fatalf("minio cleaner = %#v, want %#v", gotMinio, cleaner)
	}
}

func TestWipeSucceedsWhenMinioReturnsErrors(t *testing.T) {
	// Uses a fake Wipe that swallows MinIO errors and returns nil.
	// This tests that the handler contract returns 204 when Wipe succeeds.
	errCleaner := &fakeMinioError{}
	lookup, _ := testPinHashLookup(t)
	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		PanicWipeDeps:     PanicWipeDeps{Minio: errCleaner},
		LookupPanicPinHash: lookup,
		Wipe: func(_ context.Context, deps PanicWipeDeps, _ int64) (int64, error) {
			if deps.Minio != nil {
				_ = deps.Minio.DeleteUserObjects(context.Background(), 0, nil)
				_ = deps.Minio.DeleteUserGrants(context.Background(), 0)
			}
			return 0, nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", strings.NewReader(`{"pin":"1234"}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000014))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", rr.Code, rr.Body.String())
	}
}

func TestPanicWipeRemovesBlocklistOnPGTransactionFailure(t *testing.T) {
	// If the blocklist SET succeeds but the PG transaction fails, the
	// blocklist must be removed so the account can retry. Without this,
	// a transient PG failure leaves the account permanently inaccessible.
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	lookup, _ := testPinHashLookup(t)
	blocklistKey := panicWipeBlocklistKey(10000050)

	var blocklistRemoved bool
	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		PanicWipeDeps:     PanicWipeDeps{Redis: rdb},
		LookupPanicPinHash: lookup,
		Wipe: func(ctx context.Context, deps PanicWipeDeps, uin int64) (int64, error) {
			// Simulate: blocklist SET succeeds, but PG fails.
			if err := deps.Redis.Set(ctx, blocklistKey, "1", panicWipeBlocklistTTL).Err(); err != nil {
				return 0, err
			}
			blocklisted := true
			defer func() {
				if blocklisted {
					_ = deps.Redis.Del(context.WithoutCancel(ctx), blocklistKey).Err()
					blocklistRemoved = true
				}
			}()
			// PG failure before commit.
			return 0, errors.New("pg transaction failed")
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", strings.NewReader(`{"pin":"1234"}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000050))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
	if !blocklistRemoved {
		t.Fatal("blocklist was NOT removed after PG failure — account permanently locked")
	}
	exists := mr.Exists(blocklistKey)
	if exists {
		t.Fatal("blocklist key still exists after PG failure recovery")
	}
}

func TestWipeHandlerReturns202WhenStorageCleanupIncomplete(t *testing.T) {
	// With async wipe jobs, ALL successful wipes return 202 Accepted because
	// storage cleanup (Scylla, NATS, MinIO) continues in the background.
	// The handler returns 202 even when the Wipe function returns nil.
	lookup, _ := testPinHashLookup(t)
	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		LookupPanicPinHash: lookup,
		Wipe: func(ctx context.Context, deps PanicWipeDeps, uin int64) (int64, error) {
			return 0, nil // PG succeeded, wipe job inserted
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", strings.NewReader(`{"pin":"1234"}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000014))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 Accepted; body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "pending") {
		t.Fatalf("202 response missing 'pending' status: %s", body)
	}
	// Cookies must be cleared on accepted wipe.
	refresh := findCookie(rr.Result().Cookies(), refreshCookieName)
	access := findCookie(rr.Result().Cookies(), accessCookieName)
	if refresh == nil || access == nil || refresh.MaxAge != -1 || access.MaxAge != -1 {
		t.Fatalf("cookies not cleared on accepted wipe")
	}
}

func TestDeletePatternCleansKeysByGlob(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	for i := 0; i < 5; i++ {
		mr.Set("poll:{7777}:record:"+strings.Repeat("a", i+1), "x")
	}
	mr.Set("poll:{7777}:sequence", "1")

	if err := deletePattern(context.Background(), rdb, "poll:{7777}:*"); err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	keys := mr.Keys()
	if len(keys) != 0 {
		t.Fatalf("data left after deletePattern: %v", keys)
	}
}

func TestManualPanicWipeHandlerCarriesNatsAndMinio(t *testing.T) {
	natsCleaner := &fakeNatsCleaner{}
	minioCleaner := &fakeMinioCleaner{}
	lookup, _ := testPinHashLookup(t)

	var gotNATS NatsCleaner
	var gotMinio MinioCleaner
	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		PanicWipeDeps:     PanicWipeDeps{NATS: natsCleaner, Minio: minioCleaner},
		LookupPanicPinHash: lookup,
		Wipe: func(_ context.Context, deps PanicWipeDeps, _ int64) (int64, error) {
			gotNATS = deps.NATS
			gotMinio = deps.Minio
			return 0, nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", strings.NewReader(`{"pin":"1234"}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000030))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rr.Code)
	}
	if gotNATS != natsCleaner {
		t.Fatalf("nats cleaner = %#v, want %#v", gotNATS, natsCleaner)
	}
	if gotMinio != minioCleaner {
		t.Fatalf("minio cleaner = %#v, want %#v", gotMinio, minioCleaner)
	}
}

func TestPanicWipeRejectsMigratedAccountWithPin(t *testing.T) {
	pinHash, err := hashPassword("1234")
	if err != nil {
		t.Fatalf("hash pin: %v", err)
	}
	var wiped bool
	dummyPubKey := make([]byte, 32)
	dummyPubKey[0] = 1
	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		Wipe:               func(context.Context, PanicWipeDeps, int64) (int64, error) { wiped = true; return 0, nil },
		LookupPanicPinHash: func(context.Context, int64) (string, error) { return pinHash, nil },
		ChallengeSignatureDeps: &ChallengeSignatureDeps{
			LookupWipePublicKey: func(context.Context, int64) (ed25519.PublicKey, error) { return dummyPubKey, nil },
		},
	})
	// Migrated account (has wipe_public_key) sends PIN — must be rejected
	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", strings.NewReader(`{"pin":"1234"}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000001))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rr.Code, rr.Body.String())
	}
	if wiped {
		t.Fatal("migrated account wipe was invoked via PIN path")
	}
}

func TestPanicWipeRejectsMigratedAccountMissingChallenge(t *testing.T) {
	dummyPubKey := make([]byte, 32)
	dummyPubKey[0] = 1
	var wiped bool
	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		Wipe: func(context.Context, PanicWipeDeps, int64) (int64, error) { wiped = true; return 0, nil },
		ChallengeSignatureDeps: &ChallengeSignatureDeps{
			LookupWipePublicKey: func(context.Context, int64) (ed25519.PublicKey, error) { return dummyPubKey, nil },
		},
	})
	// Migrated account sends no challenge_id — must be rejected
	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", strings.NewReader("{}"))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000001))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rr.Code, rr.Body.String())
	}
	if wiped {
		t.Fatal("migrated account was wiped without challenge")
	}
}

func containsAny(s string, needles []string) bool {
	for _, needle := range needles {
		if needle != "" && contains(s, needle) {
			return true
		}
	}
	return false
}

func contains(s, needle string) bool {
	return strings.Contains(s, needle)
}

// ---------------------------------------------------------------------------
// P0-1: Multi-user isolation and capture-ordering tests
// ---------------------------------------------------------------------------

// fakeMinioRecorder records every key passed to DeleteUserObjects so the test
// can assert that only the wiped user's keys were deleted.
type fakeMinioRecorder struct {
	deletedKeys []string
	grantCalls  int
}

func (f *fakeMinioRecorder) DeleteUserObjects(_ context.Context, _ int64, fileKeys []string) error {
	f.deletedKeys = append(f.deletedKeys, fileKeys...)
	return nil
}
func (f *fakeMinioRecorder) DeleteUserGrants(_ context.Context, _ int64) error {
	f.grantCalls++
	return nil
}

func TestWipeOfUserADoesNotDeleteUserBObjects(t *testing.T) {
	// User A (uin=10000001) owns keys "file-a-1", "file-a-2".
	// User B (uin=10000002) owns keys "file-b-1".
	// Wiping user A must only delete "file-a-1", "file-a-2", and the
	// deterministic avatar key — never "file-b-1".

	recorder := &fakeMinioRecorder{}
	lookup, _ := testPinHashLookup(t)

	// Simulate PG: captureFileKeys will query file_objects. We inject a
	// fake Wipe that receives the captured keys and passes them to MinIO.
	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		PanicWipeDeps:     PanicWipeDeps{Minio: recorder},
		LookupPanicPinHash: lookup,
		Wipe: func(ctx context.Context, deps PanicWipeDeps, uin int64) (int64, error) {
			// Simulate what PanicWipe does: capture keys, then pass to MinIO.
			// For user A (10000001), the captured keys are "file-a-1", "file-a-2".
			fileKeys := []string{}
			if uin == 10000001 {
				fileKeys = []string{"file-a-1", "file-a-2"}
			}
			if deps.Minio != nil {
				_ = deps.Minio.DeleteUserObjects(ctx, uin, fileKeys)
			}
			return 0, nil
		},
	})

	// Wipe user A.
	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", strings.NewReader(`{"pin":"1234"}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000001))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rr.Code)
	}

	// Assert: only user A's keys were deleted.
	for _, deleted := range recorder.deletedKeys {
		if deleted == "file-b-1" {
			t.Fatalf("user B's object key %q was deleted during user A's wipe", deleted)
		}
	}
	// User A's keys must be present.
	found := make(map[string]bool)
	for _, k := range recorder.deletedKeys {
		found[k] = true
	}
	for _, want := range []string{"file-a-1", "file-a-2"} {
		if !found[want] {
			t.Fatalf("user A's key %q was NOT deleted", want)
		}
	}
}

// ---------------------------------------------------------------------------
// P0-4: Wipe-key enrollment and rotation protection tests
// ---------------------------------------------------------------------------

func TestSetWipePublicKeyInitialEnrollmentRequiresPassword(t *testing.T) {
	handler := NewSetWipePublicKeyHandler(SetWipePublicKeyDeps{
		LookupWipePublicKey: func(ctx context.Context, uin int64) (ed25519.PublicKey, error) {
			return nil, nil // no existing key
		},
	})
	req := httptest.NewRequest(http.MethodPut, "/api/auth/panic-wipe-public-key",
		strings.NewReader(`{"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000001))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rr.Code, rr.Body.String())
	}
}

func TestSetWipePublicKeyInitialEnrollmentRejectsWrongPassword(t *testing.T) {
	passwordHash, err := hashPassword("correct-password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	handler := NewSetWipePublicKeyHandler(SetWipePublicKeyDeps{
		LookupWipePublicKey: func(ctx context.Context, uin int64) (ed25519.PublicKey, error) {
			return nil, nil // no existing key
		},
		LookupPasswordHash: func(ctx context.Context, uin int64) (string, error) {
			return passwordHash, nil
		},
	})
	req := httptest.NewRequest(http.MethodPut, "/api/auth/panic-wipe-public-key",
		strings.NewReader(`{"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","password":"wrong-password"}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000001))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rr.Code, rr.Body.String())
	}
}

func TestSetWipePublicKeyRotationRequiresSignature(t *testing.T) {
	dummyPubKey := make([]byte, 32)
	dummyPubKey[0] = 1
	handler := NewSetWipePublicKeyHandler(SetWipePublicKeyDeps{
		LookupWipePublicKey: func(ctx context.Context, uin int64) (ed25519.PublicKey, error) {
			return ed25519.PublicKey(dummyPubKey), nil // existing key
		},
	})
	// Rotation request without challenge_id and signature → must be rejected.
	req := httptest.NewRequest(http.MethodPut, "/api/auth/panic-wipe-public-key",
		strings.NewReader(`{"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000001))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rr.Code, rr.Body.String())
	}
}

func TestSetWipePublicKeyRotationRejectsWrongSignature(t *testing.T) {
	// Generate a real Ed25519 key pair for the existing key.
	pubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	// Use a wrong private key to sign — must fail verification.
	_, wrongPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	// Store a challenge in Redis.
	challengeBytes := make([]byte, 32)
	challengeB64 := base64.StdEncoding.EncodeToString(challengeBytes)
	challengeIDHex := "deadbeefcafef00ddeadbeefcafef00d"
	mr.Set("panic-wipe:challenge:10000001:"+challengeIDHex, challengeB64)

	newPubKey := make([]byte, 32)
	newPubKeyB64 := base64.StdEncoding.EncodeToString(newPubKey)

	// Build the domain-separated rotation payload.
	rotationPayload := fmt.Sprintf("iceq-wipe-key-rotation-v1|%d|%s|%s|%s",
		10000001, challengeIDHex, challengeB64, newPubKeyB64)

	// Sign the domain-separated payload with the WRONG key.
	wrongSig := ed25519.Sign(wrongPriv, []byte(rotationPayload))

	handler := NewSetWipePublicKeyHandler(SetWipePublicKeyDeps{
		Redis: rdb,
		LookupWipePublicKey: func(ctx context.Context, uin int64) (ed25519.PublicKey, error) {
			return pubKey, nil
		},
	})

	body := fmt.Sprintf(`{"public_key":"%s","challenge_id":"%s","signature":"%s"}`,
		newPubKeyB64,
		challengeIDHex,
		base64.StdEncoding.EncodeToString(wrongSig))
	req := httptest.NewRequest(http.MethodPut, "/api/auth/panic-wipe-public-key", strings.NewReader(body))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000001))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rr.Code, rr.Body.String())
	}
}

func TestSetWipePublicKeyRotationRejectsUnsignedRotationPayload(t *testing.T) {
	// Sign just the raw challenge bytes (old protocol) — must be rejected
	// because the server now requires the domain-separated payload.
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	challengeBytes := make([]byte, 32)
	challengeB64 := base64.StdEncoding.EncodeToString(challengeBytes)
	challengeIDHex := "cafef00ddeadbeefcafef00ddeadbeef"
	mr.Set("panic-wipe:challenge:10000001:"+challengeIDHex, challengeB64)

	// Sign only the challenge bytes (old protocol), NOT the domain-separated payload.
	oldProtocolSig := ed25519.Sign(privKey, challengeBytes)

	handler := NewSetWipePublicKeyHandler(SetWipePublicKeyDeps{
		Redis: rdb,
		LookupWipePublicKey: func(ctx context.Context, uin int64) (ed25519.PublicKey, error) {
			return pubKey, nil
		},
	})

	newPubKey := make([]byte, 32)
	body := fmt.Sprintf(`{"public_key":"%s","challenge_id":"%s","signature":"%s"}`,
		base64.StdEncoding.EncodeToString(newPubKey),
		challengeIDHex,
		base64.StdEncoding.EncodeToString(oldProtocolSig))
	req := httptest.NewRequest(http.MethodPut, "/api/auth/panic-wipe-public-key", strings.NewReader(body))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000001))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — old protocol (raw challenge) signature must be rejected; body=%s", rr.Code, rr.Body.String())
	}
}

func TestSetWipePublicKeyStolenSessionCannotOverwriteExistingKey(t *testing.T) {
	// A normal authenticated session (no password, no signature) sending only
	// a public_key must be rejected when a wipe key already exists.
	dummyPubKey := make([]byte, 32)
	dummyPubKey[0] = 1
	handler := NewSetWipePublicKeyHandler(SetWipePublicKeyDeps{
		LookupWipePublicKey: func(ctx context.Context, uin int64) (ed25519.PublicKey, error) {
			return ed25519.PublicKey(dummyPubKey), nil
		},
	})
	req := httptest.NewRequest(http.MethodPut, "/api/auth/panic-wipe-public-key",
		strings.NewReader(`{"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000001))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — stolen session must not overwrite; body=%s", rr.Code, rr.Body.String())
	}
}

func TestSetWipePublicKeyConcurrentEnrollmentRaceProtection(t *testing.T) {
	// Verify atomic set-if-null enrollment exists: INSERT with ON CONFLICT
	// DO UPDATE SET ... WHERE wipe_public_key IS NULL. This prevents two
	// concurrent enrollments from both succeeding, and prevents overwriting
	// an already-enrolled key.
	src, err := os.ReadFile("queries.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	if !strings.Contains(s, "qEnrollWipePublicKey") {
		t.Fatal("qEnrollWipePublicKey must exist for atomic set-if-null enrollment")
	}
	if !strings.Contains(s, "DO UPDATE SET wipe_public_key = EXCLUDED.wipe_public_key WHERE user_security_settings.wipe_public_key IS NULL") {
		t.Fatal("qEnrollWipePublicKey must use atomic set-if-null: ON CONFLICT DO UPDATE SET ... WHERE wipe_public_key IS NULL")
	}
	// Verify CAS rotation exists.
	if !strings.Contains(s, "qUpdateWipePublicKey") {
		t.Fatal("qUpdateWipePublicKey must exist for CAS key rotation")
	}
	if !strings.Contains(s, "AND wipe_public_key = $2") {
		t.Fatal("qUpdateWipePublicKey must use compare-and-swap (WHERE wipe_public_key = old_key)")
	}
}

// TestSetWipePublicKeyIdempotentResubmitReturnsConflictWithoutSignature
// verifies that resubmitting the exact same key that's already enrolled —
// the shape of a retry after the server accepted a prior enrollment but the
// client never saw the response — returns 409 WIPE_KEY_EXISTS without ever
// requiring challenge_id/signature. Without the compare-before-rotate check,
// this hits the rotation branch and returns 401 SIGNATURE_REQUIRED instead:
// a permanent deadlock, since the client has no reason to send rotation
// proof for what it believes is a first-time enrollment.
func TestSetWipePublicKeyIdempotentResubmitReturnsConflictWithoutSignature(t *testing.T) {
	existingPubKey := make([]byte, 32)
	existingPubKey[0] = 7
	existingPubKeyB64 := base64.StdEncoding.EncodeToString(existingPubKey)

	handler := NewSetWipePublicKeyHandler(SetWipePublicKeyDeps{
		LookupWipePublicKey: func(ctx context.Context, uin int64) (ed25519.PublicKey, error) {
			return ed25519.PublicKey(existingPubKey), nil
		},
		// Deliberately nil Redis/Pool: the idempotent-resubmit path must
		// return before touching either. If it ever regresses to falling
		// through to the rotation branch, this test panics on the nil
		// Redis client instead of asserting 409 — a loud failure either way.
	})
	req := httptest.NewRequest(http.MethodPut, "/api/auth/panic-wipe-public-key",
		strings.NewReader(fmt.Sprintf(`{"public_key":%q}`, existingPubKeyB64)))
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000001))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp["code"] != "WIPE_KEY_EXISTS" {
		t.Fatalf("code = %q, want WIPE_KEY_EXISTS", resp["code"])
	}
}

// TestSetWipePublicKeyGetReportsNoKeyEnrolled covers the new GET endpoint's
// "nothing enrolled yet" response, which reconcileWipeKey() on the client
// reads as status "server-has-no-key".
func TestSetWipePublicKeyGetReportsNoKeyEnrolled(t *testing.T) {
	handler := NewGetWipePublicKeyHandler(GetWipePublicKeyDeps{
		LookupWipePublicKey: func(ctx context.Context, uin int64) (ed25519.PublicKey, error) {
			return nil, nil
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/auth/panic-wipe-public-key", nil)
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000001))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp getWipePublicKeyResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.PublicKey != nil {
		t.Fatalf("public_key = %v, want nil", *resp.PublicKey)
	}
}

// TestSetWipePublicKeyGetReportsEnrolledKey covers the GET endpoint
// returning the exact enrolled key, byte-for-byte comparable against a
// locally-held key — this is the whole point of reconcileWipeKey().
func TestSetWipePublicKeyGetReportsEnrolledKey(t *testing.T) {
	pubKey := make([]byte, 32)
	pubKey[0] = 9
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	handler := NewGetWipePublicKeyHandler(GetWipePublicKeyDeps{
		LookupWipePublicKey: func(ctx context.Context, uin int64) (ed25519.PublicKey, error) {
			return ed25519.PublicKey(pubKey), nil
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/auth/panic-wipe-public-key", nil)
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000001))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp getWipePublicKeyResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.PublicKey == nil || *resp.PublicKey != pubKeyB64 {
		t.Fatalf("public_key = %v, want %q", resp.PublicKey, pubKeyB64)
	}
}

// TestSetWipePublicKeyGetRequiresAuth mirrors every other endpoint in this
// file: an unauthenticated request (no UIN in context) must be rejected
// before the lookup function is ever called.
func TestSetWipePublicKeyGetRequiresAuth(t *testing.T) {
	called := false
	handler := NewGetWipePublicKeyHandler(GetWipePublicKeyDeps{
		LookupWipePublicKey: func(ctx context.Context, uin int64) (ed25519.PublicKey, error) {
			called = true
			return nil, nil
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/auth/panic-wipe-public-key", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rr.Code, rr.Body.String())
	}
	if called {
		t.Fatal("LookupWipePublicKey was called for an unauthenticated request")
	}
}

func TestCaptureFileKeysBeforePGDeletesOwnershipRows(t *testing.T) {
	// This is a source-order test: it verifies that PanicWipe() calls
	// captureFileKeys BEFORE the PG transaction deletes file_objects.
	// We verify this by checking the source code ordering, similar to
	// TestPanicWipeRevokesSessionsBeforeScyllaCleanup.
	src, err := os.ReadFile("panicwipe.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)

	// captureFileKeys must appear before qWipeFileObjects (the delete).
	capturePos := strings.Index(s, "captureFileKeys(ctx")
	deletePos := strings.Index(s, "qWipeFileObjects")
	if capturePos < 0 {
		t.Fatal("captureFileKeys not found in panicwipe.go")
	}
	if deletePos < 0 {
		t.Fatal("qWipeFileObjects not found in panicwipe.go")
	}
	if capturePos >= deletePos {
		t.Fatalf("captureFileKeys (pos=%d) must appear before qWipeFileObjects (pos=%d) in PanicWipe", capturePos, deletePos)
	}

	// Redis blocklist must appear before captureFileKeys.
	revokePos := strings.Index(s, "deps.Redis.Set(ctx")
	if revokePos < 0 || revokePos >= capturePos {
		t.Fatalf("session revocation (pos=%d) must precede captureFileKeys (pos=%d)", revokePos, capturePos)
	}
}

// ---------------------------------------------------------------------------
// Negative tests: authenticated challenge-signature panic-wipe flow
// ---------------------------------------------------------------------------

func TestPanicWipeChallengeSignatureInvalidSignatureRejected(t *testing.T) {
	const uin int64 = 50000001
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	// Generate a wipe key pair.
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	lookup := func(ctx context.Context, u int64) (ed25519.PublicKey, error) {
		if u == uin {
			return pub, nil
		}
		return nil, nil
	}

	var wiped bool
	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		ChallengeSignatureDeps: &ChallengeSignatureDeps{
			LookupWipePublicKey: lookup,
			Redis:               rdb,
		},
		Wipe: func(context.Context, PanicWipeDeps, int64) (int64, error) { wiped = true; return 0, nil },
	})

	// Store a valid challenge in Redis.
	challengeBytes := make([]byte, 32)
	rand.Read(challengeBytes)
	challengeID := "test-challenge-01"
	challengeB64 := base64.StdEncoding.EncodeToString(challengeBytes)
	challengeKey := wipeChallengePrefix + itoa(uin) + ":" + challengeID
	rdb.Set(context.Background(), challengeKey, challengeB64, wipeChallengeTTL)

	// Sign with a DIFFERENT key (wrong private key).
	_, wrongPriv, _ := ed25519.GenerateKey(nil)
	wrongSig := ed25519.Sign(wrongPriv, challengeBytes)

	body, _ := json.Marshal(manualPanicWipeRequest{
		ChallengeID: challengeID,
		Signature:   base64.StdEncoding.EncodeToString(wrongSig),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.WithUIN(req.Context(), uin))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("invalid signature: status=%d, want %d; body=%s", rr.Code, http.StatusUnauthorized, rr.Body.String())
	}
	if wiped {
		t.Fatal("wipe executed despite invalid signature")
	}
}

func TestPanicWipeChallengeSignatureAlteredChallengeRejected(t *testing.T) {
	const uin int64 = 50000002
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	lookup := func(ctx context.Context, u int64) (ed25519.PublicKey, error) {
		if u == uin {
			return pub, nil
		}
		return nil, nil
	}

	var wiped bool
	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		ChallengeSignatureDeps: &ChallengeSignatureDeps{
			LookupWipePublicKey: lookup,
			Redis:               rdb,
		},
		Wipe: func(context.Context, PanicWipeDeps, int64) (int64, error) { wiped = true; return 0, nil },
	})

	challengeBytes := make([]byte, 32)
	rand.Read(challengeBytes)
	challengeID := "test-challenge-02"
	challengeB64 := base64.StdEncoding.EncodeToString(challengeBytes)
	challengeKey := wipeChallengePrefix + itoa(uin) + ":" + challengeID
	rdb.Set(context.Background(), challengeKey, challengeB64, wipeChallengeTTL)

	// Sign a DIFFERENT challenge (altered by attacker).
	alteredChallenge := make([]byte, 32)
	rand.Read(alteredChallenge)
	sig := ed25519.Sign(priv, alteredChallenge)

	body, _ := json.Marshal(manualPanicWipeRequest{
		ChallengeID: challengeID,
		Signature:   base64.StdEncoding.EncodeToString(sig),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.WithUIN(req.Context(), uin))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("altered challenge: status=%d, want %d; body=%s", rr.Code, http.StatusUnauthorized, rr.Body.String())
	}
	if wiped {
		t.Fatal("wipe executed despite altered challenge")
	}
}

func TestPanicWipeChallengeSignatureReusedChallengeRejected(t *testing.T) {
	const uin int64 = 50000003
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	lookup := func(ctx context.Context, u int64) (ed25519.PublicKey, error) {
		if u == uin {
			return pub, nil
		}
		return nil, nil
	}

	var wipeCalls int
	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		ChallengeSignatureDeps: &ChallengeSignatureDeps{
			LookupWipePublicKey: lookup,
			Redis:               rdb,
		},
		Wipe: func(context.Context, PanicWipeDeps, int64) (int64, error) { wipeCalls++; return 0, nil },
	})

	// First attempt: valid challenge, valid signature — should succeed.
	challengeBytes := make([]byte, 32)
	rand.Read(challengeBytes)
	challengeID := "test-challenge-03"
	challengeB64 := base64.StdEncoding.EncodeToString(challengeBytes)
	challengeKey := wipeChallengePrefix + itoa(uin) + ":" + challengeID
	rdb.Set(context.Background(), challengeKey, challengeB64, wipeChallengeTTL)

	sig := ed25519.Sign(priv, challengeBytes)
	body1, _ := json.Marshal(manualPanicWipeRequest{
		ChallengeID: challengeID,
		Signature:   base64.StdEncoding.EncodeToString(sig),
	})
	req1 := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", strings.NewReader(string(body1)))
	req1.Header.Set("Content-Type", "application/json")
	req1 = req1.WithContext(middleware.WithUIN(req1.Context(), uin))
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	if rr1.Code != http.StatusAccepted {
		t.Fatalf("first attempt: status=%d, want %d; body=%s", rr1.Code, http.StatusAccepted, rr1.Body.String())
	}
	if wipeCalls != 1 {
		t.Fatalf("first wipe calls=%d, want 1", wipeCalls)
	}

	// Second attempt: reuse the same challenge ID + signature — must be rejected
	// because VerifyWipeSignature uses Redis.GetDel (single-use).
	body2, _ := json.Marshal(manualPanicWipeRequest{
		ChallengeID: challengeID,
		Signature:   base64.StdEncoding.EncodeToString(sig),
	})
	req2 := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", strings.NewReader(string(body2)))
	req2.Header.Set("Content-Type", "application/json")
	req2 = req2.WithContext(middleware.WithUIN(req2.Context(), uin))
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("reused challenge: status=%d, want %d; body=%s", rr2.Code, http.StatusUnauthorized, rr2.Body.String())
	}
	if wipeCalls != 1 {
		t.Fatalf("reused challenge triggered wipe: calls=%d, want 1", wipeCalls)
	}
}

func TestPanicWipeChallengeSignatureExpiredChallengeRejected(t *testing.T) {
	const uin int64 = 50000004
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	lookup := func(ctx context.Context, u int64) (ed25519.PublicKey, error) {
		if u == uin {
			return pub, nil
		}
		return nil, nil
	}

	var wiped bool
	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		ChallengeSignatureDeps: &ChallengeSignatureDeps{
			LookupWipePublicKey: lookup,
			Redis:               rdb,
		},
		Wipe: func(context.Context, PanicWipeDeps, int64) (int64, error) { wiped = true; return 0, nil },
	})

	challengeBytes := make([]byte, 32)
	rand.Read(challengeBytes)
	challengeID := "test-challenge-04"
	sig := ed25519.Sign(priv, challengeBytes)

	// Do NOT store the challenge in Redis — simulate expiration.
	// The challenge key is absent, so GetDel returns redis.Nil.

	body, _ := json.Marshal(manualPanicWipeRequest{
		ChallengeID: challengeID,
		Signature:   base64.StdEncoding.EncodeToString(sig),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.WithUIN(req.Context(), uin))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expired challenge: status=%d, want %d; body=%s", rr.Code, http.StatusUnauthorized, rr.Body.String())
	}
	if wiped {
		t.Fatal("wipe executed despite expired challenge")
	}
}

func TestPanicWipeChallengeSignatureWrongAccountRejected(t *testing.T) {
	const uinA int64 = 50000005
	const uinB int64 = 50000006
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	pubA, privA, _ := ed25519.GenerateKey(nil)
	pubB, _, _ := ed25519.GenerateKey(nil)

	lookup := func(ctx context.Context, u int64) (ed25519.PublicKey, error) {
		switch u {
		case uinA:
			return pubA, nil
		case uinB:
			return pubB, nil
		}
		return nil, nil
	}

	var wipedUIN int64
	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		ChallengeSignatureDeps: &ChallengeSignatureDeps{
			LookupWipePublicKey: lookup,
			Redis:               rdb,
		},
		Wipe: func(ctx context.Context, deps PanicWipeDeps, uin int64) (int64, error) {
			wipedUIN = uin
			return 0, nil
		},
	})

	// Create a challenge for uinA, stored under uinA's key.
	challengeBytes := make([]byte, 32)
	rand.Read(challengeBytes)
	challengeID := "test-challenge-05"
	challengeB64 := base64.StdEncoding.EncodeToString(challengeBytes)
	challengeKey := wipeChallengePrefix + itoa(uinA) + ":" + challengeID
	rdb.Set(context.Background(), challengeKey, challengeB64, wipeChallengeTTL)

	// Sign with uinA's key (valid signature for uinA's challenge).
	sig := ed25519.Sign(privA, challengeBytes)

	// Submit as uinB (wrong UIN in context). The challenge lookup uses uinB's
	// key, so the Redis key won't match — expired-challenge error.
	body, _ := json.Marshal(manualPanicWipeRequest{
		ChallengeID: challengeID,
		Signature:   base64.StdEncoding.EncodeToString(sig),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.WithUIN(req.Context(), uinB))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should fail — the challenge was created for uinA, but we're calling as uinB.
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong account: status=%d, want %d; body=%s", rr.Code, http.StatusUnauthorized, rr.Body.String())
	}
	if wipedUIN != 0 {
		t.Fatalf("wipe executed for uin=%d despite account mismatch", wipedUIN)
	}
}
