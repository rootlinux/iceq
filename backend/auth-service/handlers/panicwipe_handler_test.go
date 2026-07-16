package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/redis/go-redis/v9"
)

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

	var wipedUIN int64
	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		Wipe: func(ctx context.Context, deps PanicWipeDeps, uin int64) error {
			wipedUIN = uin
			return nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", nil)
	req = req.WithContext(middleware.WithUIN(req.Context(), authenticatedUIN))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusNoContent, rr.Body.String())
	}
	if wipedUIN != authenticatedUIN {
		t.Fatalf("wiped UIN = %d, want %d", wipedUIN, authenticatedUIN)
	}
	if rr.Body.Len() != 0 {
		t.Fatalf("body = %q, want empty body", rr.Body.String())
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
	var got MessageStore
	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		PanicWipeDeps: PanicWipeDeps{Scylla: store},
		Wipe: func(_ context.Context, deps PanicWipeDeps, _ int64) error {
			got = deps.Scylla
			return nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", nil)
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000003))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNoContent)
	}
	if got != store {
		t.Fatalf("message store = %#v, want %#v", got, store)
	}
}

func TestManualPanicWipeHandlerClearsCookiesOnFailureWithoutMetadata(t *testing.T) {
	handler := NewManualPanicWipeHandler(ManualPanicWipeDeps{
		Wipe: func(ctx context.Context, deps PanicWipeDeps, uin int64) error {
			return errors.New("storage unavailable for sensitive user")
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/auth/panic-wipe", nil)
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
