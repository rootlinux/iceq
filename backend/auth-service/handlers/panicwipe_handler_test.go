package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/iceq/iceq/shared/middleware"
)

func TestLoginWrongPasswordNeverTriggersPanicWipe(t *testing.T) {
	src, err := os.ReadFile("login.go")
	if err != nil {
		t.Fatalf("read login.go: %v", err)
	}
	loginGo := string(src)
	wrongPasswordStart := strings.Index(loginGo, "if !passwordResult.OK {")
	if wrongPasswordStart < 0 {
		t.Fatal("could not locate wrong-password login path")
	}
	wrongPasswordEnd := strings.Index(loginGo[wrongPasswordStart:], "// 4. Mint a fresh access + refresh pair")
	if wrongPasswordEnd < 0 {
		t.Fatal("could not locate wrong-password login path")
	}
	wrongPasswordPath := loginGo[wrongPasswordStart : wrongPasswordStart+wrongPasswordEnd]

	for _, forbidden := range []string{
		"Wipe",
		"triggerPanicWipeIfThresholdCrossed",
		"failedLogin",
		"PanicWipe",
		"session_epoch",
		"file_ownership",
		"wiped_accounts",
	} {
		if strings.Contains(wrongPasswordPath, forbidden) {
			t.Fatalf("wrong-password login path can trigger remote wipe or mutate protected state via %q", forbidden)
		}
	}
	if !strings.Contains(wrongPasswordPath, `writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid credentials")`) {
		t.Fatal("wrong-password login path must retain the generic 401 response")
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
