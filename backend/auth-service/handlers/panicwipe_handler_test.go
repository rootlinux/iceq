package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/iceq/iceq/shared/middleware"
)

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
