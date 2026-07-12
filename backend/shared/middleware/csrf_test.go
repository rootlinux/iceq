package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireCSRFAllowsSafeMethodsWithoutHeader(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		t.Run(method, func(t *testing.T) {
			nextCalled := false
			handler := RequireCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusNoContent)
			}))

			req := httptest.NewRequest(method, "/api/auth/settings", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if !nextCalled {
				t.Fatal("next handler was not called")
			}
			if rr.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusNoContent)
			}
		})
	}
}

func TestRequireCSRFRejectsUnsafeMethodsWithoutHeader(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			nextCalled := false
			handler := RequireCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusNoContent)
			}))

			req := httptest.NewRequest(method, "/api/auth/settings", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if nextCalled {
				t.Fatal("next handler was called")
			}
			if rr.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusForbidden, rr.Body.String())
			}
			if got := rr.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
				t.Fatalf("Content-Type = %q, want application/json; charset=utf-8", got)
			}
			if got := rr.Body.String(); got != "{\"error\":\"missing CSRF header\",\"code\":\"CSRF_REQUIRED\"}\n" {
				t.Fatalf("body = %q, want CSRF error envelope", got)
			}
		})
	}
}

func TestRequireCSRFAllowsUnsafeMethodWithHeader(t *testing.T) {
	nextCalled := false
	handler := RequireCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	req.Header.Set(CSRFHeaderName, CSRFHeaderValue)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if !nextCalled {
		t.Fatal("next handler was not called")
	}
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNoContent)
	}
}
