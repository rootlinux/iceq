package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrivateKeyHandlersRejectRequestWithoutAuthenticatedActor(t *testing.T) {
	tests := []struct {
		name string
		body string
		fn   http.HandlerFunc
	}{
		{"bundle", `{}`, NewPostBundleHandler(BundleDeps{}, nil)},
		{"prekeys", `{}`, NewAddPrekeysHandler(PrekeyDeps{})},
		{"count", ``, NewCountPrekeysHandler(PrekeyDeps{})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/keys/"+tt.name, strings.NewReader(tt.body))
			tt.fn(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}
