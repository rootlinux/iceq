package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestContactHandlersRejectRequestWithoutAuthenticatedActor(t *testing.T) {
	d := ContactsDeps{}
	tests := []struct {
		name, method, body string
		fn                 http.HandlerFunc
	}{
		{"list", http.MethodGet, "", NewListContactsHandler(d)},
		{"add", http.MethodPost, `{"target_uin":200}`, NewAddContactHandler(d)},
		{"accept", http.MethodPut, "", NewAcceptContactHandler(d)},
		{"block", http.MethodPut, "", NewBlockContactHandler(d)},
		{"remove", http.MethodDelete, "", NewRemoveContactHandler(d)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, "/api/contacts/200", strings.NewReader(tt.body))
			tt.fn(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}
