package handlers

import (
	"github.com/iceq/iceq/shared/middleware"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUnrelatedUserCannotReadDirectConversation(t *testing.T) {
	h := NewGetHistoryHandler(HistoryDeps{})
	req := httptest.NewRequest(http.MethodGet, "/api/messages/history?conversation_id=dm:100:200", nil)
	req = req.WithContext(middleware.WithUIN(req.Context(), 300))
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMessageHistoryRejectsMissingAuthenticatedActor(t *testing.T) {
	rr := httptest.NewRecorder()
	NewGetHistoryHandler(HistoryDeps{})(rr, httptest.NewRequest(http.MethodGet, "/api/messages/history?conversation_id=dm:100:200", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
