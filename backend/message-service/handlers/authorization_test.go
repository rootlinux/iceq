package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/iceq/iceq/shared/middleware"
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

func TestDirectHistoryRequiresCanonicalTwoUserConversation(t *testing.T) {
	for _, conversationID := range []string{"dm:200:100", "dm:100:100", "dm:100:200:300", "group:100:200"} {
		t.Run(conversationID, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/messages/history?conversation_id="+conversationID, nil)
			req = req.WithContext(middleware.WithUIN(req.Context(), 100))
			rr := httptest.NewRecorder()
			NewGetHistoryHandler(HistoryDeps{})(rr, req)
			if rr.Code != http.StatusForbidden && rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestGroupAndHistoryHandlersRejectMissingAuthenticatedActor(t *testing.T) {
	d := GroupsDeps{}
	tests := []struct {
		name, method, path, body string
		fn                       http.HandlerFunc
	}{
		{"list groups", http.MethodGet, "/api/groups", "", NewListGroupsHandler(d)},
		{"list members", http.MethodGet, "/api/groups/id/members", "", NewListGroupMembersHandler(d)},
		{"add member", http.MethodPost, "/api/groups/id/members", `{"uin":200}`, NewAddGroupMemberHandler(d)},
		{"remove member", http.MethodDelete, "/api/groups/id/members/200", "", NewRemoveGroupMemberHandler(d)},
		{"delete group", http.MethodDelete, "/api/groups/id", "", NewDeleteGroupHandler(d)},
		{"group history", http.MethodGet, "/api/messages/group-history?group_id=7f0300f2-0494-4f61-9f41-7c198f73b2fa", "", NewGetGroupHistoryHandler(HistoryDeps{})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("group_id", "7f0300f2-0494-4f61-9f41-7c198f73b2fa")
			rctx.URLParams.Add("uin", "200")
			req = req.WithContext(contextWithRoute(req, rctx))
			rr := httptest.NewRecorder()
			tt.fn(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

func contextWithRoute(req *http.Request, rctx *chi.Context) context.Context {
	return context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
}

func TestMessageHistoryRejectsMissingAuthenticatedActor(t *testing.T) {
	rr := httptest.NewRecorder()
	NewGetHistoryHandler(HistoryDeps{})(rr, httptest.NewRequest(http.MethodGet, "/api/messages/history?conversation_id=dm:100:200", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
