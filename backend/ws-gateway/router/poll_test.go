package router

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/redis/go-redis/v9"
)

type pollStoreStub struct {
	result PollResult
	req    PollRequest
	err    error
}

func TestPollReadsNonDestructivelyAndNextCursorAcknowledgesPreviousPage(t *testing.T) {
	server := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	store := NewRedisPollStore(rdb)
	ctx := context.Background()
	first := []byte(`{"type":"message","id":"00000000-0000-4000-8000-000000000001","ts":1,"payload":{}}`)
	second := []byte(`{"type":"message","id":"00000000-0000-4000-8000-000000000002","ts":2,"payload":{}}`)
	if err := store.Enqueue(ctx, 42, first); err != nil {
		t.Fatal(err)
	}
	if err := store.Enqueue(ctx, 42, second); err != nil {
		t.Fatal(err)
	}

	page, err := store.Poll(ctx, PollRequest{UIN: 42, Limit: 1})
	if err != nil || len(page.Envelopes) != 1 {
		t.Fatalf("first poll=%+v err=%v", page, err)
	}
	scope, _ := DirectRecipientScope(42)
	items, _ := store.acceptance.ReadAcceptedAfter(ctx, scope, "", 10)
	if len(items) != 2 {
		t.Fatalf("poll must be non-destructive, items=%d", len(items))
	}

	next, err := store.Poll(ctx, PollRequest{UIN: 42, Cursor: page.Cursor, Limit: 1})
	if err != nil || len(next.Envelopes) != 1 {
		t.Fatalf("next poll=%+v err=%v", next, err)
	}
	items, _ = store.acceptance.ReadAcceptedAfter(ctx, scope, "", 10)
	if len(items) != 1 || items[0].MessageID != "00000000-0000-4000-8000-000000000002" {
		t.Fatalf("previous page was not acknowledged exactly: %#v", items)
	}
}

func TestPollRejectsReservedAccountWipedControl(t *testing.T) {
	server := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	store := NewRedisPollStore(rdb)
	ctx := context.Background()
	reserved := []byte(`{"type":"account_wiped","id":"00000000-0000-4000-8000-000000000003","ts":1,"payload":{}}`)

	if err := store.Enqueue(ctx, 42, reserved); err == nil {
		t.Fatal("reserved terminal control was accepted into poll storage")
	}
	scope, _ := DirectRecipientScope(42)
	items, err := store.acceptance.ReadAcceptedAfter(ctx, scope, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("reserved control persisted in poll storage: %#v", items)
	}
}

func (s *pollStoreStub) Poll(_ context.Context, req PollRequest) (PollResult, error) {
	s.req = req
	return s.result, s.err
}

func TestPollRequiresAuthenticatedOwnerAndCapsClientBounds(t *testing.T) {
	store := &pollStoreStub{result: PollResult{Cursor: "opaque-next", Envelopes: []json.RawMessage{json.RawMessage(`{"type":"message","id":"m1","ts":1,"payload":{}}`)}}}
	h := NewPollHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/poll?limit=999&wait_ms=999999&cursor=opaque-old", nil)
	req = req.WithContext(middleware.WithUIN(req.Context(), 10000001))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if store.req.UIN != 10000001 {
		t.Fatalf("poll owner=%d", store.req.UIN)
	}
	if store.req.Limit != MaxPollBatch {
		t.Fatalf("limit=%d want %d", store.req.Limit, MaxPollBatch)
	}
	if store.req.Wait != MaxPollWait {
		t.Fatalf("wait=%s want %s", store.req.Wait, MaxPollWait)
	}
	if store.req.Cursor != "opaque-old" {
		t.Fatalf("cursor=%q", store.req.Cursor)
	}
	var body PollResult
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Cursor != "opaque-next" || len(body.Envelopes) != 1 {
		t.Fatalf("body=%+v", body)
	}
}

func TestPollRejectsMissingAuthAndWrongMethod(t *testing.T) {
	h := NewPollHandler(&pollStoreStub{})
	for _, tc := range []struct {
		method string
		auth   bool
		want   int
	}{
		{http.MethodGet, false, http.StatusUnauthorized},
		{http.MethodPost, true, http.StatusMethodNotAllowed},
	} {
		req := httptest.NewRequest(tc.method, "/poll", nil)
		if tc.auth {
			req = req.WithContext(middleware.WithUIN(req.Context(), 10000001))
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != tc.want {
			t.Fatalf("%s auth=%v status=%d want=%d", tc.method, tc.auth, rr.Code, tc.want)
		}
	}
}

func TestPollInvalidCursorHasStableMachineReadableCode(t *testing.T) {
	store := &pollStoreStub{err: ErrInvalidPollCursor}
	req := httptest.NewRequest(http.MethodGet, "/poll?cursor=stale", nil)
	req = req.WithContext(middleware.WithUIN(req.Context(), 42))
	rr := httptest.NewRecorder()
	NewPollHandler(store).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), `"code":"INVALID_POLL_CURSOR"`) {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestPollDefaultsAreBounded(t *testing.T) {
	store := &pollStoreStub{}
	req := httptest.NewRequest(http.MethodGet, "/poll", nil)
	req = req.WithContext(middleware.WithUIN(req.Context(), 1))
	rr := httptest.NewRecorder()
	NewPollHandler(store).ServeHTTP(rr, req)
	if store.req.Limit != DefaultPollBatch || store.req.Wait != DefaultPollWait {
		t.Fatalf("defaults limit=%d wait=%s", store.req.Limit, store.req.Wait)
	}
	if store.req.Wait <= 0 || store.req.Wait > 30*time.Second {
		t.Fatalf("unsafe wait %s", store.req.Wait)
	}
}
