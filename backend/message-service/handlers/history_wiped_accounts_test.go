package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gocql/gocql"
	"github.com/iceq/iceq/message-service/store"
	"github.com/iceq/iceq/shared/middleware"
)

// wipedCheckFakeStore is a local historyStore fake that (unlike
// groups_behavior_test.go's historyFakeStore) tracks calls to BOTH
// GetHistory and GetGroupHistory, so these tests can prove the Scylla store
// is never even queried once a counterpart is already known wiped.
type wipedCheckFakeStore struct {
	dmRows       []store.MessageRow
	dmHasMore    bool
	dmCalls      int
	groupRows    []store.GroupMessageRow
	groupHasMore bool
	groupCalls   int
}

func (s *wipedCheckFakeStore) GetHistory(context.Context, store.HistoryRequest) ([]store.MessageRow, bool, error) {
	s.dmCalls++
	return s.dmRows, s.dmHasMore, nil
}

func (s *wipedCheckFakeStore) GetGroupHistory(context.Context, store.GroupHistoryRequest) ([]store.GroupMessageRow, bool, error) {
	s.groupCalls++
	return s.groupRows, s.groupHasMore, nil
}

func TestDirectHistoryReturnsEmptyWhenCounterpartIsWiped(t *testing.T) {
	db := &groupFakeDB{rowQueue: [][]any{{true}}}
	fs := &wipedCheckFakeStore{dmRows: []store.MessageRow{
		{ID: gocql.TimeUUID(), SenderUIN: 200, ReceiverUIN: 100, Ciphertext: []byte("should-never-be-returned"), CreatedAt: time.Now()},
	}}
	req := httptest.NewRequest(http.MethodGet, "/api/messages/history?conversation_id=dm:100:200", nil)
	req = req.WithContext(middleware.WithUIN(req.Context(), 100))
	rr := httptest.NewRecorder()
	NewGetHistoryHandler(HistoryDeps{PG: db, Store: fs})(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if fs.dmCalls != 0 {
		t.Fatalf("Store.GetHistory must not be called once the counterpart is known wiped, got %d calls", fs.dmCalls)
	}
	var resp historyResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Messages) != 0 {
		t.Fatalf("messages = %#v, want empty", resp.Messages)
	}
	if resp.NextCursor != nil {
		t.Fatalf("next_cursor = %v, want nil (must look like a legitimately empty conversation)", resp.NextCursor)
	}
	if len(db.calls) != 1 || db.calls[0].args[0] != int64(200) {
		t.Fatalf("wiped_accounts check must query the counterpart (200), got calls=%#v", db.calls)
	}
}

func TestDirectHistoryPassesThroughWhenCounterpartIsNotWiped(t *testing.T) {
	db := &groupFakeDB{rowQueue: [][]any{{false}}}
	msgID := gocql.TimeUUID()
	fs := &wipedCheckFakeStore{dmRows: []store.MessageRow{
		{ID: msgID, SenderUIN: 200, ReceiverUIN: 100, Ciphertext: []byte("hello"), CreatedAt: time.Now()},
	}}
	req := httptest.NewRequest(http.MethodGet, "/api/messages/history?conversation_id=dm:100:200", nil)
	req = req.WithContext(middleware.WithUIN(req.Context(), 100))
	rr := httptest.NewRecorder()
	NewGetHistoryHandler(HistoryDeps{PG: db, Store: fs})(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if fs.dmCalls != 1 {
		t.Fatalf("Store.GetHistory must be called when the counterpart is not wiped, got %d calls", fs.dmCalls)
	}
	if !strings.Contains(rr.Body.String(), msgID.String()) {
		t.Fatalf("body=%s does not contain the expected message", rr.Body.String())
	}
}

func TestGroupHistoryFiltersMessagesFromWipedSenders(t *testing.T) {
	gid, _ := gocql.ParseUUID(behaviorGroupID)
	wipedMsgID := gocql.TimeUUID()
	liveMsgID := gocql.TimeUUID()
	fs := &wipedCheckFakeStore{groupRows: []store.GroupMessageRow{
		{GroupID: gid, ID: wipedMsgID, SenderUIN: 900, Ciphertext: []byte("gone"), CreatedAt: time.Now()},
		{GroupID: gid, ID: liveMsgID, SenderUIN: 100, Ciphertext: []byte("stays"), CreatedAt: time.Now()},
	}}
	// rowQueue[0] answers the membership check; rowsQueue[0] answers the
	// batched "SELECT uin FROM wiped_accounts WHERE uin = ANY($1)" query
	// with sender 900 as wiped.
	db := &groupFakeDB{rowQueue: [][]any{{1}}, rowsQueue: [][][]any{{{int64(900)}}}}
	rr := httptest.NewRecorder()
	NewGetGroupHistoryHandler(HistoryDeps{PG: db, Store: fs})(rr, groupRequest(http.MethodGet, "/api/messages/group-history?group_id="+behaviorGroupID, "", 200))

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, wipedMsgID.String()) {
		t.Fatalf("body=%s must not contain the wiped sender's message", body)
	}
	if !strings.Contains(body, liveMsgID.String()) {
		t.Fatalf("body=%s must still contain the live sender's message", body)
	}
}

func TestGroupHistoryPassesThroughWhenNoSendersAreWiped(t *testing.T) {
	gid, _ := gocql.ParseUUID(behaviorGroupID)
	msgA := gocql.TimeUUID()
	msgB := gocql.TimeUUID()
	fs := &wipedCheckFakeStore{groupRows: []store.GroupMessageRow{
		{GroupID: gid, ID: msgA, SenderUIN: 100, Ciphertext: []byte("a"), CreatedAt: time.Now()},
		{GroupID: gid, ID: msgB, SenderUIN: 400, Ciphertext: []byte("b"), CreatedAt: time.Now()},
	}}
	db := &groupFakeDB{rowQueue: [][]any{{1}}, rowsQueue: [][][]any{{}}}
	rr := httptest.NewRecorder()
	NewGetGroupHistoryHandler(HistoryDeps{PG: db, Store: fs})(rr, groupRequest(http.MethodGet, "/api/messages/group-history?group_id="+behaviorGroupID, "", 200))

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, msgA.String()) || !strings.Contains(body, msgB.String()) {
		t.Fatalf("body=%s must contain both messages when nobody is wiped", body)
	}
}
