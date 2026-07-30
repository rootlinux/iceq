package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gocql/gocql"
	"github.com/iceq/iceq/message-service/store"
	"github.com/iceq/iceq/shared/middleware"
)

// ----------------------------------------------------------------------------
// paginatedFakeStore -- unlike historyFakeStore / wipedCheckFakeStore (which
// return static rows verbatim regardless of Before/Limit), this fake
// actually implements pagination: it filters a pre-seeded, pre-sorted
// dataset by Before and Limit and applies the same limit+1-derived hasMore
// contract store.GetHistory/GetGroupHistory now implement. It exists to
// test properties that only show up when the fake behaves like a real
// paginated backend: multi-page walks, duplicate/skip safety, and ordering.
// Callers are responsible for seeding rows in DESC CreatedAt order, matching
// the ordering guarantee Scylla's clustering key provides in production.
// ----------------------------------------------------------------------------

type paginatedFakeStore struct {
	dm         []store.MessageRow
	group      []store.GroupMessageRow
	dmCalls    []store.HistoryRequest
	groupCalls []store.GroupHistoryRequest
}

func (s *paginatedFakeStore) GetHistory(_ context.Context, r store.HistoryRequest) ([]store.MessageRow, bool, error) {
	s.dmCalls = append(s.dmCalls, r)
	if r.Limit < 0 {
		return nil, false, store.ErrInvalidLimit
	}
	limit := r.Limit
	if limit == 0 {
		limit = 20
	}
	before := r.Before
	if before.IsZero() {
		before = time.Now().Add(time.Second)
	}
	var matched []store.MessageRow
	for _, row := range s.dm {
		if row.ConversationID == r.ConversationID && row.CreatedAt.Before(before) {
			matched = append(matched, row)
		}
	}
	if len(matched) > limit {
		return matched[:limit], true, nil
	}
	return matched, false, nil
}

func (s *paginatedFakeStore) GetGroupHistory(_ context.Context, r store.GroupHistoryRequest) ([]store.GroupMessageRow, bool, error) {
	s.groupCalls = append(s.groupCalls, r)
	if r.Limit < 0 {
		return nil, false, store.ErrInvalidLimit
	}
	limit := r.Limit
	if limit == 0 {
		limit = 20
	}
	before := r.Before
	if before.IsZero() {
		before = time.Now().Add(time.Second)
	}
	var matched []store.GroupMessageRow
	for _, row := range s.group {
		if row.GroupID == r.GroupID && row.CreatedAt.Before(before) {
			matched = append(matched, row)
		}
	}
	if len(matched) > limit {
		return matched[:limit], true, nil
	}
	return matched, false, nil
}

func dmRequest(uin int64, query string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/messages/history?"+query, nil)
	return req.WithContext(middleware.WithUIN(req.Context(), uin))
}

// ----------------------------------------------------------------------------
// Section 1: exact has-more / cursor matrix. wipedCheckFakeStore's explicit
// dmHasMore/groupHasMore fields let each case state the store's exact
// signal directly, independent of row count -- proving the handler now
// trusts that signal instead of re-deriving (and inverting) it from
// len(rows) < limit.
// ----------------------------------------------------------------------------

func TestDMHistory_CursorMatrix(t *testing.T) {
	cases := []struct {
		name       string
		rowCount   int
		hasMore    bool
		wantCursor bool
	}{
		{"zero rows", 0, false, false},
		{"fewer than limit", 5, false, false},
		{"exactly limit, no additional row proven", 20, false, false},
		{"limit+1 proven by store", 20, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows := make([]store.MessageRow, tc.rowCount)
			for i := range rows {
				rows[i] = store.MessageRow{ID: gocql.TimeUUID(), SenderUIN: 200, ReceiverUIN: 100, Ciphertext: []byte("x"), CreatedAt: time.Now().Add(-time.Duration(i) * time.Minute)}
			}
			db := &groupFakeDB{rowQueue: [][]any{{false}}}
			fs := &wipedCheckFakeStore{dmRows: rows, dmHasMore: tc.hasMore}
			rr := httptest.NewRecorder()
			NewGetHistoryHandler(HistoryDeps{PG: db, Store: fs})(rr, dmRequest(100, "conversation_id=dm:100:200&limit=20"))

			if rr.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
			var resp historyResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(resp.Messages) != tc.rowCount {
				t.Fatalf("messages count=%d, want %d", len(resp.Messages), tc.rowCount)
			}
			if (resp.NextCursor != nil) != tc.wantCursor {
				t.Fatalf("next_cursor=%v, wantCursor=%v", resp.NextCursor, tc.wantCursor)
			}
		})
	}
}

func TestGroupHistory_CursorMatrix(t *testing.T) {
	cases := []struct {
		name       string
		rowCount   int
		hasMore    bool
		wantCursor bool
	}{
		{"zero rows", 0, false, false},
		{"fewer than limit", 5, false, false},
		{"exactly limit, no additional row proven", 20, false, false},
		{"limit+1 proven by store", 20, true, true},
	}
	gid, _ := gocql.ParseUUID(behaviorGroupID)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows := make([]store.GroupMessageRow, tc.rowCount)
			for i := range rows {
				rows[i] = store.GroupMessageRow{GroupID: gid, ID: gocql.TimeUUID(), SenderUIN: 100, Ciphertext: []byte("x"), CreatedAt: time.Now().Add(-time.Duration(i) * time.Minute)}
			}
			rowsQueue := [][][]any{{}}
			if tc.rowCount == 0 {
				rowsQueue = nil // wipedUINsAmong short-circuits before querying when there are no candidate senders
			}
			db := &groupFakeDB{rowQueue: [][]any{{1}}, rowsQueue: rowsQueue}
			fs := &wipedCheckFakeStore{groupRows: rows, groupHasMore: tc.hasMore}
			rr := httptest.NewRecorder()
			NewGetGroupHistoryHandler(HistoryDeps{PG: db, Store: fs})(rr, groupRequest(http.MethodGet, "/api/messages/group-history?group_id="+behaviorGroupID+"&limit=20", "", 200))

			if rr.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
			var resp historyResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(resp.Messages) != tc.rowCount {
				t.Fatalf("messages count=%d, want %d", len(resp.Messages), tc.rowCount)
			}
			if (resp.NextCursor != nil) != tc.wantCursor {
				t.Fatalf("next_cursor=%v, wantCursor=%v", resp.NextCursor, tc.wantCursor)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// Section 2: multi-page walks against paginatedFakeStore. Proves no
// duplicate or skipped messages across pages, and that ordering (including
// a tied-timestamp pair within a single page -- realistic here since
// created_at is minute-truncated before storage, see messagestore.go) is
// preserved end to end through the handler.
// ----------------------------------------------------------------------------

func TestDMHistory_MultiPageWalk_NoDuplicatesNoSkips_StableOrder(t *testing.T) {
	const total = 25
	const convID = "dm:100:200"
	base := time.Now()
	rows := make([]store.MessageRow, total)
	var wantIDs []string
	for i := 0; i < total; i++ {
		ts := base.Add(-time.Duration(i) * time.Minute)
		if i == 6 {
			// Tie the timestamp of row 6 to row 5 -- both must still appear,
			// in seed order, without being duplicated or skipped by
			// pagination filtering (this tie sits mid-page, not at a page
			// boundary, at limit=20).
			ts = base.Add(-time.Duration(5) * time.Minute)
		}
		rows[i] = store.MessageRow{ID: gocql.TimeUUID(), ConversationID: convID, SenderUIN: 200, ReceiverUIN: 100, Ciphertext: []byte("x"), CreatedAt: ts}
		wantIDs = append(wantIDs, rows[i].ID.String())
	}
	fs := &paginatedFakeStore{dm: rows}
	db := &groupFakeDB{rowQueue: [][]any{{false}, {false}}} // one isAccountWiped check per page fetch

	var gotIDs []string
	before := ""
	pages := 0
	for {
		pages++
		if pages > total {
			t.Fatalf("pagination did not terminate after %d pages", pages)
		}
		q := "conversation_id=" + convID + "&limit=20"
		if before != "" {
			q += "&before=" + url.QueryEscape(before)
		}
		rr := httptest.NewRecorder()
		NewGetHistoryHandler(HistoryDeps{PG: db, Store: fs})(rr, dmRequest(100, q))
		if rr.Code != http.StatusOK {
			t.Fatalf("page %d: status=%d body=%s", pages, rr.Code, rr.Body.String())
		}
		var resp historyResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("page %d: decode: %v", pages, err)
		}
		for _, m := range resp.Messages {
			gotIDs = append(gotIDs, m.ID)
		}
		if resp.NextCursor == nil {
			break
		}
		before = resp.NextCursor.Format(time.RFC3339Nano)
	}

	if pages != 2 {
		t.Fatalf("pages=%d, want 2 (20 + 5)", pages)
	}
	if len(gotIDs) != total {
		t.Fatalf("total messages seen=%d, want %d (duplicate or skipped rows): got=%v", len(gotIDs), total, gotIDs)
	}
	seen := make(map[string]bool, len(gotIDs))
	for _, id := range gotIDs {
		if seen[id] {
			t.Fatalf("message %s appeared more than once across pages", id)
		}
		seen[id] = true
	}
	for i := range wantIDs {
		if gotIDs[i] != wantIDs[i] {
			t.Fatalf("order mismatch at position %d: got %s, want %s (full got=%v)", i, gotIDs[i], wantIDs[i], gotIDs)
		}
	}
}

func TestGroupHistory_MultiPageWalk_NoDuplicatesNoSkips_StableOrder(t *testing.T) {
	const total = 45
	gid, _ := gocql.ParseUUID(behaviorGroupID)
	base := time.Now()
	rows := make([]store.GroupMessageRow, total)
	var wantIDs []string
	for i := 0; i < total; i++ {
		ts := base.Add(-time.Duration(i) * time.Minute)
		if i == 12 {
			ts = base.Add(-time.Duration(11) * time.Minute) // tie, mid-page
		}
		rows[i] = store.GroupMessageRow{GroupID: gid, ID: gocql.TimeUUID(), SenderUIN: 100, Ciphertext: []byte("x"), CreatedAt: ts}
		wantIDs = append(wantIDs, rows[i].ID.String())
	}
	fs := &paginatedFakeStore{group: rows}
	// Three page fetches: membership check (rowQueue) + wiped-senders check
	// (rowsQueue, since every page here has at least one row) per fetch.
	db := &groupFakeDB{
		rowQueue:  [][]any{{1}, {1}, {1}},
		rowsQueue: [][][]any{{}, {}, {}},
	}

	var gotIDs []string
	before := ""
	pages := 0
	for {
		pages++
		if pages > total {
			t.Fatalf("pagination did not terminate after %d pages", pages)
		}
		q := "/api/messages/group-history?group_id=" + behaviorGroupID + "&limit=20"
		if before != "" {
			q += "&before=" + url.QueryEscape(before)
		}
		rr := httptest.NewRecorder()
		NewGetGroupHistoryHandler(HistoryDeps{PG: db, Store: fs})(rr, groupRequest(http.MethodGet, q, "", 100))
		if rr.Code != http.StatusOK {
			t.Fatalf("page %d: status=%d body=%s", pages, rr.Code, rr.Body.String())
		}
		var resp historyResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("page %d: decode: %v", pages, err)
		}
		for _, m := range resp.Messages {
			gotIDs = append(gotIDs, m.ID)
		}
		if resp.NextCursor == nil {
			break
		}
		before = resp.NextCursor.Format(time.RFC3339Nano)
	}

	if pages != 3 {
		t.Fatalf("pages=%d, want 3 (20 + 20 + 5)", pages)
	}
	if len(gotIDs) != total {
		t.Fatalf("total messages seen=%d, want %d (duplicate or skipped rows): got=%v", len(gotIDs), total, gotIDs)
	}
	seen := make(map[string]bool, len(gotIDs))
	for _, id := range gotIDs {
		if seen[id] {
			t.Fatalf("message %s appeared more than once across pages", id)
		}
		seen[id] = true
	}
	for i := range wantIDs {
		if gotIDs[i] != wantIDs[i] {
			t.Fatalf("order mismatch at position %d: got %s, want %s", i, gotIDs[i], wantIDs[i])
		}
	}
}

// ----------------------------------------------------------------------------
// Section 3: invalid cursor.
// ----------------------------------------------------------------------------

func TestDMHistory_InvalidCursor_Returns400(t *testing.T) {
	db := &groupFakeDB{}
	fs := &wipedCheckFakeStore{}
	rr := httptest.NewRecorder()
	NewGetHistoryHandler(HistoryDeps{PG: db, Store: fs})(rr, dmRequest(100, "conversation_id=dm:100:200&before=not-a-real-timestamp"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if fs.dmCalls != 0 {
		t.Fatalf("store must not be queried when the cursor fails to parse, got %d calls", fs.dmCalls)
	}
}

func TestGroupHistory_InvalidCursor_Returns400(t *testing.T) {
	db := &groupFakeDB{}
	fs := &wipedCheckFakeStore{}
	rr := httptest.NewRecorder()
	NewGetGroupHistoryHandler(HistoryDeps{PG: db, Store: fs})(rr, groupRequest(http.MethodGet, "/api/messages/group-history?group_id="+behaviorGroupID+"&before=not-a-real-timestamp", "", 200))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if fs.groupCalls != 0 {
		t.Fatalf("store must not be queried when the cursor fails to parse, got %d calls", fs.groupCalls)
	}
}

// ----------------------------------------------------------------------------
// Section 4: unauthorized conversation access remains blocked. Group-side
// membership gating already has dedicated coverage in
// TestGroupHistoryChecksActorMembershipBeforeReading (groups_behavior_test.go);
// this adds the DM-side gap.
// ----------------------------------------------------------------------------

func TestDMHistory_NonMemberOfConversation_Returns403(t *testing.T) {
	db := &groupFakeDB{}
	fs := &wipedCheckFakeStore{dmRows: []store.MessageRow{{ID: gocql.TimeUUID(), SenderUIN: 100, ReceiverUIN: 200, Ciphertext: []byte("x"), CreatedAt: time.Now()}}}
	rr := httptest.NewRecorder()
	// UIN 300 is neither party to "dm:100:200".
	NewGetHistoryHandler(HistoryDeps{PG: db, Store: fs})(rr, dmRequest(300, "conversation_id=dm:100:200"))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if fs.dmCalls != 0 {
		t.Fatalf("store must not be queried for a non-member request, got %d calls", fs.dmCalls)
	}
}

// ----------------------------------------------------------------------------
// Section 5: wiped-user rows never reappear or create a misleading cursor.
// The DM short-circuit (empty messages + nil cursor whenever the
// counterpart is wiped) already has dedicated coverage in
// history_wiped_accounts_test.go. The case that matters here is
// group-specific and previously unhandled: an entire page's senders happen
// to be wiped, filtering the response down to zero messages -- the cursor
// must still be present (derived from the real, unfiltered store page) so
// pagination keeps walking through to any real history further back,
// instead of silently truncating it.
// ----------------------------------------------------------------------------

func TestGroupHistory_AllSendersInPageWiped_StillExposesCursor(t *testing.T) {
	gid, _ := gocql.ParseUUID(behaviorGroupID)
	wipedID := gocql.TimeUUID()
	fs := &wipedCheckFakeStore{
		groupRows:    []store.GroupMessageRow{{GroupID: gid, ID: wipedID, SenderUIN: 900, Ciphertext: []byte("gone"), CreatedAt: time.Now()}},
		groupHasMore: true,
	}
	db := &groupFakeDB{rowQueue: [][]any{{1}}, rowsQueue: [][][]any{{{int64(900)}}}}
	rr := httptest.NewRecorder()
	NewGetGroupHistoryHandler(HistoryDeps{PG: db, Store: fs})(rr, groupRequest(http.MethodGet, "/api/messages/group-history?group_id="+behaviorGroupID, "", 200))

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, wipedID.String()) {
		t.Fatalf("body=%s must not contain the wiped sender's message", body)
	}
	var resp historyResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Messages) != 0 {
		t.Fatalf("messages=%#v, want empty (the only sender in this page is wiped)", resp.Messages)
	}
	if resp.NextCursor == nil {
		t.Fatal("next_cursor is nil despite hasMore=true; a page entirely filtered by wiped senders must still let the client page through to real history behind it")
	}
}
