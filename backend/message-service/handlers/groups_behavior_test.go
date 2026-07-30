package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gocql/gocql"
	"github.com/iceq/iceq/message-service/store"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const behaviorGroupID = "7f0300f2-0494-4f61-9f41-7c198f73b2fa"

type groupCall struct {
	sql  string
	args []any
}
type groupFakeDB struct {
	rowQueue  [][]any
	rowsQueue [][][]any
	tags      []pgconn.CommandTag
	calls     []groupCall
	tx        *groupFakeTx
}

func (f *groupFakeDB) Begin(context.Context) (pgx.Tx, error) {
	if f.tx != nil {
		return f.tx, nil
	}
	return nil, errors.New("unused")
}
func (f *groupFakeDB) Exec(_ context.Context, q string, a ...any) (pgconn.CommandTag, error) {
	f.calls = append(f.calls, groupCall{q, a})
	tag := pgconn.NewCommandTag("UPDATE 1")
	if len(f.tags) > 0 {
		tag = f.tags[0]
		f.tags = f.tags[1:]
	}
	return tag, nil
}
func (f *groupFakeDB) Query(_ context.Context, q string, a ...any) (pgx.Rows, error) {
	f.calls = append(f.calls, groupCall{q, a})
	var rows [][]any
	if len(f.rowsQueue) > 0 {
		rows = f.rowsQueue[0]
		f.rowsQueue = f.rowsQueue[1:]
	}
	return &groupFakeRows{rows: rows}, nil
}
func (f *groupFakeDB) QueryRow(_ context.Context, q string, a ...any) pgx.Row {
	f.calls = append(f.calls, groupCall{q, a})
	var row []any
	if len(f.rowQueue) > 0 {
		row = f.rowQueue[0]
		f.rowQueue = f.rowQueue[1:]
	}
	return groupFakeRow{row}
}

type groupFakeRow struct{ vals []any }

func (r groupFakeRow) Scan(d ...any) error {
	if r.vals == nil {
		return pgx.ErrNoRows
	}
	return groupAssign(d, r.vals)
}

type groupFakeRows struct {
	rows [][]any
	i    int
}

func (r *groupFakeRows) Close()                                       {}
func (r *groupFakeRows) Err() error                                   { return nil }
func (r *groupFakeRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *groupFakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *groupFakeRows) Next() bool {
	if r.i >= len(r.rows) {
		return false
	}
	r.i++
	return true
}
func (r *groupFakeRows) Scan(d ...any) error    { return groupAssign(d, r.rows[r.i-1]) }
func (r *groupFakeRows) Values() ([]any, error) { return r.rows[r.i-1], nil }
func (r *groupFakeRows) RawValues() [][]byte    { return nil }
func (r *groupFakeRows) Conn() *pgx.Conn        { return nil }
func groupAssign(dst, src []any) error {
	for i := range dst {
		switch p := dst[i].(type) {
		case *int:
			*p = src[i].(int)
		case *int64:
			*p = src[i].(int64)
		case *string:
			*p = src[i].(string)
		case *time.Time:
			*p = src[i].(time.Time)
		case **time.Time:
			*p = src[i].(*time.Time)
		case *bool:
			*p = src[i].(bool)
		default:
			return errors.New("unsupported scan")
		}
	}
	return nil
}

type groupFakeTx struct {
	row       []any
	calls     []groupCall
	committed bool
}

func (t *groupFakeTx) Begin(context.Context) (pgx.Tx, error) { return nil, errors.New("unused") }
func (t *groupFakeTx) Commit(context.Context) error          { t.committed = true; return nil }
func (t *groupFakeTx) Rollback(context.Context) error        { return nil }
func (t *groupFakeTx) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errors.New("unused")
}
func (t *groupFakeTx) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults { return nil }
func (t *groupFakeTx) LargeObjects() pgx.LargeObjects                         { return pgx.LargeObjects{} }
func (t *groupFakeTx) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errors.New("unused")
}
func (t *groupFakeTx) Exec(_ context.Context, q string, a ...any) (pgconn.CommandTag, error) {
	t.calls = append(t.calls, groupCall{q, a})
	return pgconn.NewCommandTag("INSERT 1"), nil
}
func (t *groupFakeTx) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unused")
}
func (t *groupFakeTx) QueryRow(_ context.Context, q string, a ...any) pgx.Row {
	t.calls = append(t.calls, groupCall{q, a})
	return groupFakeRow{t.row}
}
func (t *groupFakeTx) Conn() *pgx.Conn { return nil }
func groupRequest(method, path, body string, uin int64) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req = req.WithContext(middleware.WithUIN(req.Context(), uin))
	rc := chi.NewRouteContext()
	rc.URLParams.Add("group_id", behaviorGroupID)
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) > 4 {
		rc.URLParams.Add("uin", parts[4])
	}
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rc))
}

type historyFakeStore struct {
	rows  []store.GroupMessageRow
	calls []store.GroupHistoryRequest
}

func (s *historyFakeStore) GetHistory(context.Context, store.HistoryRequest) ([]store.MessageRow, bool, error) {
	return nil, false, nil
}
func (s *historyFakeStore) GetGroupHistory(_ context.Context, r store.GroupHistoryRequest) ([]store.GroupMessageRow, bool, error) {
	s.calls = append(s.calls, r)
	return s.rows, false, nil
}

func TestGroupListIsScopedToAuthenticatedMember(t *testing.T) {
	now := time.Now()
	db := &groupFakeDB{rowsQueue: [][][]any{{{behaviorGroupID, "team", int64(100), now, 2, int64(1)}}}}
	rr := httptest.NewRecorder()
	NewListGroupsHandler(GroupsDeps{PG: db})(rr, groupRequest(http.MethodGet, "/api/groups/", "", 200))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), behaviorGroupID) {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if db.calls[0].args[0] != int64(200) {
		t.Fatalf("args=%v", db.calls[0].args)
	}
}

func TestGroupCreateUsesAuthenticatedActorAsOwnerAndAdmin(t *testing.T) {
	now := time.Now()
	tx := &groupFakeTx{row: []any{behaviorGroupID, "team", int64(100), now}}
	db := &groupFakeDB{tx: tx}
	rr := httptest.NewRecorder()
	NewCreateGroupHandler(GroupsDeps{PG: db})(rr, groupRequest(http.MethodPost, "/api/groups/", `{"name":"team"}`, 100))
	if rr.Code != http.StatusCreated || !tx.committed {
		t.Fatalf("status=%d committed=%v body=%s", rr.Code, tx.committed, rr.Body.String())
	}
	if tx.calls[0].args[1] != int64(100) || tx.calls[1].args[1] != int64(100) {
		t.Fatalf("calls=%v", tx.calls)
	}
	bad := httptest.NewRecorder()
	NewCreateGroupHandler(GroupsDeps{PG: db})(bad, groupRequest(http.MethodPost, "/api/groups/", `{"name":"team","owner_uin":999}`, 100))
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("client actor field status=%d body=%s", bad.Code, bad.Body.String())
	}
}
func TestGroupMembersRequireMembershipAndUseUniformForbiddenShape(t *testing.T) {
	var bodies []string
	for _, actor := range []int64{200, 300} {
		db := &groupFakeDB{rowQueue: [][]any{nil}}
		rr := httptest.NewRecorder()
		NewListGroupMembersHandler(GroupsDeps{PG: db})(rr, groupRequest(http.MethodGet, "/api/groups/"+behaviorGroupID+"/members", "", actor))
		if rr.Code != 403 {
			t.Fatalf("actor=%d status=%d body=%s", actor, rr.Code, rr.Body.String())
		}
		bodies = append(bodies, rr.Body.String())
		if db.calls[0].args[1] != actor {
			t.Fatalf("actor predicate args=%v", db.calls[0].args)
		}
	}
	if bodies[0] != bodies[1] {
		t.Fatalf("different forbidden shapes: %q vs %q", bodies[0], bodies[1])
	}
}
func TestGroupMemberListSucceedsForMember(t *testing.T) {
	db := &groupFakeDB{rowQueue: [][]any{{"member"}, {int64(1)}}, rowsQueue: [][][]any{{{int64(100), "alice", "", "admin"}, {int64(200), "bob", "", "member"}}}}
	rr := httptest.NewRecorder()
	NewListGroupMembersHandler(GroupsDeps{PG: db})(rr, groupRequest(http.MethodGet, "/api/groups/"+behaviorGroupID+"/members", "", 200))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"uin":100`) {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
func TestOnlyAdminCanAddGroupMember(t *testing.T) {
	for _, tc := range []struct {
		authorized bool
		status     int
	}{{false, 403}, {true, 201}} {
		db := &groupFakeDB{rowQueue: [][]any{{tc.authorized, tc.authorized}, {"team"}}}
		rr := httptest.NewRecorder()
		NewAddGroupMemberHandler(GroupsDeps{PG: db})(rr, groupRequest(http.MethodPost, "/api/groups/"+behaviorGroupID+"/members", `{"uin":300}`, 200))
		if rr.Code != tc.status {
			t.Fatalf("authorized=%v status=%d body=%s", tc.authorized, rr.Code, rr.Body.String())
		}
		if db.calls[0].args[1] != int64(200) {
			t.Fatalf("actor predicate args=%v", db.calls[0].args)
		}
		q := strings.ToUpper(db.calls[0].sql)
		if !strings.Contains(q, "FOR UPDATE") || !strings.Contains(q, "ROLE='ADMIN'") || !strings.Contains(q, "INSERT INTO GROUP_MEMBERS") {
			t.Fatalf("authorization and mutation are not atomic: %s", q)
		}
		if !tc.authorized && len(db.calls) != 1 {
			t.Fatalf("unauthorized add performed follow-up work: %#v", db.calls)
		}
	}
}

func TestAddMemberFailsClosedWhenAtomicMutationReturnsNoResult(t *testing.T) {
	db := &groupFakeDB{rowQueue: [][]any{nil}}
	rr := httptest.NewRecorder()
	NewAddGroupMemberHandler(GroupsDeps{PG: db})(rr, groupRequest(http.MethodPost, "/api/groups/"+behaviorGroupID+"/members", `{"uin":300}`, 200))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(db.calls) != 1 {
		t.Fatalf("partial add-member flow executed: %#v", db.calls)
	}
}
func TestOnlyAdminCanRemoveAnotherGroupMember(t *testing.T) {
	for _, tc := range []struct {
		role   string
		status int
	}{{"member", 403}, {"admin", 204}} {
		rows := [][]any{{tc.role}}
		if tc.role == "admin" {
			rows = append(rows, []any{true, int64(2)})
		}
		db := &groupFakeDB{rowQueue: rows}
		rr := httptest.NewRecorder()
		NewRemoveGroupMemberHandler(GroupsDeps{PG: db})(rr, groupRequest(http.MethodDelete, "/api/groups/"+behaviorGroupID+"/members/300", "", 200))
		if rr.Code != tc.status {
			t.Fatalf("role=%s status=%d body=%s", tc.role, rr.Code, rr.Body.String())
		}
	}
}
func TestAtomicOwnerLeaveFailureCannotCommitPartialMembershipMutation(t *testing.T) {
	db := &groupFakeDB{rowQueue: [][]any{{"admin"}, nil}}
	rr := httptest.NewRecorder()
	NewRemoveGroupMemberHandler(GroupsDeps{PG: db})(rr, groupRequest(http.MethodDelete, "/api/groups/"+behaviorGroupID+"/members/200", "", 200))
	if rr.Code != 500 {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(db.calls) != 2 || !strings.Contains(strings.ToUpper(db.calls[1].sql), "FOR UPDATE") {
		t.Fatalf("removal was not isolated to one atomic statement: %#v", db.calls)
	}
}
func TestGroupDeleteUsesOwnerPredicateAndUniformNotFoundShape(t *testing.T) {
	var bodies []string
	for _, actor := range []int64{200, 300} {
		db := &groupFakeDB{tags: []pgconn.CommandTag{pgconn.NewCommandTag("DELETE 0")}}
		rr := httptest.NewRecorder()
		NewDeleteGroupHandler(GroupsDeps{PG: db})(rr, groupRequest(http.MethodDelete, "/api/groups/"+behaviorGroupID, "", actor))
		if rr.Code != 404 {
			t.Fatalf("actor=%d status=%d", actor, rr.Code)
		}
		if db.calls[0].args[1] != actor {
			t.Fatalf("owner predicate args=%v", db.calls[0].args)
		}
		bodies = append(bodies, rr.Body.String())
	}
	if bodies[0] != bodies[1] {
		t.Fatalf("different not-found shapes: %q vs %q", bodies[0], bodies[1])
	}
	db := &groupFakeDB{tags: []pgconn.CommandTag{pgconn.NewCommandTag("DELETE 1")}}
	rr := httptest.NewRecorder()
	NewDeleteGroupHandler(GroupsDeps{PG: db})(rr, groupRequest(http.MethodDelete, "/api/groups/"+behaviorGroupID, "", 100))
	if rr.Code != 204 {
		t.Fatalf("owner status=%d body=%s", rr.Code, rr.Body.String())
	}
}
func TestGroupHistoryChecksActorMembershipBeforeReading(t *testing.T) {
	gid, _ := gocql.ParseUUID(behaviorGroupID)
	hs := &historyFakeStore{rows: []store.GroupMessageRow{{GroupID: gid, ID: gocql.TimeUUID(), SenderUIN: 100, Ciphertext: []byte("x"), CreatedAt: time.Now()}}}
	db := &groupFakeDB{rowQueue: [][]any{{1}}}
	rr := httptest.NewRecorder()
	NewGetGroupHistoryHandler(HistoryDeps{PG: db, Store: hs})(rr, groupRequest(http.MethodGet, "/api/messages/group-history?group_id="+behaviorGroupID, "", 200))
	if rr.Code != 200 || len(hs.calls) != 1 {
		t.Fatalf("status=%d calls=%d body=%s", rr.Code, len(hs.calls), rr.Body.String())
	}
	if db.calls[0].args[1] != int64(200) {
		t.Fatalf("membership args=%v", db.calls[0].args)
	}
	db = &groupFakeDB{rowQueue: [][]any{nil}}
	hs = &historyFakeStore{}
	rr = httptest.NewRecorder()
	NewGetGroupHistoryHandler(HistoryDeps{PG: db, Store: hs})(rr, groupRequest(http.MethodGet, "/api/messages/group-history?group_id="+behaviorGroupID, "", 300))
	if rr.Code != 403 || len(hs.calls) != 0 {
		t.Fatalf("status=%d store calls=%d body=%s", rr.Code, len(hs.calls), rr.Body.String())
	}
}
