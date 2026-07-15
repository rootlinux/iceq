package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type contactCall struct {
	sql  string
	args []any
}
type contactFakeDB struct {
	rows     [][]any
	row      []any
	tx       *contactFakeTx
	execTags []pgconn.CommandTag
	calls    []contactCall
}

func (f *contactFakeDB) Begin(context.Context) (pgx.Tx, error) {
	f.calls = append(f.calls, contactCall{"BEGIN", nil})
	return f.tx, nil
}
func (f *contactFakeDB) Exec(_ context.Context, q string, a ...any) (pgconn.CommandTag, error) {
	f.calls = append(f.calls, contactCall{q, a})
	if len(f.execTags) == 0 {
		return pgconn.NewCommandTag("UPDATE 1"), nil
	}
	x := f.execTags[0]
	f.execTags = f.execTags[1:]
	return x, nil
}
func (f *contactFakeDB) Query(_ context.Context, q string, a ...any) (pgx.Rows, error) {
	f.calls = append(f.calls, contactCall{q, a})
	return &contactFakeRows{rows: f.rows}, nil
}
func (f *contactFakeDB) QueryRow(_ context.Context, q string, a ...any) pgx.Row {
	f.calls = append(f.calls, contactCall{q, a})
	return contactFakeRow{f.row}
}

type contactFakeRow struct{ vals []any }

func (r contactFakeRow) Scan(d ...any) error {
	if r.vals == nil {
		return pgx.ErrNoRows
	}
	return contactAssign(d, r.vals)
}

type contactFakeRows struct {
	rows [][]any
	i    int
}

func (r *contactFakeRows) Close()                                       {}
func (r *contactFakeRows) Err() error                                   { return nil }
func (r *contactFakeRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *contactFakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *contactFakeRows) Next() bool {
	if r.i >= len(r.rows) {
		return false
	}
	r.i++
	return true
}
func (r *contactFakeRows) Scan(d ...any) error    { return contactAssign(d, r.rows[r.i-1]) }
func (r *contactFakeRows) Values() ([]any, error) { return r.rows[r.i-1], nil }
func (r *contactFakeRows) RawValues() [][]byte    { return nil }
func (r *contactFakeRows) Conn() *pgx.Conn        { return nil }

type contactFakeTx struct {
	tags      []pgconn.CommandTag
	calls     []contactCall
	committed bool
}

func (t *contactFakeTx) Begin(context.Context) (pgx.Tx, error) { return nil, errors.New("unused") }
func (t *contactFakeTx) Commit(context.Context) error          { t.committed = true; return nil }
func (t *contactFakeTx) Rollback(context.Context) error        { return nil }
func (t *contactFakeTx) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errors.New("unused")
}
func (t *contactFakeTx) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults { return nil }
func (t *contactFakeTx) LargeObjects() pgx.LargeObjects                         { return pgx.LargeObjects{} }
func (t *contactFakeTx) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errors.New("unused")
}
func (t *contactFakeTx) Exec(_ context.Context, q string, a ...any) (pgconn.CommandTag, error) {
	t.calls = append(t.calls, contactCall{q, a})
	x := pgconn.NewCommandTag("UPDATE 1")
	if len(t.tags) > 0 {
		x = t.tags[0]
		t.tags = t.tags[1:]
	}
	return x, nil
}
func (t *contactFakeTx) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unused")
}
func (t *contactFakeTx) QueryRow(context.Context, string, ...any) pgx.Row { return contactFakeRow{nil} }
func (t *contactFakeTx) Conn() *pgx.Conn                                  { return nil }
func contactAssign(dst, src []any) error {
	for i := range dst {
		switch p := dst[i].(type) {
		case *int:
			*p = src[i].(int)
		case *int64:
			*p = src[i].(int64)
		case *string:
			*p = src[i].(string)
		default:
			return errors.New("unsupported scan")
		}
	}
	return nil
}
func contactRequest(method, path, body string, uin int64) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req = req.WithContext(middleware.WithUIN(req.Context(), uin))
	rc := chi.NewRouteContext()
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) > 2 {
		rc.URLParams.Add("target_uin", parts[2])
	}
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rc))
}

func TestContactListIsScopedToAuthenticatedOwner(t *testing.T) {
	db := &contactFakeDB{rows: [][]any{{int64(200), "bob", "", "accepted", "incoming"}}}
	rr := httptest.NewRecorder()
	NewListContactsHandler(ContactsDeps{Pool: db})(rr, contactRequest(http.MethodGet, "/api/contacts/", "", 100))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"uin":200`) {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := db.calls[0].args[0]; got != int64(100) {
		t.Fatalf("owner arg=%v", got)
	}
}
func TestContactAddUsesActorForBothDirectedRows(t *testing.T) {
	tx := &contactFakeTx{}
	db := &contactFakeDB{row: []any{1}, tx: tx}
	rr := httptest.NewRecorder()
	NewAddContactHandler(ContactsDeps{Pool: db})(rr, contactRequest(http.MethodPost, "/api/contacts/", `{"target_uin":200}`, 100))
	if rr.Code != 201 || !tx.committed {
		t.Fatalf("status=%d committed=%v body=%s", rr.Code, tx.committed, rr.Body.String())
	}
	want := [][]any{{int64(100), int64(200), int64(100)}, {int64(200), int64(100), int64(100)}}
	for i := range want {
		for j := range want[i] {
			if tx.calls[i].args[j] != want[i][j] {
				t.Fatalf("call %d args=%v", i, tx.calls[i].args)
			}
		}
	}
}
func TestContactAcceptCannotAcceptAnotherUsersRequest(t *testing.T) {
	tx := &contactFakeTx{tags: []pgconn.CommandTag{pgconn.NewCommandTag("UPDATE 0")}}
	db := &contactFakeDB{tx: tx}
	rr := httptest.NewRecorder()
	NewAcceptContactHandler(ContactsDeps{Pool: db})(rr, contactRequest(http.MethodPut, "/api/contacts/200/accept", "", 300))
	if rr.Code != 404 || !strings.Contains(rr.Body.String(), `"code":"REQUEST_NOT_FOUND"`) {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if tx.calls[0].args[0] != int64(300) || tx.calls[0].args[1] != int64(200) {
		t.Fatalf("args=%v", tx.calls[0].args)
	}
}
func TestContactAcceptSucceedsOnlyForAuthenticatedRecipient(t *testing.T) {
	tx := &contactFakeTx{}
	db := &contactFakeDB{tx: tx}
	rr := httptest.NewRecorder()
	NewAcceptContactHandler(ContactsDeps{Pool: db})(rr, contactRequest(http.MethodPut, "/api/contacts/200/accept", "", 100))
	if rr.Code != 200 || !tx.committed {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
func TestContactDeleteOnlyDeletesAuthenticatedOwnersEdge(t *testing.T) {
	db := &contactFakeDB{}
	rr := httptest.NewRecorder()
	NewRemoveContactHandler(ContactsDeps{Pool: db})(rr, contactRequest(http.MethodDelete, "/api/contacts/200", "", 100))
	if rr.Code != 204 {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if db.calls[0].args[0] != int64(100) || db.calls[0].args[1] != int64(200) {
		t.Fatalf("args=%v", db.calls[0].args)
	}
}

func TestContactBlockOnlyMutatesAuthenticatedOwnersEdge(t *testing.T) {
	for _, actor := range []int64{100, 300} {
		db := &contactFakeDB{execTags: []pgconn.CommandTag{pgconn.NewCommandTag("UPDATE 1")}}
		rr := httptest.NewRecorder()
		NewBlockContactHandler(ContactsDeps{Pool: db})(rr, contactRequest(http.MethodPut, "/api/contacts/200/block", "", actor))
		if rr.Code != http.StatusOK {
			t.Fatalf("actor=%d status=%d body=%s", actor, rr.Code, rr.Body.String())
		}
		if db.calls[0].args[0] != actor || db.calls[0].args[1] != int64(200) {
			t.Fatalf("actor=%d args=%v", actor, db.calls[0].args)
		}
	}
}

func TestContactBlockCreatesOnlyActorsEdgeWhenMissing(t *testing.T) {
	db := &contactFakeDB{execTags: []pgconn.CommandTag{pgconn.NewCommandTag("UPDATE 0"), pgconn.NewCommandTag("INSERT 1")}}
	rr := httptest.NewRecorder()
	NewBlockContactHandler(ContactsDeps{Pool: db})(rr, contactRequest(http.MethodPut, "/api/contacts/200/block", "", 100))
	if rr.Code != http.StatusOK || len(db.calls) != 2 {
		t.Fatalf("status=%d calls=%d body=%s", rr.Code, len(db.calls), rr.Body.String())
	}
	if db.calls[1].args[0] != int64(100) || db.calls[1].args[1] != int64(200) {
		t.Fatalf("insert args=%v", db.calls[1].args)
	}
}
