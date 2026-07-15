package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/iceq/iceq/presence-service/store"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/jackc/pgx/v5"
)

type fakePresenceReader struct {
	states map[int64]*store.PresenceState
	reads  []int64
}

func (f *fakePresenceReader) GetPresence(_ context.Context, uin int64) (*store.PresenceState, error) {
	f.reads = append(f.reads, uin)
	if s, ok := f.states[uin]; ok {
		return s, nil
	}
	return &store.PresenceState{Status: "offline"}, nil
}
func (f *fakePresenceReader) GetBulkPresence(_ context.Context, uins []int64) (map[int64]*store.PresenceState, error) {
	out := map[int64]*store.PresenceState{}
	for _, uin := range uins {
		f.reads = append(f.reads, uin)
		if s, ok := f.states[uin]; ok {
			out[uin] = s
		} else {
			out[uin] = &store.PresenceState{Status: "offline"}
		}
	}
	return out, nil
}

type fakeContactRow struct {
	accepted bool
	err      error
}

func (r fakeContactRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*(dest[0].(*bool)) = r.accepted
	return nil
}

type fakeContactChecker struct{ accepted map[[2]int64]bool }

func (f fakeContactChecker) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	return fakeContactRow{accepted: f.accepted[[2]int64{args[0].(int64), args[1].(int64)}]}
}

type contactCheckerFunc func(context.Context, string, ...any) pgx.Row

func (f contactCheckerFunc) QueryRow(ctx context.Context, q string, args ...any) pgx.Row {
	return f(ctx, q, args...)
}

func authenticatedRequest(method, target, body string, uin int64) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	return req.WithContext(middleware.WithUIN(req.Context(), uin))
}
func presenceRouter(get, bulk http.HandlerFunc) http.Handler {
	r := chi.NewRouter()
	r.Get("/api/presence/{uin}", get)
	r.Post("/api/presence/bulk", bulk)
	return r
}

func TestGetPresenceRejectsUnrelatedAndNonexistentUniformly(t *testing.T) {
	reader := &fakePresenceReader{states: map[int64]*store.PresenceState{200: {Status: "online"}}}
	checker := fakeContactChecker{accepted: map[[2]int64]bool{}}
	r := presenceRouter(newGetPresenceHandler(reader, checker), newGetBulkPresenceHandler(reader, checker))
	var bodies []string
	for _, target := range []string{"200", "999999"} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, authenticatedRequest(http.MethodGet, "/api/presence/"+target, "", 100))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("target %s: status=%d want 404", target, rec.Code)
		}
		bodies = append(bodies, rec.Body.String())
	}
	if bodies[0] != bodies[1] {
		t.Fatalf("responses differ: %q vs %q", bodies[0], bodies[1])
	}
	if len(reader.reads) != 0 {
		t.Fatalf("unauthorized targets reached store: %v", reader.reads)
	}
}

func TestGetPresenceAllowsSelfAndAcceptedContact(t *testing.T) {
	reader := &fakePresenceReader{states: map[int64]*store.PresenceState{100: {Status: "online"}, 200: {Status: "away"}}}
	checker := fakeContactChecker{accepted: map[[2]int64]bool{{100, 200}: true}}
	r := presenceRouter(newGetPresenceHandler(reader, checker), newGetBulkPresenceHandler(reader, checker))
	for _, target := range []string{"100", "200"} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, authenticatedRequest(http.MethodGet, "/api/presence/"+target, "", 100))
		if rec.Code != http.StatusOK {
			t.Fatalf("target %s: status=%d want 200", target, rec.Code)
		}
	}
}

func TestBulkPresenceOmitsUnrelatedAndNonexistentTargets(t *testing.T) {
	reader := &fakePresenceReader{states: map[int64]*store.PresenceState{100: {Status: "online"}, 200: {Status: "away"}, 300: {Status: "online"}}}
	checker := fakeContactChecker{accepted: map[[2]int64]bool{{100, 200}: true}}
	r := presenceRouter(newGetPresenceHandler(reader, checker), newGetBulkPresenceHandler(reader, checker))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, authenticatedRequest(http.MethodPost, "/api/presence/bulk", `{"uins":[100,200,300,999999]}`, 100))
	if rec.Code != 200 {
		t.Fatalf("status=%d: %s", rec.Code, rec.Body.String())
	}
	var got map[string]*store.PresenceState
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, visible := range []string{"100", "200"} {
		if _, ok := got[visible]; !ok {
			t.Errorf("visible %s missing", visible)
		}
	}
	for _, hidden := range []string{"300", "999999"} {
		if _, ok := got[hidden]; ok {
			t.Errorf("hidden %s leaked", hidden)
		}
	}
	if len(reader.reads) != 2 {
		t.Fatalf("store reads=%v", reader.reads)
	}
}

func TestPresenceHandlersRequireAuthenticatedContext(t *testing.T) {
	reader := &fakePresenceReader{states: map[int64]*store.PresenceState{}}
	checker := fakeContactChecker{accepted: map[[2]int64]bool{}}
	r := presenceRouter(newGetPresenceHandler(reader, checker), newGetBulkPresenceHandler(reader, checker))
	for _, tc := range []struct{ method, path, body string }{{http.MethodGet, "/api/presence/100", ""}, {http.MethodPost, "/api/presence/bulk", `{"uins":[100]}`}} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
		if rec.Code != 401 {
			t.Fatalf("%s %s status=%d want 401", tc.method, tc.path, rec.Code)
		}
	}
}

func TestContactAuthorizationDatabaseErrorFailsClosed(t *testing.T) {
	reader := &fakePresenceReader{states: map[int64]*store.PresenceState{}}
	checker := contactCheckerFunc(func(context.Context, string, ...any) pgx.Row { return fakeContactRow{err: errors.New("db down")} })
	r := presenceRouter(newGetPresenceHandler(reader, checker), newGetBulkPresenceHandler(reader, checker))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, authenticatedRequest(http.MethodGet, "/api/presence/200", "", 100))
	if rec.Code != 500 {
		t.Fatalf("status=%d want 500", rec.Code)
	}
}
