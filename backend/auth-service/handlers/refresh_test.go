package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	sharedjwt "github.com/iceq/iceq/shared/jwt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type refreshManagerStub struct {
	claims *sharedjwt.Claims
	err    error
}

func (m refreshManagerStub) Verify(context.Context, string, string) (*sharedjwt.Claims, error) {
	return m.claims, m.err
}

func (refreshManagerStub) Sign(int64, string) (sharedjwt.SignResult, error) {
	return sharedjwt.SignResult{}, nil
}
func (refreshManagerStub) BumpSessionEpoch(context.Context, int64) error { return nil }

type refreshLimiterStub struct {
	called bool
	uin    int64
	action string
	allow  bool
	err    error
}

func (l *refreshLimiterStub) Allow(_ context.Context, uin int64, action string) (bool, error) {
	l.called, l.uin, l.action = true, uin, action
	return l.allow, l.err
}

func refreshRequest(token string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: refreshCookieName, Value: token})
	return req
}

func TestRefreshInvalidTokenDoesNotConsumeRateLimitBucket(t *testing.T) {
	limiter := &refreshLimiterStub{allow: true}
	h := NewRefreshHandler(RefreshDeps{
		Manager: refreshManagerStub{err: sharedjwt.ErrTokenInvalid},
		Limiter: limiter,
	})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, refreshRequest("invalid"))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	if limiter.called {
		t.Fatal("rate limiter called for an invalid refresh token")
	}
}

func TestRefreshRateLimitUsesVerifiedUINAndReturns429(t *testing.T) {
	limiter := &refreshLimiterStub{allow: false}
	h := NewRefreshHandler(RefreshDeps{
		Manager: refreshManagerStub{claims: &sharedjwt.Claims{UIN: 4242}},
		Limiter: limiter,
	})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, refreshRequest("valid"))
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rr.Code)
	}
	if !limiter.called || limiter.uin != 4242 || limiter.action != "auth:refresh" {
		t.Fatalf("limiter call = (%v, %d, %q), want (true, 4242, auth:refresh)", limiter.called, limiter.uin, limiter.action)
	}
}

func TestRefreshRateLimiterFailureReturns503(t *testing.T) {
	limiter := &refreshLimiterStub{allow: true, err: errors.New("redis unavailable")}
	h := NewRefreshHandler(RefreshDeps{
		Manager: refreshManagerStub{claims: &sharedjwt.Claims{UIN: 4242}},
		Limiter: limiter,
	})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, refreshRequest("valid"))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

type atomicRefreshManager struct {
	mu       sync.Mutex
	signings int
	bumps    int
}

func (m *atomicRefreshManager) Verify(context.Context, string, string) (*sharedjwt.Claims, error) {
	return &sharedjwt.Claims{UIN: 4242}, nil
}
func (m *atomicRefreshManager) Sign(_ int64, tokenType string) (sharedjwt.SignResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.signings++
	return sharedjwt.SignResult{Token: tokenType + "-new"}, nil
}
func (m *atomicRefreshManager) BumpSessionEpoch(context.Context, int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bumps++
	return nil
}

type atomicRefreshDB struct {
	mu      sync.Mutex
	present bool
}

func (d *atomicRefreshDB) Begin(context.Context) (pgx.Tx, error) {
	return &atomicRefreshTx{db: d}, nil
}
func (d *atomicRefreshDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag("DELETE 1"), nil
}

type atomicRefreshTx struct{ db *atomicRefreshDB }

func (t *atomicRefreshTx) Begin(context.Context) (pgx.Tx, error) { return nil, errors.New("unused") }
func (t *atomicRefreshTx) Commit(context.Context) error          { return nil }
func (t *atomicRefreshTx) Rollback(context.Context) error        { return nil }
func (t *atomicRefreshTx) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errors.New("unused")
}
func (t *atomicRefreshTx) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults { return nil }
func (t *atomicRefreshTx) LargeObjects() pgx.LargeObjects                         { return pgx.LargeObjects{} }
func (t *atomicRefreshTx) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errors.New("unused")
}
func (t *atomicRefreshTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag("INSERT 1"), nil
}
func (t *atomicRefreshTx) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unused")
}
func (t *atomicRefreshTx) QueryRow(context.Context, string, ...any) pgx.Row {
	t.db.mu.Lock()
	defer t.db.mu.Unlock()
	if !t.db.present {
		return atomicRefreshRow{err: pgx.ErrNoRows}
	}
	t.db.present = false
	return atomicRefreshRow{uin: 4242, expires: time.Now().Add(time.Hour)}
}
func (t *atomicRefreshTx) Conn() *pgx.Conn { return nil }

type atomicRefreshRow struct {
	uin     int64
	expires time.Time
	err     error
}

func (r atomicRefreshRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*(dest[0].(*int64)) = r.uin
	*(dest[1].(*time.Time)) = r.expires
	return nil
}

func TestRefreshConcurrentUseAtomicallyMintsExactlyOnePair(t *testing.T) {
	db := &atomicRefreshDB{present: true}
	manager := &atomicRefreshManager{}
	h := NewRefreshHandler(RefreshDeps{
		Pool:    db,
		Manager: manager,
		Limiter: &refreshLimiterStub{allow: true},
	})

	statuses := make(chan int, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, refreshRequest("same-refresh-token"))
			statuses <- rr.Code
		}()
	}
	wg.Wait()
	close(statuses)
	got := make([]int, 0, 2)
	for status := range statuses {
		got = append(got, status)
	}
	sort.Ints(got)
	if got[0] != http.StatusOK || got[1] != http.StatusUnauthorized {
		t.Fatalf("statuses = %v, want [200 401]", got)
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.signings != 2 {
		t.Fatalf("Sign calls = %d, want 2 (one access and one refresh)", manager.signings)
	}
	if manager.bumps != 1 {
		t.Fatalf("epoch bumps = %d, want 1 for detected reuse", manager.bumps)
	}
}
