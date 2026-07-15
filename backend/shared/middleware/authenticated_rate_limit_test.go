package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

type stubRateLimitRedis struct {
	count int64
	err   error
	key   string
	args  []any
}

func (s *stubRateLimitRedis) Eval(_ context.Context, _ string, keys []string, args ...any) *redis.Cmd {
	s.key = keys[0]
	s.args = args
	cmd := redis.NewCmd(context.Background())
	if s.err != nil {
		cmd.SetErr(s.err)
	} else {
		cmd.SetVal(s.count)
	}
	return cmd
}

func TestAuthenticatedRateLimiterUsesVerifiedUINActionAndBudget(t *testing.T) {
	store := &stubRateLimitRedis{count: 1}
	limiter := NewAuthenticatedRateLimiter(AuthenticatedRateLimitConfig{
		Redis: store, Action: "files:download", Limit: 20, Window: time.Minute,
	})

	allowed, err := limiter.Allow(context.Background(), 123456)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("first request was denied")
	}
	if store.key != "ratelimit:auth:123456:files:download" {
		t.Fatalf("key = %q", store.key)
	}
	if len(store.args) != 1 || store.args[0] != int64(60) {
		t.Fatalf("script args = %#v", store.args)
	}
}

func TestAuthenticatedRateLimiterDeniesOverBudget(t *testing.T) {
	store := &stubRateLimitRedis{count: 6}
	limiter := NewAuthenticatedRateLimiter(AuthenticatedRateLimitConfig{
		Redis: store, Action: "auth:settings:write", Limit: 5, Window: time.Minute,
	})
	allowed, err := limiter.Allow(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("over-budget request was allowed")
	}
}

func TestAuthenticatedRateLimitMiddlewareFailsClosedWhenRedisUnavailable(t *testing.T) {
	store := &stubRateLimitRedis{err: errors.New("redis unavailable")}
	mw := NewAuthenticatedRateLimit(AuthenticatedRateLimitConfig{
		Redis: store, Action: "keys:upload", Limit: 10, Window: time.Minute,
	})
	nextCalled := false
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalled = true }))
	req := httptest.NewRequest(http.MethodPost, "/api/keys/bundle", nil)
	req = req.WithContext(WithUIN(req.Context(), 77))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
	if nextCalled {
		t.Fatal("handler ran while the limiter was unavailable")
	}
}

func TestAuthenticatedRateLimitMiddlewareReturns429AndRetryAfter(t *testing.T) {
	store := &stubRateLimitRedis{count: 11}
	mw := NewAuthenticatedRateLimit(AuthenticatedRateLimitConfig{
		Redis: store, Action: "messages:history", Limit: 10, Window: 90 * time.Second,
	})
	nextCalled := false
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalled = true }))
	req := httptest.NewRequest(http.MethodGet, "/api/messages/history", nil)
	req = req.WithContext(WithUIN(req.Context(), 88))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rr.Code)
	}
	if rr.Header().Get("Retry-After") != "90" {
		t.Fatalf("Retry-After = %q", rr.Header().Get("Retry-After"))
	}
	if nextCalled {
		t.Fatal("handler ran over budget")
	}
}

func TestAuthenticatedRateLimitMiddlewareRejectsMissingVerifiedUIN(t *testing.T) {
	store := &stubRateLimitRedis{count: 1}
	mw := NewAuthenticatedRateLimit(AuthenticatedRateLimitConfig{
		Redis: store, Action: "files:upload", Limit: 10, Window: time.Minute,
	})
	rr := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler ran without verified UIN")
	})).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/files/upload-url", nil))

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}
