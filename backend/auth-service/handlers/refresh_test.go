package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	sharedjwt "github.com/iceq/iceq/shared/jwt"
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
