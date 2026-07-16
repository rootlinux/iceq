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
	"github.com/iceq/iceq/key-service/models"
)

type bundleRateLimitStore struct{ getCalls int }

func (s *bundleRateLimitStore) GetBundle(context.Context, int64) (models.BundleResponse, error) {
	s.getCalls++
	return models.BundleResponse{}, errors.New("must not consume an OPK")
}
func (*bundleRateLimitStore) UpsertBundle(context.Context, int64, string, models.SignedPrekey, int) error {
	return nil
}
func (*bundleRateLimitStore) AddOneTimePrekeys(context.Context, int64, []models.OneTimePrekey) error {
	return nil
}
func (*bundleRateLimitStore) CountUnusedPrekeys(context.Context, int64) (int, error) { return 0, nil }

func bundleRequest(t *testing.T, deps BundleDeps) *httptest.ResponseRecorder {
	t.Helper()
	r := chi.NewRouter()
	r.Get("/api/keys/bundle/{uin}", NewGetBundleHandler(deps))
	req := httptest.NewRequest(http.MethodGet, "/api/keys/bundle/42", nil)
	req.Header.Set("X-IceQ-RateLimit-Identity", "v1.0123456789ab.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	req.Header.Set("User-Agent", "private-browser-fingerprint")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	return rr
}

func TestGetBundleFailsClosedBeforeOPKConsumptionWhenLimiterUnavailable(t *testing.T) {
	store := &bundleRateLimitStore{}
	rr := bundleRequest(t, BundleDeps{
		Keystore:        store,
		RateLimitSecret: []byte(strings.Repeat("s", 32)),
		CheckRateLimit: func(context.Context, string, time.Duration) (int64, error) {
			return 0, errors.New("redis unavailable")
		},
	})

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"code":"RATE_LIMITER_UNAVAILABLE"`) {
		t.Fatalf("body = %s, want limiter unavailable code", rr.Body.String())
	}
	if store.getCalls != 0 {
		t.Fatalf("GetBundle calls = %d, want 0 before OPK consumption", store.getCalls)
	}
}

func TestGetBundleReturns429BeforeOPKConsumptionAndPersistsOnlyHMACBucket(t *testing.T) {
	store := &bundleRateLimitStore{}
	var persistedKey string
	rr := bundleRequest(t, BundleDeps{
		Keystore:        store,
		RateLimitSecret: []byte(strings.Repeat("s", 32)),
		CheckRateLimit: func(_ context.Context, key string, window time.Duration) (int64, error) {
			persistedKey = key
			if window != time.Minute {
				t.Fatalf("window = %s, want 1m", window)
			}
			return bundleFetchRateLimit + 1, nil
		},
	})

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"code":"RATE_LIMITED"`) {
		t.Fatalf("body = %s, want rate limited code", rr.Body.String())
	}
	if store.getCalls != 0 {
		t.Fatalf("GetBundle calls = %d, want 0 before OPK consumption", store.getCalls)
	}
	for _, raw := range []string{"203.0.113.9", "private-browser-fingerprint"} {
		if strings.Contains(persistedKey, raw) {
			t.Fatalf("rate-limit key %q contains raw request identity %q", persistedKey, raw)
		}
	}
	if !strings.HasPrefix(persistedKey, "ratelimit:key-bundle:anon:key-bundle:") {
		t.Fatalf("rate-limit key = %q, want scoped rotating HMAC bucket", persistedKey)
	}
}

func TestGetBundleFailsClosedWhenEdgeIdentityMissing(t *testing.T) {
	store := &bundleRateLimitStore{}
	called := false
	r := chi.NewRouter()
	r.Get("/api/keys/bundle/{uin}", NewGetBundleHandler(BundleDeps{
		Keystore:        store,
		RateLimitSecret: []byte(strings.Repeat("s", 32)),
		CheckRateLimit: func(context.Context, string, time.Duration) (int64, error) {
			called = true
			return 1, nil
		},
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/keys/bundle/42", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
	if called || store.getCalls != 0 {
		t.Fatalf("limiter called=%v, GetBundle calls=%d; want neither", called, store.getCalls)
	}
}
