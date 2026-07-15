// Package handlers contains the HTTP handlers that implement the
// key-service's REST surface. The package is split per endpoint
// family (bundle.go, prekeys.go) plus this file's sibling
// `common.go` for the shared JSON error writer.
package handlers

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/iceq/iceq/key-service/models"
	"github.com/iceq/iceq/key-service/store"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/redis/go-redis/v9"
)

// ----------------------------------------------------------------------------
// Bundle endpoints.
//
//   GET  /api/keys/bundle/{uin}  — no auth, public by design
//   POST /api/keys/bundle        — auth required (own bundle only)
// ----------------------------------------------------------------------------

// BundleDeps captures the dependencies both bundle handlers need.
type keyStore interface {
	GetBundle(context.Context, int64) (models.BundleResponse, error)
	UpsertBundle(context.Context, int64, string, models.SignedPrekey, int) error
	AddOneTimePrekeys(context.Context, int64, []models.OneTimePrekey) error
	CountUnusedPrekeys(context.Context, int64) (int, error)
}

type BundleDeps struct {
	Keystore        keyStore
	RateLimitSecret []byte
	CheckRateLimit  func(context.Context, string, time.Duration) (int64, error)
}

const (
	bundleFetchRateLimit     = int64(30)
	bundleRateLimitKeyPrefix = "ratelimit:key-bundle:"
)

const bundleRateLimitScript = `
local current = redis.call("INCR", KEYS[1])
if current == 1 then
    redis.call("EXPIRE", KEYS[1], ARGV[1])
end
return current
`

// NewRedisFixedWindowRateLimiter implements the same atomic INCR plus
// first-hit expiry semantics used by the auth-service anonymous limiters.
func NewRedisFixedWindowRateLimiter(rdb *redis.Client) func(context.Context, string, time.Duration) (int64, error) {
	script := redis.NewScript(bundleRateLimitScript)
	return func(ctx context.Context, key string, window time.Duration) (int64, error) {
		return script.Run(ctx, rdb, []string{key}, int(window.Seconds())).Int64()
	}
}

// NewGetBundleHandler returns the http.HandlerFunc mounted at
// GET /api/keys/bundle/{uin}.
//
// This endpoint is intentionally UNauthenticated. The whole
// point of the key-service is to let Alice fetch Bob's keys
// BEFORE a Signal session exists; if it required Bob to
// approve every read of his public bundle, the protocol would
// not be useful. The trust model is: identity_key, signed_prekey,
// and one_time_prekey are all PUBLIC by Signal's design —
// they're published so that anyone can derive a shared secret
// with the holder. Compromising them does not reveal plaintext
// to the server; it only enables an active MITM by the server,
// which is a separate threat.
func NewGetBundleHandler(deps BundleDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// chi URL params are populated by the router only
		// when this handler is mounted under a route
		// template that includes {uin}. Parsing failure
		// would be a 404 (router never matched), so a
		// strconv error here is genuinely unexpected.
		uinStr := chi.URLParam(r, "uin")
		uin, err := strconv.ParseInt(uinStr, 10, 64)
		if err != nil || uin <= 0 {
			writeError(w, http.StatusBadRequest, "INVALID_UIN", "uin must be a positive integer")
			return
		}

		// Enforce the anonymous caller budget before GetBundle can consume a
		// one-time prekey. The edge identity is transformed immediately into a
		// daily rotating HMAC bucket; raw IP and User-Agent values never enter
		// the persisted Redis key.
		bucket, err := middleware.AnonymousRateLimitBucket(
			deps.RateLimitSecret,
			r.Header.Get("X-IceQ-RateLimit-Identity"),
			"key-bundle",
			time.Now(),
		)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "RATE_LIMIT_IDENTITY_UNAVAILABLE", "service is temporarily unavailable")
			return
		}
		if deps.CheckRateLimit == nil {
			writeError(w, http.StatusServiceUnavailable, "RATE_LIMITER_UNAVAILABLE", "service is temporarily unavailable")
			return
		}
		count, err := deps.CheckRateLimit(r.Context(), bundleRateLimitKeyPrefix+bucket, time.Minute)
		if err != nil {
			log.Printf("[key-service] bundle rate limiter unavailable: %v", err)
			writeError(w, http.StatusServiceUnavailable, "RATE_LIMITER_UNAVAILABLE", "service is temporarily unavailable")
			return
		}
		if count > bundleFetchRateLimit {
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "too many bundle requests; try again later")
			return
		}

		// 5 s is comfortable for one SELECT + one UPDATE
		// round trip. The keystore.GetBundle does both in
		// sequence; if either stalls, the deadline surfaces
		// the failure as a 504 at the upstream proxy.
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		bundle, err := deps.Keystore.GetBundle(ctx, uin)
		if err != nil {
			if errors.Is(err, store.ErrBundleNotFound) {
				// The user exists in `users` (they
				// have a UIN) but hasn't uploaded a
				// prekey bundle yet. 404 is the
				// honest answer: "this resource is
				// not here".
				writeError(w, http.StatusNotFound, "BUNDLE_NOT_FOUND", "user has no prekey bundle")
				return
			}
			log.Printf("[key-service] get bundle: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not fetch bundle")
			return
		}

		log.Printf("[key-service] get bundle served opk=%v", bundle.OneTimePrekey != nil)
		writeJSON(w, http.StatusOK, bundle)
	}
}

// NewPostBundleHandler returns the http.HandlerFunc mounted at
// POST /api/keys/bundle. MUST be wrapped with BearerAuth — we
// don't enforce that here so the wiring stays explicit in
// main.go.
//
// The handler upserts the bundle for the AUTHENTICATED user;
// the request body's identity_key is verified to match the
// user's registered identity_key (a one-line consistency check
// that catches "I rotated my identity key but forgot to update
// the server" — a known footgun in real Signal deployments).
func NewPostBundleHandler(deps BundleDeps, fetchRegisteredIdentityKey func(ctx context.Context, uin int64) (string, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uin, ok := middleware.GetUIN(r.Context())
		if !ok {
			// Should be unreachable: the route is
			// mounted behind BearerAuth. Treat as 401
			// rather than panic.
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}

		// 16 KiB ceiling. The web client uploads the signed
		// prekey and initial one-time prekey pool together.
		var req models.UploadBundleRequest
		if !decodeJSON(w, r, &req, 16*1024) {
			return
		}
		if err := req.Validate(); err != nil {
			writeValidationError(w, err)
			return
		}

		// 5 s covers: SELECT users.identity_key + UPSERT.
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// Consistency check: the identity_key the client
		// is uploading must match the one on file at
		// registration. The Signal Protocol treats the
		// identity key as long-term-stable; rotating it
		// without server-side coordination would create
		// two "Johns" the server can't tell apart.
		//
		// This is a deliberate fail-loud: the client is
		// expected to manage its own identity-key
		// rotation, and a mismatch is almost always a
		// bug.
		registered, err := fetchRegisteredIdentityKey(ctx, uin)
		if err != nil {
			log.Printf("[key-service] fetch registered identity_key: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not verify identity key")
			return
		}
		if registered != "" && registered != req.IdentityKey {
			log.Printf("[key-service] identity_key mismatch")
			writeError(w, http.StatusConflict, "IDENTITY_KEY_MISMATCH", "identity_key does not match registered key")
			return
		}

		if err := deps.Keystore.UpsertBundle(ctx, uin, req.IdentityKey, req.SignedPrekey, req.RegistrationID); err != nil {
			log.Printf("[key-service] upsert bundle: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not store bundle")
			return
		}
		if err := deps.Keystore.AddOneTimePrekeys(ctx, uin, req.OneTimePrekeys); err != nil {
			log.Printf("[key-service] add bundle prekeys count=%d: %v", len(req.OneTimePrekeys), err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not store prekeys")
			return
		}

		log.Printf("[key-service] bundle uploaded opk_count=%d", len(req.OneTimePrekeys))
		// 204 No Content — there is intentionally no
		// body. The client already knows the bundle it
		// sent; echoing it back is bandwidth and a
		// source of "did the server mangle it?" bugs.
		w.WriteHeader(http.StatusNoContent)
	}
}
