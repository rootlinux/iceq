// Package middleware contains the HTTP middlewares shared by every
// IceQ backend service. Only BearerAuth lives here for now; future
// middlewares (request ID, structured-logging access log, CORS,
// body-size cap) can be added without growing the surface area of
// this file beyond reason.
package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/iceq/iceq/shared/jwt"
	"github.com/iceq/iceq/shared/models"
)

// AnonymousRateLimitBucket creates the only value an unauthenticated service
// may persist for abuse control. The edge supplies an opaque network identity;
// neither that identity nor User-Agent/IP bytes are retained. Daily rotation
// limits long-term linkability if the rate-limit store is inspected.
func AnonymousRateLimitBucket(secret []byte, edgeIdentity, action string, now time.Time) (string, error) {
	if len(secret) < 32 {
		return "", errors.New("rate-limit HMAC secret must be at least 32 bytes")
	}
	edgeIdentity = strings.TrimSpace(edgeIdentity)
	action = strings.TrimSpace(action)
	if edgeIdentity == "" || action == "" {
		return "", errors.New("rate-limit identity and action are required")
	}
	parts := strings.Split(edgeIdentity, ".")
	if len(parts) != 3 || parts[0] != "v1" || len(parts[1]) != 12 || len(parts[2]) != 43 {
		return "", errors.New("rate-limit identity has invalid edge signature format")
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return "", errors.New("rate-limit identity has invalid edge key id")
	}
	if digest, err := base64.RawURLEncoding.DecodeString(parts[2]); err != nil || len(digest) != sha256.Size {
		return "", errors.New("rate-limit identity has invalid edge digest")
	}
	day := now.UTC().Format("2006-01-02")
	rotation := hmac.New(sha256.New, secret)
	_, _ = rotation.Write([]byte(day))
	bucket := hmac.New(sha256.New, rotation.Sum(nil))
	_, _ = bucket.Write([]byte(action + "\x00" + edgeIdentity))
	return "anon:" + action + ":" + base64.RawURLEncoding.EncodeToString(bucket.Sum(nil)), nil
}

// AuthenticatedRateLimitKey scopes an abuse bucket to the verified actor and
// action. Callers must obtain uin from GetUIN, never from request input.
func AuthenticatedRateLimitKey(uin int64, action string) (string, error) {
	action = strings.TrimSpace(action)
	if uin <= 0 || action == "" {
		return "", errors.New("valid authenticated uin and action are required")
	}
	return fmt.Sprintf("auth:%d:%s", uin, action), nil
}

// ----------------------------------------------------------------------------
// Context key. Unexported on purpose: a string key is a footgun because
// any other package that picks the same name would silently alias.
// Wrapping the key in an unexported type makes the compile-time
// guarantee airtight: only this package can construct or read a
// uinKey. The empty struct is a zero-cost marker.
// ----------------------------------------------------------------------------

type uinKey struct{}

// uinKeyStr is the string form we embed in error messages for ops
// visibility. It is not used for lookup — context.WithValue takes
// the typed key, not the string.
const uinKeyStr = "uin"

// WithUIN returns a new context carrying the authenticated user's
// UIN. The handler chain calls this from inside BearerAuth, and
// the rest of the request lifecycle reads it back with GetUIN.
func WithUIN(ctx context.Context, uin int64) context.Context {
	return context.WithValue(ctx, uinKey{}, uin)
}

// GetUIN retrieves the authenticated user's UIN from a request
// context. Returns false when the request was never authenticated
// (e.g. a handler forgot to mount BearerAuth, or a test called it
// without the middleware). Handlers that need the UIN should
// always check the bool before dereferencing.
func GetUIN(ctx context.Context) (int64, bool) {
	v, ok := ctx.Value(uinKey{}).(int64)
	return v, ok
}

// ----------------------------------------------------------------------------
// Configuration. BearerAuth is a closure that returns the middleware
// itself: this lets main.go inject the jwt.Manager (which itself
// owns the Redis client) without making this package depend on
// pgxpool, redis, or any other service-level type.
// ----------------------------------------------------------------------------

// BearerAuthConfig captures every dependency BearerAuth needs.
// Constructed once in main.go and passed to NewBearerAuth.
type BearerAuthConfig struct {
	// Manager verifies the access token. Must be non-nil.
	Manager *jwt.Manager
	// OnError is the response writer used for 401s. Centralizing
	// it here means BearerAuth and the handlers share the same
	// error envelope shape. If nil, defaultErrorResponder is
	// used; it writes the shared models.ErrorResponse.
	OnError func(w http.ResponseWriter, r *http.Request, status int, code, message string)
	// Timeout caps a single Verify call. The default of 5 s is
	// generous for a Redis EXISTS round trip; if Redis is dead
	// the request fails fast rather than holding the connection.
	Timeout time.Duration
}

// ----------------------------------------------------------------------------
// Middleware constructor.
// ----------------------------------------------------------------------------

// NewBearerAuth returns the chi-compatible middleware that enforces
// a valid access token on every request. Usage:
//
//	r.Use(middleware.NewBearerAuth(middleware.BearerAuthConfig{...}))
//
// Successful verification puts the UIN into the request context
// and lets the request proceed. Any failure — missing header,
// wrong scheme, invalid signature, wrong type, revoked, expired,
// blocklist lookup error — short-circuits with a 401.
func NewBearerAuth(cfg BearerAuthConfig) func(http.Handler) http.Handler {
	if cfg.Manager == nil {
		panic("middleware: BearerAuthConfig.Manager is nil")
	}
	if cfg.OnError == nil {
		cfg.OnError = defaultErrorResponder
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, err := extractBearerToken(r)
			if err != nil {
				cfg.OnError(w, r, http.StatusUnauthorized, "AUTH_MISSING_BEARER", err.Error())
				return
			}

			ctx, cancel := context.WithTimeout(r.Context(), cfg.Timeout)
			defer cancel()
			claims, err := cfg.Manager.Verify(ctx, raw, jwt.TokenTypeAccess)
			if err != nil {
				// Map the jwt package's sentinels onto a stable
				// set of error codes. The handler doesn't need
				// to know which internal error fired; the client
				// can act on the code (e.g. trigger a refresh on
				// TOKEN_EXPIRED).
				code, message := classifyJWTError(err)
				cfg.OnError(w, r, http.StatusUnauthorized, code, message)
				return
			}

			// Inject the UIN and hand off to the next handler.
			next.ServeHTTP(w, r.WithContext(WithUIN(r.Context(), claims.UIN)))
		})
	}
}

// ----------------------------------------------------------------------------
// Helpers.
// ----------------------------------------------------------------------------

// extractBearerToken pulls the token out of the Authorization
// header. We require the "Bearer " prefix case-sensitively per
// RFC 6750; "bearer" lowercase is rejected so a sloppy client
// doesn't quietly bypass the auth path.
func extractBearerToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", errors.New("Authorization header is missing")
	}
	// Exact "Bearer " prefix. We avoid strings.HasPrefix to keep
	// the comparison deterministic and case-sensitive.
	const prefix = "Bearer "
	if len(h) <= len(prefix) || h[:len(prefix)] != prefix {
		return "", errors.New("Authorization header must use the Bearer scheme")
	}
	tok := strings.TrimSpace(h[len(prefix):])
	if tok == "" {
		return "", errors.New("Bearer token is empty")
	}
	return tok, nil
}

// classifyJWTError maps a jwt.Manager error onto a stable
// (code, message) pair. The codes are part of the public API
// (clients can switch on them); the messages are not.
func classifyJWTError(err error) (code, message string) {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return "TOKEN_EXPIRED", "access token has expired; use /api/auth/refresh"
	case errors.Is(err, jwt.ErrTokenRevoked):
		return "TOKEN_REVOKED", "access token has been revoked; please log in again"
	case errors.Is(err, jwt.ErrTokenWrongType):
		return "TOKEN_WRONG_TYPE", "expected an access token"
	default:
		return "TOKEN_INVALID", "access token is invalid"
	}
}

// defaultErrorResponder writes the standard ErrorResponse JSON
// body. main.go can override this if it wants a different log
// sink, but the response shape stays the same. The default does
// not log anything — BearerAuth failure paths carry no caller
// data worth persisting, and the message itself is the (code,
// message) pair already on its way to the client.
func defaultErrorResponder(w http.ResponseWriter, _ *http.Request, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(models.ErrorResponse{Error: message, Code: code})
}
