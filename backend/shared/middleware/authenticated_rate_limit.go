package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// AuthenticatedRateLimitActions is the complete set of action strings
// registered with AuthenticatedRateLimitConfig across every service.
// Each entry maps to a Redis key of the form ratelimit:auth:{uin}:{action}.
//
// When adding a new rate-limited endpoint, add its action string here so
// the panic-wipe Redis cleaner can deterministically delete the key without
// SCAN or KEYS. Missing an action here means a rate-limit key tied to the
// wiped UIN survives until its natural TTL expiry — a privacy regression.
//
// Audit point: grep -rn 'Action:' backend/ --include="*.go" | grep -v _test.go
var AuthenticatedRateLimitActions = []string{
	// auth-service (handlers + refresh limiter)
	"auth:logout",
	"auth:me",
	"auth:crypto-binding",
	"auth:panic-wipe",
	"auth:panic-pin",
	"auth:panic-wipe-public-key",
	"auth:panic-wipe-public-key-get",
	"auth:panic-wipe-challenge",
	"auth:refresh",
	"contacts:list",
	"contacts:add",
	"contacts:accept",
	"contacts:block",
	"contacts:remove",
	// ws-gateway
	"ws:connect",
	"ws:frame",
	"transport:poll",
	"transport:send",
	// presence-service
	"presence:read",
	"presence:bulk",
	// message-service
	"messages:history",
	"messages:group-history",
	// file-service
	"files:upload",
	"files:download",
	"files:avatar-upload",
	"files:grant",
	"files:grant:revoke",
	// key-service
	"keys:bundle:upload",
	"keys:prekeys:add",
	"keys:prekeys:count",
}

// AuthenticatedRateLimitKeysForUIN returns every ratelimit:auth key that may
// exist for the given UIN. Keys are constructed deterministically — no SCAN,
// no KEYS, no unbounded iteration. The returned keys are safe to DEL
// unconditionally: DEL on a non-existent key is a no-op.
func AuthenticatedRateLimitKeysForUIN(uin int64) []string {
	keys := make([]string, 0, len(AuthenticatedRateLimitActions))
	for _, action := range AuthenticatedRateLimitActions {
		k, err := AuthenticatedRateLimitKey(uin, action)
		if err != nil {
			// Statically-defined actions never fail key construction.
			// If they do, it's a bug caught at dev time — skip
			// without panicking so a bad action doesn't block the
			// rest of the wipe.
			continue
		}
		keys = append(keys, "ratelimit:"+k)
	}
	return keys
}

// AuthenticatedRateLimitKeyPrefix returns the prefix shared by every
// authenticated rate-limit key for a given UIN. Useful for SCAN-based
// verification when an exhaustive check is needed (acceptance tests).
func AuthenticatedRateLimitKeyPrefix(uin int64) string {
	return fmt.Sprintf("ratelimit:auth:%d:", uin)
}

const authenticatedRateLimitScript = `
local current = redis.call("INCR", KEYS[1])
if current == 1 then
    redis.call("EXPIRE", KEYS[1], ARGV[1])
end
return current
`

type rateLimitRedis interface {
	Eval(ctx context.Context, script string, keys []string, args ...any) *redis.Cmd
}

// AuthenticatedRateLimitConfig defines one explicit authenticated action
// budget. Redis failures deny the request so an unavailable abuse-control
// dependency cannot silently remove the limit.
type AuthenticatedRateLimitConfig struct {
	Redis   rateLimitRedis
	Action  string
	Limit   int64
	Window  time.Duration
	Timeout time.Duration
	OnError func(w http.ResponseWriter, r *http.Request, status int, code, message string)
}

// AuthenticatedRateLimiter can be used by authenticated transports that are
// not ordinary HTTP middleware, including the WebSocket auth-frame flow.
type AuthenticatedRateLimiter struct {
	redis   rateLimitRedis
	action  string
	limit   int64
	window  time.Duration
	timeout time.Duration
}

func NewAuthenticatedRateLimiter(cfg AuthenticatedRateLimitConfig) *AuthenticatedRateLimiter {
	if cfg.Redis == nil {
		panic("middleware: AuthenticatedRateLimitConfig.Redis is nil")
	}
	if _, err := AuthenticatedRateLimitKey(1, cfg.Action); err != nil {
		panic("middleware: AuthenticatedRateLimitConfig.Action is empty")
	}
	if cfg.Limit <= 0 || cfg.Window <= 0 {
		panic("middleware: authenticated rate-limit budget must be positive")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 500 * time.Millisecond
	}
	return &AuthenticatedRateLimiter{
		redis: cfg.Redis, action: cfg.Action, limit: cfg.Limit,
		window: cfg.Window, timeout: cfg.Timeout,
	}
}

// Allow atomically consumes one unit from the verified actor's action bucket.
func (l *AuthenticatedRateLimiter) Allow(ctx context.Context, uin int64) (bool, error) {
	key, err := AuthenticatedRateLimitKey(uin, l.action)
	if err != nil {
		return false, err
	}
	limitCtx, cancel := context.WithTimeout(ctx, l.timeout)
	defer cancel()
	seconds := int64((l.window + time.Second - 1) / time.Second)
	count, err := l.redis.Eval(limitCtx, authenticatedRateLimitScript, []string{"ratelimit:" + key}, seconds).Int64()
	if err != nil {
		return false, err
	}
	return count <= l.limit, nil
}

// NewAuthenticatedRateLimit creates middleware that must be mounted after
// BearerAuth. It derives identity only from the verified request context.
func NewAuthenticatedRateLimit(cfg AuthenticatedRateLimitConfig) func(http.Handler) http.Handler {
	limiter := NewAuthenticatedRateLimiter(cfg)
	onError := cfg.OnError
	if onError == nil {
		onError = defaultErrorResponder
	}
	retryAfter := strconv.FormatInt(int64((cfg.Window+time.Second-1)/time.Second), 10)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			uin, ok := GetUIN(r.Context())
			if !ok || uin <= 0 {
				onError(w, r, http.StatusUnauthorized, "AUTH_REQUIRED", "verified authentication is required")
				return
			}
			allowed, err := limiter.Allow(r.Context(), uin)
			if err != nil {
				onError(w, r, http.StatusServiceUnavailable, "RATE_LIMIT_UNAVAILABLE", "rate limit service is unavailable")
				return
			}
			if !allowed {
				w.Header().Set("Retry-After", retryAfter)
				onError(w, r, http.StatusTooManyRequests, "RATE_LIMITED", "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
