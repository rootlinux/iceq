package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/iceq/iceq/auth-service/models"
	"github.com/iceq/iceq/shared/jwt"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
)

// ----------------------------------------------------------------------------
// Refresh handler. Implements refresh-token rotation: every call
// consumes the presented refresh token (deletes it from the DB
// after a successful exchange) and mints a brand-new pair. This
// is the OAuth 2.0 BCP recommendation because a stolen refresh
// token's next legitimate use will fail, alerting the user.
//
// The old row is conditionally deleted and the new row inserted in one
// transaction. PostgreSQL's row locking makes the conditional delete the
// single-winner gate for concurrent requests.
// ----------------------------------------------------------------------------

type RefreshTokenManager interface {
	Verify(context.Context, string, string) (*jwt.Claims, error)
	Sign(int64, string) (jwt.SignResult, error)
	BumpSessionEpoch(context.Context, int64) error
}

type RefreshRateLimiter interface {
	Allow(context.Context, int64, string) (bool, error)
}

type RefreshDB interface {
	Begin(context.Context) (pgx.Tx, error)
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

type RedisRefreshRateLimiter struct {
	client *redis.Client
	script *redis.Script
}

func NewRedisRefreshRateLimiter(client *redis.Client) *RedisRefreshRateLimiter {
	return &RedisRefreshRateLimiter{client: client, script: redis.NewScript(rateLimitScript)}
}

func (l *RedisRefreshRateLimiter) Allow(ctx context.Context, uin int64, action string) (bool, error) {
	key, err := middleware.AuthenticatedRateLimitKey(uin, action)
	if err != nil {
		return false, err
	}
	count, err := l.script.Run(ctx, l.client, []string{"ratelimit:" + key}, int(rateLimitWindow.Seconds())).Int64()
	if err != nil {
		return false, err
	}
	return count <= rateLimitPerMinute, nil
}

type RefreshDeps struct {
	Pool    RefreshDB
	Manager RefreshTokenManager
	Limiter RefreshRateLimiter
}

// NewRefreshHandler returns the http.HandlerFunc mounted at
// POST /api/auth/refresh.
func NewRefreshHandler(deps RefreshDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqCtx, ok := decodeRefreshRequest(w, r)
		if !ok {
			clearSessionCookies(w)
			return
		}
		r = r.WithContext(reqCtx)
		refreshToken, _ := refreshTokenFromRequest(r)

		// 10 s covers: JWT verify (Redis EXISTS) + DB lookup +
		// DB delete + 2x JWT sign + DB insert. Comfortable margin.
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		// ------------------------------------------------------------
		// 1. Verify the JWT. This catches: bad signature,
		// expired token, wrong type (i.e. someone tried to
		// refresh with an access token), or a token whose
		// JTI is on the blocklist (revoked).
		// ------------------------------------------------------------
		claims, err := deps.Manager.Verify(ctx, refreshToken, jwt.TokenTypeRefresh)
		if err != nil {
			clearSessionCookies(w)
			code, msg := classifyJWTError(err)
			writeError(w, http.StatusUnauthorized, code, msg)
			return
		}

		allowed, err := deps.Limiter.Allow(ctx, claims.UIN, "auth:refresh")
		if err != nil {
			log.Printf("[auth-service] refresh rate limiter unavailable: %v", err)
			writeError(w, http.StatusServiceUnavailable, "RATE_LIMITER_UNAVAILABLE", "service is temporarily unavailable")
			return
		}
		if !allowed {
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "too many refresh attempts; try again later")
			return
		}

		// ------------------------------------------------------------
		// 2. Atomically consume the refresh token row by hash. This is a
		// belt-and-suspenders check: even if the JWT itself is
		// valid, the token must also exist in our DB and not
		// be past its DB-stored expires_at.
		//
		// Why both? Two reasons:
		//   (a) If the JWT secret is ever rotated, tokens
		//       issued under the old secret would fail verify
		//       but their DB rows would still exist; we'd
		//       want a clean "your session ended" path
		//       rather than an opaque "invalid token".
		//   (b) If a row was deleted (e.g. by a previous
		//       refresh or a manual cleanup) the JWT may
		//       still verify until its natural expiry. The
		//       DB check is the source of truth for "is
		//       this token still revocable / usable".
		// ------------------------------------------------------------
		tokenHash := sha256Hex(refreshToken)
		var (
			dbUIN       int64
			dbExpiresAt time.Time
		)
		tx, err := deps.Pool.Begin(ctx)
		if err != nil {
			writeDBError(w, err, "refresh: begin rotation")
			return
		}
		defer func() { _ = tx.Rollback(ctx) }()

		err = tx.QueryRow(ctx, qConsumeRefreshTokenByHash, tokenHash).
			Scan(&dbUIN, &dbExpiresAt)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				if !commitRefreshReuseRevocation(w, ctx, tx, claims.UIN) {
					return
				}
				clearSessionCookies(w)
				writeError(w, http.StatusUnauthorized, "REFRESH_REVOKED", "session is no longer valid")
				return
			}
			writeDBError(w, err, "refresh: consume refresh token")
			return
		}

		// Belt: the JWT carries its own `exp`; suspenders: the
		// DB row carries expires_at. We check the DB's value
		// because the operator can shorten token lifetime
		// (e.g. on a security incident) by UPDATE-ing
		// refresh_tokens without rotating the JWT secret.
		if time.Now().UTC().After(dbExpiresAt) {
			// Clean up the stale row so the next refresh
			// attempt also fails fast at the DB level.
			if commitErr := tx.Commit(ctx); commitErr != nil {
				writeDBError(w, commitErr, "refresh: commit expired token consume")
				return
			}
			clearSessionCookies(w)
			writeError(w, http.StatusUnauthorized, "REFRESH_EXPIRED", "refresh token has expired")
			return
		}

		// ------------------------------------------------------------
		// 3. Cross-check: the JWT's UIN must match the DB
		// row's UIN. A mismatch means either (a) the DB row
		// was reassigned (impossible given how we issue
		// tokens, but defense in depth) or (b) the token
		// was tampered with in a way that passed signature
		// verification (impossible without the secret).
		// Either way: reject.
		//
		// F-5d (JWT assessment): on the OAuth 2.0 BCP
		// "automatic detection of refresh token reuse"
		// path, we MUST also invalidate every other
		// session this user has, because the attacker who
		// triggered this path almost certainly has more
		// than one stolen credential. Just deleting the
		// single row is too narrow. Bumping the user's
		// session_epoch invalidates ALL of their access
		// and refresh tokens (server-side) in O(1) writes
		// and O(1) reads-per-request. The physical
		// DELETE of every refresh_tokens row for this
		// user is housekeeping, not security.
		// ------------------------------------------------------------
		if dbUIN != claims.UIN {
			log.Printf("[auth-service] refresh uin mismatch (possible token reuse attack)")
			if !commitRefreshReuseRevocation(w, ctx, tx, claims.UIN) {
				return
			}
			clearSessionCookies(w)
			writeError(w, http.StatusUnauthorized, "REFRESH_REVOKED", "session is no longer valid")
			return
		}

		// ------------------------------------------------------------
		// 4. Mint a fresh pair. Same secret, same signing
		// path as login, new JTIs.
		// ------------------------------------------------------------
		access, err := deps.Manager.Sign(claims.UIN, jwt.TokenTypeAccess)
		if err != nil {
			log.Printf("[auth-service] refresh: sign access: %v", err)
			writeError(w, http.StatusInternalServerError, "TOKEN_ISSUE_FAILED", "could not issue access token")
			return
		}
		refresh, err := deps.Manager.Sign(claims.UIN, jwt.TokenTypeRefresh)
		if err != nil {
			log.Printf("[auth-service] refresh: sign refresh: %v", err)
			writeError(w, http.StatusInternalServerError, "TOKEN_ISSUE_FAILED", "could not issue refresh token")
			return
		}

		// ------------------------------------------------------------
		// 5. Persist the new refresh token's hash in the same transaction.
		// ------------------------------------------------------------
		newHash := sha256Hex(refresh.Token)
		newExpires := time.Now().UTC().Add(jwt.RefreshTokenTTL)
		if _, err := tx.Exec(ctx, qInsertRefreshToken, claims.UIN, newHash, newExpires); err != nil {
			// Neither token is returned, and rollback restores the old
			// database row so the failed rotation does not strand the user.
			log.Printf("[auth-service] refresh: insert new refresh token: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not persist new refresh token")
			return
		}
		if err := tx.Commit(ctx); err != nil {
			writeDBError(w, err, "refresh: commit rotation")
			return
		}

		tokens := models.AuthTokens{
			AccessToken:  access.Token,
			RefreshToken: refresh.Token,
		}
		setSessionCookies(w, tokens)
		log.Printf("[auth-service] refresh (rotated)")
		writeJSON(w, http.StatusOK, models.RefreshResponse{
			AccessToken:  tokens.AccessToken,
			RefreshToken: tokens.RefreshToken,
		})
	}
}

func commitRefreshReuseRevocation(w http.ResponseWriter, ctx context.Context, tx pgx.Tx, uin int64) bool {
	if _, err := tx.Exec(ctx, qRevokeAllSessionsOnRefreshReuse, uin); err != nil {
		log.Printf("[auth-service] refresh reuse revocation transaction failed: %v", err)
		writeError(w, http.StatusInternalServerError, "SESSION_REVOCATION_FAILED", "service is temporarily unavailable")
		return false
	}
	if err := tx.Commit(ctx); err != nil {
		log.Printf("[auth-service] refresh reuse revocation commit failed: %v", err)
		writeError(w, http.StatusInternalServerError, "SESSION_REVOCATION_FAILED", "service is temporarily unavailable")
		return false
	}
	return true
}

// Compile-time assertion: sha256Hex exists in login.go and is
// also used here. This block does nothing at runtime; it just
// documents the cross-file dependency and would catch a rename
// at compile time if login.go's sha256Hex were ever deleted.
var _ = sha256.Sum256
var _ = hex.EncodeToString
