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
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

// ----------------------------------------------------------------------------
// Rate limiter. The limit is enforced before we touch the database
// or the bcrypt comparison — a brute-force attack should be
// stopped at the door, not after we've spent 250 ms of CPU on a
// bcrypt comparison.
//
// The Lua script implements a fixed-window counter: it INCRs the
// per-IP key and, on the first increment only, sets the TTL. The
// single-shot TTL is critical: resetting the TTL on every
// increment would turn a 5/minute limit into a "5 per minute of
// silence" limit, which is the wrong shape.
// ----------------------------------------------------------------------------

const (
	// rateLimitPerMinute is the threshold above which login
	// attempts are rejected with 429. Five per minute matches
	// the OWASP "credential stuffing cheat sheet" guidance and
	// tolerates two or three mis-typed passwords by a real user.
	rateLimitPerMinute = 5

	// rateLimitWindow is the TTL applied to the counter on its
	// first increment. With a 60 s window, a user who hits the
	// limit gets a clean slate one minute later — predictable
	// for both the user (knows when to retry) and the operator
	// (knows the worst-case attack bandwidth).
	rateLimitWindow = time.Minute

	// rateLimitKeyPrefix scopes the rate-limit keys so an
	// SCAN/KEYS against `ratelimit:*` doesn't accidentally hit
	// the JWT blocklist (`jwt:*`) or the presence map.
	rateLimitKeyPrefix = "ratelimit:login:"
)

// rateLimitScript is the atomic INCR + (set TTL on first hit) Lua.
// Returning the post-increment value lets the handler compare
// against the limit in a single round trip.
//
// KEYS = one current and optionally one previous rotating identity key
// ARGV[1] = window seconds (rateLimitWindow in seconds)
const rateLimitScript = `
local maximum = 0
for _, key in ipairs(KEYS) do
    local current = redis.call("INCR", key)
    if current == 1 then redis.call("EXPIRE", key, ARGV[1]) end
    if current > maximum then maximum = current end
end
return maximum
`

// #nosec G101 -- this is a SQL statement (the column name
// "password_hash" is what gosec's heuristic matches), not a
// credential literal.
const qUpdateUserPasswordHash = `
	UPDATE users
	SET password_hash = $1,
	    updated_at = NOW()
	WHERE uin = $2
`

// ----------------------------------------------------------------------------
// Login handler dependencies. The full set of services the login
// flow touches: Postgres for the user lookup, Redis for the rate
// limiter and (transitively) for the JWT blocklist, and the JWT
// manager for signing the new tokens.
// ----------------------------------------------------------------------------

type LoginDeps struct {
	Pool    *pgxpool.Pool
	Redis   *redis.Client
	Manager *jwt.Manager
	// RateLimitSecret keys rotating HMAC buckets. Reusing the already
	// mandatory high-entropy service secret avoids another operator secret.
	RateLimitSecret []byte
	// LookupUser is an optional narrow test seam for the read-only credential
	// lookup. Production uses Pool when it is nil.
	LookupUser func(context.Context, string, bool) (LoginUser, error)
}

type LoginUser struct {
	UIN          int64
	Username     string
	Email        string
	PasswordHash string
}

// NewLoginHandler returns the http.HandlerFunc mounted at
// POST /api/auth/login.
func NewLoginHandler(deps LoginDeps) http.HandlerFunc {
	// Pre-compile the Lua script once at handler-construction
	// time. The script's SHA1 is cached on the Redis side, so
	// repeated calls after the first are EVALSHA-only — no
	// resend of the script body.
	script := redis.NewScript(rateLimitScript)

	return func(w http.ResponseWriter, r *http.Request) {
		// 10 KiB is generous for a login form.
		var req models.LoginRequest
		if !decodeJSON(w, r, &req, 10*1024) {
			return
		}
		if err := req.Validate(); err != nil {
			writeValidationError(w, err)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		// ------------------------------------------------------------
		// 1. Rate-limit check. Done BEFORE the DB lookup so a
		// brute-force attempt never reaches the bcrypt path.
		// ------------------------------------------------------------
		buckets, err := middleware.AnonymousRateLimitBuckets(deps.RateLimitSecret, r.Header.Values(middleware.EdgeIdentityHeader), r.Header.Values(middleware.EdgePreviousIdentityHeader), "login", time.Now())
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "RATE_LIMIT_IDENTITY_UNAVAILABLE", "service is temporarily unavailable")
			return
		}
		keys := make([]string, len(buckets))
		for i, bucket := range buckets {
			keys[i] = rateLimitKeyPrefix + bucket
		}
		// windowSeconds is passed as ARGV[1] (string) because
		// Lua treats every ARGV as a string; Redis implicitly
		// coerces it to int for EXPIRE.
		windowSeconds := int(rateLimitWindow.Seconds())
		count, err := script.Run(ctx, deps.Redis, keys, windowSeconds).Int64()
		if err != nil {
			// Fail-closed. A security-critical service should
			// not silently allow logins when its rate limiter
			// is degraded; the right move is to surface the
			// failure to the client (503) and to the operator
			// (log + metrics).
			log.Printf("[auth-service] rate limiter unavailable: %v", err)
			writeError(w, http.StatusServiceUnavailable, "RATE_LIMITER_UNAVAILABLE", "service is temporarily unavailable")
			return
		}
		if count > rateLimitPerMinute {
			// We don't expose Retry-After because the
			// window is fixed and the client can't know
			// when the bucket resets. Adding it would
			// require a second Redis call (TTL) for a
			// cosmetic header.
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "too many login attempts; try again later")
			return
		}

		// ------------------------------------------------------------
		// 2. Look up the user by username or email. We keep the
		// resolution explicit so a username collision with some
		// other user's email cannot silently authenticate the
		// wrong row.
		// that pulls every column the login path needs. The
		// unique index on the selected field makes this a single B-tree
		// descent.
		// ------------------------------------------------------------
		var (
			uin          int64
			username     string
			email        string
			passwordHash string
		)
		loginValue, byUsername := req.LoginIdentifier()
		query := qSelectUserByEmail
		if byUsername {
			query = qSelectUserByUsername
		}
		if deps.LookupUser != nil {
			user, lookupErr := deps.LookupUser(ctx, loginValue, byUsername)
			err = lookupErr
			uin, username, email, passwordHash = user.UIN, user.Username, user.Email, user.PasswordHash
		} else {
			err = deps.Pool.QueryRow(ctx, query, loginValue).
				Scan(&uin, &username, &email, &passwordHash)
		}
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				// Generic 401 — no enumeration. We
				// still burn a bcrypt comparison to
				// keep the response time roughly
				// constant against an attacker who
				// can otherwise distinguish "no
				// such user" from "wrong password"
				// by latency.
				burnCPUToMaskTiming(req.Password)
				writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid credentials")
				return
			}
			writeDBError(w, err, "login: select user")
			return
		}

		// ------------------------------------------------------------
		// 3. Password verification. New hashes use Argon2id;
		// legacy bcrypt hashes remain valid and are upgraded
		// after a successful login.
		// ------------------------------------------------------------
		passwordResult := verifyPassword(passwordHash, req.Password)
		if !passwordResult.OK {
			writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid credentials")
			return
		}

		// ------------------------------------------------------------
		// 4. Rehash legacy password hashes (best-effort, non-fatal).
		//    Done before the serialization transaction so a rehash
		//    failure does not roll back the session issuance.
		// ------------------------------------------------------------
		if passwordResult.NeedsRehash {
			rehash, err := hashPassword(req.Password)
			if err != nil {
				log.Printf("[auth-service] password rehash failed: %v", err)
			} else if _, err := deps.Pool.Exec(ctx, qUpdateUserPasswordHash, rehash, uin); err != nil {
				log.Printf("[auth-service] password rehash update failed: %v", err)
			}
		}

		// ------------------------------------------------------------
		// 5. Serialize with PanicWipe via SELECT ... FOR UPDATE on
		//    the user row. PanicWipe acquires the same row lock before
		//    deleting refresh tokens, so the two transactions cannot
		//    pass each other. After acquiring the lock we check the
		//    wiped_accounts marker inside the same transaction —
		//    the check and the session issuance are atomic.
		// ------------------------------------------------------------
		tx, txErr := deps.Pool.Begin(ctx)
		if txErr != nil {
			log.Printf("[auth-service] login: begin tx: %v", txErr)
			writeError(w, http.StatusServiceUnavailable, "AUTH_SERVICE_UNAVAILABLE", "service is temporarily unavailable")
			return
		}
		defer func() { _ = tx.Rollback(ctx) }()

		// Lock the user row. PanicWipe takes the same conflicting lock
		// at the beginning of its transaction; this guarantees that either
		// PanicWipe committed before we acquired the lock (wiped_accounts
		// marker is visible) or it blocks until we commit (marker is
		// absent, session is created, then PanicWipe deletes it).
		var lockUIN int64
		if err := tx.QueryRow(ctx, qLockUserRow, uin).Scan(&lockUIN); err != nil {
			// No rows means the user row was deleted between the
			// initial lookup and now (worker final erasure). Every
			// other error is a database failure. Both are fail-closed.
			log.Printf("[auth-service] login: lock user row: %v", err)
			writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid credentials")
			return
		}

		// Check the wiped_accounts marker inside the locked transaction.
		var wiped bool
		if err := tx.QueryRow(ctx, qCheckWipedAccount, uin).Scan(&wiped); err != nil {
			// Fail-closed: cannot determine whether the account is
			// wiped, so reject the login. A 503 would leak whether
			// the account exists, so return the generic 401.
			log.Printf("[auth-service] login: wiped-account check: %v", err)
			writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid credentials")
			return
		}
		if wiped {
			// The account was wiped between password verification
			// and now. Reject with the same generic 401 as a wrong
			// password — the bcrypt already ran, so the timing is
			// indistinguishable.
			writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid credentials")
			return
		}

		// Issue the session inside the transaction. The refresh-token
		// row is committed atomically with the wiped-account check.
		tokens, err := issueSessionTx(ctx, tx, deps.Manager, uin)
		if err != nil {
			log.Printf("[auth-service] issue login session: %v", err)
			writeError(w, http.StatusInternalServerError, "TOKEN_ISSUE_FAILED", "could not issue session")
			return
		}

		if err := tx.Commit(ctx); err != nil {
			log.Printf("[auth-service] login: commit tx: %v", err)
			writeError(w, http.StatusInternalServerError, "TOKEN_ISSUE_FAILED", "could not issue session")
			return
		}

		setSessionCookies(w, tokens)
		log.Printf("[auth-service] login successful")
		writeJSON(w, http.StatusOK, models.LoginResponse{
			AccessToken: tokens.AccessToken,
			UIN:         uin,
			Username:    username,
			User: models.AuthUser{
				UIN:      uin,
				Username: username,
				Email:    email,
			},
			Tokens: tokens,
		})
	}
}

// sha256Hex returns the hex-encoded SHA-256 of s. We use this
// to fingerprint refresh tokens at rest. Plain SHA-256 is
// appropriate here because the input (the refresh token) is
// already a 256-bit random secret — there is no weak password
// to salt against. The hash exists only so a DB dump can't
// replay sessions.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// burnCPUToMaskTiming runs a bcrypt comparison against a known-
// invalid hash so the time-to-respond for "no such user" is
// indistinguishable from "wrong password". The decoy hash is
// generated once at package init time from a fixed plaintext;
// the comparison will always fail, but the wall-clock cost
// matches the success path's bcrypt cost.
//
// Without this, an attacker can enumerate which emails are
// registered by timing the response: ~250 ms = real user
// (real bcrypt compare), ~1 ms = no such user.
func burnCPUToMaskTiming(password string) {
	_ = bcrypt.CompareHashAndPassword(decoyBcryptHash, []byte(password))
	_ = verifyArgon2idPassword(decoyArgon2idHash, password)
}

// decoyBcryptHash is built once at package init so the cost-12
// hashing only happens once per process. If generation fails
// (e.g. /dev/urandom is unavailable, which would prevent any
// bcrypt operation in this process), we fall back to a no-op
// decoy — the timing-mask stops working, but the handler still
// functions. The risk is real but the failure mode is rare
// enough to log rather than panic on.
var decoyBcryptHash []byte
var decoyArgon2idHash string

func init() {
	const decoyPlaintext = "iceq-login-timing-decoy"
	h, err := bcrypt.GenerateFromPassword([]byte(decoyPlaintext), bcryptCost)
	if err != nil {
		// Fall back to an empty hash. CompareHashAndPassword
		// will return ErrHashTooShort or similar; the timing
		// will be off but login still works.
		log.Printf("[auth-service] could not pre-compute timing decoy hash: %v", err)
		decoyBcryptHash = []byte("")
		return
	}
	decoyBcryptHash = h
	if h, err := hashPassword(decoyPlaintext); err != nil {
		log.Printf("[auth-service] could not pre-compute timing decoy argon2id hash: %v", err)
	} else {
		decoyArgon2idHash = h
	}
}
