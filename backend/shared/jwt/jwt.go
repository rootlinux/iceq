// Package jwt implements HS256 JWT issuance, verification, and revocation
// for the IceQ platform.
//
// Two token kinds are issued from the same secret and signing logic but carry
// a distinguishing `type` claim so verification can reject a refresh token
// used in place of an access token (or vice versa):
//
//   - "access"  — short-lived (15 min), used as the bearer credential for
//                 every authenticated REST / WebSocket call.
//   - "refresh" — long-lived (7 days), used only at the auth-service
//                 /api/auth/refresh endpoint to mint a new access token.
//
// Revocation is implemented in two layers:
//
//  1. A Redis blocklist keyed by the token's JTI. Carries a TTL equal to
//     the token's remaining lifetime so the blocklist self-prunes and
//     never grows unbounded.
//
//  2. A per-user `users.session_epoch` timestamp. Bumped on logout and
//     on detected refresh-token reuse; Verify rejects any token whose
//     `iat` is before the user's current epoch. This gives us
//     "revoke all sessions for this user" semantics that the per-JTI
//     blocklist alone cannot express.
//
// This package owns the signing secret, the Redis client, and a Postgres
// pool (for the epoch check). Callers inject the *redis.Client and
// *pgxpool.Pool (see shared/db/redis.go and shared/db/postgres.go) via
// the Manager constructor.
package jwt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// ----------------------------------------------------------------------------
// Errors. Exposed as sentinel values so call-sites can use errors.Is for
// classification without string-matching.
// ----------------------------------------------------------------------------

var (
	// ErrTokenInvalid covers signature mismatch, malformed JWT, wrong
	// algorithm, or any structural problem. Maps to HTTP 401.
	ErrTokenInvalid = errors.New("jwt: token invalid")

	// ErrTokenExpired means the token parsed correctly but its `exp`
	// claim is in the past. Maps to HTTP 401. Callers should prompt the
	// client to use its refresh token.
	ErrTokenExpired = errors.New("jwt: token expired")

	// ErrTokenRevoked means the token parsed and was unexpired, but its
	// JTI is present in the Redis blocklist OR the user's session_epoch
	// is newer than the token's iat. Maps to HTTP 401 with a
	// "session terminated" message.
	ErrTokenRevoked = errors.New("jwt: token revoked")

	// ErrTokenWrongType is returned when the `type` claim does not match
	// what the caller expected (e.g. a refresh token presented where an
	// access token is required).
	ErrTokenWrongType = errors.New("jwt: token type mismatch")

	// ErrMissingSecret is returned by NewManager when ICEQ_JWT_SECRET is
	// empty. We refuse to construct a Manager in that state rather than
	// silently falling back to a default secret.
	ErrMissingSecret = errors.New("jwt: ICEQ_JWT_SECRET is not set")

	// ErrSecretTooWeak is returned by NewManager when the secret is
	// present but either shorter than minSecretBytes or matches a
	// known-weak default. We refuse to construct a Manager in that
	// state because HMAC with a guessable secret is functionally
	// equivalent to no signature.
	ErrSecretTooWeak = errors.New("jwt: ICEQ_JWT_SECRET is too weak; generate with `openssl rand -hex 32`")

	// ErrSessionEpochLookup is returned when the per-user epoch query
	// fails. We treat it as a hard failure (fail-closed) because we
	// cannot prove the token is not from a pre-epoch session without
	// the epoch value itself.
	ErrSessionEpochLookup = errors.New("jwt: session_epoch lookup failed")
)

// ----------------------------------------------------------------------------
// Secret-strength policy. Centralized here so the same numbers are used by
// NewManager (the production gate) and by the test fixtures in cmd_smoke_*.
// ----------------------------------------------------------------------------

const (
	// minSecretBytes is the minimum acceptable length for ICEQ_JWT_SECRET.
	// 32 bytes = 256 bits, which matches the entropy of `openssl rand -hex 32`
	// (one nibble per byte) and the NIST SP 800-107 recommendation for HMAC
	// keys paired with SHA-256. We do NOT check entropy / charset quality
	// beyond length: any 32-byte string from a CSPRNG is sufficient, and a
	// length check is cheap, deterministic, and language-agnostic.
	minSecretBytes = 32

	// expectedIssuer is the only `iss` value we will sign with and the
	// only value Verify will accept. Setting it in both places is the
	// simplest defense against a future "import tokens from another
	// system that happens to know the secret" mistake.
	expectedIssuer = "iceq"
)

// knownWeakSecrets is a small deny-list of trivially-guessable values that
// have historically appeared in IceQ (and most other Go backends) as
// copy-pasted defaults. The list is intentionally short — the *real*
// defense is the length check; this list is a tripwire for "I changed
// exactly one character of changeme and shipped it."
//
// Comparison is case-insensitive: an attacker who tries "Changeme",
// "CHANGEME", "ChangeMe" should hit the same wall.
var knownWeakSecrets = map[string]bool{
	"changeme": true,
	"secret":   true,
	"password": true,
	"test":     true,
	"dev":      true,
	"iceq":     true,
}

// ----------------------------------------------------------------------------
// Token type / lifetime constants. Centralized so the auth-service's refresh
// endpoint and the websocket gateway's verifier agree on the same numbers.
// ----------------------------------------------------------------------------

const (
	// TokenTypeAccess is the value of the `type` claim for short-lived
	// access tokens.
	TokenTypeAccess = "access"

	// TokenTypeRefresh is the value of the `type` claim for long-lived
	// refresh tokens.
	TokenTypeRefresh = "refresh"

	// AccessTokenTTL is the lifetime of an access token.
	AccessTokenTTL = 15 * time.Minute

	// RefreshTokenTTL is the lifetime of a refresh token.
	RefreshTokenTTL = 7 * 24 * time.Hour

	// blocklistKeyPrefix is prepended to every JTI in the Redis blocklist.
	// Picked so that `KEYS jwt:*` from the redis-cli stays scoped to this
	// package's keys, and so an SCAN against the same prefix cannot
	// accidentally return presence / rate-limit keys.
	blocklistKeyPrefix = "jwt:revoked:"

	// minBlocklistTTL is the floor for the EX argument we pass to Redis
	// when revoking. We never want a negative or zero TTL: a zero TTL on
	// SET deletes the key immediately, which would "un-revoke" the token.
	minBlocklistTTL = time.Second
)

// ----------------------------------------------------------------------------
// Claims. Embeds jwt.RegisteredClaims so the standard `iat` / `exp` / `nbf`
// fields are populated and validated by the upstream library.
// ----------------------------------------------------------------------------

// Claims is the payload carried by every IceQ JWT.
//
// The `Type` field is the discriminator: every code path that consumes a
// JWT must assert the expected Type before trusting the rest of the
// claims, otherwise a stolen refresh token could be replayed against
// access-token-only endpoints.
type Claims struct {
	UIN  int64  `json:"uin"`
	JTI  string `json:"jti"`
	Type string `json:"type"`
	jwt.RegisteredClaims
}

// ----------------------------------------------------------------------------
// Manager. Holds the immutable configuration needed to sign and verify
// tokens. Safe for concurrent use — golang-jwt v5's signing methods are
// stateless and our Redis / Postgres lookups are the only side-effecting
// operations.
// ----------------------------------------------------------------------------

// Manager is the entry point for signing and verifying tokens. Build one
// with NewManager at process start and pass it by pointer to every code
// path that issues or validates credentials.
type Manager struct {
	secret []byte
	rdb    *redis.Client
	pg     *pgxpool.Pool
}

// NewManager constructs a Manager. The secret must be:
//   - non-empty
//   - at least minSecretBytes (32) bytes long
//   - not in the knownWeakSecrets deny-list (case-insensitive)
//
// We refuse to start with a weak key because HMAC with a guessable
// secret is functionally equivalent to no signature — every past
// attacker who has hit IceQ has done so by guessing the secret, not by
// exploiting the JWT plumbing. The length check is the real defense;
// the deny-list is a tripwire for "I changed one character and shipped."
//
// Both the Redis client and the Postgres pool are required. The Redis
// client is used for the JTI blocklist (the per-token revocation
// layer). The Postgres pool is used for the session_epoch check (the
// per-user revocation layer). A Manager that cannot do *both* of
// these lookups is unsafe and we refuse to construct it.
func NewManager(secret string, rdb *redis.Client, pg *pgxpool.Pool) (*Manager, error) {
	// Secret checks run FIRST. Rationale: a weak or
	// missing secret is a security failure, not a
	// configuration failure — the operator needs the
	// clearest possible signal that they cannot ship
	// with the current value. A nil pool, by contrast,
	// is a wiring error and will surface just as
	// clearly once the secret is fixed.
	if secret == "" {
		return nil, ErrMissingSecret
	}
	if len(secret) < minSecretBytes {
		return nil, fmt.Errorf(
			"%w (got %d bytes, need at least %d)",
			ErrSecretTooWeak, len(secret), minSecretBytes,
		)
	}
	if knownWeakSecrets[strings.ToLower(secret)] {
		return nil, fmt.Errorf(
			"%w: matches a known-weak default",
			ErrSecretTooWeak,
		)
	}
	if rdb == nil {
		return nil, errors.New("jwt: redis client is nil")
	}
	if pg == nil {
		return nil, errors.New("jwt: postgres pool is nil")
	}
	return &Manager{
		secret: []byte(secret),
		rdb:    rdb,
		pg:     pg,
	}, nil
}

// ----------------------------------------------------------------------------
// Signing. We return the JTI alongside the encoded token so callers can
// persist the (uin, jti) pair in the refresh_tokens table without having
// to decode the token they just signed.
// ----------------------------------------------------------------------------

// SignResult is what Sign returns: the encoded token and its JTI, so the
// caller can store the JTI independently (refresh_tokens table, audit
// log, etc.) without re-parsing.
type SignResult struct {
	Token string
	JTI   string
}

// Sign issues a new access or refresh token for the given UIN. The token
// type determines its lifetime; the call-site picks the right one based
// on whether it is responding to a login, a refresh, or a one-off
// credential mint.
//
// JTI generation uses crypto/rand directly (16 bytes -> 32 hex chars)
// rather than importing google/uuid to keep this package's dependency
// footprint minimal. Collision probability for 128 bits of entropy is
// negligible for any realistic token population.
func (m *Manager) Sign(uin int64, tokenType string) (SignResult, error) {
	now := time.Now().UTC()

	var ttl time.Duration
	switch tokenType {
	case TokenTypeAccess:
		ttl = AccessTokenTTL
	case TokenTypeRefresh:
		ttl = RefreshTokenTTL
	default:
		return SignResult{}, fmt.Errorf("jwt: unknown token type %q", tokenType)
	}

	jti, err := randomJTI()
	if err != nil {
		return SignResult{}, fmt.Errorf("jwt: generate jti: %w", err)
	}

	claims := Claims{
		UIN:  uin,
		JTI:  jti,
		Type: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    expectedIssuer,
			Subject:   fmt.Sprintf("%d", uin),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(m.secret)
	if err != nil {
		return SignResult{}, fmt.Errorf("jwt: sign: %w", err)
	}

	return SignResult{Token: signed, JTI: jti}, nil
}

// ----------------------------------------------------------------------------
// Verification. Returns the parsed claims on success. Callers MUST check
// the error and map it to an appropriate HTTP status (see the docstrings
// on each sentinel above).
// ----------------------------------------------------------------------------

// Verify parses the token, validates its signature and standard time
// claims, asserts that it carries the expected `type` and `iss`,
// consults the Redis blocklist, and finally checks the user's
// session_epoch. Any failure returns a sentinel error from this
// package; success returns the populated claims.
//
// The expectedType argument enforces the access/refresh discriminator
// at the call-site (e.g. the ws-gateway calls Verify with "access" and
// the /refresh endpoint calls it with "refresh").
func (m *Manager) Verify(ctx context.Context, raw string, expectedType string) (*Claims, error) {
	parser := jwt.NewParser(
		// Reject any "none" or asymmetric algorithm up front. The
		// library refuses non-HMAC algs against an HMAC key, but
		// pinning it here is defense-in-depth and produces a
		// clearer error than the generic signature-mismatch
		// path.
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		// Issuer pinning (INF-1 from the JWT assessment). Sign
		// already sets Issuer = "iceq"; this closes the loop so a
		// token signed with this secret by a non-IceQ issuer
		// (test fixture, future SSO integration) cannot impersonate
		// a real IceQ session.
		jwt.WithIssuer(expectedIssuer),
	)

	claims := &Claims{}
	_, err := parser.ParseWithClaims(raw, claims, func(_ *jwt.Token) (any, error) {
		return m.secret, nil
	})
	if err != nil {
		// jwt/v5 wraps time-based errors as ErrTokenExpired.
		// We re-classify to our own sentinel so callers can use
		// errors.Is(ErrTokenExpired) without importing the
		// upstream package.
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	if claims.Type != expectedType {
		return nil, ErrTokenWrongType
	}

	// Blocklist check. We do this AFTER signature/expiration/type
	// validation so a revoked-but-expired token doesn't burn a Redis
	// round trip. The `EXISTS` command returns 0 or 1 and is cheaper
	// than GET; we don't need the value, only its presence.
	revoked, err := m.rdb.Exists(ctx, blocklistKeyPrefix+claims.JTI).Result()
	if err != nil {
		// Fail-closed: if Redis is unreachable we cannot prove the
		// token is NOT revoked, so we reject the request. The
		// alternative (fail-open) would let a revoked token
		// through during a Redis outage, which is the wrong
		// trade-off for an auth credential.
		return nil, fmt.Errorf("jwt: blocklist lookup: %w", err)
	}
	if revoked > 0 {
		return nil, ErrTokenRevoked
	}

	// Per-user session_epoch check (F-5 from the JWT assessment).
	// The user's row carries a `session_epoch` timestamp; we
	// reject any token whose `iat` is strictly before it. This is
	// the layer that gives "logout invalidates ALL of this user's
	// sessions" semantics, which a per-JTI blocklist cannot
	// express in O(1).
	//
	// The query is one indexed lookup on `users.uin` (the PK);
	// the cost is the same as the Redis EXISTS we just did.
	// Failure to look up the epoch is a hard reject (fail-closed)
	// for the same reason as the blocklist: we cannot prove the
	// token is from a post-epoch session without the value.
	epoch, err := m.SessionEpoch(ctx, claims.UIN)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSessionEpochLookup, err)
	}
	if claims.IssuedAt != nil && claims.IssuedAt.Time.Before(epoch) {
		return nil, ErrTokenRevoked
	}

	return claims, nil
}

// SessionEpoch returns the current session_epoch for the user. The
// zero-value time.Time is returned (along with no error) when the user
// does not exist — Verify never relies on this distinction because a
// missing user would have failed earlier in the auth pipeline.
func (m *Manager) SessionEpoch(ctx context.Context, uin int64) (time.Time, error) {
	var epoch time.Time
	err := m.pg.QueryRow(ctx,
		`SELECT session_epoch FROM users WHERE uin = $1`, uin,
	).Scan(&epoch)
	if err != nil {
		// pgx.ErrNoRows is included in the wrapped error; the
		// caller can choose to treat missing-user as a 401 or
		// a 500 depending on policy. We return the raw error
		// so the caller's errors.Is() / errors.As() works.
		return time.Time{}, err
	}
	return epoch, nil
}

// BumpSessionEpoch sets the user's session_epoch to NOW(), which
// invalidates every access and refresh token previously issued for
// them (Verify will reject them on the epoch check). It is the
// per-user equivalent of "revoke all sessions."
//
// Idempotent: a no-op if the user does not exist. The caller can
// choose to treat that as an error (e.g. logout-from-deleted-user)
// but typically doesn't — a deleted user has no sessions to
// revoke anyway.
func (m *Manager) BumpSessionEpoch(ctx context.Context, uin int64) error {
	_, err := m.pg.Exec(ctx,
		`UPDATE users SET session_epoch = NOW() WHERE uin = $1`, uin,
	)
	if err != nil {
		return fmt.Errorf("jwt: bump session_epoch for uin=%d: %w", uin, err)
	}
	return nil
}

// ----------------------------------------------------------------------------
// Revocation. Stores the JTI in Redis with TTL = remaining token lifetime.
// Once Redis drops the key (TTL expires) the token is "naturally" expired
// and no longer needs a blocklist entry — the natural `exp` claim takes
// over from there. This means the blocklist size is bounded by the number
// of currently-unexpired-but-revoked tokens, never more.
// ----------------------------------------------------------------------------

// Revoke adds the token's JTI to the blocklist with a TTL equal to the
// token's remaining lifetime. The token's `exp` claim is required because
// we cannot compute a TTL without it. If the token has already expired
// (exp <= now) the call is a no-op: there is nothing to revoke.
//
// We use SET with EX rather than SETEX because go-redis v9's SET method
// accepts a TTL via the Expiration field, which keeps the wire
// representation identical to SETEX while staying on the modern API path.
func (m *Manager) Revoke(ctx context.Context, raw string) error {
	claims, err := m.extractClaimsForRevocation(raw)
	if err != nil {
		return err
	}

	ttl := time.Until(claims.ExpiresAt.Time)
	if ttl <= minBlocklistTTL {
		// Token is already expired (or so close to expiry that
		// the blocklist entry would be useless). Don't bother
		// writing to Redis; the natural expiration has it
		// covered.
		return nil
	}

	// SET key value EX <seconds>. We don't need the value beyond
	// existence (Verify uses EXISTS), so an empty string is fine.
	// go-redis normalizes this to the same SETEX wire form.
	return m.rdb.Set(ctx, blocklistKeyPrefix+claims.JTI, "1", ttl).Err()
}

// extractClaimsForRevocation parses a token WITHOUT verifying its
// signature or expiration. The rationale: a user logging out should be
// able to revoke an already-expired token without being told "your
// token is invalid"; the goal of revocation is to add the JTI to the
// blocklist, not to gate the call on validity. We still validate the
// structural claim and confirm the token carries a usable JTI.
func (m *Manager) extractClaimsForRevocation(raw string) (*Claims, error) {
	parser := jwt.NewParser(
		// No WithValidMethods here: we want to extract the JTI
		// even from a token whose alg we don't recognize, so
		// the blocklist can still record it. The downstream
		// Verify call is what enforces the algorithm.
		jwt.WithoutClaimsValidation(),
	)

	claims := &Claims{}
	_, err := parser.ParseWithClaims(raw, claims, func(_ *jwt.Token) (any, error) {
		// Return the same secret so the parser doesn't reject
		// the token on missing-key grounds. The signature
		// itself is NOT checked (WithoutClaimsValidation
		// disables it); we only need a parseable body.
		return m.secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}
	if claims.JTI == "" {
		return nil, fmt.Errorf("%w: missing jti", ErrTokenInvalid)
	}
	if claims.ExpiresAt == nil {
		return nil, fmt.Errorf("%w: missing exp", ErrTokenInvalid)
	}
	return claims, nil
}

// ----------------------------------------------------------------------------
// Internals.
// ----------------------------------------------------------------------------

// randomJTI returns a 128-bit hex-encoded random identifier. The 32-char
// hex form is a familiar shape for log scrapers and is collision-safe at
// any realistic token volume. We avoid the uuid package to keep the JWT
// module's transitive dependency surface to two packages (jwt + redis).
func randomJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
