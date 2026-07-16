// Package handlers — panicwipe.go
//
// PanicWipe is the explicit authenticated account-erasure operation. It
// removes every key, every
// contact, every group membership, every prekey bundle, every refresh
// token, and every identifying row is gone. The user's record is
// anonymized (username -> "deleted_<UIN>", email -> NULL, identity_key
// -> "") so a future attacker cannot register with the same email or
// impersonate the wiped user via their public key.
//
// Design constraints from the spec:
//
//  1. PG atomicity, Scylla best-effort. Everything inside Postgres
//     happens in a single transaction so the partial state is never
//     visible to a concurrent reader. Scylla deletes run AFTER the
//     PG commit. We log if a Scylla delete fails, but we do NOT
//     fail the wipe — ciphertext without the matching private keys
//     is a successful cryptographic erase.
//
//  2. Audit-trail discipline. The log line is timestamp + UIN + the
//     constant string "panic_wipe_executed". We do NOT log
//     passwords, the count that triggered the wipe, the source IP,
//     or any of the field values being scrubbed. A wipe that fires
//     is itself a security event; the audit log should be useful to
//     incident response, not a side channel for an attacker who
//     has read access to logs.
//
//  3. Blocklist with TTL. The wipe also sets
//     `jwt:blocklist:wipe:{uin}` in Redis with a 7-day TTL. The
//     ws-gateway checks this key on every inbound message; if it
//     exists, the connection is closed with code 4403 (custom
//     close code meaning "account wiped, clear local storage").
//     The 7-day window is a comfortable bound: access tokens
//     expire in 15 minutes by default, so by then any token that
//     could have been used is long gone.
package handlers

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/iceq/iceq/shared/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// ----------------------------------------------------------------------------
// Constants. Pulled out of the function body so the wipe logic reads
// top-down ("a wipe sets a blocklist key with this TTL") rather than
// being interrupted by a magic-number footnote.
// ----------------------------------------------------------------------------

const (
	// legacyLoginAttemptsKeyPrefix is retained only so an explicit wipe can
	// remove counters left by older deployments.
	legacyLoginAttemptsKeyPrefix = "login_attempts:"

	// panicWipeBlocklistPrefix scopes the per-user wipe
	// blocklist. The ws-gateway does an EXISTS on this key for
	// every message; the key has a TTL (see
	// panicWipeBlocklistTTL) so it eventually disappears
	// without manual cleanup.
	panicWipeBlocklistPrefix = "jwt:blocklist:wipe:"

	// panicWipeBlocklistTTL is the lifetime of the wipe key.
	// 7 days is well past the longest access-token TTL (15
	// minutes) and well past the longest refresh-token TTL (30
	// days by spec) for any token that was already issued and
	// could still be in flight. After 7 days, even a clock
	// skew or an offline client with a stale token cannot
	// re-attach, so the key can safely expire.
	panicWipeBlocklistTTL = 7 * 24 * time.Hour

	// presenceKeyPrefix is the convention used by the
	// presence-service. We hard-code it here rather than
	// importing the presence package, because importing a
	// service-level package from the auth-service would
	// create a circular dep (presence imports auth for token
	// verification, auth would import presence for cleanup).
	// The string contract is documented in both packages.
	presenceKeyPrefix = "presence:"
)

// panicWipeBlocklistKey returns the Redis key under which the
// ws-gateway checks for a wiped user. Exported as a helper so the
// ws-gateway can use the same string format without re-deriving it.
func panicWipeBlocklistKey(uin int64) string {
	return panicWipeBlocklistPrefix + itoa(uin)
}

// itoa is a small wrapper around strconv.FormatInt. Kept as a
// helper so the call sites read like English
// (legacyLoginAttemptsKeyPrefix + itoa(uin)) rather than the noisier
// strconv.FormatInt(uin, 10). UINs are non-negative by
// construction (the sequence starts at 10_000_000) but the helper
// is robust to negatives for testing.
func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}

// ----------------------------------------------------------------------------
// PanicWipe.
//
// Performs the 11-step wipe as specified. The PG portion is a single
// transaction; the Scylla portion is best-effort. Returns the first
// error encountered, but the function is designed to be idempotent —
// calling it twice on the same uin is a no-op for the second call
// (every query has either a WHERE clause that matches a no-longer-
// matching row, or an idempotent shape like DEL).
//
// Errors are logged but not re-raised for the Scylla portion because:
//
//  1. PG has already committed; the user's keys are gone.
//  2. Ciphertext in Scylla is unreadable without the keys.
//  3. A future "Scylla message GC" pass can clean up the orphans.
//
// For the PG portion, an error rolls back the whole transaction so
// the wipe either happened or it didn't, never partially.
// ----------------------------------------------------------------------------

// MessageStore is the optional interface the wipe calls to delete
// the user's ciphertext from ScyllaDB. We define it as a small
// interface in this package so the auth-service does not import a
// Scylla client (the auth-service has no direct Scylla connection
// at the time of step 3). When the message-service comes online in
// a later step, it can satisfy this interface with its gocql
// session and main.go wires the concrete value in.
//
// The interface is intentionally tiny: two methods, one per
// keyspace that holds user-addressable ciphertext.
type MessageStore interface {
	DeleteUserMessages(ctx context.Context, uin int64) error
	DeleteUserGroupMessages(ctx context.Context, uin int64) error
}

// PanicWipeDeps bundles the explicit wipe's dependencies.
type PanicWipeDeps struct {
	// Pool is the PG pool. Required.
	Pool *pgxpool.Pool
	// Redis is the Redis client. Required.
	Redis *redis.Client
	// Scylla is the optional Scylla session. May be nil if the
	// deployment is not running Scylla (e.g. a local
	// dev environment that uses Postgres for everything). When
	// nil, the Scylla portion is logged and skipped. The
	// interface is satisfied by the message-service's gocql
	// session in a later step.
	Scylla MessageStore
}

// ManualPanicWipeDeps wires the authenticated manual panic-wipe
// endpoint. Wipe defaults to PanicWipe; tests can replace it so
// the handler contract stays unit-testable without a live PG/Redis
// stack.
type ManualPanicWipeDeps struct {
	PanicWipeDeps
	Wipe    func(context.Context, PanicWipeDeps, int64) error
	Timeout time.Duration
}

// NewManualPanicWipeHandler returns the handler mounted at
// POST /api/auth/panic-wipe. The route MUST be wrapped with
// BearerAuth; the authenticated UIN is the only input to the wipe.
func NewManualPanicWipeHandler(deps ManualPanicWipeDeps) http.HandlerFunc {
	if deps.Wipe == nil {
		deps.Wipe = PanicWipe
	}
	if deps.Timeout <= 0 {
		deps.Timeout = 10 * time.Second
	}

	return func(w http.ResponseWriter, r *http.Request) {
		uin, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), deps.Timeout)
		defer cancel()

		if err := deps.Wipe(ctx, deps.PanicWipeDeps, uin); err != nil {
			log.Printf("[auth-service] manual panic wipe failed")
			clearSessionCookies(w)
			writeError(w, http.StatusServiceUnavailable, "PANIC_WIPE_FAILED",
				"could not wipe account; please retry")
			return
		}

		clearSessionCookies(w)
		w.WriteHeader(http.StatusNoContent)
	}
}

// PanicWipe executes the full wipe sequence. If ctx expires mid-wipe the
// transaction is rolled back and the function returns ctx.Err().
//
// The function logs the timestamp + UIN + sentinel string on
// success. Any other log line omits identifying details.
func PanicWipe(ctx context.Context, deps PanicWipeDeps, uin int64) error {
	if deps.Pool == nil {
		return errors.New("panicwipe: pg pool is nil")
	}
	if deps.Redis == nil {
		return errors.New("panicwipe: redis client is nil")
	}

	// ----- 1. PG transaction -------------------------------------------------
	// Every PG delete/anonymize inside one tx so a concurrent
	// reader never sees a half-wiped row. The tx is committed
	// BEFORE we touch Scylla (see below) because XA between
	// Postgres and Scylla is not available.
	tx, err := deps.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("panicwipe: begin tx: %w", err)
	}
	// Defer a rollback that fires only if the tx is still open.
	// After Commit() the tx is closed and the Rollback call
	// returns ErrTxClosed which we explicitly ignore.
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	// 3. DELETE FROM one_time_prekeys WHERE uin = $1
	// (ScyllaDB deletes — steps 1, 2 — run AFTER the PG commit
	//  in the best-effort block below; they cannot be folded
	//  into the PG transaction because they touch a different
	//  data store.)
	if _, err := tx.Exec(ctx, qWipeOneTimePrekeys, uin); err != nil {
		return fmt.Errorf("panicwipe: delete one_time_prekeys: %w", err)
	}

	// 4. DELETE FROM prekey_bundles WHERE uin = $1
	if _, err := tx.Exec(ctx, qWipePrekeyBundles, uin); err != nil {
		return fmt.Errorf("panicwipe: delete prekey_bundles: %w", err)
	}

	// 5. DELETE FROM refresh_tokens WHERE uin = $1
	if _, err := tx.Exec(ctx, qWipeRefreshTokens, uin); err != nil {
		return fmt.Errorf("panicwipe: delete refresh_tokens: %w", err)
	}

	// 6. DELETE FROM group_members WHERE uin = $1
	if _, err := tx.Exec(ctx, qWipeGroupMemberships, uin); err != nil {
		return fmt.Errorf("panicwipe: delete group_members: %w", err)
	}

	// 7. DELETE FROM contacts WHERE owner_uin = ? OR target_uin = ?
	if _, err := tx.Exec(ctx, qWipeContacts, uin); err != nil {
		return fmt.Errorf("panicwipe: delete contacts: %w", err)
	}

	// Delete the security-settings row too. Done in the same
	// tx so the post-wipe state is internally consistent: no
	// settings, no prekey bundle, no prekeys, no membership.
	if _, err := tx.Exec(ctx, qWipeSecuritySettings, uin); err != nil {
		return fmt.Errorf("panicwipe: delete user_security_settings: %w", err)
	}
	if _, err := tx.Exec(ctx, qMarkAccountWiped, uin); err != nil {
		return fmt.Errorf("panicwipe: mark account wiped: %w", err)
	}

	// 8. UPDATE users SET ... (anonymize in place; the row stays
	//    for FK integrity)
	if _, err := tx.Exec(ctx, qWipeUser, uin); err != nil {
		return fmt.Errorf("panicwipe: anonymize users row: %w", err)
	}

	// Commit the PG portion. After this point the wipe is
	// observable to every other connection.
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("panicwipe: commit: %w", err)
	}

	// ----- 9. Wipe blocklist ------------------------------------------------
	// Sets the per-user blocklist key. The ws-gateway does
	// EXISTS on this key for every message; if it returns 1,
	// the gateway closes the connection with code 4403.
	// 7-day TTL: long enough to cover every active token, short
	// enough to keep Redis tidy.
	if err := deps.Redis.Set(ctx,
		panicWipeBlocklistKey(uin),
		"1",
		panicWipeBlocklistTTL,
	).Err(); err != nil {
		return fmt.Errorf("panicwipe: revoke active sessions: %w", err)
	}

	// Remove any failed-login counter left by a legacy deployment.
	if err := deps.Redis.Del(ctx, legacyLoginAttemptsKeyPrefix+itoa(uin)).Err(); err != nil {
		log.Printf("[auth-service] panicwipe: del legacy counter failed: %v", err)
	}

	// ----- 11. DEL presence:{uin} -------------------------------------------
	// Best-effort. The presence-service may or may not have a
	// row; if it does, removing it speeds up the "user is
	// offline" transition for any client that has the
	// (now-defunct) UIN in a recent-chat list.
	if err := deps.Redis.Del(ctx, presenceKeyPrefix+itoa(uin)).Err(); err != nil {
		log.Printf("[auth-service] panicwipe: del presence failed: %v", err)
	}

	// Ciphertext cleanup is deliberately last. It receives an independent,
	// bounded context so a slow Scylla node cannot consume the request budget
	// needed for token/session revocation above.
	if deps.Scylla != nil {
		cleanupScylla(ctx, deps.Scylla, uin, 5*time.Second)
	}

	// Audit log contains no request or account metadata.
	log.Printf("[auth-service] panic_wipe_executed")
	return nil
}

func cleanupScylla(parent context.Context, store MessageStore, uin int64, timeout time.Duration) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), timeout)
	defer cancel()
	if err := store.DeleteUserMessages(cleanupCtx, uin); err != nil {
		log.Printf("[auth-service] panicwipe: scylla delete messages failed: %v (ciphertext retained; keys gone)", err)
	}
	if err := store.DeleteUserGroupMessages(cleanupCtx, uin); err != nil {
		log.Printf("[auth-service] panicwipe: scylla delete group_messages failed: %v (ciphertext retained; keys gone)", err)
	}
}
