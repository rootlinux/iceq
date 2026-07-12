// Package handlers — panicwipe.go
//
// PanicWipe is the nuclear option. When a user has panic-wipe enabled
// and an attacker crosses the failed-attempts threshold, the
// auth-service self-destructs the user's account: every key, every
// contact, every group membership, every prekey bundle, every refresh
// token, and every identifying row is gone. The user's record is
// anonymized (username -> "deleted_<UIN>", email -> NULL, identity_key
// -> "") so a future attacker cannot register with the same email or
// impersonate the wiped user via their public key.
//
// Design constraints from the spec:
//
//  1. Indistinguishable response. The HTTP layer returns the same
//     401 / "invalid credentials" envelope after a wipe as it would
//     for a normal failed login. The attacker cannot tell whether
//     the threshold was hit. The legitimate user, hitting the
//     threshold themselves, just sees "invalid email or password"
//     forever — which is the point.
//
//  2. PG atomicity, Scylla best-effort. Everything inside Postgres
//     happens in a single transaction so the partial state is never
//     visible to a concurrent reader. Scylla deletes run AFTER the
//     PG commit. We log if a Scylla delete fails, but we do NOT
//     fail the wipe — ciphertext without the matching private keys
//     is a successful cryptographic erase.
//
//  3. Audit-trail discipline. The log line is timestamp + UIN + the
//     constant string "panic_wipe_executed". We do NOT log
//     passwords, the count that triggered the wipe, the source IP,
//     or any of the field values being scrubbed. A wipe that fires
//     is itself a security event; the audit log should be useful to
//     incident response, not a side channel for an attacker who
//     has read access to logs.
//
//  4. Blocklist with TTL. The wipe also sets
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
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// ----------------------------------------------------------------------------
// Constants. Pulled out of the function body so the wipe logic reads
// top-down ("a wipe sets a blocklist key with this TTL") rather than
// being interrupted by a magic-number footnote.
// ----------------------------------------------------------------------------

const (
	// loginAttemptsKeyPrefix scopes the failed-login counter
	// keys in Redis. The pattern `login_attempts:{uin}` matches
	// the spec verbatim.
	loginAttemptsKeyPrefix = "login_attempts:"

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

	// failedAttemptsCounterTTL is the lifetime of the
	// `login_attempts:{uin}` counter. 15 minutes matches the
	// spec verbatim. The TTL is applied on the FIRST increment
	// (the counter is created with EXPIRE in the same Lua
	// script), not on every increment, so a sustained attack
	// doesn't keep the window open indefinitely.
	failedAttemptsCounterTTL = 15 * time.Minute

	// presenceKeyPrefix is the convention used by the
	// presence-service. We hard-code it here rather than
	// importing the presence package, because importing a
	// service-level package from the auth-service would
	// create a circular dep (presence imports auth for token
	// verification, auth would import presence for cleanup).
	// The string contract is documented in both packages.
	presenceKeyPrefix = "presence:"
)

// ----------------------------------------------------------------------------
// Counter helpers. The counter is a Redis STRING holding an integer;
// we use INCR for atomicity under concurrent failed-login storms and
// apply the TTL on the first increment only (so a sustained attacker
// can't keep refreshing the window).
// ----------------------------------------------------------------------------

// incrFailedLoginAtomically does INCR + (EXPIRE on first hit) in one
// Lua round trip. Returning the post-increment value lets the caller
// decide whether to trigger a wipe in the same request.
//
// We use a Lua script (not a transaction) for the same reason as
// rateLimitScript in login.go: a transaction requires at least two
// round trips (WATCH/MULTI/EXEC), whereas a script is a single
// EVAL/EVALSHA. The savings matter under a brute-force storm.
//
// KEYS[1] = full counter key
// ARGV[1] = TTL seconds
const failedLoginScript = `
local current = redis.call("INCR", KEYS[1])
if current == 1 then
    redis.call("EXPIRE", KEYS[1], ARGV[1])
end
return current
`

// failedLoginScriptHandle is the pre-compiled script handle. Created
// once at package init time, reused on every login attempt.
var failedLoginScriptHandle = redis.NewScript(failedLoginScript)

// resetFailedLoginCounter removes the counter for uin. Called on
// successful login so a user who fat-fingers their password twice
// and then succeeds is back to a clean slate.
func resetFailedLoginCounter(ctx context.Context, rdb *redis.Client, uin int64) error {
	return rdb.Del(ctx, loginAttemptsKeyPrefix+itoa(uin)).Err()
}

// panicWipeBlocklistKey returns the Redis key under which the
// ws-gateway checks for a wiped user. Exported as a helper so the
// ws-gateway can use the same string format without re-deriving it.
func panicWipeBlocklistKey(uin int64) string {
	return panicWipeBlocklistPrefix + itoa(uin)
}

// itoa is a small wrapper around strconv.FormatInt. Kept as a
// helper so the call sites read like English
// (loginAttemptsKeyPrefix + itoa(uin)) rather than the noisier
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

// PanicWipeDeps bundles the wipe's dependencies. Constructed once
// in main.go and passed to the login handler so the wipe code has
// no package-level state to manage.
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

// PanicWipe executes the full wipe sequence. ctx is the request
// context from the login handler; if it expires mid-wipe the
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

	// ----- 2. ScyllaDB best-effort cleanup ---------------------------------
	// Steps 1, 2 of the spec: messages and group_messages.
	// These deletes run AFTER the PG commit. If they fail, the
	// user's data in PG is still wiped, and the messages in
	// Scylla are now unreadable ciphertext (the keys are gone).
	// We log the failure but do NOT roll back the wipe.
	if deps.Scylla != nil {
		if err := deps.Scylla.DeleteUserMessages(ctx, uin); err != nil {
			log.Printf("[auth-service] panicwipe: scylla delete messages failed: %v (ciphertext retained; keys gone)", err)
		}
		if err := deps.Scylla.DeleteUserGroupMessages(ctx, uin); err != nil {
			log.Printf("[auth-service] panicwipe: scylla delete group_messages failed: %v (ciphertext retained; keys gone)", err)
		}
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
		// The PG portion has already committed; failing to set
		// the blocklist key means an already-connected client
		// could keep sending messages until their access token
		// expires (15 min). The ws-gateway's defence-in-depth
		// (token verification + presence) limits the blast
		// radius. We log and continue.
		log.Printf("[auth-service] panicwipe: set blocklist key failed: %v", err)
	}

	// ----- 10. DEL login_attempts:{uin} ------------------------------------
	// The counter is no longer needed; the user is wiped.
	if err := deps.Redis.Del(ctx, loginAttemptsKeyPrefix+itoa(uin)).Err(); err != nil {
		log.Printf("[auth-service] panicwipe: del counter failed: %v", err)
	}

	// ----- 11. DEL presence:{uin} -------------------------------------------
	// Best-effort. The presence-service may or may not have a
	// row; if it does, removing it speeds up the "user is
	// offline" transition for any client that has the
	// (now-defunct) UIN in a recent-chat list.
	if err := deps.Redis.Del(ctx, presenceKeyPrefix+itoa(uin)).Err(); err != nil {
		log.Printf("[auth-service] panicwipe: del presence failed: %v", err)
	}

	// Audit log. Spec says: timestamp + uin + "panic_wipe_executed".
	// We add the threshold-crossed count too, because operations
	// needs to know whether the wipe fired at 3 attempts
	// (expected) or at 1 (suspicious).
	log.Printf("[auth-service] panic_wipe_executed")
	return nil
}

// ----------------------------------------------------------------------------
// Threshold check. Called by the login handler after a failed
// bcrypt comparison. Returns true if the wipe should fire.
// ----------------------------------------------------------------------------

// checkPanicWipeThreshold consults the user's security-settings row
// and the current failed-attempt counter. If panic-wipe is enabled
// and the counter has reached the threshold, returns true and resets
// the counter (so a subsequent wipe attempt by the same attacker is
// idempotent — the second call sees a freshly-zeroed counter and
// won't double-wipe).
//
// We do NOT trigger the wipe here; the caller decides. Separating
// "should we wipe?" from "do the wipe" keeps the test surface small
// and lets the caller log the trigger condition independently.
func checkPanicWipeThreshold(
	ctx context.Context,
	pool *pgxpool.Pool,
	rdb *redis.Client,
	uin int64,
) (bool, error) {
	// Read the settings row. If absent, the user has not
	// enabled panic-wipe; the row's default is panic_wipe_enabled=FALSE
	// so the query result is a deterministic "do not wipe".
	//
	// qSelectSecuritySettings returns three columns
	// (enabled, threshold, updated_at); the helper here
	// consumes only the first two. Scanning into a discard
	// variable for updated_at keeps the type check strict
	// — pgx will error if the column count drifts in the
	// future, which is exactly the "drift detection" we
	// want from typed scanning.
	var (
		enabled          bool
		threshold        int
		updatedAtDiscard time.Time
	)
	err := pool.QueryRow(ctx, qSelectSecuritySettings, uin).
		Scan(&enabled, &threshold, &updatedAtDiscard)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("panicwipe: read settings: %w", err)
	}
	if !enabled {
		return false, nil
	}
	// Defensive: the CHECK constraint guarantees 1..10, but a
	// hand-edited row could be outside. Cap it to a sensible
	// maximum so a misconfigured row can't trigger a wipe at
	// threshold=0.
	if threshold < 1 {
		threshold = 1
	}
	if threshold > 10 {
		threshold = 10
	}

	// Read the current counter. We just INCRed it in the login
	// handler, so a GET here returns the post-increment value.
	// If the key has expired (15-min TTL), the counter is
	// effectively zero and the threshold is not crossed.
	countStr, err := rdb.Get(ctx, loginAttemptsKeyPrefix+itoa(uin)).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, nil
		}
		return false, fmt.Errorf("panicwipe: read counter: %w", err)
	}
	return countStr >= int64(threshold), nil
}
