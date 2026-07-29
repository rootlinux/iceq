// Package handlers — panicwipe.go
//
// PanicWipe is the explicit authenticated account-erasure operation.
//
// Execution order is critical:
//  1. IMMEDIATE: Set Redis blocklist key to revoke all sessions.
//  2. Capture exact file-object keys from Postgres BEFORE they are deleted.
//  3. Atomic PG transaction: delete prekeys, tokens, memberships, contacts,
//     file ownership, security settings, disable the account (set
//     session_epoch), insert the transient wiped_accounts marker, AND
//     insert a durable wipe_job row. Every piece is committed atomically
//     with the account mutation — if any insert fails, the entire
//     transaction rolls back so the account is never disabled without a
//     corresponding cleanup job and wiped-account marker. This means a
//     wiped user already fails every wiped_accounts-aware check
//     (BearerAuth, DM/group history) the instant this transaction commits
//     — before the HTTP response is even sent, and long before any
//     worker has polled.
//  4. Best-effort Redis auxiliary cleanup.
//
// After the PG transaction commits, a background worker picks up the job
// and executes Scylla, NATS, and MinIO cleanup. Only after every external
// storage layer confirms deletion does the worker execute a final PG
// transaction that permanently deletes the user row, wiped_accounts
// entries, and the completed wipe-job row — leaving zero rows associated
// with the wiped UIN in any PostgreSQL table. There is no "deleted_<UIN>"
// tombstone, and no permanent wiped-account record survives cleanup.
//
// Recovery: if the blocklist SET succeeds but any subsequent step before
// the PG commit fails, the blocklist key is removed so the account is not
// permanently inaccessible. The caller can retry the wipe.
//
// Always returns 202 Accepted — storage cleanup continues asynchronously
// via the persisted wipe job. The client must clear local state immediately
// without waiting for the background worker to finish.
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

type NatsCleaner interface {
	PurgeUserStreams(ctx context.Context, uin int64) error
}

type MinioCleaner interface {
	DeleteUserObjects(ctx context.Context, uin int64, fileKeys []string) error
	DeleteUserGrants(ctx context.Context, uin int64) error
}

// RedisCleaner removes user-scoped keys from Redis during durable wipe
// cleanup.
//
// Two-phase deletion:
//   1. CleanupUserKeys — deletes user data keys (presence, poll, undelivered,
//      login attempts). Called during the "redis" wipe phase. Does NOT
//      delete the blocklist key.
//   2. DeleteBlocklistKey — deletes the panic-wipe blocklist key
//      (jwt:blocklist:wipe:{uin}). Called ONLY after the final PG erasure
//      transaction commits (user row no longer exists, all connections
//      terminated). Until then the blocklist key must remain to reject
//      in-flight sessions.
//
// Blocklist key lifetime:
//   - Set by PanicWipe with a 7-day TTL (panicWipeBlocklistTTL).
//   - Removed by the worker after final PG erasure confirms the user row
//     is permanently deleted.
//   - If the worker never runs (e.g., crash before final erasure), the
//     key self-expires after 7 days, which exceeds the maximum access-token
//     TTL (15 min) and maximum refresh-token TTL (30 days by spec).
//   - Zero server footprint is achieved only after the blocklist key is
//     confirmed deleted by the wipe worker. If the worker cannot reach
//     Redis, the wipe_job row remains as a durable retry marker and the
//     key self-expires after 7 days.
type RedisCleaner interface {
	CleanupUserKeys(ctx context.Context, uin int64) error
	DeleteBlocklistKey(ctx context.Context, uin int64) error
}

// redisWipeAdapter wraps *redis.Client to satisfy RedisCleaner.
type redisWipeAdapter struct {
	rdb *redis.Client
}

// NewRedisWipeCleaner returns a RedisCleaner backed by the given Redis
// client. The returned cleaner deletes every user-scoped key except the
// wipe blocklist key.
func NewRedisWipeCleaner(rdb *redis.Client) RedisCleaner {
	return &redisWipeAdapter{rdb: rdb}
}

func (a *redisWipeAdapter) CleanupUserKeys(ctx context.Context, uin int64) error {
	s := itoa(uin)

	// Deterministic per-user keys — DEL directly.
	// The blocklist key (jwt:blocklist:wipe:{uin}) is NOT deleted here;
	// it is removed by DeleteBlocklistKey after final PG erasure.
	for _, key := range []string{
		"presence:" + s,
		"undelivered:" + s,
		"poll:stream:" + s,
		"poll:cursors:" + s,
		"poll:cursor-order:" + s,
		"login_attempts:" + s,
	} {
		if err := a.rdb.Del(ctx, key).Err(); err != nil {
			return fmt.Errorf("redis del %s: %w", key, err)
		}
	}

	// Hash-tag poll keys — SCAN + DEL.
	patterns := []string{
		"poll:{" + s + "}:*",
		"poll:{" + s + "}",
	}
	for _, pattern := range patterns {
		if err := deletePattern(ctx, a.rdb, pattern); err != nil {
			return fmt.Errorf("redis scan+del %s: %w", pattern, err)
		}
	}

	return nil
}

// DeleteBlocklistKey removes the panic-wipe session-revocation key.
// Must only be called after the final PG erasure transaction commits —
// at that point the user row no longer exists and all connections have
// been terminated via the ws-gateway's blocklist check.
func (a *redisWipeAdapter) DeleteBlocklistKey(ctx context.Context, uin int64) error {
	key := panicWipeBlocklistKey(uin)
	if err := a.rdb.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("redis del blocklist %s: %w", key, err)
	}
	return nil
}

// Existing helper — reused by both HTTP-handler best-effort cleanup
// and the durable worker phase.

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
	NATS  NatsCleaner  // optional: nil means skip NATS cleanup
	Minio MinioCleaner // optional: nil means skip MinIO cleanup
}

// ManualPanicWipeDeps wires the authenticated manual panic-wipe
// endpoint. Wipe defaults to PanicWipe; tests can replace it so
// the handler contract stays unit-testable without a live PG/Redis
// stack. LookupPanicPinHash defaults to a Postgres-backed lookup via
// PanicWipeDeps.Pool when Pool is set; tests inject a stub instead of
// standing up a real database, matching Wipe's pattern. A nil Pool and
// nil override both mean "the panic-PIN feature is off" -- the wipe
// proceeds unconditionally, which is also the pre-PIN behavior every
// existing caller relies on.
type ManualPanicWipeDeps struct {
	PanicWipeDeps
	Wipe                    func(context.Context, PanicWipeDeps, int64) (int64, error)
	Timeout                 time.Duration
	LookupPanicPinHash      func(ctx context.Context, uin int64) (string, error)
	ChallengeSignatureDeps  *ChallengeSignatureDeps
}

type manualPanicWipeRequest struct {
	Pin         string `json:"pin,omitempty"`
	ChallengeID string `json:"challenge_id,omitempty"`
	Signature   string `json:"signature,omitempty"`
}

// NewManualPanicWipeHandler returns the handler mounted at
// POST /api/auth/panic-wipe. The route MUST be wrapped with
// BearerAuth; the authenticated UIN and (if the account configured one)
// the panic PIN are the only inputs to the wipe.
func NewManualPanicWipeHandler(deps ManualPanicWipeDeps) http.HandlerFunc {
	if deps.Wipe == nil {
		deps.Wipe = PanicWipe
	}
	if deps.Timeout <= 0 {
		deps.Timeout = 10 * time.Second
	}
	if deps.LookupPanicPinHash == nil && deps.Pool != nil {
		pool := deps.Pool
		deps.LookupPanicPinHash = func(ctx context.Context, uin int64) (string, error) {
			var hash *string
			if err := pool.QueryRow(ctx, qSelectPanicPinHash, uin).Scan(&hash); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return "", nil
				}
				return "", err
			}
			if hash == nil {
				return "", nil
			}
			return *hash, nil
		}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		uin, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}
		var req manualPanicWipeRequest
		if !decodeJSON(w, r, &req, 256) {
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), deps.Timeout)
		defer cancel()

		// Determine which verifier the account uses by inspecting server-side state.
		// The server decides, never the client.
		hasWipePublicKey := false
		if deps.ChallengeSignatureDeps != nil && deps.ChallengeSignatureDeps.LookupWipePublicKey != nil {
			pubKey, err := deps.ChallengeSignatureDeps.LookupWipePublicKey(ctx, uin)
			if err != nil {
				writeError(w, http.StatusServiceUnavailable, "PANIC_WIPE_FAILED", "could not verify account state; please retry")
				return
			}
			hasWipePublicKey = pubKey != nil
		}

		if hasWipePublicKey {
			// Challenge-signature path is mandatory for migrated accounts.
			if req.ChallengeID == "" || req.Signature == "" {
				writeError(w, http.StatusUnauthorized, "SIGNATURE_REQUIRED", "challenge_id and signature are required")
				return
			}
			if err := VerifyWipeSignature(ctx, *deps.ChallengeSignatureDeps, uin, req.ChallengeID, req.Signature); err != nil {
				log.Printf("[auth-service] panic wipe signature verification failed for UIN %d: %v", uin, err)
				writeError(w, http.StatusUnauthorized, "INVALID_SIGNATURE", "invalid or expired signature")
				return
			}
			// Successful challenge-signature → retire any lingering PIN hash.
			if deps.Pool != nil {
				if _, err := deps.Pool.Exec(ctx, qNullPanicPinHash, uin); err != nil {
					log.Printf("[auth-service] panicwipe: null pin hash after signature verification failed: %v", err)
				}
			}
		} else {
			// Legacy PIN path: check if a PIN hash exists.
			var pinHash string
			if deps.LookupPanicPinHash != nil {
				var err error
				pinHash, err = deps.LookupPanicPinHash(ctx, uin)
				if err != nil {
					writeError(w, http.StatusServiceUnavailable, "PANIC_WIPE_FAILED", "could not wipe account; please retry")
					return
				}
			}
			if pinHash != "" {
				if !verifyPassword(pinHash, req.Pin).OK {
					writeError(w, http.StatusUnauthorized, "INVALID_PIN", "incorrect panic PIN")
					return
				}
			} else {
				// No wipe_public_key AND no panic_pin_hash → security setup required.
				writeError(w, http.StatusForbidden, "SECURITY_SETUP_REQUIRED", "panic wipe requires security setup (wipe key or PIN)")
				return
			}
		}

		if _, err := deps.Wipe(ctx, deps.PanicWipeDeps, uin); err != nil {

			// Hard failure — PG transaction rolled back (or blocklist failed),
			// nothing was wiped. The recovery deferred-remove cleared the
			// blocklist if it was set. The caller can retry.
			log.Printf("[auth-service] manual panic wipe failed")
			clearSessionCookies(w)
			writeError(w, http.StatusServiceUnavailable, "PANIC_WIPE_FAILED",
				"could not wipe account; please retry")
			return
		}

		// PG data is wiped and the cleanup job is committed atomically.
		// Storage cleanup (Scylla, NATS, MinIO) continues asynchronously
		// via the persisted wipe job. Always return 202 Accepted so the
		// client clears local state immediately while durable cleanup
		// proceeds independently of this HTTP request.
		clearSessionCookies(w)
		writeJSON(w, http.StatusAccepted, map[string]any{
			"status": "pending",
		})
	}
}

// PanicWipe executes the full wipe sequence. If ctx expires mid-wipe the
// transaction is rolled back and the function returns ctx.Err().
//
// Execution order is critical:
//  1. IMMEDIATE: Set Redis blocklist key to revoke all sessions.
//  2. Capture exact file-object keys from Postgres BEFORE they are deleted.
//  3. Atomic PG transaction: delete prekeys, tokens, memberships, contacts,
//     file ownership, security settings, disable the account (set
//     session_epoch), insert the transient wiped_accounts marker, AND
//     insert a durable wipe_job row. Every piece is committed atomically
//     with the account mutation — if any insert fails, the entire
//     transaction rolls back so the account is never disabled without a
//     corresponding cleanup job and wiped-account marker.
//  4. Best-effort Redis auxiliary cleanup.
//
// Recovery: if the blocklist SET succeeds but any subsequent step before
// the PG commit fails, the blocklist key is removed so the account is not
// permanently inaccessible. The caller can retry the wipe.
//
// Always returns (jobID, nil) on success. A wipe job and a wiped_accounts
// marker are always created together — even with no storage layers, the
// worker must execute final PG erasure (delete user row, wiped_accounts,
// and the job itself).
func PanicWipe(ctx context.Context, deps PanicWipeDeps, uin int64) (int64, error) {
	if deps.Pool == nil {
		return 0, errors.New("panicwipe: pg pool is nil")
	}
	if deps.Redis == nil {
		return 0, errors.New("panicwipe: redis client is nil")
	}

	blocklistKey := panicWipeBlocklistKey(uin)

	// ----- 1. IMMEDIATE session revocation ----------------------------------
	// The blocklist key MUST be set before any data is touched. This
	// ensures no valid token can observe half-wiped state. The ws-gateway
	// checks this key on every message; if it exists, the connection is
	// closed with code 4403. 7-day TTL: long enough to cover every active
	// token, short enough to keep Redis tidy.
	if err := deps.Redis.Set(ctx, blocklistKey, "1", panicWipeBlocklistTTL).Err(); err != nil {
		return 0, fmt.Errorf("panicwipe: revoke active sessions: %w", err)
	}

	// If any step after blocklisting fails before the PG commit succeeds,
	// remove the blocklist so the account can retry. blocklisted=true means
	// "we must clean up on failure"; it is cleared once the PG commit
	// confirms the wipe is durable.
	blocklisted := true
	defer func() {
		if blocklisted {
			if err := deps.Redis.Del(context.WithoutCancel(ctx), blocklistKey).Err(); err != nil {
				log.Printf("[auth-service] panicwipe: failed to remove blocklist during recovery: %v", err)
			}
		}
	}()

	// ----- 2. Capture exact cleanup targets ---------------------------------
	fileKeys, err := captureFileKeys(ctx, deps.Pool, uin)
	if err != nil {
		return 0, fmt.Errorf("panicwipe: capture file keys: %w", err)
	}

	// ----- 3. PG transaction -------------------------------------------------
	tx, err := deps.Pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("panicwipe: begin tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	// DELETE FROM one_time_prekeys WHERE uin = $1
	if _, err := tx.Exec(ctx, qWipeOneTimePrekeys, uin); err != nil {
		return 0, fmt.Errorf("panicwipe: delete one_time_prekeys: %w", err)
	}

	// DELETE FROM prekey_bundles WHERE uin = $1
	if _, err := tx.Exec(ctx, qWipePrekeyBundles, uin); err != nil {
		return 0, fmt.Errorf("panicwipe: delete prekey_bundles: %w", err)
	}

	// DELETE FROM refresh_tokens WHERE uin = $1
	if _, err := tx.Exec(ctx, qWipeRefreshTokens, uin); err != nil {
		return 0, fmt.Errorf("panicwipe: delete refresh_tokens: %w", err)
	}

	// DELETE FROM group_members WHERE uin = $1
	if _, err := tx.Exec(ctx, qWipeGroupMemberships, uin); err != nil {
		return 0, fmt.Errorf("panicwipe: delete group_members: %w", err)
	}

	// DELETE FROM contacts WHERE owner_uin = $1 OR target_uin = $1
	if _, err := tx.Exec(ctx, qWipeContacts, uin); err != nil {
		return 0, fmt.Errorf("panicwipe: delete contacts: %w", err)
	}

	// Delete file-object grant rows. Must run AFTER captureFileKeys above.
	if _, err := tx.Exec(ctx, qWipeFileGrants, uin); err != nil {
		return 0, fmt.Errorf("panicwipe: delete file_object_grants: %w", err)
	}
	if _, err := tx.Exec(ctx, qWipeFileObjects, uin); err != nil {
		return 0, fmt.Errorf("panicwipe: delete file_objects: %w", err)
	}

	// Delete security settings.
	if _, err := tx.Exec(ctx, qWipeSecuritySettings, uin); err != nil {
		return 0, fmt.Errorf("panicwipe: delete user_security_settings: %w", err)
	}

	// Disable the account by advancing session_epoch. This invalidates all
	// existing access/refresh tokens immediately. The user row stays in
	// place (preserving FK integrity for the wipe_job row) until the
	// background worker confirms all external storage deletion and executes
	// the final PG erasure transaction.
	if _, err := tx.Exec(ctx, `UPDATE users SET session_epoch = NOW(), updated_at = NOW() WHERE uin = $1`, uin); err != nil {
		return 0, fmt.Errorf("panicwipe: disable account: %w", err)
	}

	// ----- 3a. Insert the wiped_accounts marker INSIDE the transaction ------
	// Primary insertion path (see qInsertWipedAccountMarker's doc comment):
	// committed atomically with the account mutation, so BearerAuth's
	// IsAccountWiped check and the history endpoints' peer/sender checks
	// already see this uin as wiped the instant this transaction commits —
	// before the HTTP response is sent, independent of whether any worker
	// has polled yet. The worker's own claim-time insert
	// (wipejob.go's qClaimPendingJob) is only a recovery backstop now.
	if _, err := tx.Exec(ctx, qInsertWipedAccountMarker, uin); err != nil {
		return 0, fmt.Errorf("panicwipe: insert wiped_accounts marker: %w", err)
	}

	// ----- 3b. Insert cleanup job INSIDE the transaction --------------------
	// The wipe_job row is committed atomically with the account mutation.
	// If this INSERT fails, the entire transaction rolls back — the wipe
	// is never committed without a corresponding cleanup job. This
	// prevents permanent loss of the captured MinIO object keys.
	// A job is ALWAYS created — even with no storage layers configured,
	// the worker must execute final PG erasure (delete user row,
	// wiped_accounts, and the job itself).
	jobID, err := InsertWipeJobTx(ctx, tx, uin, fileKeys)
	if err != nil {
		return 0, fmt.Errorf("panicwipe: insert wipe job: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("panicwipe: commit: %w", err)
	}
	// PG commit succeeded — the wipe is durable. Clear the recovery flag so
	// the deferred blocklist removal does NOT fire.
	blocklisted = false

	// ----- 4. Redis auxiliary cleanup (best-effort, non-fatal) --------------
	if err := deps.Redis.Del(ctx, legacyLoginAttemptsKeyPrefix+itoa(uin)).Err(); err != nil {
		log.Printf("[auth-service] panicwipe: del legacy counter failed: %v", err)
	}
	if err := deps.Redis.Del(ctx, presenceKeyPrefix+itoa(uin)).Err(); err != nil {
		log.Printf("[auth-service] panicwipe: del presence failed: %v", err)
	}
	if err := deps.Redis.Del(ctx, "undelivered:"+itoa(uin)).Err(); err != nil {
		log.Printf("[auth-service] panicwipe: del undelivered queue failed: %v", err)
	}
	cleanupPollKeys(ctx, deps.Redis, uin)

	log.Printf("[auth-service] panic_wipe_executed wipe_job=%d", jobID)
	return jobID, nil
}

// captureFileKeys queries file_objects for every object_key owned by the
// given UIN. It MUST be called BEFORE the PG transaction deletes the
// ownership rows — the returned keys are the exact set MinIO should delete.
// An empty list is valid (the user may never have uploaded a file).
func captureFileKeys(ctx context.Context, pool *pgxpool.Pool, uin int64) ([]string, error) {
	rows, err := pool.Query(ctx, qSelectFileObjectKeys, uin)
	if err != nil {
		return nil, fmt.Errorf("query file object keys: %w", err)
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, fmt.Errorf("scan file object key: %w", err)
		}
		if key != "" {
			keys = append(keys, key)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate file object keys: %w", err)
	}
	return keys, nil
}

func deletePattern(ctx context.Context, rdb *redis.Client, pattern string) error {
	var cursor uint64
	for {
		keys, nextCursor, err := rdb.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return err
		}
		for _, key := range keys {
			if err := rdb.Del(ctx, key).Err(); err != nil {
				log.Printf("[auth-service] panicwipe: del key %s failed: %v", key, err)
			}
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return nil
}

func cleanupPollKeys(ctx context.Context, rdb *redis.Client, uin int64) {
	uinStr := itoa(uin)

	// Deterministic per-user keys — DEL directly.
	for _, key := range []string{
		"poll:stream:" + uinStr,
		"poll:cursors:" + uinStr,
		"poll:cursor-order:" + uinStr,
	} {
		if err := rdb.Del(ctx, key).Err(); err != nil {
			log.Printf("[auth-service] panicwipe: del poll key %s failed: %v", key, err)
		}
	}

	// Hash-tag keys: poll:{UIN}:sequence, poll:{UIN}:seen:*, poll:{UIN}:record:*
	// SCAN is required here because seen and record keys contain per-message digests
	// whose names we cannot enumerate up front.
	patterns := []string{
		"poll:{" + uinStr + "}:*",
		"poll:{" + uinStr + "}",
	}
	for _, pattern := range patterns {
		if err := deletePattern(ctx, rdb, pattern); err != nil {
			log.Printf("[API_WIPE] panicwipe: scan+del %s failed: %v", pattern, err)
		}
	}

}

func cleanupScylla(parent context.Context, store MessageStore, uin int64, timeout time.Duration) error {
	cleanupCtx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if err := store.DeleteUserMessages(cleanupCtx, uin); err != nil {
		return fmt.Errorf("scylla delete messages: %w", err)
	}
	if err := store.DeleteUserGroupMessages(cleanupCtx, uin); err != nil {
		return fmt.Errorf("scylla delete group_messages: %w", err)
	}
	return nil
}
