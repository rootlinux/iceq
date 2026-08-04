// Package handlers contains the HTTP handlers that implement the
// auth-service's REST surface. The package is split per endpoint
// (register.go, login.go, refresh.go, logout.go) plus this file
// for shared SQL constants and the JSON error writer.
//
// SQL is kept here, not in the handler files, so the planner can
// see the entire query set in one place during review and so a
// query is never accidentally duplicated or subtly drifted between
// two call sites.
package handlers

// ----------------------------------------------------------------------------
// SQL. Every query uses named parameters ($1, $2, ...) via pgx.
// We use $N rather than @name because pgx is the only driver we
// use; the explicit numeric binding is faster to read and harder
// to typo (a typo'd @name silently binds the wrong variable, a
// typo'd $N is a compile-time error in the QueryRow/Query call
// site via the variadic args check).
// ----------------------------------------------------------------------------

const (
	// qInsertUser creates a new user and returns the auto-assigned
	// UIN from the uin_seq sequence. The RETURNING clause is what
	// lets us hand the new UIN to the client in the same round
	// trip — no separate SELECT, no race window.
	//
	// E2EE-aware changes (architecture update):
	//   - email is wrapped in NULLIF($2, '') so an empty string
	//     becomes SQL NULL. Postgres UNIQUE treats NULLs as
	//     distinct, so two users with no email can co-exist.
	//   - identity_key is added as $4 and stored verbatim. It
	//     is a public key by definition, so no encryption is
	//     required server-side.
	qInsertUser = `
		INSERT INTO users (username, email, password_hash, identity_key)
		VALUES ($1, NULLIF($2, ''), $3, $4)
		RETURNING uin, username, COALESCE(email, '') AS email, created_at
	`

	// qSelectUserByEmail fetches the row needed to verify a login
	// attempt: the user record (for UIN/username) and the bcrypt
	// hash. Indexed by the unique email constraint, so the lookup
	// is a single B-tree descent.
	qSelectUserByEmail = `
			SELECT uin, username, email, password_hash
			FROM users
			WHERE email = $1
		`

	qSelectUserByUsername = `
			SELECT uin, username, COALESCE(email, '') AS email, password_hash
			FROM users
			WHERE username = $1
		`

	qSelectUserPublicByUIN = `
			SELECT uin, username, COALESCE(email, '') AS email, created_at
			FROM users
			WHERE uin = $1
		`

	// qInsertRefreshToken records the SHA-256 hash of a freshly
	// minted refresh token. We store the hash, not the token
	// itself, so a stolen DB dump cannot be replayed.
	//
	// The token's JTI is not stored here because the JWT carries
	// it. If we ever need to revoke a refresh token by JTI (e.g.
	// in a "log out all sessions" flow) we extend this table with
	// a jti column and add an index on it.
	// #nosec G101 -- this is a SQL statement (the column name
	// "token_hash" is what gosec's heuristic matches), not a
	// credential literal. See the doc comment above.
	qInsertRefreshToken = `
		INSERT INTO refresh_tokens (uin, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`

	// qSelectRefreshTokenByHash looks up an active refresh token
	// by its SHA-256 hash. We use SCAN, not QueryRow + ErrNoRows,
	// via the handler-side helper checkRefreshToken.
	// #nosec G101 -- SQL statement, not a credential literal.
	qSelectRefreshTokenByHash = `
		SELECT uin, expires_at
		FROM refresh_tokens
		WHERE token_hash = $1
	`

	// qDeleteRefreshTokenByHash removes a refresh token. Used by
	// logout (revoke one) and by refresh-rotation (consume the
	// old one before issuing the new).
	// #nosec G101 -- SQL statement, not a credential literal.
	qDeleteRefreshTokenByHash = `
		DELETE FROM refresh_tokens
		WHERE token_hash = $1
	`

	// qConsumeRefreshTokenByHash is the rotation compare-and-delete. PostgreSQL
	// serializes concurrent DELETEs of the same row; RETURNING therefore gives
	// exactly one caller the consumed token metadata and all losers ErrNoRows.
	// #nosec G101 -- SQL statement, not a credential literal.
	qConsumeRefreshTokenByHash = `
		DELETE FROM refresh_tokens
		WHERE token_hash = $1
		RETURNING uin, expires_at
	`

	// qRevokeAllSessionsOnRefreshReuse is deliberately one PostgreSQL
	// statement, executed and committed in the same transaction that observed
	// the missing consumed row. Advancing session_epoch invalidates existing
	// access tokens; deleting refresh rows prevents any remaining rotation.
	qRevokeAllSessionsOnRefreshReuse = `
		WITH revoked_user AS (
			UPDATE users
			SET session_epoch = GREATEST(NOW(), session_epoch + INTERVAL '1 microsecond')
			WHERE uin = $1
			RETURNING uin
		)
		DELETE FROM refresh_tokens
		WHERE uin IN (SELECT uin FROM revoked_user)
	`

	// ------------------------------------------------------------------------
	// Panic-wipe cleanup queries. PanicWipe() runs these inside
	// a single PG transaction so the partial state is never
	// visible to a concurrent reader.
	// ------------------------------------------------------------------------

	// qWipePrekeyBundles removes the user's prekey bundle and
	// every one-time prekey. After this, /api/keys/bundle/{uin}
	// returns 404 to anyone trying to start a session with
	// the wiped user.
	qWipePrekeyBundles  = `DELETE FROM prekey_bundles WHERE uin = $1`
	qWipeOneTimePrekeys = `DELETE FROM one_time_prekeys WHERE uin = $1`

	// qWipeRefreshTokens removes every persisted refresh token
	// for the user. After this, the user cannot refresh their
	// session even if they still hold a valid access token.
	qWipeRefreshTokens = `DELETE FROM refresh_tokens WHERE uin = $1` // #nosec G101 -- SQL statement, not a credential literal.

	// qWipeGroupMemberships removes the user from every group,
	// promotes the deterministic successor when the owner is wiped,
	// and deletes groups that have no surviving member.
	qWipeGroupMemberships = `
	 WITH affected AS (SELECT g.id,g.owner_uin FROM groups g JOIN group_members m ON m.group_id=g.id WHERE m.uin=$1 FOR UPDATE),
	 removed AS (DELETE FROM group_members WHERE uin=$1 RETURNING group_id),
	 survivors AS (SELECT a.id,(SELECT uin FROM group_members WHERE group_id=a.id AND uin<>$1 ORDER BY joined_at,uin LIMIT 1) successor FROM affected a),
	 promoted AS (UPDATE group_members m SET role='admin' FROM affected a, survivors s
	   WHERE m.group_id=a.id AND m.uin=s.successor AND a.owner_uin=$1 RETURNING 1),
	 updated AS (UPDATE groups g SET crypto_epoch=crypto_epoch+1,
	   owner_uin=CASE WHEN g.owner_uin=$1 THEN s.successor ELSE g.owner_uin END
	   FROM survivors s WHERE g.id=s.id AND s.successor IS NOT NULL RETURNING g.id),
	 retired AS (UPDATE sender_key_distributions d SET retired_at=COALESCE(retired_at,NOW()) WHERE d.group_id IN (SELECT id FROM affected) RETURNING 1)
	 DELETE FROM groups g USING survivors s WHERE g.id=s.id AND s.successor IS NULL`

	// qWipeContacts removes the user from everyone's contact
	// list AND removes every contact from the user's own
	// (now-blank) contact list. Both directions in one query.
	qWipeContacts = `
		DELETE FROM contacts
		WHERE owner_uin = $1 OR target_uin = $1
	`

	// qWipeSecuritySettings deletes the settings row too. The
	// user can re-register with the same UIN in the future, but
	// the panic-wipe flag should not be inherited.
	qWipeSecuritySettings = `DELETE FROM user_security_settings WHERE uin = $1`
	qWipeFileGrants       = `DELETE FROM file_object_grants WHERE owner_uin = $1 OR grantee_uin = $1`
	qWipeFileObjects      = `DELETE FROM file_objects WHERE owner_uin = $1`
	qSelectFileObjectKeys = `SELECT object_key FROM file_objects WHERE owner_uin = $1`
	qSelectPasswordHash   = `SELECT password_hash FROM users WHERE uin = $1`
	// qEnrollWipePublicKey inserts or sets the wipe key only if no key is
	// currently enrolled (atomic set-if-null). ON CONFLICT DO UPDATE with a
	// WHERE clause ensures: new row → INSERT, existing row with NULL key →
	// UPDATE, existing row with non-NULL key → no-op (RowsAffected=0).
	qEnrollWipePublicKey = `INSERT INTO user_security_settings (uin, wipe_public_key) VALUES ($1, $2) ON CONFLICT (uin) DO UPDATE SET wipe_public_key = EXCLUDED.wipe_public_key WHERE user_security_settings.wipe_public_key IS NULL`
	qUpdateWipePublicKey = `UPDATE user_security_settings SET wipe_public_key = $3 WHERE uin = $1 AND wipe_public_key = $2`

	// qLockUserRow acquires a row-level lock on the user row. Used by login
	// to serialize with PanicWipe, which acquires the same lock before any
	// destructive database write. The two operations cannot pass each other. The
	// lock is held until the calling transaction commits or rolls back.
	qLockUserRow = `SELECT uin FROM users WHERE uin = $1 FOR UPDATE`

	// qCheckWipedAccount returns true when the wiped_accounts marker exists
	// for the given UIN. Used inside the login transaction (after FOR UPDATE
	// lock) to reject logins for wiped accounts atomically with session
	// creation.
	qCheckWipedAccount = `SELECT EXISTS (SELECT 1 FROM wiped_accounts WHERE uin = $1)`

	// qInsertWipedAccountMarker creates the transient wiped_accounts row
	// inside PanicWipe's own transaction -- the PRIMARY insertion path. It
	// must be visible to every other request touching this uin (BearerAuth's
	// IsAccountWiped check, and the history endpoints' peer/sender checks)
	// the instant PanicWipe's transaction commits, not only once a worker
	// happens to poll and claim the wipe job. ON CONFLICT DO NOTHING makes
	// a hypothetical repeat call harmless. wiped_accounts.uin has a FOREIGN
	// KEY to users(uin) (migration 005); it is always satisfied here
	// because PanicWipe runs strictly before the user row is ever deleted
	// (only the worker's later final-erasure step deletes it). The
	// worker's own claim-time insert (wipejob.go's qClaimPendingJob) is
	// now only an idempotent recovery backstop for this same row, not the
	// primary path.
	qInsertWipedAccountMarker = `INSERT INTO wiped_accounts (uin) VALUES ($1) ON CONFLICT (uin) DO NOTHING`

	// Account erasure design:
	//
	// PanicWipe deletes every FK-referencing row, disables the account
	// (advances session_epoch), inserts the wiped_accounts marker, and
	// inserts the wipe_job row, all inside ONE PG transaction — so a wiped
	// user already fails every wiped_accounts-aware check (BearerAuth,
	// DM/group history) the instant the HTTP response is sent, before any
	// worker has run. The user row is NOT anonymized — it stays in place
	// temporarily so the wipe_job row can reference it.
	//
	// After the background worker confirms all external storage deletion
	// (Scylla, NATS, MinIO), it executes a final PG transaction that
	// permanently deletes the user row, wiped_accounts entries, and the
	// completed wipe-job row. Zero rows associated with the wiped UIN
	// remain in any PostgreSQL table. There is no "deleted_<UIN>" tombstone,
	// and no permanent wiped-account record survives cleanup.

	// ------------------------------------------------------------------------
	// Contact management queries (added by the contacts addendum,
	// Step 10). All operate on the `contacts` table that lives in
	// the shared `postgres-init.sql` schema. The `contacts` table has
	// composite PK (owner_uin, target_uin); a row exists for EVERY
	// directed edge in the social graph, so the reverse direction
	// is also stored explicitly (it is NOT a symmetric relationship
	// because blocking and pending status are per-direction).
	// ------------------------------------------------------------------------

	// qListContactsForOwner returns the owner's full contact list
	// joined against users for the public-facing fields. The status
	// is a column on contacts (not users) because it is per-edge.
	//
	// No ORDER BY — the caller (handler) sorts in Go so we keep
	// the index-only plan and the planner has a single fixed shape
	// to optimize.
	qListContactsForOwner = `
		SELECT
			u.uin,
			u.username,
			COALESCE(u.avatar_url, '') AS avatar_url,
			c.status,
			CASE
				WHEN c.status = 'pending' AND c.requested_by_uin = $1 THEN 'outgoing'
				WHEN c.status = 'pending' THEN 'incoming'
				ELSE ''
			END AS direction
		FROM contacts c
		JOIN users u ON u.uin = c.target_uin
		WHERE c.owner_uin = $1
	`

	// qUserExists is a one-row existence probe used to validate
	// the target_uin on POST /api/contacts before we touch the
	// contacts table. Avoids a FK violation turning into a 500.
	qUserExists = `SELECT 1 FROM users WHERE uin = $1 LIMIT 1`

	// qUpsertContact inserts a directed edge (owner → target) with
	// status=pending. ON CONFLICT DO NOTHING means a duplicate
	// POST is a no-op rather than an error: the handler still
	// returns 201 because the intent ("I want this person as a
	// pending contact") is satisfied.
	qUpsertContact = `
		INSERT INTO contacts (owner_uin, target_uin, requested_by_uin, status)
		VALUES ($1, $2, $3, 'pending')
		ON CONFLICT (owner_uin, target_uin) DO NOTHING
	`

	// qAcceptContact flips a pending edge to accepted. We restrict
	// the UPDATE to status='pending' so an accept on an already-
	// accepted edge is a no-op (handler returns 404 in that case
	// to signal "no pending request to accept"). The reverse edge
	// (target → owner) is updated in a separate query; the
	// composite PK guarantees there IS a reverse row because the
	// POST handler created both atomically.
	qAcceptContact = `
		UPDATE contacts
		SET status = 'accepted'
		WHERE owner_uin = $1
		  AND target_uin = $2
		  AND status = 'pending'
		  AND requested_by_uin = $2
	`

	// qAcceptContactReverse mirrors qAcceptContact for the other
	// direction of the edge.
	qAcceptContactReverse = `
		UPDATE contacts
		SET status = 'accepted'
		WHERE owner_uin = $2
		  AND target_uin = $1
		  AND status = 'pending'
		  AND requested_by_uin = $2
	`

	// qBlockContact sets the edge to blocked regardless of
	// previous status. Used by PUT /api/contacts/{target}/block.
	// We do NOT touch the reverse edge: blocking is one-way, so
	// the blocked user can still see and message the blocker
	// (this is consistent with every other major chat app).
	qBlockContact = `
		UPDATE contacts
		SET status = 'blocked'
		WHERE owner_uin = $1 AND target_uin = $2
	`

	// qDeleteContact removes the directed edge. Used by DELETE
	// /api/contacts/{target}. The reverse edge is preserved —
	// the other party can still see the relationship from their
	// side until they choose to remove it too.
	qDeleteContact = `
		DELETE FROM contacts
		WHERE owner_uin = $1 AND target_uin = $2
	`

	// qUpsertContactBlocked inserts a directed edge with
	// status=blocked, or leaves the existing row untouched if
	// there is one. Used by PUT /api/contacts/{target}/block
	// AFTER the qBlockContact UPDATE returns RowsAffected=0
	// (i.e. there was no prior contact to flip). This is the
	// "block without prior contact" case.
	qUpsertContactBlocked = `
		INSERT INTO contacts (owner_uin, target_uin, status)
		VALUES ($1, $2, 'blocked')
		ON CONFLICT (owner_uin, target_uin) DO NOTHING
	`
)
