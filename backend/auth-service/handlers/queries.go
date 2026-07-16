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
	qInsertRefreshToken = `
		INSERT INTO refresh_tokens (uin, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`

	// qSelectRefreshTokenByHash looks up an active refresh token
	// by its SHA-256 hash. We use SCAN, not QueryRow + ErrNoRows,
	// via the handler-side helper checkRefreshToken.
	qSelectRefreshTokenByHash = `
		SELECT uin, expires_at
		FROM refresh_tokens
		WHERE token_hash = $1
	`

	// qDeleteRefreshTokenByHash removes a refresh token. Used by
	// logout (revoke one) and by refresh-rotation (consume the
	// old one before issuing the new).
	qDeleteRefreshTokenByHash = `
		DELETE FROM refresh_tokens
		WHERE token_hash = $1
	`

	// qConsumeRefreshTokenByHash is the rotation compare-and-delete. PostgreSQL
	// serializes concurrent DELETEs of the same row; RETURNING therefore gives
	// exactly one caller the consumed token metadata and all losers ErrNoRows.
	qConsumeRefreshTokenByHash = `
		DELETE FROM refresh_tokens
		WHERE token_hash = $1
		RETURNING uin, expires_at
	`

	// ------------------------------------------------------------------------
	// Security-settings + panic-wipe queries (added by the
	// panic-wipe addendum).
	// ------------------------------------------------------------------------

	// qSelectSecuritySettings fetches one user's row from
	// user_security_settings. May return ErrNoRows if the user
	// has never visited the settings page; the handler
	// translates that into the documented defaults rather than
	// an error.
	qSelectSecuritySettings = `
		SELECT panic_wipe_enabled, panic_wipe_threshold, updated_at
		FROM user_security_settings
		WHERE uin = $1
	`

	// qUpsertSecuritySettings creates or replaces a user's
	// security-settings row. ON CONFLICT (uin) catches the
	// second-and-later PUT; DO UPDATE rewrites both knobs and
	// bumps updated_at. The order of SET clauses matters for
	// diff-friendliness but not for correctness.
	qUpsertSecuritySettings = `
		INSERT INTO user_security_settings
			(uin, panic_wipe_enabled, panic_wipe_threshold, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (uin) DO UPDATE
		SET panic_wipe_enabled   = EXCLUDED.panic_wipe_enabled,
		    panic_wipe_threshold = EXCLUDED.panic_wipe_threshold,
		    updated_at           = NOW()
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
	qWipeRefreshTokens = `DELETE FROM refresh_tokens WHERE uin = $1`

	// qWipeGroupMemberships removes the user from every group
	// they were a member of. Group ownership is NOT transferred
	// here; an orphaned group is left in place (a separate
	// cleanup pass in the future could prune empty groups).
	qWipeGroupMemberships = `DELETE FROM group_members WHERE uin = $1`

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
	qMarkAccountWiped     = `INSERT INTO wiped_accounts (uin) VALUES ($1) ON CONFLICT (uin) DO NOTHING`

	// qWipeUserAnonymizes the users row. The shell record
	// stays (so FKs into it still resolve to something) but
	// every identifying field is scrubbed:
	//   - identity_key = ''  : the X25519 public key is gone,
	//                          so a future client cannot be
	//                          identified as the same party
	//                          even if they knew the username.
	//   - avatar_url = NULL  : the URL pointed to MinIO; we
	//                          don't delete the object here
	//                          because Scylla/MinIO deletes are
	//                          a separate concern (the addendum
	//                          leaves object cleanup as future
	//                          work).
	//   - username = 'deleted_' || uin : the original username
	//                          is replaced with a deterministic
	//                          placeholder. We pick a
	//                          recognizable name (not a hash) so
	//                          operators inspecting the DB can
	//                          see at a glance which rows have
	//                          been wiped.
	//   - password_hash = '' : a future login attempt with
	//                          the original password will
	//                          fail at the bcrypt layer (the
	//                          stored hash is no longer a
	//                          valid bcrypt-encoded string).
	//                          We deliberately don't drop the
	//                          user from the table because
	//                          that would break FK integrity
	//                          in messages, group_members, etc.
	//   - email = NULL       : the original email is removed
	//                          so a future attacker can't
	//                          even start a re-registration
	//                          with it.
	qWipeUser = `
		UPDATE users
		SET identity_key  = '',
		    avatar_url    = NULL,
		    username      = 'deleted_' || $1::text,
		    password_hash = '',
		    email         = NULL,
		    session_epoch = NOW(),
		    updated_at    = NOW()
		WHERE uin = $1
	`

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
