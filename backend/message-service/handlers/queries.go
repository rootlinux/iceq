// Group management SQL constants. Mirrors the style of
// auth-service/handlers/queries.go: every query is a const string
// with positional ($1, $2, ...) placeholders, all colocated in one
// file so the planner can see the entire query set during review.
//
// Group operations touch the `groups` and `group_members` tables
// defined in deploy/init/postgres-init.sql. The schema is:
//
//	groups(id UUID PK, name TEXT, owner_uin BIGINT, created_at)
//	group_members(group_id UUID, uin BIGINT, role TEXT, joined_at, PK(group_id, uin))
//
// group_members has ON DELETE CASCADE on group_id, so deleting a
// group automatically removes every membership row.
package handlers

const (
	// qCreateGroup inserts a new group and returns the
	// server-assigned UUID. The owner is the requesting user,
	// supplied via $1. UUID generation is left to Postgres'
	// gen_random_uuid() default so the handler does not need
	// to import google/uuid.
	qCreateGroup = `
		INSERT INTO groups (name, owner_uin)
		VALUES ($1, $2)
		RETURNING id, name, owner_uin, created_at
	`

	// qInsertGroupAdmin inserts the OWNER as a group_member
	// with role=admin. This is the second half of group
	// creation: the spec calls for the creator to be a
	// member of their own group.
	qInsertGroupAdmin = `
		INSERT INTO group_members (group_id, uin, role)
		VALUES ($1, $2, 'admin')
	`

	// qListGroupsForMember returns every group the requesting
	// user belongs to, joined with a sub-query that counts
	// the members. ORDER BY groups.created_at DESC so the
	// newest group is at the top of the sidebar.
	qListGroupsForMember = `
		SELECT g.id, g.name, g.owner_uin, g.created_at,
		       (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) AS member_count
		       , g.crypto_epoch
		FROM groups g
		JOIN group_members m ON m.group_id = g.id
		WHERE m.uin = $1
		ORDER BY g.created_at DESC
	`

	// qListGroupMembers returns the membership roster of one
	// group, joined with users for the public-facing fields.
	// The handler filters by membership (requesting user must
	// also be a member) before this query runs.
	qListGroupMembers = `
		SELECT u.uin, u.username, COALESCE(u.avatar_url, '') AS avatar_url, m.role
		FROM group_members m
		JOIN users u ON u.uin = m.uin
		WHERE m.group_id = $1
		ORDER BY m.joined_at ASC
	`

	// qGetGroupRole fetches the requesting user's role in a
	// group. Returns the role string ('admin' or 'member')
	// when the user is a member, or no rows when they are
	// not. Used as the authn check for admin-only routes
	// (POST /members) and as the membership check for any
	// member-allowed route.
	qGetGroupRole = `
		SELECT role FROM group_members
		WHERE group_id = $1 AND uin = $2
		LIMIT 1
	`

	// qGetGroupOwner fetches the group's owner_uin. Used by
	// DELETE /api/groups/{id} to authorize the operation
	// (only the owner can delete a group).
	qGetGroupOwner = `
		SELECT owner_uin FROM groups WHERE id = $1
	`

	// qInsertGroupMember inserts a fresh (group_id, uin) row
	// with role='member'. ON CONFLICT DO NOTHING makes
	// re-adding an existing member a no-op (handler returns
	// 201 because the intent is satisfied).
	qInsertGroupMember = `
		WITH inserted AS (
		  INSERT INTO group_members (group_id, uin, role) VALUES ($1, $2, 'member')
		  ON CONFLICT (group_id, uin) DO NOTHING RETURNING group_id
		)
		UPDATE groups SET crypto_epoch = crypto_epoch + 1
		WHERE id = $1 AND EXISTS (SELECT 1 FROM inserted)
	`

	// qDeleteGroupMember removes a (group_id, uin) row.
	// Used both for the "leave group" case (where uin is
	// the requester's own UIN) and the "kick" case (where
	// uin is some other member's UIN).
	qDeleteGroupMember = `
		WITH removed AS (
		  DELETE FROM group_members WHERE group_id = $1 AND uin = $2 RETURNING group_id
		)
		UPDATE groups SET crypto_epoch = crypto_epoch + 1
		WHERE id = $1 AND EXISTS (SELECT 1 FROM removed)
	`

	// qCountGroupMembers counts the current members of a
	// group. Used after a DELETE to decide whether the
	// group is now empty (delete the group) or has at least
	// one survivor (transfer ownership if needed).
	qCountGroupMembers = `
		SELECT COUNT(*) FROM group_members WHERE group_id = $1
	`

	// qOldestRemainingMember returns the uin of the
	// longest-tenured member of a group. Used to transfer
	// ownership when the current owner leaves a non-empty
	// group. Ties are broken by uin ASC (deterministic
	// across re-runs).
	qOldestRemainingMember = `
		SELECT uin FROM group_members
		WHERE group_id = $1
		ORDER BY joined_at ASC, uin ASC
		LIMIT 1
	`

	// qUpdateGroupOwner sets a new owner_uin. Used to
	// transfer ownership when the current owner leaves.
	qUpdateGroupOwner = `
		UPDATE groups SET owner_uin = $2 WHERE id = $1
	`

	// qDeleteGroup cascades to group_members (per the
	// schema's ON DELETE CASCADE). Used by the explicit
	// DELETE /api/groups/{id} endpoint, AND by the
	// "last member leaves" cleanup path.
	qDeleteGroup = `DELETE FROM groups WHERE id = $1`

	// qGetGroupName is a small lookup used to build a
	// human-readable notification body ("you've been added
	// to group X"). Avoids the handler re-querying the
	// membership roster just to get the group's name.
	qGetGroupName = `SELECT name FROM groups WHERE id = $1`
	qGetGroupEpoch = `SELECT crypto_epoch FROM groups WHERE id = $1`
)
