// Group management endpoints. Mounted at /api/groups
// from message-service/main.go, all routes are behind
// middleware.BearerAuth (the user's UIN comes from the JWT, not
// from the request body).
//
//	POST   /api/groups                              → create a new group
//	GET    /api/groups                              → list groups the user belongs to
//	GET    /api/groups/{group_id}/members           → list group members
//	POST   /api/groups/{group_id}/members           → invite a new member (admin only)
//	DELETE /api/groups/{group_id}/members/{uin}     → leave (own UIN) or kick (admin only)
//	DELETE /api/groups/{group_id}                   → delete the group (owner only)
//
// Authorization model:
//
//   - group_id comes from the URL path. Validation is
//     gocql.ParseUUID (we reuse the Scylla UUID parser — same
//     canonical hex format).
//   - owner_uin and member-uins come from the verified JWT
//     (middleware.GetUIN) or the path, NEVER from the request
//     body — a tampered client cannot impersonate other
//     members.
//   - The membership and role lookups are done inside the
//     handler with qGetGroupRole. 403 is returned uniformly
//     for "not a member", "not an admin", or "not the owner"
//     to avoid leaking role distinctions to a probing caller.
//   - Ownership transfer (when the current owner leaves) goes
//     to the oldest remaining member by joined_at, with uin
//     ASC as a deterministic tie-breaker. If the leaving
//     owner is the LAST member, the group is deleted (the
//     schema's ON DELETE CASCADE drops the membership row
//     automatically).
//
// Privacy: every log line omits the requester's UIN, the
// target's UIN, the group_id, and the group name. Only
// operational error strings are logged.

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gocql/gocql"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/iceq/iceq/shared/models"
	"github.com/iceq/iceq/shared/natsclient"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ----------------------------------------------------------------------------
// Dependencies. Injected once from main.go.
// ----------------------------------------------------------------------------

// GroupsDeps carries the shared resources every groups handler
// needs. The pool is required; the bus is required because the
// "add member" path publishes a notification to the new member.
type GroupsDeps struct {
	PG  groupDB
	Bus *natsclient.Client
}

type groupDB interface {
	Begin(context.Context) (pgx.Tx, error)
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// ----------------------------------------------------------------------------
// Response / request types. Colocated with the handlers for the
// same reason as in contacts.go: the JSON field names are the
// public API and should live next to the code that produces them.
// ----------------------------------------------------------------------------

// createGroupRequest is the body of POST /api/groups.
type createGroupRequest struct {
	Name string `json:"name"`
}

// groupItem is one row in the GET /api/groups response and
// the body of POST /api/groups.
type groupItem struct {
	GroupID     string    `json:"group_id"`
	Name        string    `json:"name"`
	OwnerUIN    int64     `json:"owner_uin"`
	MemberCount int       `json:"member_count"`
	CreatedAt   time.Time `json:"created_at"`
	CryptoEpoch int64     `json:"crypto_epoch"`
}

// listGroupsResponse is the body of GET /api/groups.
type listGroupsResponse struct {
	Groups []groupItem `json:"groups"`
}

// groupMember is one row in the GET /api/groups/{id}/members
// response. AvatarURL is an empty string (NOT null) when the
// user has no avatar; the web client renders a fallback.
type groupMember struct {
	UIN       int64  `json:"uin"`
	Username  string `json:"username"`
	AvatarURL string `json:"avatar_url"`
	Role      string `json:"role"`
}

// listGroupMembersResponse is the body of GET
// /api/groups/{id}/members.
type listGroupMembersResponse struct {
	Members     []groupMember `json:"members"`
	CryptoEpoch int64         `json:"crypto_epoch"`
}

// addMemberRequest is the body of POST
// /api/groups/{id}/members.
type addMemberRequest struct {
	UIN int64 `json:"uin"`
}

// ----------------------------------------------------------------------------
// Handlers.
// ----------------------------------------------------------------------------

// NewCreateGroupHandler returns the http.HandlerFunc for
// POST /api/groups. MUST be wrapped with BearerAuth.
//
// Body: { "name": "<3-50 chars>" }
//
// The handler runs two inserts in a single transaction:
//  1. INSERT INTO groups → returns the new group_id (UUID).
//  2. INSERT INTO group_members (group_id, owner_uin, 'admin').
//
// If either fails, both roll back so we never leave a group
// without its owner-membership row.
func NewCreateGroupHandler(deps GroupsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ownerUIN, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}

		var req createGroupRequest
		if !decodeJSON(w, r, &req, 1<<14) {
			return
		}
		// --- Validation: name length --------------------------------
		// The spec calls for 3-50 chars. We count runes (not
		// bytes) so a name with non-ASCII characters gets the
		// same effective limit. A leading/trailing-whitespace
		// name is also rejected; the client can strip on its
		// end if it wants.
		name := strings.TrimSpace(req.Name)
		runeCount := len([]rune(name))
		if runeCount < 3 || runeCount > 50 {
			writeError(w, http.StatusUnprocessableEntity, "NAME_LENGTH", "group name must be 3-50 characters")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		tx, err := deps.PG.Begin(ctx)
		if err != nil {
			log.Printf("[message-service] begin create-group tx: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not start group transaction")
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck

		var (
			groupID    string
			storedName string
			ownerOut   int64
			createdAt  time.Time
		)
		err = tx.QueryRow(ctx, qCreateGroup, name, ownerUIN).Scan(
			&groupID, &storedName, &ownerOut, &createdAt,
		)
		if err != nil {
			log.Printf("[message-service] insert group: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not create group")
			return
		}
		if _, err := tx.Exec(ctx, qInsertGroupAdmin, groupID, ownerUIN); err != nil {
			log.Printf("[message-service] insert owner-membership: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not create group")
			return
		}
		if err := tx.Commit(ctx); err != nil {
			log.Printf("[message-service] commit create-group tx: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not commit group")
			return
		}

		writeJSON(w, http.StatusCreated, groupItem{
			GroupID:     groupID,
			Name:        storedName,
			OwnerUIN:    ownerOut,
			MemberCount: 1,
			CreatedAt:   createdAt,
			CryptoEpoch: 1,
		})
	}
}

// NewListGroupsHandler returns the http.HandlerFunc for
// GET /api/groups. MUST be wrapped with BearerAuth.
//
// Returns every group the requesting user is a member of,
// newest first. The subquery for member_count runs once per
// row in the result set; for users in a small number of
// groups (the typical case) this is fine.
func NewListGroupsHandler(deps GroupsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uin, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		rows, err := deps.PG.Query(ctx, qListGroupsForMember, uin)
		if err != nil {
			log.Printf("[message-service] list groups: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not list groups")
			return
		}
		defer rows.Close()

		groups := make([]groupItem, 0, 8)
		for rows.Next() {
			var g groupItem
			if err := rows.Scan(&g.GroupID, &g.Name, &g.OwnerUIN, &g.CreatedAt, &g.MemberCount, &g.CryptoEpoch); err != nil {
				log.Printf("[message-service] scan group row: %v", err)
				writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not read groups")
				return
			}
			groups = append(groups, g)
		}
		if err := rows.Err(); err != nil {
			log.Printf("[message-service] iterate group rows: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not read groups")
			return
		}

		writeJSON(w, http.StatusOK, listGroupsResponse{Groups: groups})
	}
}

// NewListGroupMembersHandler returns the http.HandlerFunc
// for GET /api/groups/{group_id}/members. MUST be wrapped
// with BearerAuth.
//
// Auth: requesting user must be a member of the group. 403
// is returned for non-members (uniformly — the same code is
// used for "group doesn't exist" to avoid leaking
// existence).
func NewListGroupMembersHandler(deps GroupsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uin, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}
		groupID, err := parseGroupIDParam(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "GROUP_ID_INVALID", err.Error())
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// Authn: requester must be a member. Reuse
		// qGetGroupRole — it returns one row iff the user
		// is a member, no rows otherwise.
		isMember, err := isMemberOf(ctx, deps.PG, groupID, uin)
		if err != nil {
			log.Printf("[message-service] membership check: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not check membership")
			return
		}
		if !isMember {
			writeError(w, http.StatusForbidden, "NOT_A_MEMBER", "requesting user is not a member of this group")
			return
		}

		rows, err := deps.PG.Query(ctx, qListGroupMembers, groupID)
		if err != nil {
			log.Printf("[message-service] list group members: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not list members")
			return
		}
		defer rows.Close()

		members := make([]groupMember, 0, 8)
		for rows.Next() {
			var m groupMember
			if err := rows.Scan(&m.UIN, &m.Username, &m.AvatarURL, &m.Role); err != nil {
				log.Printf("[message-service] scan member row: %v", err)
				writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not read members")
				return
			}
			members = append(members, m)
		}
		if err := rows.Err(); err != nil {
			log.Printf("[message-service] iterate member rows: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not read members")
			return
		}

		var epoch int64
		if err := deps.PG.QueryRow(ctx, qGetGroupEpoch, groupID).Scan(&epoch); err != nil {
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not read group epoch")
			return
		}
		writeJSON(w, http.StatusOK, listGroupMembersResponse{Members: members, CryptoEpoch: epoch})
	}
}

// NewAddGroupMemberHandler returns the http.HandlerFunc for
// POST /api/groups/{group_id}/members. MUST be wrapped with
// BearerAuth.
//
// Auth: requesting user must be an admin of the group. (The
// group's owner is always an admin by construction; an admin
// can promote other members to admin out of band in a future
// step.)
//
// Body: { "uin": <int64> }
//
// Side effects:
//   - INSERT (group_id, uin, 'member') — the membership row.
//     ON CONFLICT DO NOTHING makes a duplicate add a no-op.
//   - Publish `notification.<uin>` with kind=group_invite so
//     the new member sees a toast.
func NewAddGroupMemberHandler(deps GroupsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actorUIN, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}
		groupID, err := parseGroupIDParam(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "GROUP_ID_INVALID", err.Error())
			return
		}

		var req addMemberRequest
		if !decodeJSON(w, r, &req, 1<<14) {
			return
		}
		if req.UIN <= 0 {
			writeError(w, http.StatusUnprocessableEntity, "FIELD_INVALID", "uin must be a positive integer")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// Authn: actor must be admin of the group.
		role, err := getGroupRole(ctx, deps.PG, groupID, actorUIN)
		if err != nil {
			log.Printf("[message-service] group role check: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not check group role")
			return
		}
		if role != "admin" {
			// Uniform 403 for "not a member" and "not an
			// admin" — same code prevents probing for
			// group existence.
			writeError(w, http.StatusForbidden, "NOT_ADMIN", "requesting user is not an admin of this group")
			return
		}

		if _, err := deps.PG.Exec(ctx, qInsertGroupMember, groupID, req.UIN); err != nil {
			log.Printf("[message-service] insert group member: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not add member")
			return
		}
		_, _ = deps.PG.Exec(ctx, `UPDATE sender_key_distributions d SET retired_at=COALESCE(retired_at,NOW()) WHERE d.group_id=$1 AND d.epoch <> (SELECT crypto_epoch FROM groups WHERE id=$1)`, groupID)

		// Look up the group name for the notification body.
		// Failure here is non-fatal: the membership row is
		// already committed and the user will see the group
		// in their list regardless.
		var groupName string
		_ = deps.PG.QueryRow(ctx, qGetGroupName, groupID).Scan(&groupName)

		publishGroupInviteNotification(r.Context(), deps.Bus, req.UIN, groupID, groupName, actorUIN)

		w.WriteHeader(http.StatusCreated)
	}
}

// NewRemoveGroupMemberHandler returns the http.HandlerFunc
// for DELETE /api/groups/{group_id}/members/{uin}. MUST be
// wrapped with BearerAuth.
//
// Two cases:
//
//  1. The path uin equals the requester's own UIN → "leave".
//     Any member (admin or member) can leave a group.
//  2. The path uin is someone else's UIN → "kick". Only
//     the group's admin can kick.
//
// After the membership row is deleted we re-count members.
// If the group is now empty, we DELETE the group (the schema's
// ON DELETE CASCADE on group_members.group_id is the safety
// net for the inverse case, but the explicit count + delete
// here keeps the "is the group gone?" decision in Go rather
// than in CASCADE semantics).
//
// If the leaver is the OWNER and at least one other member
// remains, ownership is transferred to the longest-tenured
// remaining member (ORDER BY joined_at ASC, with uin ASC as a
// deterministic tie-breaker so the choice is stable across
// re-runs).
func NewRemoveGroupMemberHandler(deps GroupsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actorUIN, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}
		groupID, err := parseGroupIDParam(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "GROUP_ID_INVALID", err.Error())
			return
		}
		targetUIN, err := strconv.ParseInt(chi.URLParam(r, "uin"), 10, 64)
		if err != nil || targetUIN <= 0 {
			writeError(w, http.StatusBadRequest, "FIELD_INVALID", "uin must be a positive integer")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// Pre-check authorization. We need to know:
		//   - the actor's role (admin or not) for the kick path
		//   - the group's owner for the ownership-transfer path
		// One role query covers both: if the actor is the
		// target, they're leaving (any role); if the actor
		// is admin and the target is someone else, they're
		// kicking.
		actorRole, err := getGroupRole(ctx, deps.PG, groupID, actorUIN)
		if err != nil {
			log.Printf("[message-service] role check: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not check group role")
			return
		}

		// Determine operation mode.
		var isLeave bool
		if targetUIN == actorUIN {
			isLeave = true
			if actorRole == "" {
				// Leaving a group you're not in. 404:
				// there is nothing to leave.
				writeError(w, http.StatusNotFound, "NOT_A_MEMBER", "requesting user is not a member of this group")
				return
			}
		} else {
			// Kicking. Must be admin.
			if actorRole != "admin" {
				writeError(w, http.StatusForbidden, "NOT_ADMIN", "only admins can remove other members")
				return
			}
		}
		_ = isLeave // documented for clarity; the action is the same
		// regardless of leave vs. kick: DELETE the row, then
		// count and decide.

		var removed bool
		var remaining int64
		if err := deps.PG.QueryRow(ctx, qRemoveGroupMemberAtomically, groupID, actorUIN, targetUIN).Scan(&removed, &remaining); err != nil {
			log.Printf("[message-service] atomic member removal: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not remove member")
			return
		}
		if !removed {
			writeError(w, http.StatusNotFound, "NOT_A_MEMBER", "target user is not a member of this group")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// NewDeleteGroupHandler returns the http.HandlerFunc for
// DELETE /api/groups/{group_id}. MUST be wrapped with
// BearerAuth.
//
// Auth: requesting user must be the group's owner. The
// spec deliberately does NOT let admins delete a group they
// don't own — only the owner can. group_members is dropped
// automatically via ON DELETE CASCADE.
func NewDeleteGroupHandler(deps GroupsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actorUIN, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}
		groupID, err := parseGroupIDParam(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "GROUP_ID_INVALID", err.Error())
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// Single-statement ownership check + delete: the
		// WHERE clause carries the owner check, and
		// RowsAffected tells us whether we actually
		// deleted anything. A 404 is returned uniformly
		// for "not the owner" and "group doesn't exist".
		tag, err := deps.PG.Exec(ctx, `DELETE FROM groups WHERE id = $1 AND owner_uin = $2`, groupID, actorUIN)
		if err != nil {
			log.Printf("[message-service] delete group: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not delete group")
			return
		}
		if tag.RowsAffected() == 0 {
			writeError(w, http.StatusNotFound, "NOT_OWNER", "requesting user is not the owner of this group")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// ----------------------------------------------------------------------------
// Local helpers. Kept here (not exported) so the handler
// signatures stay uncluttered.
// ----------------------------------------------------------------------------

// parseGroupIDParam extracts the {group_id} URL parameter and
// returns it as a Postgres-compatible string. We don't return
// a gocql.UUID here because the underlying driver (pgx) is
// happy with a string for UUID columns; parsing on the Go
// side would just be an extra round-trip.
func parseGroupIDParam(r *http.Request) (string, error) {
	raw := chi.URLParam(r, "group_id")
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("group_id is required")
	}
	// gocql.ParseUUID is the canonical UUID parser in the
	// codebase; reusing it here keeps the validation rule
	// identical to the group-history handler.
	if _, err := gocql.ParseUUID(raw); err != nil {
		return "", errors.New("group_id is not a valid UUID")
	}
	return raw, nil
}

// isMemberOf returns true iff (groupID, uin) is a row in
// group_members. A non-existent group looks identical to a
// non-member (both return false) — intentional, to prevent
// group-ID enumeration via the membership check.
func isMemberOf(ctx context.Context, pg groupDB, groupID string, uin int64) (bool, error) {
	var role string
	err := pg.QueryRow(ctx, qGetGroupRole, groupID, uin).Scan(&role)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// getGroupRole returns the actor's role in a group. An empty
// string and a nil error means "not a member".
func getGroupRole(ctx context.Context, pg groupDB, groupID string, uin int64) (string, error) {
	var role string
	err := pg.QueryRow(ctx, qGetGroupRole, groupID, uin).Scan(&role)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return "", nil
		}
		return "", err
	}
	return role, nil
}

// ----------------------------------------------------------------------------
// Notification helper. Best-effort: errors are logged but do
// not fail the calling handler.
// ----------------------------------------------------------------------------

func publishGroupInviteNotification(
	parentCtx context.Context,
	bus *natsclient.Client,
	targetUIN int64,
	groupID, groupName string,
	fromUIN int64,
) {
	if bus == nil {
		return
	}
	_, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_ = parentCtx

	payload := models.NotificationPayload{
		Kind:  models.NotificationKindGroupInvite,
		Title: "Added to a group",
		Body:  "You have been added to a group",
		Data: map[string]any{
			"group_id":   groupID,
			"group_name": groupName,
			"from_uin":   fromUIN,
		},
	}
	env, err := models.NewEnvelope(models.EnvelopeTypeNotification, payload)
	if err != nil {
		log.Printf("[message-service] build group-invite envelope: %v", err)
		return
	}
	raw, err := json.Marshal(env)
	if err != nil {
		log.Printf("[message-service] marshal group-invite envelope: %v", err)
		return
	}

	subject := "notification." + strconv.FormatInt(targetUIN, 10)
	if err := bus.Publish(subject, raw); err != nil {
		log.Printf("[message-service] publish group-invite notification: %v", err)
	}
}

// ----------------------------------------------------------------------------
// Re-use the message-service's existing JSON helpers. They
// are defined in handlers/common.go (writeJSON, writeError,
// decodeJSON) — created for the groups handler because the
// history handler only ever had writeError (it doesn't
// accept a body or emit success JSON). groups.go needs
// writeJSON for its success bodies and decodeJSON for its
// request bodies, so we add the pair here.
// ----------------------------------------------------------------------------
