package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gocql/gocql"
	"github.com/iceq/iceq/message-service/store"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ----------------------------------------------------------------------------
// History endpoints.
//
//   GET /api/messages/history         → DM history (auth required)
//   GET /api/messages/group-history   → group history (auth required)
//
// Both endpoints are read-only and accept the same query
// parameters:
//
//   - conversation_id (or group_id)  — the canonical
//                                      conversation identifier
//                                      ("dm:<min>:<max>" or
//                                      a UUID for groups).
//   - before                         — RFC3339 timestamp cursor.
//                                      Default: now. Rows with
//                                      created_at < before are
//                                      returned.
//   - limit                          — 1..50, default 20.
//
// Both endpoints require BearerAuth (the requesting user's
// UIN comes from the verified JWT, never from a query
// param). On success the response shape is:
//
//	{
//	  "messages": [ { ... }, ... ],   // newest first
//	  "next_cursor": "<RFC3339|null>" // for pagination
//	}
//
// next_cursor is the CreatedAt of the LAST row returned
// (which is the OLDEST row on this page, because the rows
// are in DESC order). Pass it back as `before` to fetch
// the next page. A null value means "no more pages" —
// the response was a partial page (< limit rows).
//
// E2EE contract: the response body carries the
// base64url-encoded ciphertext bytes from each row. We
// encode them for JSON-safety and forward them as-is. We
// never log, inspect, or transform the bytes themselves.
// ----------------------------------------------------------------------------

// HistoryDeps captures the dependencies both history
// handlers need. Inject once in main.go and pass by value
// to the handler constructors.
type HistoryDeps struct {
	Store *store.MessageStore
	PG    *pgxpool.Pool
}

// ----------------------------------------------------------------------------
// Response shape. We define the wire types here so the
// JSON keys are colocated with the handler that produces
// them. The on-wire shape is the public API; the struct
// field names below are the source of truth.
// ----------------------------------------------------------------------------

// historyMessage is one row of the response. The
// ciphertext is base64url-encoded so the JSON body is
// valid (binary bytes in JSON require escaping, and
// base64 keeps the wire form compact).
type historyMessage struct {
	ID             string    `json:"id"`
	ConversationID string    `json:"conversation_id,omitempty"`
	GroupID        string    `json:"group_id,omitempty"`
	SenderUIN      int64     `json:"sender_uin"`
	ReceiverUIN    int64     `json:"receiver_uin,omitempty"`
	ContentType    string    `json:"content_type"`
	Ciphertext     string    `json:"ciphertext"`
	MsgType        string    `json:"msg_type"`
	Status         string    `json:"status,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// historyResponse is the envelope returned by both
// history endpoints.
type historyResponse struct {
	Messages   []historyMessage `json:"messages"`
	NextCursor *time.Time       `json:"next_cursor"`
}

// ----------------------------------------------------------------------------
// NewGetHistoryHandler returns the http.HandlerFunc mounted
// at GET /api/messages/history. MUST be wrapped with
// BearerAuth.
// ----------------------------------------------------------------------------

// NewGetHistoryHandler serves GET /api/messages/history.
//
// Auth: the requesting UIN comes from middleware.GetUIN.
// The conversation_id must start with "dm:"; the rest is
// parsed into two UINs and one of them must equal the
// requesting UIN. A foreign request (requesting a
// conversation you are not part of) is a 403.
//
// Pagination: limit defaults to 20, max 50. before is
// optional RFC3339; missing or empty means "now".
func NewGetHistoryHandler(deps HistoryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uin, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}

		// --- Query string parsing ------------------------------------
		convID := strings.TrimSpace(r.URL.Query().Get("conversation_id"))
		if convID == "" {
			writeError(w, http.StatusBadRequest, "FIELD_REQUIRED", "conversation_id is required")
			return
		}
		if !strings.HasPrefix(convID, "dm:") {
			writeError(w, http.StatusBadRequest, "CONVERSATION_ID_INVALID", "conversation_id must start with \"dm:\"")
			return
		}

		before, err := parseBeforeParam(r.URL.Query().Get("before"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "BEFORE_INVALID", err.Error())
			return
		}
		limit, err := parseLimitParam(r.URL.Query().Get("limit"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "LIMIT_INVALID", err.Error())
			return
		}

		// --- Authorization: the requesting UIN must be a member -----
		// Conversation IDs are "dm:<min>:<max>" where min and max
		// are decimal int64s. The order is canonical so the same
		// conversation always produces the same string regardless
		// of who initiated it.
		otherUIN, ok := parseDMMembers(convID, uin)
		if !ok {
			// Either the format is wrong (not parseable as
			// "dm:int:int") or the requesting UIN is not
			// one of the two members. We collapse both
			// cases to a 403 to avoid leaking the
			// conversation shape to a probing caller.
			writeError(w, http.StatusForbidden, "NOT_A_MEMBER", "requesting user is not a member of this conversation")
			return
		}
		_ = otherUIN // not needed for the query path; the partition
		// key (convID) is the same either way.

		// --- Query ---------------------------------------------------
		// 5 s is generous for a single-partition read on a
		// keyspace with CL=QUORUM. Scylla is sub-millisecond
		// on local networks; this leaves headroom for a cold
		// coordinator or a network blip.
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		rows, err := deps.Store.GetHistory(ctx, store.HistoryRequest{
			ConversationID: convID,
			Before:         before,
			Limit:          limit,
		})
		if err != nil {
			// Limit validation surfaces here; everything
			// else is a transport / DB error.
			if errors.Is(err, store.ErrInvalidLimit) {
				writeError(w, http.StatusBadRequest, "LIMIT_INVALID", err.Error())
				return
			}
			log.Printf("[message-service] get history: %v", err)
			writeError(w, http.StatusInternalServerError, "STORE_ERROR", "could not fetch history")
			return
		}

		writeHistoryResponse(w, convID, "", rows, len(rows) < limit, dmRowToMessage)
	}
}

// ----------------------------------------------------------------------------
// NewGetGroupHistoryHandler returns the http.HandlerFunc
// mounted at GET /api/messages/group-history. MUST be
// wrapped with BearerAuth.
// ----------------------------------------------------------------------------

// NewGetGroupHistoryHandler serves
// GET /api/messages/group-history.
//
// Auth: the requesting UIN must be a row in
// group_members for the given group_id. A non-member
// request is a 403 (we deliberately do NOT distinguish
// "group does not exist" from "you are not a member" —
// the leak would let a probing caller enumerate group
// IDs).
func NewGetGroupHistoryHandler(deps HistoryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uin, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}

		// --- Query string parsing ------------------------------------
		groupIDStr := strings.TrimSpace(r.URL.Query().Get("group_id"))
		if groupIDStr == "" {
			writeError(w, http.StatusBadRequest, "FIELD_REQUIRED", "group_id is required")
			return
		}
		groupID, err := gocql.ParseUUID(groupIDStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "GROUP_ID_INVALID", "group_id is not a valid UUID")
			return
		}

		before, err := parseBeforeParam(r.URL.Query().Get("before"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "BEFORE_INVALID", err.Error())
			return
		}
		limit, err := parseLimitParam(r.URL.Query().Get("limit"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "LIMIT_INVALID", err.Error())
			return
		}

		// --- Authorization: requesting UIN must be a member --------
		ctxAuth, cancelAuth := context.WithTimeout(r.Context(), 2*time.Second)
		isMember, err := isGroupMember(ctxAuth, deps.PG, groupID, uin)
		cancelAuth()
		if err != nil {
			log.Printf("[message-service] group membership check: %v", err)
			writeError(w, http.StatusInternalServerError, "STORE_ERROR", "could not check group membership")
			return
		}
		if !isMember {
			writeError(w, http.StatusForbidden, "NOT_A_MEMBER", "requesting user is not a member of this group")
			return
		}

		// --- Query ---------------------------------------------------
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		rows, err := deps.Store.GetGroupHistory(ctx, store.GroupHistoryRequest{
			GroupID: groupID,
			Before:  before,
			Limit:   limit,
		})
		if err != nil {
			if errors.Is(err, store.ErrInvalidLimit) {
				writeError(w, http.StatusBadRequest, "LIMIT_INVALID", err.Error())
				return
			}
			log.Printf("[message-service] get group history: %v", err)
			writeError(w, http.StatusInternalServerError, "STORE_ERROR", "could not fetch group history")
			return
		}

		writeHistoryResponse(w, "", groupIDStr, rows, len(rows) < limit, groupRowToMessage)
	}
}

// ----------------------------------------------------------------------------
// Row → response conversion. Two small adapter closures
// keep the dispatch site in writeHistoryResponse tidy.
// ----------------------------------------------------------------------------

// dmRowToMessage converts a direct-message row into the
// wire-format historyMessage. The ciphertext is
// base64url-encoded so the JSON body is safe to transport
// over any 8-bit-clean link.
func dmRowToMessage(convID, groupID string, row any) historyMessage {
	r := row.(store.MessageRow)
	return historyMessage{
		ID:             r.ID.String(),
		ConversationID: convID,
		SenderUIN:      r.SenderUIN,
		ReceiverUIN:    r.ReceiverUIN,
		Ciphertext:     base64.RawURLEncoding.EncodeToString(r.Ciphertext),
		MsgType:        r.MsgType,
		Status:         r.Status,
		CreatedAt:      r.CreatedAt,
	}
}

// groupRowToMessage converts a group-message row into the
// wire-format historyMessage. Group rows have no
// receiver_uin or status field.
func groupRowToMessage(convID, groupID string, row any) historyMessage {
	r := row.(store.GroupMessageRow)
	return historyMessage{
		ID:          r.ID.String(),
		GroupID:     groupID,
		SenderUIN:   r.SenderUIN,
		ContentType: "text",
		Ciphertext:  base64.RawURLEncoding.EncodeToString(r.Ciphertext),
		MsgType:     r.MsgType,
		CreatedAt:   r.CreatedAt,
	}
}

// rowConverter is the function signature for the
// row-to-message adapter. The two implementations differ
// only in the source type; the result type is shared so
// the dispatch site can be one block.
type rowConverter func(convID, groupID string, row any) historyMessage

// writeHistoryResponse marshals rows to JSON, sets the
// Content-Type, and computes next_cursor. hasMore=false
// means the caller should treat next_cursor as
// "no more pages".
func writeHistoryResponse(
	w http.ResponseWriter,
	convID, groupID string,
	rows any,
	hasMore bool,
	convert rowConverter,
) {
	// Reflect on the slice type so we can iterate without
	// a type switch at every call site. The rows are
	// always one of []store.MessageRow or
	// []store.GroupMessageRow; both are []any under the
	// hood.
	msgs := make([]historyMessage, 0)
	switch r := rows.(type) {
	case []store.MessageRow:
		for _, row := range r {
			msgs = append(msgs, convert(convID, groupID, row))
		}
	case []store.GroupMessageRow:
		for _, row := range r {
			msgs = append(msgs, convert(convID, groupID, row))
		}
	}

	// next_cursor: the CreatedAt of the last (oldest)
	// row in DESC order. nil when we returned a partial
	// page, signaling end-of-history to the client.
	var nextCursor *time.Time
	if !hasMore && len(msgs) > 0 {
		// partial page: end of stream
		nextCursor = nil
	} else if len(msgs) > 0 {
		last := msgs[len(msgs)-1].CreatedAt
		nextCursor = &last
	}

	resp := historyResponse{
		Messages:   msgs,
		NextCursor: nextCursor,
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ----------------------------------------------------------------------------
// Query-string parsers. Kept here (rather than in a
// helper file) because they're used only by the two
// history handlers.
// ----------------------------------------------------------------------------

// parseBeforeParam parses the `before` query parameter as
// RFC3339. Empty / missing means "now" (caller passes
// time.Time{}).
func parseBeforeParam(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, s)
}

// parseLimitParam parses the `limit` query parameter.
// Empty / missing means "default" (caller passes 0 and
// the store applies defaultHistoryLimit). Values < 1
// or > 50 are rejected; the spec calls for a 1..50 range.
func parseLimitParam(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, errors.New("limit must be an integer in [1, 50]")
	}
	if n < 1 || n > 50 {
		return 0, errors.New("limit must be an integer in [1, 50]")
	}
	return n, nil
}

// parseDMMembers parses a "dm:<min>:<max>" conversation
// ID and returns the OTHER UIN (the one that isn't the
// requesting user). The boolean is true iff the
// conversation ID parses correctly AND the requesting
// UIN is one of the two members.
func parseDMMembers(convID string, requestingUIN int64) (int64, bool) {
	parts := strings.Split(convID, ":")
	if len(parts) != 3 || parts[0] != "dm" {
		return 0, false
	}
	a, errA := strconv.ParseInt(parts[1], 10, 64)
	b, errB := strconv.ParseInt(parts[2], 10, 64)
	if errA != nil || errB != nil || a <= 0 || b <= 0 || a >= b {
		return 0, false
	}
	switch requestingUIN {
	case a:
		return b, true
	case b:
		return a, true
	default:
		return 0, false
	}
}

// isGroupMember checks the group_members table for a
// (group_id, uin) row. Returns true iff such a row
// exists. A non-existent group looks identical to a
// non-member (both return false) — this is intentional,
// to prevent group-ID enumeration via the history
// endpoint.
func isGroupMember(ctx context.Context, pg *pgxpool.Pool, groupID gocql.UUID, uin int64) (bool, error) {
	const q = `SELECT 1 FROM group_members WHERE group_id = $1 AND uin = $2 LIMIT 1`
	var x int
	err := pg.QueryRow(ctx, q, groupID, uin).Scan(&x)
	if err != nil {
		// pgx returns ErrNoRows when the SELECT found
		// nothing; that is the "not a member" case,
		// not a transport error.
		if err.Error() == "no rows in result set" {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// writeError was here historically but moved to common.go
// when the groups handler (groups.go) was added in Step 10
// and needed writeJSON + decodeJSON alongside writeError.
// The history handlers now use the common.go version.
