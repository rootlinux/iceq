// Contact management endpoints. Mounted at /api/contacts
// from auth-service/main.go, all routes are behind
// middleware.BearerAuth (the user's UIN comes from the JWT, not
// from the request body).
//
//	GET    /api/contacts                       → list owner's contacts
//	POST   /api/contacts                       → add a new contact (creates a pending edge in BOTH directions)
//	PUT    /api/contacts/{target_uin}/accept   → accept a pending request TO me
//	PUT    /api/contacts/{target_uin}/block    → block (or unblock-by-blocking) a contact
//	DELETE /api/contacts/{target_uin}          → remove a contact from my list
//
// Trust model:
//
//   - target_uin is server-validated against the users table; an
//     unknown UIN returns 404, not 500 (the FK violation path).
//   - owner_uin comes from middleware.GetUIN, NEVER from the
//     request body. A tampered client cannot add contacts on
//     someone else's behalf.
//   - "Add" creates a directed edge in BOTH directions so the
//     other party can see the request in their pending list.
//     Status on both edges is 'pending' until the recipient
//     explicitly accepts.
//   - "Accept" flips the recipient's view of the edge to
//     'accepted' and ALSO flips the originator's view, so the
//     originator's contact list moves the row from "pending I
//     sent" to "accepted" without a second API call.
//   - "Block" is one-way: only the blocker's edge flips to
//     'blocked'. The blocked user can still see and message the
//     blocker (this is the WhatsApp/Signal/Telegram model).
//   - "Delete" is also one-way and only touches the requester's
//     edge.
//
// All log lines omit the requester's UIN, the target's UIN, and
// the contact's username. Only operational error strings are
// logged.

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/iceq/iceq/shared/models"
	"github.com/iceq/iceq/shared/natsclient"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ----------------------------------------------------------------------------
// Dependencies. Injected once from main.go so handlers stay pure
// functions of their inputs (which makes them trivial to unit-test
// against a fixture pool + a no-op bus).
// ----------------------------------------------------------------------------

// ContactsDeps carries the shared resources every contacts handler
// needs. The pool is required; the bus is also required because the
// "add" path publishes a notification to the target user — without
// it the social graph would be silently invisible to the other
// party.
type ContactsDeps struct {
	Pool contactDB
	Bus  *natsclient.Client
}

type contactDB interface {
	Begin(context.Context) (pgx.Tx, error)
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// ----------------------------------------------------------------------------
// Response types. Kept here (rather than in a models package) so the
// wire shape is colocated with the handler that produces it. The
// JSON field names are the source of truth — never rename without
// a coordinated client rollout.
// ----------------------------------------------------------------------------

// contactItem is one row in the GET /api/contacts response. Avatar
// is an empty string (NOT null) when the user has not set one; the
// web client renders a fallback initial.
type contactItem struct {
	UIN       int64  `json:"uin"`
	Username  string `json:"username"`
	AvatarURL string `json:"avatar_url"`
	Status    string `json:"status"`
	Direction string `json:"direction,omitempty"`
}

// listContactsResponse is the body of GET /api/contacts.
type listContactsResponse struct {
	Contacts []contactItem `json:"contacts"`
}

// addContactRequest is the body of POST /api/contacts. We accept
// only a target UIN — no nickname or display name; the client pulls
// the username from the join result.
type addContactRequest struct {
	TargetUIN int64 `json:"target_uin"`
}

// contactStatusResponse is the body of every POST/PUT that returns
// a status. 204 is used for DELETE so this type does not apply
// there.
type contactStatusResponse struct {
	Status string `json:"status"`
}

// ----------------------------------------------------------------------------
// Handlers.
// ----------------------------------------------------------------------------

// NewListContactsHandler returns the http.HandlerFunc for
// GET /api/contacts. MUST be wrapped with BearerAuth.
func NewListContactsHandler(deps ContactsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uin, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		rows, err := deps.Pool.Query(ctx, qListContactsForOwner, uin)
		if err != nil {
			log.Printf("[auth-service] list contacts: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not list contacts")
			return
		}
		defer rows.Close()

		// Pre-allocate with a sensible default to avoid resizing
		// for users with 50+ contacts.
		contacts := make([]contactItem, 0, 32)
		for rows.Next() {
			var c contactItem
			if err := rows.Scan(&c.UIN, &c.Username, &c.AvatarURL, &c.Status, &c.Direction); err != nil {
				log.Printf("[auth-service] scan contact row: %v", err)
				writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not read contacts")
				return
			}
			contacts = append(contacts, c)
		}
		if err := rows.Err(); err != nil {
			log.Printf("[auth-service] iterate contact rows: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not read contacts")
			return
		}

		writeJSON(w, http.StatusOK, listContactsResponse{Contacts: contacts})
	}
}

// NewAddContactHandler returns the http.HandlerFunc for POST
// /api/contacts. MUST be wrapped with BearerAuth.
//
// Body: { "target_uin": <int64> }
//
// Side effects:
//   - INSERT (owner, target, 'pending') — the row that puts the
//     contact into the owner's "pending I sent" list.
//   - INSERT (target, owner, 'pending') — the reverse row that
//     surfaces in the target's "incoming requests" list. This
//     row is what GET /api/contacts returns with status=pending
//     and is what the Accept button acts on.
//   - Publish `notification.<target_uin>` with
//     EnvelopeType=notification, kind=contact_request. The web
//     client subscribes to this subject and shows a toast.
func NewAddContactHandler(deps ContactsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ownerUIN, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}

		var req addContactRequest
		if !decodeJSON(w, r, &req, 1<<14) {
			return
		}

		// --- Validation ---------------------------------------------
		if req.TargetUIN <= 0 {
			writeError(w, http.StatusUnprocessableEntity, "FIELD_INVALID", "target_uin must be a positive integer")
			return
		}
		if req.TargetUIN == ownerUIN {
			// Adding yourself is a no-op the spec calls out
			// explicitly. We use 422 (Unprocessable Entity)
			// rather than 400 because the request is well-
			// formed JSON; the constraint failure is
			// semantic.
			writeError(w, http.StatusUnprocessableEntity, "SELF_CONTACT_FORBIDDEN", "cannot add yourself as a contact")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// --- Existence check ----------------------------------------
		var one int
		err := deps.Pool.QueryRow(ctx, qUserExists, req.TargetUIN).Scan(&one)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "USER_NOT_FOUND", "target user does not exist")
				return
			}
			log.Printf("[auth-service] user-exists check: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not validate target user")
			return
		}

		// --- Inserts (two rows, one in each direction) --------------
		// We run them in a single transaction so a partial failure
		// (e.g. one of the two rows violates a constraint we
		// haven't anticipated) doesn't leave the social graph in
		// a half-built state.
		tx, err := deps.Pool.Begin(ctx)
		if err != nil {
			log.Printf("[auth-service] begin contact tx: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not start contact transaction")
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck

		if _, err := tx.Exec(ctx, qUpsertContact, ownerUIN, req.TargetUIN, ownerUIN); err != nil {
			log.Printf("[auth-service] insert contact row: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not insert contact")
			return
		}
		if _, err := tx.Exec(ctx, qUpsertContact, req.TargetUIN, ownerUIN, ownerUIN); err != nil {
			log.Printf("[auth-service] insert contact reverse row: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not insert contact")
			return
		}
		if err := tx.Commit(ctx); err != nil {
			log.Printf("[auth-service] commit contact tx: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not commit contact")
			return
		}

		// --- Publish notification -----------------------------------
		// The notification is best-effort. If NATS is down, the
		// contact row is still created and the target will see
		// the request on their next GET /api/contacts. We log the
		// publish error but do not fail the request.
		publishContactRequestNotification(r.Context(), deps.Bus, req.TargetUIN, ownerUIN)

		writeJSON(w, http.StatusCreated, contactStatusResponse{Status: "pending"})
	}
}

// NewAcceptContactHandler returns the http.HandlerFunc for
// PUT /api/contacts/{target_uin}/accept. MUST be wrapped with
// BearerAuth.
//
// Auth: the requesting user (the auth context's UIN) is the
// RECIPIENT of the request. The path parameter is the
// REQUESTER. The handler flips BOTH edges to 'accepted':
//
//	(target_uin → owner_uin): "from their perspective, I
//	                            accepted them"
//	(owner_uin → target_uin): "from my perspective, they're
//	                            now in my accepted list"
//
// Both updates run in a single transaction so a partial state
// is never visible. 404 is returned if the incoming edge was
// not in 'pending' state — that signals "no such request" to
// the client without distinguishing "never existed" from
// "already accepted" (the latter would leak whether the
// request was once pending).
func NewAcceptContactHandler(deps ContactsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ownerUIN, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}
		targetUIN, err := strconv.ParseInt(chi.URLParam(r, "target_uin"), 10, 64)
		if err != nil || targetUIN <= 0 {
			writeError(w, http.StatusBadRequest, "FIELD_INVALID", "target_uin must be a positive integer")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		tx, err := deps.Pool.Begin(ctx)
		if err != nil {
			log.Printf("[auth-service] begin accept tx: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not start accept transaction")
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck

		// First update: the recipient's view of the edge
		// (owner=recipient, target=requester). This is the row
		// that GET /api/contacts returned with status=pending
		// for the recipient; flipping it is what makes the
		// request "disappear" from the pending bucket.
		tag, err := tx.Exec(ctx, qAcceptContact, ownerUIN, targetUIN)
		if err != nil {
			log.Printf("[auth-service] accept contact: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not accept contact")
			return
		}
		if tag.RowsAffected() == 0 {
			// Either the row doesn't exist (target never
			// sent a request) or it was already in a
			// non-pending state. Either way the spec
			// wants a 404.
			writeError(w, http.StatusNotFound, "REQUEST_NOT_FOUND", "no pending contact request from this user")
			return
		}

		// Second update: the requester's view of the edge
		// (owner=requester, target=recipient). Created at POST
		// time so the row always exists; the update is a
		// no-op if the requester has since deleted the row,
		// which is fine (we don't 404 on a no-op reverse).
		if _, err := tx.Exec(ctx, qAcceptContactReverse, ownerUIN, targetUIN); err != nil {
			log.Printf("[auth-service] accept contact reverse: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not accept contact")
			return
		}
		if err := tx.Commit(ctx); err != nil {
			log.Printf("[auth-service] commit accept tx: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not commit accept")
			return
		}

		// Notify the original requester that their request was
		// accepted, so their UI updates without a manual reload.
		// Best-effort: NATS failures are logged but don't fail
		// the handler — the DB is already committed.
		publishContactAcceptedNotification(r.Context(), deps.Bus, targetUIN, ownerUIN)

		writeJSON(w, http.StatusOK, contactStatusResponse{Status: "accepted"})
	}
}

// NewBlockContactHandler returns the http.HandlerFunc for
// PUT /api/contacts/{target_uin}/block. MUST be wrapped with
// BearerAuth.
//
// Blocking is one-way: only the requester's edge flips to
// 'blocked'. The target's view of the relationship is
// untouched — they can still see the requester as a contact
// (pending or accepted) and still message them. The spec
// deliberately does not "mirror" the block.
//
// If the edge doesn't exist at all (target was never a
// contact), the handler INSERTs a fresh blocked row so the
// blocker can later see "I have blocked this person" in their
// list. We use an UPSERT pattern: insert with status=blocked,
// or update the existing row to blocked.
//
// The qBlockContact query is an UPDATE; we follow it with an
// INSERT (with ON CONFLICT DO NOTHING) to handle the
// "block without prior contact" case. Two queries, no
// transaction needed because the second is idempotent.
func NewBlockContactHandler(deps ContactsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ownerUIN, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}
		targetUIN, err := strconv.ParseInt(chi.URLParam(r, "target_uin"), 10, 64)
		if err != nil || targetUIN <= 0 {
			writeError(w, http.StatusBadRequest, "FIELD_INVALID", "target_uin must be a positive integer")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// First, try to UPDATE the existing edge.
		tag, err := deps.Pool.Exec(ctx, qBlockContact, ownerUIN, targetUIN)
		if err != nil {
			log.Printf("[auth-service] block contact: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not block contact")
			return
		}
		// If no row was updated, INSERT a fresh blocked row.
		// The reverse direction is intentionally NOT touched.
		if tag.RowsAffected() == 0 {
			if _, err := deps.Pool.Exec(ctx, qUpsertContactBlocked, ownerUIN, targetUIN); err != nil {
				log.Printf("[auth-service] insert blocked row: %v", err)
				writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not block contact")
				return
			}
		}

		writeJSON(w, http.StatusOK, contactStatusResponse{Status: "blocked"})
	}
}

// NewRemoveContactHandler returns the http.HandlerFunc for
// DELETE /api/contacts/{target_uin}. MUST be wrapped with
// BearerAuth.
//
// Removes the requester's edge only. The target's edge is
// preserved — they can still see the requester in their list
// (or not; the spec is silent on what the target sees after
// the requester removes them, but we deliberately do not
// "unblock from the other side" because that would be a
// privacy-violating side effect on a third-party row).
//
// 204 is returned on success regardless of whether the row
// existed. The client treats DELETE as idempotent.
func NewRemoveContactHandler(deps ContactsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ownerUIN, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}
		targetUIN, err := strconv.ParseInt(chi.URLParam(r, "target_uin"), 10, 64)
		if err != nil || targetUIN <= 0 {
			writeError(w, http.StatusBadRequest, "FIELD_INVALID", "target_uin must be a positive integer")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// We do not check RowsAffected — DELETE is idempotent
		// and a no-op is the right answer when the row
		// doesn't exist.
		if _, err := deps.Pool.Exec(ctx, qDeleteContact, ownerUIN, targetUIN); err != nil {
			log.Printf("[auth-service] delete contact: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not remove contact")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// ----------------------------------------------------------------------------
// Notification helper. Builds the contact_request envelope and
// publishes it on `notification.<target_uin>`. Best-effort: an
// error is logged but does not fail the calling handler — the
// contact row is already committed and the target will see the
// request on their next poll of GET /api/contacts.
// ----------------------------------------------------------------------------

func publishContactRequestNotification(
	parentCtx context.Context,
	bus *natsclient.Client,
	targetUIN, fromUIN int64,
) {
	if bus == nil {
		// Defensive: the bus is wired in main.go, but a
		// future test might construct the deps with a nil
		// bus. In that case we silently skip the publish.
		return
	}

	// Use a short, fresh context for the publish so a slow
	// NATS doesn't hold onto the parent request context. The
	// publish is fire-and-forget at the NATS level (no
	// request/reply), so 1 s is plenty.
	_, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_ = parentCtx // not used directly; we deliberately don't bind to the request

	payload := models.NotificationPayload{
		Kind:  models.NotificationKindContactRequest,
		Title: "New contact request",
		Body:  "You have a new contact request",
		Data: map[string]any{
			"from_uin": fromUIN,
		},
	}
	env, err := models.NewEnvelope(models.EnvelopeTypeNotification, payload)
	if err != nil {
		log.Printf("[auth-service] build contact-request envelope: %v", err)
		return
	}
	raw, err := json.Marshal(env)
	if err != nil {
		log.Printf("[auth-service] marshal contact-request envelope: %v", err)
		return
	}

	subject := "notification." + strconv.FormatInt(targetUIN, 10)
	if err := bus.Publish(subject, raw); err != nil {
		log.Printf("[auth-service] publish contact-request notification: %v", err)
	}
}

// publishContactAcceptedNotification tells the original requester that
// their pending contact request was accepted. Best-effort — an error is
// logged but does not fail the caller because the contact rows are
// already committed.
func publishContactAcceptedNotification(
	parentCtx context.Context,
	bus *natsclient.Client,
	requesterUIN, acceptorUIN int64,
) {
	if bus == nil {
		return
	}
	_, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_ = parentCtx

	payload := models.NotificationPayload{
		Kind:  models.NotificationKindContactAccepted,
		Title: "Contact request accepted",
		Body:  "Your contact request was accepted",
		Data: map[string]any{
			"from_uin": acceptorUIN,
		},
	}
	env, err := models.NewEnvelope(models.EnvelopeTypeNotification, payload)
	if err != nil {
		log.Printf("[auth-service] build contact-accepted envelope: %v", err)
		return
	}
	raw, err := json.Marshal(env)
	if err != nil {
		log.Printf("[auth-service] marshal contact-accepted envelope: %v", err)
		return
	}

	subject := "notification." + strconv.FormatInt(requesterUIN, 10)
	if err := bus.Publish(subject, raw); err != nil {
		log.Printf("[auth-service] publish contact-accepted notification: %v", err)
	}
}
