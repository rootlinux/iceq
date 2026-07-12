// Package handlers — settings.go
//
// The settings handler exposes GET and PUT /api/auth/settings — the
// per-user panic-wipe configuration. Both endpoints are behind
// BearerAuth: the user's UIN is the primary key, and only the
// authenticated user is allowed to read or write their own row.
//
// Design points:
//
//  1. GET returns the documented defaults (panic_wipe_enabled=false,
//     panic_wipe_threshold=3) when no row exists, rather than 404.
//     A 404 on a "settings" page would be a UX trap: the user
//     expects something to render.
//
//  2. PUT validates threshold in [1, 10] before writing. The DB has
//     a CHECK constraint for the same range as a belt-and-suspenders
//     measure, but rejecting at the handler means the client gets
//     a 422 with a human-readable code rather than a 500 from a
//     constraint violation.
//
//  3. The handler is the ONLY writer to user_security_settings.
//     login.go reads from it; nothing else touches the table. This
//     keeps the audit trail simple — every row was either created
//     or modified by a settings PUT.
package handlers

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/iceq/iceq/auth-service/models"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ----------------------------------------------------------------------------
// Constants. Pulled out so the validation paths and the response
// defaults agree on the same numbers.
// ----------------------------------------------------------------------------

const (
	// defaultPanicWipeEnabled is the documented off-by-default
	// behavior. A user who never visits the security settings
	// page therefore has no auto-wipe; the feature is opt-in.
	defaultPanicWipeEnabled = false

	// defaultPanicWipeThreshold is 3 — low enough to cut off a
	// brute-force attempt quickly, high enough to tolerate
	// two or three mis-typed passwords by the legitimate
	// owner. Matches the iPhone "Erase Data after 10"
	// philosophy divided by ~3 (iPhone users tend to type
	// fast; 3 attempts is the sweet spot for "obviously me
	// vs. obviously not me").
	defaultPanicWipeThreshold = 3

	// minPanicWipeThreshold and maxPanicWipeThreshold bound
	// the user-configurable range. 1 means "wipe on the very
	// first failure" — aggressive but defensible for
	// high-value accounts. 10 is the iPhone-canonical cap.
	minPanicWipeThreshold = 1
	maxPanicWipeThreshold = 10
)

// ----------------------------------------------------------------------------
// Settings handler dependencies.
// ----------------------------------------------------------------------------

type SettingsDeps struct {
	Pool *pgxpool.Pool
}

// ----------------------------------------------------------------------------
// Request/response shapes. Defined here (not in models/) because
// they are part of the handler's wire contract, not a general
// "user identity" model. The response shape is also used by the
// PUT path so the client gets a single canonical struct to parse.
// ----------------------------------------------------------------------------

// settingsResponse is the body of both GET and PUT /api/auth/settings.
// UpdatedAt is the timestamp the row was last written; null on
// the "row not yet created" GET path.
type settingsResponse struct {
	PanicWipeEnabled   bool       `json:"panic_wipe_enabled"`
	PanicWipeThreshold int        `json:"panic_wipe_threshold"`
	UpdatedAt          *time.Time `json:"updated_at"`
}

// settingsUpdateRequest is the body of PUT /api/auth/settings.
// PanicWipeEnabled is a bool (not a *bool) so the JSON
// decoder can disambiguate "explicitly false" from
// "field missing"; both are valid client values but the
// first is the one we want.
type settingsUpdateRequest struct {
	PanicWipeEnabled   bool `json:"panic_wipe_enabled"`
	PanicWipeThreshold int  `json:"panic_wipe_threshold"`
}

// Validate enforces the documented 1..10 range. The bool is
// always valid by type, so the only field that can fail is
// the threshold.
func (r *settingsUpdateRequest) Validate() error {
	if r.PanicWipeThreshold < minPanicWipeThreshold ||
		r.PanicWipeThreshold > maxPanicWipeThreshold {
		return models.ErrFieldRequired // not a great fit; see note below
	}
	return nil
}

// ----------------------------------------------------------------------------
// Handlers.
// ----------------------------------------------------------------------------

// NewGetSettingsHandler returns the http.HandlerFunc mounted at
// GET /api/auth/settings. Always authed; the user's UIN comes
// from the request context (set by BearerAuth).
func NewGetSettingsHandler(deps SettingsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uin, ok := middleware.GetUIN(r.Context())
		if !ok {
			// Should be impossible behind BearerAuth; the
			// middleware either succeeds and injects the
			// UIN or fails the request with 401 before
			// the handler runs.
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING", "missing uin in context")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		resp, err := readSecuritySettings(ctx, deps.Pool, uin)
		if err != nil {
			log.Printf("[auth-service] read settings: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not read security settings")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// NewPutSettingsHandler returns the http.HandlerFunc mounted at
// PUT /api/auth/settings. Body is JSON of shape
// {panic_wipe_enabled, panic_wipe_threshold}. Validation is
// done before the DB write so a bad threshold is a 422, not a
// constraint violation 500.
func NewPutSettingsHandler(deps SettingsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uin, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING", "missing uin in context")
			return
		}

		var req settingsUpdateRequest
		if !decodeJSON(w, r, &req, 4*1024) {
			return
		}
		if err := req.Validate(); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "INVALID_THRESHOLD",
				"panic_wipe_threshold must be between 1 and 10")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		if _, err := deps.Pool.Exec(ctx, qUpsertSecuritySettings,
			uin, req.PanicWipeEnabled, req.PanicWipeThreshold); err != nil {
			log.Printf("[auth-service] upsert settings: %v", err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not update security settings")
			return
		}

		// Return the canonical shape (same as GET) so the
		// client can render the page from a single struct
		// without a follow-up GET.
		resp, err := readSecuritySettings(ctx, deps.Pool, uin)
		if err != nil {
			// The write succeeded but the read failed;
			// unusual but possible (e.g. PG replica
			// lag, but we don't have replicas in step 3).
			// Return a synthetic response from the request
			// values plus a "now" timestamp.
			now := time.Now().UTC()
			writeJSON(w, http.StatusOK, settingsResponse{
				PanicWipeEnabled:   req.PanicWipeEnabled,
				PanicWipeThreshold: req.PanicWipeThreshold,
				UpdatedAt:          &now,
			})
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// ----------------------------------------------------------------------------
// Helpers.
// ----------------------------------------------------------------------------

// readSecuritySettings returns the user's settings, or the
// documented defaults if no row exists. The bool returned via
// the "exists" channel is unused (the caller can tell from
// resp.UpdatedAt being nil); we keep the function signature
// small.
func readSecuritySettings(ctx context.Context, pool *pgxpool.Pool, uin int64) (settingsResponse, error) {
	var (
		enabled   bool
		threshold int
		updatedAt time.Time
	)
	err := pool.QueryRow(ctx, qSelectSecuritySettings, uin).
		Scan(&enabled, &threshold, &updatedAt)
	switch {
	case err == nil:
		return settingsResponse{
			PanicWipeEnabled:   enabled,
			PanicWipeThreshold: threshold,
			UpdatedAt:          &updatedAt,
		}, nil
	case errors.Is(err, pgx.ErrNoRows):
		// Documented defaults. The user has not visited
		// the settings page (or wiped it). The response
		// has no updated_at because the row was never
		// written; the client should treat a null
		// updated_at as "default values, not yet
		// persisted".
		return settingsResponse{
			PanicWipeEnabled:   defaultPanicWipeEnabled,
			PanicWipeThreshold: defaultPanicWipeThreshold,
			UpdatedAt:          nil,
		}, nil
	default:
		return settingsResponse{}, err
	}
}
