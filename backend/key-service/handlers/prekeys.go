package handlers

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/iceq/iceq/key-service/models"
	"github.com/iceq/iceq/key-service/store"
	"github.com/iceq/iceq/shared/middleware"
)

// ----------------------------------------------------------------------------
// Prekey endpoints.
//
//   POST /api/keys/prekeys        — auth required (own prekeys only)
//   GET  /api/keys/prekeys/count  — auth required (own count only)
// ----------------------------------------------------------------------------

// PrekeyDeps captures the dependencies both prekey handlers need.
type PrekeyDeps struct {
	Keystore *store.Keystore
}

// NewAddPrekeysHandler returns the http.HandlerFunc mounted at
// POST /api/keys/prekeys. MUST be wrapped with BearerAuth.
//
// The handler accepts a batch of one-time prekeys and appends
// them to the authenticated user's pool. The batch is capped
// at models.maxPrekeysPerBatch to prevent a malicious caller
// from filling the table with one large request.
func NewAddPrekeysHandler(deps PrekeyDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uin, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}

		// 16 KiB ceiling. 100 prekeys * ~50 bytes each =
		// 5 KiB. 16 KiB leaves headroom for the JSON
		// envelope and any future field additions.
		var req models.AddPrekeysRequest
		if !decodeJSON(w, r, &req, 16*1024) {
			return
		}
		if err := req.Validate(); err != nil {
			writeValidationError(w, err)
			return
		}

		// 10 s covers one INSERT with a UNNEST on 100
		// rows. Comfortable margin for a slow disk.
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		if err := deps.Keystore.AddOneTimePrekeys(ctx, uin, req.Prekeys); err != nil {
			log.Printf("[key-service] add prekeys count=%d: %v", len(req.Prekeys), err)
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not store prekeys")
			return
		}

		log.Printf("[key-service] prekeys added count=%d", len(req.Prekeys))
		// 204 No Content — the client doesn't need an
		// acknowledgement beyond "the request
		// succeeded". The next /count call will reflect
		// the new keys.
		w.WriteHeader(http.StatusNoContent)
	}
}

// NewCountPrekeysHandler returns the http.HandlerFunc mounted
// at GET /api/keys/prekeys/count. MUST be wrapped with
// BearerAuth.
//
// Returns the number of unused one-time prekeys the
// authenticated user has. The client uses this to decide when
// to replenish — the convention is to upload more when the
// count drops below a threshold (e.g. 20) so a slow consumer
// doesn't run out between checks.
func NewCountPrekeysHandler(deps PrekeyDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uin, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}

		// 3 s for one indexed count.
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		count, err := deps.Keystore.CountUnusedPrekeys(ctx, uin)
		if err != nil {
			// Defensive: a real pgx error here would be
			// unexpected (it's a simple COUNT). Treat
			// as 500.
			if !errors.Is(err, context.Canceled) {
				log.Printf("[key-service] count prekeys: %v", err)
			}
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "could not count prekeys")
			return
		}

		writeJSON(w, http.StatusOK, models.PrekeyCountResponse{Count: count})
	}
}
