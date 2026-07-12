// Package handlers common helpers for the message-service.
//
// writeError was originally defined in history.go for the
// history endpoints. writeJSON and decodeJSON were added
// later, for the groups endpoints, which need to read a
// request body and emit success bodies. They share the
// auth-service's writeError envelope shape so the client
// can use a single error decoder across services.
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/iceq/iceq/shared/models"
)

// writeJSON serializes v as JSON with the standard
// Content-Type. The auth-service and key-service have
// their own writeJSON with the same signature; we keep a
// local copy here (rather than promoting it to shared/)
// because the handlers package is supposed to be
// self-contained — the small duplication is cheaper than a
// new shared sub-package just for two helpers.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[message-service] failed to encode response: %v", err)
	}
}

// writeError emits the standard ErrorResponse envelope.
// Identical signature to the other services' writeError
// so the contract is uniform: status + SNAKE_CASE code +
// human-readable message.
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(models.ErrorResponse{
		Error: message,
		Code:  code,
	})
}

// decodeJSON parses a JSON body of at most maxBytes into
// dst. Returns false and writes the error response on any
// failure. The 1 MiB default ceiling used in the
// auth-service is overkill for the groups endpoints
// (largest legitimate body is a group name + UIN); callers
// pass an explicit maxBytes that suits their endpoint.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if strings.Contains(err.Error(), "request body too large") {
			writeError(w, http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", "request body exceeds size limit")
			return false
		}
		writeError(w, http.StatusBadRequest, "MALFORMED_JSON", "request body is not valid JSON")
		return false
	}
	return true
}
