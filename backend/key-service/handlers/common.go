package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/iceq/iceq/key-service/models"
)

// ----------------------------------------------------------------------------
// JSON response writer. Every handler funnels through writeJSON
// and writeError so the Content-Type header, status code, and
// error envelope are set in exactly one place. Same shape as
// the auth-service's; same rationale — drift between handlers
// is what produces "this endpoint returns {error: ...} but the
// other one returns {message: ...}" bugs.
// ----------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[key-service] failed to encode response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, models.ErrorResponse{Error: message, Code: code})
}

// ----------------------------------------------------------------------------
// Validation error → HTTP mapping.
// ----------------------------------------------------------------------------

// writeValidationError maps a models.Validate() error to a 422
// response. The public code is derived from the deepest
// (non-ErrValidation) sentinel in the chain. We translate
// each sentinel to a specific SNAKE_CASE code so a client can
// switch on it without parsing the human-readable message.
func writeValidationError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	switch {
	case errors.Is(err, models.ErrFieldRequired):
		writeError(w, http.StatusUnprocessableEntity, "FIELD_REQUIRED", "a required field is missing")
	case errors.Is(err, models.ErrKeyInvalid):
		writeError(w, http.StatusUnprocessableEntity, "KEY_INVALID", "key must be base64url-encoded byte string of the right length")
	case errors.Is(err, models.ErrKeyWrongLength):
		writeError(w, http.StatusUnprocessableEntity, "KEY_WRONG_LENGTH", "key decoded to wrong byte length")
	case errors.Is(err, models.ErrSignatureWrongLength):
		writeError(w, http.StatusUnprocessableEntity, "SIGNATURE_WRONG_LENGTH", "signature must decode to 64 bytes")
	case errors.Is(err, models.ErrTooManyPrekeys):
		writeError(w, http.StatusUnprocessableEntity, "TOO_MANY_PREKEYS", "prekey batch exceeds 100")
	default:
		writeError(w, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "request body failed validation")
	}
}

// ----------------------------------------------------------------------------
// Body decoding. Kept here so the per-handler boilerplate
// (limit reader, content-type, decode) lives in one place.
// ----------------------------------------------------------------------------

// decodeJSON parses a JSON body of at most maxBytes into dst.
// Returns false and writes the error response if the body is
// too large or the JSON is malformed. On success returns true
// and the caller proceeds.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // reject typos in the request body
	if err := dec.Decode(dst); err != nil {
		// Distinguish "too large" from "malformed" by
		// sniffing the error string. MaxBytesReader
		// returns a *http.MaxBytesError only in newer Go
		// versions; the strings.Contains path is
		// portable.
		if strings.Contains(err.Error(), "request body too large") {
			writeError(w, http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", "request body exceeds size limit")
			return false
		}
		writeError(w, http.StatusBadRequest, "MALFORMED_JSON", "request body is not valid JSON")
		return false
	}
	return true
}
