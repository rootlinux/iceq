package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/iceq/iceq/auth-service/models"
	"github.com/iceq/iceq/shared/jwt"
	"github.com/jackc/pgx/v5/pgconn"
)

// ----------------------------------------------------------------------------
// JSON response writer. Every handler funnels through writeJSON
// and writeError so the Content-Type header, status code, and
// error envelope are set in exactly one place. Drift between
// handlers is what produces "this endpoint returns {error: ...}
// but the other one returns {message: ...}" — centralizing the
// shape here makes that class of bug impossible.
// ----------------------------------------------------------------------------

// writeJSON serializes v as JSON with status and the standard
// Content-Type. Any encoding error is logged but cannot be
// surfaced to the client (the status was already sent). In
// practice the only failure mode is a type whose MarshalJSON
// returns an error, which is a bug we'd want to know about
// before the response went out.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[auth-service] failed to encode response: %v", err)
	}
}

// writeError emits the standard ErrorResponse envelope. The
// `code` is the public, machine-readable identifier; the
// `message` is human-readable and may be tweaked without a
// breaking change to clients.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, models.ErrorResponse{Error: message, Code: code})
}

// ----------------------------------------------------------------------------
// Validation error → HTTP mapping. The models package's
// validation methods return wrapped sentinels. This helper walks
// the chain once and emits the right public code.
// ----------------------------------------------------------------------------

// writeValidationError maps a models.Validate() error to a 422
// response. The public code is derived from the deepest
// (non-ErrValidation) sentinel in the chain.
func writeValidationError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	switch {
	case errors.Is(err, models.ErrUsernameInvalid):
		writeError(w, http.StatusUnprocessableEntity, "USERNAME_INVALID", "username must be 3-30 chars, alphanumeric or underscore")
	case errors.Is(err, models.ErrEmailInvalid):
		writeError(w, http.StatusUnprocessableEntity, "EMAIL_INVALID", "email is not a valid address")
	case errors.Is(err, models.ErrPasswordTooShort):
		writeError(w, http.StatusUnprocessableEntity, "PASSWORD_TOO_SHORT", "password must be at least 8 characters")
	case errors.Is(err, models.ErrPasswordTooLong):
		writeError(w, http.StatusUnprocessableEntity, "PASSWORD_TOO_LONG", "password must be at most 128 characters")
	case errors.Is(err, models.ErrFieldRequired):
		writeError(w, http.StatusUnprocessableEntity, "FIELD_REQUIRED", "a required field is missing")
	case errors.Is(err, models.ErrRefreshTokenMissing):
		writeError(w, http.StatusUnprocessableEntity, "REFRESH_TOKEN_REQUIRED", "refresh_token is required")
	case errors.Is(err, models.ErrIdentityKeyRequired):
		writeError(w, http.StatusUnprocessableEntity, "IDENTITY_KEY_REQUIRED", "identity_key is required")
	case errors.Is(err, models.ErrIdentityKeyInvalid):
		writeError(w, http.StatusUnprocessableEntity, "IDENTITY_KEY_INVALID", "identity_key must be a base64url-encoded 32-byte X25519 public key")
	case errors.Is(err, models.ErrLoginIdentifierMissing):
		writeError(w, http.StatusUnprocessableEntity, "LOGIN_IDENTIFIER_REQUIRED", "username or email is required")
	default:
		writeError(w, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "request body failed validation")
	}
}

// ----------------------------------------------------------------------------
// Postgres unique-violation mapping. The pgx driver returns
// *pgconn.PgError with a Code field; 23505 is the SQLSTATE for
// unique_violation. We map that to a 409 because the user
// already exists; any other pg error is a 500 because the DB
// is doing something unexpected.
// ----------------------------------------------------------------------------

// writeDBError translates a *pgconn.PgError (or any other error
// from a pgx call) into a public error response. Returns true
// if a response was written, false if err was nil. Callers
// should log err at this layer so the server-side log has the
// full driver diagnostic.
func writeDBError(w http.ResponseWriter, err error, context string) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		// 23505 = unique_violation. The auth-service's users
		// table has UNIQUE on username and email; the
		// refresh_tokens table has no uniques.
		if pgErr.Code == "23505" {
			// We don't surface WHICH field collided because
			// doing so would let an attacker enumerate which
			// usernames / emails are taken. The generic 409
			// is deliberate.
			writeError(w, http.StatusConflict, "USER_EXISTS", "username or email is already taken")
			return true
		}
		// 23503 = foreign_key_violation. We shouldn't hit this
		// on the user table (no FKs into it that we control),
		// but if we do, it's a server-side bug, not a client
		// problem.
		if pgErr.Code == "23503" {
			log.Printf("[auth-service] %s: foreign key violation: %v", context, pgErr)
			writeError(w, http.StatusInternalServerError, "DB_CONSTRAINT", "database constraint violated")
			return true
		}
		log.Printf("[auth-service] %s: pg error: %v", context, pgErr)
		writeError(w, http.StatusInternalServerError, "DB_ERROR", "database error")
		return true
	}
	// Non-pg error — network blip, context deadline, etc.
	// We deliberately return 500 with a generic message and
	// log the full detail server-side.
	log.Printf("[auth-service] %s: %v", context, err)
	writeError(w, http.StatusInternalServerError, "DB_ERROR", "database error")
	return true
}

// ----------------------------------------------------------------------------
// Body decoding. Keeps the per-handler boilerplate (limit reader,
// content-type check, decode) in one place.
// ----------------------------------------------------------------------------

// decodeJSON parses a JSON body of at most maxBytes into dst.
// Returns false and writes the error response if the body is
// too large, the content type is wrong, or the JSON is
// malformed. On success returns true and the caller proceeds.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) bool {
	// 1 MiB is a comfortable ceiling for the auth-service: the
	// largest legitimate body is the registration form at a
	// few hundred bytes.
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // reject typos in the request body
	if err := dec.Decode(dst); err != nil {
		// Distinguish "too large" from "malformed" by sniffing
		// the error string. MaxBytesReader returns a *http.MaxBytesError
		// but only in newer Go versions; the strings.Contains
		// path is portable.
		if strings.Contains(err.Error(), "request body too large") {
			writeError(w, http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", "request body exceeds size limit")
			return false
		}
		writeError(w, http.StatusBadRequest, "MALFORMED_JSON", "request body is not valid JSON")
		return false
	}
	return true
}

// clientIP returns the verified client IP.
// Priority: X-Real-IP (set by Caddy to TCP peer) → r.RemoteAddr.
// X-Forwarded-For is intentionally ignored — it is client-supplied
// and trivially spoofable. Caddy is the only trusted upstream proxy;
// it sets X-Real-IP, not X-Forwarded-For.
func clientIP(r *http.Request) string {
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	// RemoteAddr is "host:port". Split off the port.
	if i := strings.LastIndex(r.RemoteAddr, ":"); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}

// ----------------------------------------------------------------------------
// JWT error classification. Maps a jwt.Manager error onto a stable
// (code, message) pair. The middleware package has its own copy of
// this function (used inside BearerAuth) — we keep a parallel copy
// here so the refresh handler can render the same error envelope
// shape without depending on the middleware's internal API.
//
// Codes are part of the public API (clients switch on them) and
// are identical to the middleware's codes so a client can use a
// single error-code switch across all 401 responses. The messages
// differ because the context here is a refresh token, not an
// access token.
// ----------------------------------------------------------------------------

// classifyJWTError translates a jwt.Manager sentinel error into
// the public (code, message) tuple. The codes are stable across
// the auth-service's lifetime; the messages are not.
func classifyJWTError(err error) (code, message string) {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return "TOKEN_EXPIRED", "token has expired; please log in again"
	case errors.Is(err, jwt.ErrTokenRevoked):
		return "TOKEN_REVOKED", "token has been revoked; please log in again"
	case errors.Is(err, jwt.ErrTokenWrongType):
		return "TOKEN_WRONG_TYPE", "wrong token type for this endpoint"
	default:
		return "TOKEN_INVALID", "token is invalid"
	}
}
