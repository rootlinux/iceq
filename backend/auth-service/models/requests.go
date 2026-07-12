// Package models defines the wire-shape of every request and response
// the auth-service exposes. The handlers convert these to and from
// JSON via encoding/json's standard reflection path — no third-party
// marshaller, no field-tag soup beyond the json tags below.
//
// Validation lives on the structs themselves as methods. Each method
// returns a typed sentinel error so the handler can map it to a
// specific HTTP status (422) and machine-readable error code
// (VALIDATION_FAILED, USERNAME_INVALID, etc.) without re-implementing
// the rules in the handler body.
package models

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// ----------------------------------------------------------------------------
// Sentinel validation errors. Handlers classify with errors.Is and
// translate into the public error code returned to the client.
// ----------------------------------------------------------------------------

var (
	ErrValidation          = errors.New("models: validation failed")
	ErrUsernameInvalid     = errors.New("models: username must be 3-30 chars, alphanumeric or underscore")
	ErrEmailInvalid        = errors.New("models: email is not a valid address")
	ErrPasswordTooShort    = errors.New("models: password must be at least 8 characters")
	ErrPasswordTooLong     = errors.New("models: password must be at most 128 characters")
	ErrFieldRequired       = errors.New("models: required field is missing")
	ErrRefreshTokenMissing = errors.New("models: refresh_token is required")

	// ErrIdentityKeyRequired is returned when the client
	// omits identity_key on /register. The Signal Protocol
	// handshake cannot start without the user's long-term
	// X25519 public key, so the field is mandatory on
	// registration. The user can, however, rotate it later via
	// the key-service's POST /api/keys/bundle.
	ErrIdentityKeyRequired = errors.New("models: identity_key is required")

	// ErrIdentityKeyInvalid is returned when identity_key is
	// present but does not base64url-decode to exactly 32
	// bytes (the X25519 public-key length). Anything else —
	// 31 bytes, 33 bytes, 16 bytes — is rejected because the
	// cryptographic primitive is not length-tolerant.
	ErrIdentityKeyInvalid = errors.New("models: identity_key must be base64url-encoded 32-byte X25519 public key")

	// ErrLoginIdentifierMissing is returned when neither username
	// nor email is present on /login.
	ErrLoginIdentifierMissing = errors.New("models: username or email is required")
)

// ----------------------------------------------------------------------------
// Request / response shapes.
// ----------------------------------------------------------------------------

// RegisterRequest is the body of POST /api/auth/register.
//
// Field semantics under the E2EE architecture:
//
//   - Username, Password: identification + credential, as before.
//   - Email: OPTIONAL. An empty string is treated as "no email
//     provided" and stored as NULL in the database. Multiple users
//     with no email are permitted (Postgres UNIQUE treats NULLs as
//     distinct). This is a deliberate departure from the pre-E2EE
//     spec, which required an email — the architecture update
//     recognized that the identity key is the canonical identifier
//     for an E2EE system, and forcing an email exposed a
//     metadata-leak side channel.
//   - IdentityKey: REQUIRED. Base64url-encoded 32-byte X25519
//     public key. The server stores it in users.identity_key as
//     plaintext (it's a public key by definition). The
//     corresponding private key is generated client-side and
//     NEVER crosses the network.
type RegisterRequest struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	IdentityKey string `json:"identity_key"`
}

// Validate enforces the registration rules:
//   - username: 3-30 chars, alphanumeric or underscore
//   - email: optional; if present must be RFC 5322-shaped
//   - password: 8-128 utf8 runes
//   - identity_key: required; must base64url-decode to 32 bytes
//
// Returns the first violation wrapped in ErrValidation so handlers
// can surface the field name in the error code.
func (r *RegisterRequest) Validate() error {
	if r.Username == "" {
		return fmt.Errorf("%w: username: %w", ErrValidation, ErrFieldRequired)
	}
	if !usernamePattern.MatchString(r.Username) {
		return fmt.Errorf("%w: username: %w", ErrValidation, ErrUsernameInvalid)
	}
	// Email is optional under the E2EE architecture. An empty
	// string skips both the "required" check and the
	// "well-formed" check; any non-empty value must be a
	// valid address.
	if r.Email != "" {
		if _, err := mail.ParseAddress(r.Email); err != nil {
			return fmt.Errorf("%w: email: %w", ErrValidation, ErrEmailInvalid)
		}
	}
	if r.Password == "" {
		return fmt.Errorf("%w: password: %w", ErrValidation, ErrFieldRequired)
	}
	if utf8.RuneCountInString(r.Password) < 8 {
		return fmt.Errorf("%w: password: %w", ErrValidation, ErrPasswordTooShort)
	}
	if utf8.RuneCountInString(r.Password) > 128 {
		return fmt.Errorf("%w: password: %w", ErrValidation, ErrPasswordTooLong)
	}
	if r.IdentityKey == "" {
		return fmt.Errorf("%w: identity_key: %w", ErrValidation, ErrIdentityKeyRequired)
	}
	if !isBase64URL32(r.IdentityKey) {
		return fmt.Errorf("%w: identity_key: %w", ErrValidation, ErrIdentityKeyInvalid)
	}
	return nil
}

// usernamePattern is the registration-time check. We keep it stricter
// than the RFC's broad definition because usernames are visible in
// URLs, group rosters, and @mentions — restricting the charset stops
// homograph / injection attacks at the source.
//
// The set is intentionally ASCII-only. Real international usernames
// can be added by extending this regex to the Unicode Letter
// categories, but that requires IDN normalization and a homograph
// check we'd rather defer until there's a concrete product need.
var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{3,30}$`)

// x25519PublicKeyLen is the byte length of an X25519 public key.
// Hardcoded to 32 because that's the fixed output size of the
// X25519 function. Stored as a const so a future change to a
// different curve is a single-edit search-replace, not a hunt
// across the codebase.
const x25519PublicKeyLen = 32

// isBase64URL32 returns true iff s is a base64url-encoded value
// (with or without padding) that decodes to exactly 32 bytes.
//
// We use RawURLEncoding (no padding) because that's what the
// @signalapp/libsignal-client JavaScript bindings produce. Std
// URLEncoding (with "=" padding) is also accepted for
// compatibility with clients that use it.
func isBase64URL32(s string) bool {
	// Reject anything that contains characters outside the
	// base64url alphabet (A-Z a-z 0-9 - _) before calling
	// Decode, because the decoder is permissive about
	// non-canonical inputs (whitespace, mixed padding).
	for _, c := range s {
		if !isBase64URLChar(byte(c)) {
			return false
		}
	}
	// Try padded first, then unpadded. DecodeString returns
	// an error on bad input; we don't care which kind.
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return len(b) == x25519PublicKeyLen
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return len(b) == x25519PublicKeyLen
	}
	return false
}

// isBase64URLChar is the alphabet check for base64url encoding.
func isBase64URLChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_' || c == '='
}

// RegisterResponse is the success body of POST /api/auth/register.
// It does NOT include the access/refresh tokens — clients must call
// /login next, which is intentional: it lets us rate-limit and
// audit-log auth attempts independently of the signup flow.
//
// Email is reported as an empty string when the user registered
// without one (the DB column is NULL, but JSON has no NULL — we
// normalize on the way out for client convenience).
type RegisterResponse struct {
	UIN       int64      `json:"uin"`
	Username  string     `json:"username"`
	Email     string     `json:"email"`
	CreatedAt time.Time  `json:"created_at"`
	User      AuthUser   `json:"user"`
	Tokens    AuthTokens `json:"tokens"`
}

// LoginRequest is the body of POST /api/auth/login.
type LoginRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Validate enforces the login rules: at least one identifier
// (username or email) and a non-empty password. We do NOT validate
// the email format here — a malformed email simply means the user
// lookup will return ErrNoRows, which the handler maps to the same
// 401 as a wrong password. That prevents account-enumeration via
// the "this email looks malformed" side channel.
func (r *LoginRequest) Validate() error {
	if strings.TrimSpace(r.Username) == "" && strings.TrimSpace(r.Email) == "" {
		return fmt.Errorf("%w: login: %w", ErrValidation, ErrLoginIdentifierMissing)
	}
	if r.Password == "" {
		return fmt.Errorf("%w: password: %w", ErrValidation, ErrFieldRequired)
	}
	return nil
}

// LoginIdentifier returns the canonical lookup value and whether it
// should be resolved as a username or email. Username wins when both
// are present so the web client can keep sending the field it already
// owns without also needing a mirrored email property.
func (r *LoginRequest) LoginIdentifier() (value string, byUsername bool) {
	if u := strings.TrimSpace(r.Username); u != "" {
		return u, true
	}
	return strings.TrimSpace(r.Email), false
}

// AuthUser is the frontend-facing authenticated user shape.
type AuthUser struct {
	UIN       int64      `json:"uin"`
	Username  string     `json:"username"`
	Email     string     `json:"email,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
}

// AuthTokens is the frontend-facing token envelope.
type AuthTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// LoginResponse is the success body of POST /api/auth/login.
// Both tokens are returned so the client can use the access token
// immediately and stash the refresh token for the next 7 days.
type LoginResponse struct {
	AccessToken  string     `json:"access_token"`
	RefreshToken string     `json:"refresh_token"`
	UIN          int64      `json:"uin"`
	Username     string     `json:"username"`
	User         AuthUser   `json:"user"`
	Tokens       AuthTokens `json:"tokens"`
}

// RefreshRequest is the body of POST /api/auth/refresh.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Validate enforces that the refresh token is present. We don't
// try to parse it here — that's the job of jwt.Manager.Verify.
func (r *RefreshRequest) Validate() error {
	if strings.TrimSpace(r.RefreshToken) == "" {
		return fmt.Errorf("%w: refresh_token: %w", ErrValidation, ErrRefreshTokenMissing)
	}
	return nil
}

// RefreshResponse is the success body of POST /api/auth/refresh.
type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// LogoutRequest is the optional body of POST /api/auth/logout.
// The access token is read from the Authorization header, but a
// client may also include a refresh token to invalidate it server-
// side at the same time.
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// HealthResponse is the body of GET /api/auth/health. The fields
// here are what an external monitor (k8s liveness, LB healthcheck)
// needs to decide the pod is healthy. Each dependency reports
// its own status so a partial failure is observable, not just a
// binary up/down.
type HealthResponse struct {
	Status       string            `json:"status"`       // "ok" or "degraded"
	Service      string            `json:"service"`      // "auth-service"
	Version      string            `json:"version"`      // git SHA or build tag, "dev" if unset
	Time         time.Time         `json:"time"`         // server clock, useful for skew detection
	Dependencies map[string]string `json:"dependencies"` // dep -> "ok" / error message
}

// ----------------------------------------------------------------------------
// Error body. Every non-2xx response across the auth-service uses
// this shape. Keeping the field names lowercase + stable lets the
// client map on `code` and present `error` as-is.
// ----------------------------------------------------------------------------

// ErrorResponse is the JSON body returned for every non-2xx response.
// The `code` field is machine-readable (SNAKE_CASE) and is meant
// for client logic; `error` is human-readable and may change wording
// between releases without breaking consumers.
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}
