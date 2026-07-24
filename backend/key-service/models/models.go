// Package models defines the wire-shape of every request and
// response the key-service exposes. The handlers convert these
// to and from JSON via encoding/json's standard reflection path.
//
// All keys in this package are base64url-encoded because the
// @signalapp/libsignal-client JavaScript bindings produce that
// encoding and the X3DH wire format expects it. We accept
// either padded ("=") or unpadded forms, but reject anything
// that doesn't decode to the expected byte length for the
// primitive in question:
//
//   - 32 bytes  — X25519 public key (identity key, SPK, OPK)
//   - 64 bytes  — X25519 signature (SPK signature)
package models

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ----------------------------------------------------------------------------
// Sentinel validation errors.
// ----------------------------------------------------------------------------

var (
	ErrValidation           = errors.New("models: validation failed")
	ErrFieldRequired        = errors.New("models: required field is missing")
	ErrKeyInvalid           = errors.New("models: key must be base64url-encoded byte string")
	ErrKeyWrongLength       = errors.New("models: key decoded to wrong byte length")
	ErrSignatureWrongLength = errors.New("models: signature must decode to 64 bytes")
	ErrTooManyPrekeys       = errors.New("models: too many prekeys in one batch")
)

// ----------------------------------------------------------------------------
// Constants. Pulled out so the validation paths and the SQL
// type casts agree on the same numbers.
// ----------------------------------------------------------------------------

// maxPrekeysPerBatch caps the number of one-time prekeys a
// single POST /api/keys/prekeys call can upload. 100 is a
// comfortable ceiling: large enough to let a client replenish
// in one round trip, small enough that a malicious caller
// can't fill the table by replaying one large request.
const maxPrekeysPerBatch = 100

// ----------------------------------------------------------------------------
// Shared shapes.
// ----------------------------------------------------------------------------

// SignedPrekey is the long-term rotated key uploaded with the
// bundle. The signature is the user's identity key signing the
// SPK public key; clients can verify it before using the SPK
// to derive a shared secret.
//
// ID is the client's monotonically-increasing counter; the
// server stores it as JSONB alongside the public key and
// returns it verbatim on bundle fetch.
type SignedPrekey struct {
	ID        int    `json:"id"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

// OneTimePrekey is a single-use X25519 public key uploaded in
// bulk via POST /api/keys/prekeys. The server returns ONE of
// these per /api/keys/bundle/{uin} call and marks it used=true.
//
// key_id is the client's own counter; the server uses it to
// detect duplicate uploads and to ORDER BY key_id when
// consuming the lowest-numbered unused key.
type OneTimePrekey struct {
	ID        int    `json:"id"`
	PublicKey string `json:"public_key"`
}

// ----------------------------------------------------------------------------
// Request shapes.
// ----------------------------------------------------------------------------

// UploadBundleRequest is the body of POST /api/keys/bundle.
// The identity_key here is asserted to match the one on file
// at registration time (the auth-service stores the
// registration-time key; the key-service stores the latest
// uploaded one). A mismatch is rejected at the handler layer.
type UploadBundleRequest struct {
	IdentityKey    string          `json:"identity_key"`
	SignedPrekey   SignedPrekey    `json:"signed_pre_key"`
	OneTimePrekeys []OneTimePrekey `json:"one_time_pre_keys"`
	RegistrationID int             `json:"registration_id"`
}

// Validate enforces that all three fields are well-formed
// base64url-encoded keys/signatures of the right length. An
// empty IdentityKey or SignedPrekey.PublicKey is rejected
// here; an empty Signature is also rejected because a SPK
// without a signature is unauthenticatable and the
// @signalapp/libsignal-client bindings will reject it on the
// verifier side.
func (r *UploadBundleRequest) Validate() error {
	if r.IdentityKey == "" {
		return fmt.Errorf("%w: identity_key: %w", ErrValidation, ErrFieldRequired)
	}
	if !isBase64URLBytes(r.IdentityKey, 32) {
		return fmt.Errorf("%w: identity_key: %w", ErrValidation, ErrKeyInvalid)
	}
	if err := validateSignedPrekey(r.SignedPrekey); err != nil {
		return fmt.Errorf("%w: signed_prekey: %w", ErrValidation, err)
	}
	if len(r.OneTimePrekeys) > maxPrekeysPerBatch {
		return fmt.Errorf("%w: one_time_pre_keys (max %d): %w", ErrValidation, maxPrekeysPerBatch, ErrTooManyPrekeys)
	}
	for i, k := range r.OneTimePrekeys {
		if k.PublicKey == "" {
			return fmt.Errorf("%w: one_time_pre_keys[%d].public_key: %w", ErrValidation, i, ErrFieldRequired)
		}
		if !isBase64URLBytes(k.PublicKey, 32) {
			return fmt.Errorf("%w: one_time_pre_keys[%d].public_key: %w", ErrValidation, i, ErrKeyInvalid)
		}
	}
	return nil
}

// validateSignedPrekey is a helper that checks a SignedPrekey
// in isolation. Pulled out so the same rules apply to the
// bundle's upload (where the SPK is in the request body) and
// to any future "rotate SPK only" endpoint.
func validateSignedPrekey(sp SignedPrekey) error {
	if sp.PublicKey == "" {
		return ErrFieldRequired
	}
	if !isBase64URLBytes(sp.PublicKey, 32) {
		return ErrKeyInvalid
	}
	if sp.Signature == "" {
		return ErrFieldRequired
	}
	if !isBase64URLBytes(sp.Signature, 64) {
		return ErrSignatureWrongLength
	}
	return nil
}

// AddPrekeysRequest is the body of POST /api/keys/prekeys.
// At most maxPrekeysPerBatch keys may be uploaded per call.
type AddPrekeysRequest struct {
	Prekeys []OneTimePrekey `json:"prekeys"`
}

// Validate enforces the size cap and per-key well-formedness.
// Returns the first violation so the client can fix and retry
// without ambiguity.
func (r *AddPrekeysRequest) Validate() error {
	if len(r.Prekeys) == 0 {
		return fmt.Errorf("%w: prekeys: %w", ErrValidation, ErrFieldRequired)
	}
	if len(r.Prekeys) > maxPrekeysPerBatch {
		return fmt.Errorf("%w: prekeys (max %d): %w", ErrValidation, maxPrekeysPerBatch, ErrTooManyPrekeys)
	}
	for i, k := range r.Prekeys {
		if k.PublicKey == "" {
			return fmt.Errorf("%w: prekeys[%d].public_key: %w", ErrValidation, i, ErrFieldRequired)
		}
		if !isBase64URLBytes(k.PublicKey, 32) {
			return fmt.Errorf("%w: prekeys[%d].public_key: %w", ErrValidation, i, ErrKeyInvalid)
		}
	}
	return nil
}

// ----------------------------------------------------------------------------
// Response shapes.
// ----------------------------------------------------------------------------

// BundleResponse is the body of GET /api/keys/bundle/{uin}.
// It is the wire format Alice consumes in order to start a
// Signal Protocol session with Bob (UIN).
//
// OneTimePrekey is a pointer so it can be nil when the
// recipient has exhausted their OPK pool. The client must
// tolerate a null one_time_prekey — the X3DH handshake can
// proceed without one, falling back to the signed_prekey
// alone.
type BundleResponse struct {
	UIN            int64          `json:"uin"`
	IdentityKey    string         `json:"identity_key"`
	SignedPrekey   SignedPrekey   `json:"signed_pre_key"`
	OneTimePrekey  *OneTimePrekey `json:"pre_key"`
	RegistrationID int            `json:"registration_id"`
}

// PrekeyCountResponse is the body of GET /api/keys/prekeys/count.
// The client uses this to decide when to upload more one-time
// prekeys; the convention is to replenish when the count drops
// below a threshold (e.g. 20) so a slow consumer doesn't run
// out between checks.
type PrekeyCountResponse struct {
	Count int `json:"count"`
}

// ErrorResponse is the body of every non-2xx response from the
// key-service. Kept identical in shape to the auth-service's
// ErrorResponse so a client decoding both with a single
// {error, code} struct stays simple.
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// KeyServiceHealth is the body of GET /api/keys/health. Each
// dependency reports its own status so a partial failure is
// observable, not just a binary up/down.
type KeyServiceHealth struct {
	Status       string            `json:"status"`       // "ok" or "degraded"
	Service      string            `json:"service"`      // "key-service"
	Version      string            `json:"version"`      // git SHA or build tag, "dev" if unset
	Time         time.Time         `json:"time"`         // server clock, useful for skew detection
	Dependencies map[string]string `json:"dependencies"` // dep -> "ok" / error message
}

// ----------------------------------------------------------------------------
// Decoding helpers. Public so handlers can re-validate
// individual fields after JSON parsing.
// ----------------------------------------------------------------------------

// DecodeSignedPrekeyJSON parses the stored JSONB representation
// of a signed prekey into a SignedPrekey struct. We accept the
// stored form from prekey_bundles.signed_prekey and re-emit it
// in the response. The bytes come from Postgres and are trusted
// (we wrote them ourselves in POST /api/keys/bundle), so we
// don't re-validate the contents here.
//
// Exported because the store package needs it after reading the
// JSONB column from prekey_bundles.
func DecodeSignedPrekeyJSON(raw json.RawMessage) (SignedPrekey, error) {
	var sp SignedPrekey
	if err := json.Unmarshal(raw, &sp); err != nil {
		return SignedPrekey{}, fmt.Errorf("models: malformed signed_prekey JSON: %w", err)
	}
	return sp, nil
}

// isBase64URLBytes returns true iff s is a base64url string
// that decodes to exactly wantLen bytes. Accepts both
// padded (URLEncoding) and unpadded (RawURLEncoding) forms.
func isBase64URLBytes(s string, wantLen int) bool {
	for _, c := range s {
		// c > 127 rejects any non-ASCII rune before the byte(c)
		// truncation can fold it onto a valid base64url byte value
		// (e.g. codepoint 0x141 truncating to a byte that happens
		// to equal 'A'). Not currently exploitable — the subsequent
		// DecodeString call independently rejects non-ASCII UTF-8 —
		// but this loop shouldn't rely on that second check alone.
		if c > 127 || !isBase64URLChar(byte(c)) { // #nosec G115
			return false
		}
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return len(b) == wantLen
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return len(b) == wantLen
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
