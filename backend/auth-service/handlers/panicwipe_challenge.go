package handlers

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/iceq/iceq/shared/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

const (
	wipeChallengePrefix  = "panic-wipe:challenge:"
	wipeChallengeTTL     = 5 * time.Minute
	wipeChallengeBytes   = 32
)

var qSelectWipePublicKey = `SELECT wipe_public_key FROM user_security_settings WHERE uin = $1`

// ---------------------------------------------------------------------------
// SetWipePublicKeyDeps wires the endpoint that stores the client's Panic Wipe
// Ed25519 verification (public) key.
//
// Enrollment vs rotation is determined server-side by whether a wipe key
// already exists for this account:
//
//   - Initial enrollment: requires password reauthentication. Uses
//     INSERT ... ON CONFLICT DO NOTHING (insert-if-absent).
//
//   - Rotation: requires a signature from the EXISTING wipe key over a
//     single-use challenge. Uses UPDATE ... WHERE wipe_public_key IS NOT NULL.
//
// A normal authenticated session with neither password nor signature is
// always rejected — a stolen session token can never overwrite the key.
// ---------------------------------------------------------------------------

type SetWipePublicKeyDeps struct {
	Pool                 *pgxpool.Pool
	Redis                *redis.Client
	LookupWipePublicKey  func(ctx context.Context, uin int64) (ed25519.PublicKey, error)
	LookupPasswordHash   func(ctx context.Context, uin int64) (string, error)
}

type setWipePublicKeyRequest struct {
	PublicKey   string `json:"public_key"`
	Password    string `json:"password,omitempty"`
	ChallengeID string `json:"challenge_id,omitempty"`
	Signature   string `json:"signature,omitempty"`
}

func NewSetWipePublicKeyHandler(deps SetWipePublicKeyDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uin, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}
		var req setWipePublicKeyRequest
		if !decodeJSON(w, r, &req, 1024) {
			return
		}

		// Validate the public key format.
		pubBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
		if err != nil || len(pubBytes) != ed25519.PublicKeySize {
			writeError(w, http.StatusBadRequest, "INVALID_PUBLIC_KEY", "public key must be 32 bytes base64-encoded")
			return
		}

		// Determine whether we're enrolling or rotating by looking up any
		// existing key. The server decides, never the client.
		existingKey, err := deps.LookupWipePublicKey(r.Context(), uin)
		if err != nil {
			log.Printf("[auth-service] set-wipe-public-key lookup failed: %v", err)
			writeError(w, http.StatusServiceUnavailable, "WIPE_KEY_UNAVAILABLE", "could not verify account state")
			return
		}

		if existingKey == nil {
			// ---- INITIAL ENROLLMENT ----
			// No existing key: require password reauthentication.
			if req.Password == "" {
				writeError(w, http.StatusUnauthorized, "PASSWORD_REQUIRED", "password is required for initial wipe-key enrollment")
				return
			}
			if deps.LookupPasswordHash == nil {
				writeError(w, http.StatusInternalServerError, "WIPE_KEY_UNAVAILABLE", "password verification not configured")
				return
			}
			passwordHash, err := deps.LookupPasswordHash(r.Context(), uin)
			if err != nil {
				log.Printf("[auth-service] set-wipe-public-key password lookup failed: %v", err)
				writeError(w, http.StatusServiceUnavailable, "WIPE_KEY_UNAVAILABLE", "could not verify password")
				return
			}
			if passwordHash == "" || !verifyPassword(passwordHash, req.Password).OK {
				writeError(w, http.StatusUnauthorized, "INVALID_PASSWORD", "incorrect password")
				return
			}

			// Atomic set-if-null: INSERT with ON CONFLICT DO UPDATE SET ...
			// WHERE wipe_public_key IS NULL. Three outcomes:
			//   1. No row → INSERT (RowsAffected=1)
			//   2. Row with NULL key → UPDATE (RowsAffected=1)
			//   3. Row with non-NULL key → WHERE blocks UPDATE (RowsAffected=0)
			tag, err := deps.Pool.Exec(r.Context(), qEnrollWipePublicKey, uin, base64.StdEncoding.EncodeToString(pubBytes))
			if err != nil {
				log.Printf("[auth-service] set-wipe-public-key enroll failed: %v", err)
				writeError(w, http.StatusServiceUnavailable, "WIPE_KEY_UNAVAILABLE", "could not store wipe key")
				return
			}
			if tag.RowsAffected() == 0 {
				writeError(w, http.StatusConflict, "WIPE_KEY_EXISTS", "a wipe key is already enrolled; use rotation to change it")
				return
			}
		} else {
			// ---- ROTATION (or idempotent resubmission) ----
			newPubKeyB64 := base64.StdEncoding.EncodeToString(pubBytes)
			oldPubKeyB64 := base64.StdEncoding.EncodeToString(existingKey)

			// If the resubmitted key is byte-for-byte identical to what's
			// already stored, this is a retry of a prior successful
			// enrollment whose response the client never saw — not a
			// rotation attempt — so it needs no signature. Checking this
			// BEFORE the signature requirement is what makes the client's
			// retry-on-any-error path safe: requiring proof of the OLD key
			// to resubmit the SAME key would strand a client that has no
			// reason to believe it's rotating anything. This does not
			// weaken rotation protection: an attacker without the existing
			// wipe private key still cannot install any key OTHER than the
			// one already enrolled, which is the only thing that requires
			// a signature in the first place.
			if newPubKeyB64 == oldPubKeyB64 {
				writeError(w, http.StatusConflict, "WIPE_KEY_EXISTS", "a wipe key is already enrolled; use rotation to change it")
				return
			}

			// A genuinely different key: this is a real rotation, and
			// requires a domain-separated signature from the current key
			// over the rotation payload. This binds the authorization to
			// the new key, the challenge, and the actor.
			if req.ChallengeID == "" || req.Signature == "" {
				writeError(w, http.StatusUnauthorized, "SIGNATURE_REQUIRED", "challenge_id and signature are required for rotation")
				return
			}
			if deps.Redis == nil {
				writeError(w, http.StatusInternalServerError, "WIPE_KEY_UNAVAILABLE", "challenge verification not configured")
				return
			}

			// Single-use challenge: fetch and consume from Redis.
			challengeKey := wipeChallengePrefix + itoa(uin) + ":" + req.ChallengeID
			storedChallengeB64, err := deps.Redis.GetDel(r.Context(), challengeKey).Result()
			if err != nil {
				if err == redis.Nil {
					writeError(w, http.StatusUnauthorized, "CHALLENGE_EXPIRED", "challenge expired or already used")
					return
				}
				writeError(w, http.StatusServiceUnavailable, "WIPE_KEY_UNAVAILABLE", "could not verify challenge")
				return
			}

			// Verify the domain-separated rotation payload.
			rotationPayload := fmt.Sprintf("iceq-wipe-key-rotation-v1|%d|%s|%s|%s",
				uin, req.ChallengeID, storedChallengeB64, newPubKeyB64)

			sigBytes, err := base64.StdEncoding.DecodeString(req.Signature)
			if err != nil || len(sigBytes) != ed25519.SignatureSize {
				writeError(w, http.StatusBadRequest, "INVALID_SIGNATURE", "signature must be 64 bytes base64-encoded")
				return
			}

			if !ed25519.Verify(existingKey, []byte(rotationPayload), sigBytes) {
				writeError(w, http.StatusUnauthorized, "INVALID_SIGNATURE", "incorrect signature")
				return
			}

			// Compare-and-swap: update only if the key is exactly the one
			// that signed the rotation payload. Two concurrent rotations
			// with the same old key cannot both succeed.
			tag, err := deps.Pool.Exec(r.Context(), qUpdateWipePublicKey, uin, oldPubKeyB64, newPubKeyB64)
			if err != nil {
				log.Printf("[auth-service] set-wipe-public-key update failed: %v", err)
				writeError(w, http.StatusServiceUnavailable, "WIPE_KEY_UNAVAILABLE", "could not update wipe key")
				return
			}
			if tag.RowsAffected() == 0 {
				writeError(w, http.StatusConflict, "WIPE_KEY_GONE", "wipe key changed between verification and update; retry rotation")
				return
			}
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// ---------------------------------------------------------------------------
// GetWipePublicKeyDeps wires the read-only endpoint that reports whether an
// account already has a wipe key enrolled and, if so, exactly which public
// key it is. The client uses this to reconcile a locally-held wipe key pair
// against server state after any ambiguous PUT outcome (network drop, lost
// response) instead of guessing from an HTTP status code — see
// reconcileWipeKey() in web/src/lib/panicWipeKey.ts.
// ---------------------------------------------------------------------------

type GetWipePublicKeyDeps struct {
	LookupWipePublicKey func(ctx context.Context, uin int64) (ed25519.PublicKey, error)
}

type getWipePublicKeyResponse struct {
	PublicKey *string `json:"public_key"`
}

func NewGetWipePublicKeyHandler(deps GetWipePublicKeyDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uin, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}
		existingKey, err := deps.LookupWipePublicKey(r.Context(), uin)
		if err != nil {
			log.Printf("[auth-service] get-wipe-public-key lookup failed: %v", err)
			writeError(w, http.StatusServiceUnavailable, "WIPE_KEY_UNAVAILABLE", "could not verify account state")
			return
		}
		if existingKey == nil {
			writeJSON(w, http.StatusOK, getWipePublicKeyResponse{PublicKey: nil})
			return
		}
		encoded := base64.StdEncoding.EncodeToString(existingKey)
		writeJSON(w, http.StatusOK, getWipePublicKeyResponse{PublicKey: &encoded})
	}
}

// ---------------------------------------------------------------------------
// WipeChallengeDeps wires the challenge-generation endpoint.
// ---------------------------------------------------------------------------

type WipeChallengeDeps struct {
	Redis *redis.Client
}

type wipeChallengeResponse struct {
	ChallengeID string `json:"challenge_id"`
	Challenge   string `json:"challenge"`
}

func NewWipeChallengeHandler(deps WipeChallengeDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uin, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}

		challengeBytes := make([]byte, wipeChallengeBytes)
		if _, err := rand.Read(challengeBytes); err != nil {
			writeError(w, http.StatusInternalServerError, "CHALLENGE_FAILED", "could not generate challenge")
			return
		}

		challengeIDBytes := make([]byte, 16)
		if _, err := rand.Read(challengeIDBytes); err != nil {
			writeError(w, http.StatusInternalServerError, "CHALLENGE_FAILED", "could not generate challenge")
			return
		}
		challengeID := hex.EncodeToString(challengeIDBytes)

		key := wipeChallengePrefix + itoa(uin) + ":" + challengeID
		challengeB64 := base64.StdEncoding.EncodeToString(challengeBytes)

		if err := deps.Redis.Set(r.Context(), key, challengeB64, wipeChallengeTTL).Err(); err != nil {
			writeError(w, http.StatusServiceUnavailable, "CHALLENGE_FAILED", "could not store challenge")
			return
		}

		writeJSON(w, http.StatusOK, wipeChallengeResponse{
			ChallengeID: challengeID,
			Challenge:   challengeB64,
		})
	}
}

// ---------------------------------------------------------------------------
// ChallengeSignatureDeps wires the wipe public-key lookup so the handler can
// verify the client's Ed25519 signature over the challenge. Tests inject a
// stub function instead of requiring a real DB.
// ---------------------------------------------------------------------------

type ChallengeSignatureDeps struct {
	Pool                    *pgxpool.Pool
	LookupWipePublicKey     func(ctx context.Context, uin int64) (ed25519.PublicKey, error)
	Redis                   *redis.Client
}

func NewLookupWipePublicKey(pool *pgxpool.Pool) func(ctx context.Context, uin int64) (ed25519.PublicKey, error) {
	return func(ctx context.Context, uin int64) (ed25519.PublicKey, error) {
		var encoded *string
		if err := pool.QueryRow(ctx, qSelectWipePublicKey, uin).Scan(&encoded); err != nil {
			if err == pgx.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
		if encoded == nil || *encoded == "" {
			return nil, nil
		}
		decoded, err := base64.StdEncoding.DecodeString(*encoded)
		if err != nil {
			return nil, fmt.Errorf("malformed wipe public key: %w", err)
		}
		if len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("wipe public key has wrong length: %d", len(decoded))
		}
		return ed25519.PublicKey(decoded), nil
	}
}

// NewLookupPasswordHash returns a function that queries the user's current
// password hash from the users table. Used by SetWipePublicKey for initial
// enrollment reauthentication.
func NewLookupPasswordHash(pool *pgxpool.Pool) func(ctx context.Context, uin int64) (string, error) {
	return func(ctx context.Context, uin int64) (string, error) {
		var hash string
		if err := pool.QueryRow(ctx, qSelectPasswordHash, uin).Scan(&hash); err != nil {
			if err == pgx.ErrNoRows {
				return "", nil
			}
			return "", err
		}
		return hash, nil
	}
}

// VerifyWipeSignature is called from the panic-wipe handler. It:
//  1. Looks up the user's wipe public key from PostgreSQL.
//  2. Fetches the challenge value from Redis (single-use; consumed after read).
//  3. Verifies the Ed25519 signature over challenge_bytes.
//
// It returns nil on success or an error that the caller should translate into
// an HTTP 401 / 403 / 503 response.
func VerifyWipeSignature(ctx context.Context, deps ChallengeSignatureDeps, uin int64, challengeID, sigB64 string) error {
	if deps.LookupWipePublicKey == nil {
		return fmt.Errorf("no wipe public key lookup configured")
	}

	pubKey, err := deps.LookupWipePublicKey(ctx, uin)
	if err != nil {
		return fmt.Errorf("lookup wipe public key: %w", err)
	}
	if pubKey == nil {
		return fmt.Errorf("no wipe credential configured for this account")
	}

	challengeKey := wipeChallengePrefix + itoa(uin) + ":" + challengeID
	storedChallengeB64, err := deps.Redis.GetDel(ctx, challengeKey).Result()
	if err != nil {
		if err == redis.Nil {
			return fmt.Errorf("challenge expired or already used")
		}
		return fmt.Errorf("redis read challenge: %w", err)
	}

	challengeBytes, err := base64.StdEncoding.DecodeString(storedChallengeB64)
	if err != nil {
		return fmt.Errorf("malformed stored challenge: %w", err)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("malformed signature: %w", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("signature has wrong length: %d", len(sigBytes))
	}

	if !ed25519.Verify(pubKey, challengeBytes, sigBytes) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}
