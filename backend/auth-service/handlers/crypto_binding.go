package handlers

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/iceq/iceq/shared/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// qSelectIdentityKeyByUIN returns only the public identity_key for the
// authenticated user. This is the minimum disclosure required to prove
// that a staged browser identity belongs to a newly registered account
// without exposing any private material.
const qSelectIdentityKeyByUIN = `
	SELECT identity_key
	FROM users
	WHERE uin = $1
`

// CryptoBindingResponse is the response body for GET /api/auth/crypto-binding.
type CryptoBindingResponse struct {
	UIN         int64  `json:"uin"`
	IdentityKey string `json:"identity_key"`
}

// CryptoBindingDeps holds the dependencies for the crypto-binding handler.
type CryptoBindingDeps struct {
	Pool *pgxpool.Pool
}

// NewCryptoBindingHandler serves GET /api/auth/crypto-binding behind BearerAuth.
// It returns the authenticated user's public identity key, allowing a staged
// browser registration to bind to its server-created account after a response-
// loss event. This endpoint is self-only — it never accepts a target UIN and
// never exposes private keys, password verifiers, recovery secrets, or prekey
// private components.
func NewCryptoBindingHandler(deps CryptoBindingDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uin, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		var identityKey string
		err := deps.Pool.QueryRow(ctx, qSelectIdentityKeyByUIN, uin).Scan(&identityKey)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "USER_NOT_FOUND", "authenticated user does not exist")
				return
			}
			writeDBError(w, err, "crypto-binding: select identity_key")
			return
		}

		writeJSON(w, http.StatusOK, CryptoBindingResponse{
			UIN:         uin,
			IdentityKey: identityKey,
		})
	}
}
