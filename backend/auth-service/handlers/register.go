package handlers

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/iceq/iceq/auth-service/models"
	"github.com/iceq/iceq/shared/jwt"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RegisterDeps captures the dependencies the register handler
// needs. Constructed once in main.go and passed in via the
// handler factory pattern below.
type RegisterDeps struct {
	Pool    *pgxpool.Pool
	Manager *jwt.Manager
}

// NewRegisterHandler returns the http.HandlerFunc mounted at
// POST /api/auth/register. The factory pattern keeps the
// dependency wiring (which needs main.go's locals) out of the
// package init path.
func NewRegisterHandler(deps RegisterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Hard cap of 10 KiB on the request body. A legitimate
		// registration form is well under 1 KiB; anything larger
		// is either malicious or a bug in the client.
		var req models.RegisterRequest
		if !decodeJSON(w, r, &req, 10*1024) {
			return
		}
		if err := req.Validate(); err != nil {
			writeValidationError(w, err)
			return
		}

		// Hash the password BEFORE the DB round trip so a
		// rejected INSERT (duplicate) doesn't burn 250 ms of
		// CPU on an invalid request. The cost is paid only
		// for plausible inputs.
		hash, err := hashPassword(req.Password)
		if err != nil {
			log.Printf("[auth-service] password hash: %v", err)
			writeError(w, http.StatusInternalServerError, "HASH_FAILED", "could not hash password")
			return
		}

		// 5 s is enough for a healthy Postgres; tighter than
		// the http.Server's read/write timeout so a stuck DB
		// surfaces as 504 from the upstream proxy rather than
		// hanging the connection.
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		var resp models.RegisterResponse
		// E2EE: identity_key is the Signal Protocol X25519
		// public key. We store the raw base64url text (not the
		// decoded bytes) because the key-service reads it back
		// verbatim when serving /api/keys/bundle/{uin}. The
		// server never has the corresponding private key —
		// that one is generated in the browser and never
		// crosses the network.
		err = deps.Pool.QueryRow(ctx, qInsertUser, req.Username, req.Email, hash, req.IdentityKey).
			Scan(&resp.UIN, &resp.Username, &resp.Email, &resp.CreatedAt)
		if err != nil {
			if writeDBError(w, err, "register: insert user") {
				return
			}
			// writeDBError returned false only if err was nil,
			// which by this branch's preconditions is impossible.
			// Treat the unexpected as a 500.
			writeError(w, http.StatusInternalServerError, "DB_ERROR", "database error")
			return
		}

		tokens, err := issueSession(ctx, deps.Pool, deps.Manager, resp.UIN)
		if err != nil {
			log.Printf("[auth-service] issue register session: %v", err)
			writeError(w, http.StatusInternalServerError, "TOKEN_ISSUE_FAILED", "could not issue session")
			return
		}
		resp.User = models.AuthUser{
			UIN:       resp.UIN,
			Username:  resp.Username,
			Email:     resp.Email,
			CreatedAt: &resp.CreatedAt,
		}
		resp.Tokens = tokens

		setSessionCookies(w, tokens)
		log.Printf("[auth-service] registered")
		writeJSON(w, http.StatusCreated, resp)
	}
}
