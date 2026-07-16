package handlers

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/iceq/iceq/auth-service/models"
	"github.com/iceq/iceq/shared/jwt"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// RegisterDeps captures the dependencies the register handler
// needs. Constructed once in main.go and passed in via the
// handler factory pattern below.
type RegisterDeps struct {
	Pool            *pgxpool.Pool
	Manager         *jwt.Manager
	Redis           *redis.Client
	RateLimitSecret []byte
}

// NewRegisterHandler returns the http.HandlerFunc mounted at
// POST /api/auth/register. The factory pattern keeps the
// dependency wiring (which needs main.go's locals) out of the
// package init path.
func NewRegisterHandler(deps RegisterDeps) http.HandlerFunc {
	script := redis.NewScript(rateLimitScript)
	return func(w http.ResponseWriter, r *http.Request) {
		buckets, err := middleware.AnonymousRateLimitBuckets(deps.RateLimitSecret, r.Header.Values(middleware.EdgeIdentityHeader), r.Header.Values(middleware.EdgePreviousIdentityHeader), "register", time.Now())
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "RATE_LIMIT_IDENTITY_UNAVAILABLE", "service is temporarily unavailable")
			return
		}
		ctxLimit, cancelLimit := context.WithTimeout(r.Context(), 2*time.Second)
		keys := make([]string, len(buckets))
		for i, bucket := range buckets {
			keys[i] = "ratelimit:register:" + bucket
		}
		count, err := script.Run(ctxLimit, deps.Redis, keys, int(rateLimitWindow.Seconds())).Int64()
		cancelLimit()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "RATE_LIMITER_UNAVAILABLE", "service is temporarily unavailable")
			return
		}
		if count > 3 {
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "too many registration attempts; try again later")
			return
		}
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
