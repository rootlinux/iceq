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
)

// ----------------------------------------------------------------------------
// Logout handler. Three layers of revocation happen here:
//   1. The presented access token's JTI is added to the Redis
//      blocklist with TTL = remaining token lifetime. From this
//      point on, the access token cannot be used even if it
//      hasn't expired.
//   2. The user's session_epoch is bumped to NOW(). This is
//      the per-user mass-revocation layer: every access AND
//      refresh token previously issued for this user, on every
//      device, becomes invalid on the next Verify call.
//   3. Every refresh_tokens row for this user is physically
//      deleted. Step 2 already makes them useless, but the
//      physical delete keeps the table from accumulating
//      dead rows for users who never log in again.
//
// Every step fails SECURE (returns 5xx, not 2xx) on a partial
// failure, because the user's intent is "log me out everywhere"
// and a partial log-out is a security regression. We accept the
// UX cost of "you may need to retry if the server is flapping"
// as the lesser evil.
//
// The handler requires the access token (BearerAuth runs as
// middleware), so the user is already authenticated. The
// refresh-token body field is now ignored for the purpose of
// revocation: we revoke ALL sessions for the user, not just
// the ones they happened to mention in the body.
// ----------------------------------------------------------------------------

type LogoutDeps struct {
	Pool    *pgxpool.Pool
	Manager *jwt.Manager
}

// NewLogoutHandler returns the http.HandlerFunc mounted at
// POST /api/auth/logout. The returned handler MUST be wrapped
// with middleware.BearerAuth; we don't enforce that here so the
// wiring stays explicit in main.go.
func NewLogoutHandler(deps LogoutDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The middleware put the authenticated UIN here.
		// We use it only for logging; the access token
		// itself (re-extracted from the header) is what
		// carries the JTI we need to revoke.
		uin, ok := middleware.GetUIN(r.Context())
		if !ok {
			// Should be unreachable: the route is
			// mounted behind BearerAuth. Treat as 401
			// rather than panic.
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}

		// 1 KiB ceiling — the body is at most one field,
		// and we no longer act on it (see comment above).
		var req models.LogoutRequest
		if !decodeJSON(w, r, &req, 1024) {
			return
		}
		_ = req // retained for backward-compat with the wire shape

		// 5 s covers JWT revoke (Redis SET) + DB update +
		// (DB delete). Tighter than login because the
		// user is already on the way out.
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// ------------------------------------------------------------
		// 1. Revoke the access token. We re-read the
		//    Authorization header rather than carrying the
		//    token through the context because the JWT
		//    Manager's Revoke API takes the raw string.
		//
		//    Fail-secure: if Redis is unreachable, the
		//    JTI blocklist write fails, and we MUST NOT
		//    return 204. We return 503 so the client knows
		//    to retry. (F-5b in the JWT assessment.)
		// ------------------------------------------------------------
		rawToken, err := extractRawBearer(r)
		if err != nil {
			// Unreachable if the middleware ran, but
			// defense in depth.
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", err.Error())
			return
		}
		if err := deps.Manager.Revoke(ctx, rawToken); err != nil {
			log.Printf("[auth-service] revoke access token failed: %v", err)
			clearSessionCookies(w)
			writeError(w, http.StatusServiceUnavailable, "LOGOUT_FAILED",
				"could not revoke session; please retry")
			return
		}

		// ------------------------------------------------------------
		// 2. Bump session_epoch. This is the per-user
		//    mass-revocation layer: it invalidates every
		//    access and refresh token previously issued
		//    for this user, on every device, on the next
		//    Verify call. (F-5c in the JWT assessment.)
		//
		//    Fail-secure: if Postgres is unreachable, the
		//    bump fails, and we MUST NOT return 204 — the
		//    user would believe they are logged out but
		//    their other-device refresh tokens would
		//    continue to work for up to 7 days.
		// ------------------------------------------------------------
		if err := deps.Manager.BumpSessionEpoch(ctx, uin); err != nil {
			log.Printf("[auth-service] bump session_epoch failed: %v", err)
			clearSessionCookies(w)
			writeError(w, http.StatusServiceUnavailable, "LOGOUT_FAILED",
				"could not revoke all sessions; please retry")
			return
		}

		// ------------------------------------------------------------
		// 3. Physically delete every refresh token row for
		//    this user. The session_epoch bump already
		//    makes them useless at the JWT layer, but the
		//    physical delete keeps the table small and
		//    prevents a dangling row from being
		//    mistakenly "restored" by a future schema
		//    change that drops the epoch column.
		//
		//    Non-fatal: the epoch bump is the security-
		//    relevant layer. The DELETE is housekeeping.
		//    A failure here is logged but not surfaced
		//    to the client.
		// ------------------------------------------------------------
		if _, err := deps.Pool.Exec(ctx,
			`DELETE FROM refresh_tokens WHERE uin = $1`, uin); err != nil {
			log.Printf("[auth-service] delete refresh tokens failed (non-fatal): %v", err)
		}

		log.Printf("[auth-service] logout (all sessions revoked)")
		clearSessionCookies(w)
		// 204 No Content — there is intentionally no
		// body. A successful logout needs no payload.
		w.WriteHeader(http.StatusNoContent)
	}
}

// extractRawBearer pulls the raw token out of the Authorization
// header. Kept private here so logout.go has no dependency on
// the shared middleware package (which would create a longer
// import chain for a single helper). If these helpers ever drift
// apart it is a sign the auth pipeline needs a refactor.
func extractRawBearer(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || h[:len(prefix)] != prefix {
		return "", errNoBearer
	}
	tok := ""
	for _, c := range h[len(prefix):] {
		if c == ' ' || c == '\t' {
			continue
		}
		tok += string(c)
	}
	if tok == "" {
		return "", errEmptyBearer
	}
	return tok, nil
}

var (
	errNoBearer    = stringError("Authorization header must use the Bearer scheme")
	errEmptyBearer = stringError("Bearer token is empty")
)

// stringError is a tiny error type so we don't pull errors.New
// into this file's import list for two one-shot sentinels.
type stringError string

func (e stringError) Error() string { return string(e) }
