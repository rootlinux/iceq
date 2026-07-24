package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/iceq/iceq/auth-service/models"
	"github.com/iceq/iceq/shared/jwt"
)

const (
	accessCookieName  = "iceq_access_token"
	refreshCookieName = "iceq_refresh_token"
)

type refreshTokenContextKey struct{}

func withRefreshToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, refreshTokenContextKey{}, strings.TrimSpace(token))
}

func refreshTokenFromRequest(r *http.Request) (string, bool) {
	if token, ok := r.Context().Value(refreshTokenContextKey{}).(string); ok && token != "" {
		return token, true
	}
	c, err := r.Cookie(refreshCookieName)
	if err != nil {
		return "", false
	}
	token := strings.TrimSpace(c.Value)
	return token, token != ""
}

func decodeRefreshRequest(w http.ResponseWriter, r *http.Request) (context.Context, bool) {
	var req models.RefreshRequest
	if r.Body != nil && r.ContentLength != 0 {
		if !decodeJSON(w, r, &req, 1024) {
			return r.Context(), false
		}
		if strings.TrimSpace(req.RefreshToken) != "" {
			return withRefreshToken(r.Context(), req.RefreshToken), true
		}
	}
	if token, ok := refreshTokenFromRequest(r); ok {
		return withRefreshToken(r.Context(), token), true
	}
	writeValidationError(w, models.ErrRefreshTokenMissing)
	return r.Context(), false
}

func setSessionCookies(w http.ResponseWriter, tokens models.AuthTokens) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    tokens.RefreshToken,
		Path:     "/api/auth",
		MaxAge:   int(jwt.RefreshTokenTTL.Seconds()),
		Expires:  time.Now().UTC().Add(jwt.RefreshTokenTTL),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	// #nosec G124 -- HttpOnly is intentionally false on the
	// access-token cookie: the web client's WebSocket bearer-auth
	// handshake reads this cookie from JavaScript to attach the
	// token to the WS upgrade request, which HttpOnly would block.
	// The refresh token (the higher-value credential) stays
	// HttpOnly above. Secure and SameSite are both still set.
	http.SetCookie(w, &http.Cookie{
		Name:     accessCookieName,
		Value:    tokens.AccessToken,
		Path:     "/",
		MaxAge:   int(jwt.AccessTokenTTL.Seconds()),
		Expires:  time.Now().UTC().Add(jwt.AccessTokenTTL),
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// clearSessionCookies expires both session cookies. Built as two
// explicit full http.Cookie literals (mirroring setSessionCookies)
// rather than a loop that mutates a shared partial literal — gosec's
// G124 check can only verify Secure/HttpOnly/SameSite when they're
// set directly in the composite literal, not via a later field
// assignment on a loop variable.
func clearSessionCookies(w http.ResponseWriter) {
	expired := time.Unix(0, 0).UTC()
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Path:     "/api/auth",
		Value:    "",
		MaxAge:   -1,
		Expires:  expired,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	// #nosec G124 -- see setSessionCookies: matches the non-HttpOnly
	// access-token cookie it's clearing. Secure and SameSite are both
	// still set.
	http.SetCookie(w, &http.Cookie{
		Name:     accessCookieName,
		Path:     "/",
		Value:    "",
		MaxAge:   -1,
		Expires:  expired,
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}
