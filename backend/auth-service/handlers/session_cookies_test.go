package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/iceq/iceq/auth-service/models"
)

func TestSetSessionCookiesUsesSecureHttpOnlyRefreshCookie(t *testing.T) {
	rr := httptest.NewRecorder()
	tokens := models.AuthTokens{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
	}

	setSessionCookies(rr, tokens)

	cookies := rr.Result().Cookies()
	refresh := findCookie(cookies, refreshCookieName)
	if refresh == nil {
		t.Fatalf("refresh cookie missing in %#v", cookies)
	}
	if refresh.Value != "refresh-token" {
		t.Fatalf("refresh cookie value = %q, want refresh-token", refresh.Value)
	}
	if !refresh.HttpOnly {
		t.Fatal("refresh cookie HttpOnly = false, want true")
	}
	if !refresh.Secure {
		t.Fatal("refresh cookie Secure = false, want true")
	}
	if refresh.SameSite != http.SameSiteStrictMode {
		t.Fatalf("refresh SameSite = %v, want Strict", refresh.SameSite)
	}
	if refresh.Path != "/api/auth" {
		t.Fatalf("refresh Path = %q, want /api/auth", refresh.Path)
	}
	if refresh.MaxAge <= 0 {
		t.Fatalf("refresh MaxAge = %d, want positive", refresh.MaxAge)
	}
}

func TestSetSessionCookiesUsesReadableShortLivedAccessCookie(t *testing.T) {
	rr := httptest.NewRecorder()

	setSessionCookies(rr, models.AuthTokens{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
	})

	access := findCookie(rr.Result().Cookies(), accessCookieName)
	if access == nil {
		t.Fatal("access cookie missing")
	}
	if access.Value != "access-token" {
		t.Fatalf("access cookie value = %q, want access-token", access.Value)
	}
	if access.HttpOnly {
		t.Fatal("access cookie HttpOnly = true, want false for WebSocket compatibility")
	}
	if !access.Secure {
		t.Fatal("access cookie Secure = false, want true")
	}
	if access.SameSite != http.SameSiteStrictMode {
		t.Fatalf("access SameSite = %v, want Strict", access.SameSite)
	}
	if access.Path != "/" {
		t.Fatalf("access Path = %q, want /", access.Path)
	}
	if access.MaxAge <= 0 || time.Duration(access.MaxAge)*time.Second > 16*time.Minute {
		t.Fatalf("access MaxAge = %d, want short lived", access.MaxAge)
	}
}

func TestRefreshTokenFromRequestPrefersJSONThenCookie(t *testing.T) {
	bodyReq := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	bodyReq = bodyReq.WithContext(withRefreshToken(bodyReq.Context(), "body-token"))
	bodyToken, ok := refreshTokenFromRequest(bodyReq)
	if !ok || bodyToken != "body-token" {
		t.Fatalf("body token = %q %v, want body-token true", bodyToken, ok)
	}

	cookieReq := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	cookieReq.AddCookie(&http.Cookie{Name: refreshCookieName, Value: "cookie-token"})
	cookieToken, ok := refreshTokenFromRequest(cookieReq)
	if !ok || cookieToken != "cookie-token" {
		t.Fatalf("cookie token = %q %v, want cookie-token true", cookieToken, ok)
	}
}

func TestClearSessionCookiesExpiresBothCookies(t *testing.T) {
	rr := httptest.NewRecorder()

	clearSessionCookies(rr)

	refresh := findCookie(rr.Result().Cookies(), refreshCookieName)
	access := findCookie(rr.Result().Cookies(), accessCookieName)
	if refresh == nil || access == nil {
		t.Fatalf("cookies = %#v, want both auth cookies", rr.Result().Cookies())
	}
	if refresh.MaxAge != -1 || access.MaxAge != -1 {
		t.Fatalf("MaxAge refresh=%d access=%d, want -1", refresh.MaxAge, access.MaxAge)
	}
}

func TestDecodeRefreshRequestAllowsCookieOnlyRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: refreshCookieName, Value: "cookie-refresh"})

	rr := httptest.NewRecorder()
	ctx, ok := decodeRefreshRequest(rr, req)
	if !ok {
		t.Fatalf("decodeRefreshRequest ok = false, response = %d", rr.Code)
	}
	token, ok := ctxRefreshToken(ctx)
	if !ok || token != "cookie-refresh" {
		t.Fatalf("ctx refresh token = %q %v, want cookie-refresh true", token, ok)
	}
}

func TestDecodeRefreshRequestPrefersJSONBodyOverCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", strings.NewReader(`{"refresh_token":"body-refresh"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: refreshCookieName, Value: "cookie-refresh"})

	rr := httptest.NewRecorder()
	ctx, ok := decodeRefreshRequest(rr, req)
	if !ok {
		t.Fatalf("decodeRefreshRequest ok = false, response = %d", rr.Code)
	}
	token, ok := ctxRefreshToken(ctx)
	if !ok || token != "body-refresh" {
		t.Fatalf("ctx refresh token = %q %v, want body-refresh true", token, ok)
	}
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func ctxRefreshToken(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(refreshTokenContextKey{}).(string)
	return token, ok
}
