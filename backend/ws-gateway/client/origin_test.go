package client

import (
	"net/http/httptest"
	"testing"
)

func TestIsOriginAllowed_EmptyAllowlistAllowsAll(t *testing.T) {
	// Development mode: no origins configured → allow everything.
	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Origin", "https://evil.example.com")

	if !isOriginAllowed(nil, req) {
		t.Fatal("nil allowlist should allow all origins")
	}
	if !isOriginAllowed([]string{}, req) {
		t.Fatal("empty allowlist should allow all origins")
	}
}

func TestIsOriginAllowed_TrustedOriginAccepted(t *testing.T) {
	allowed := []string{"https://iceq.space", "https://www.iceq.space"}

	for _, origin := range []string{
		"https://iceq.space",
		"https://www.iceq.space",
	} {
		req := httptest.NewRequest("GET", "/ws", nil)
		req.Header.Set("Origin", origin)
		if !isOriginAllowed(allowed, req) {
			t.Fatalf("trusted origin %q should be allowed", origin)
		}
	}
}

func TestIsOriginAllowed_UntrustedOriginRejected(t *testing.T) {
	allowed := []string{"https://iceq.space"}

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Origin", "https://evil.example.com")

	if isOriginAllowed(allowed, req) {
		t.Fatal("untrusted origin should be rejected")
	}
}

func TestIsOriginAllowed_UntrustedOriginWithMatchingSubstringRejected(t *testing.T) {
	// "https://iceq.space.evil.com" should NOT match "https://iceq.space"
	allowed := []string{"https://iceq.space"}

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Origin", "https://iceq.space.evil.com")

	if isOriginAllowed(allowed, req) {
		t.Fatal("origin with matching substring should be rejected")
	}
}

func TestIsOriginAllowed_MissingOriginAllowedForNonBrowser(t *testing.T) {
	allowed := []string{"https://iceq.space"}

	// Non-browser clients (mobile apps, native tools) don't send Origin.
	req := httptest.NewRequest("GET", "/ws", nil)
	// No Origin header set.

	if !isOriginAllowed(allowed, req) {
		t.Fatal("missing Origin (non-browser client) should be allowed")
	}
}

func TestIsOriginAllowed_NullOriginRejected(t *testing.T) {
	allowed := []string{"https://iceq.space"}

	// "null" is a special Origin value sent by sandboxed iframes and
	// some privacy-sensitive contexts. It must never match an allowlist.
	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Origin", "null")

	if isOriginAllowed(allowed, req) {
		t.Fatal("'null' origin should be rejected")
	}
}

func TestIsOriginAllowed_MalformedOriginRejected(t *testing.T) {
	allowed := []string{"https://iceq.space"}

	for _, origin := range []string{
		"not-a-valid-origin",
		"://missing-scheme",
		"javascript:alert(1)",
	} {
		req := httptest.NewRequest("GET", "/ws", nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if isOriginAllowed(allowed, req) {
			t.Fatalf("malformed origin %q should be rejected", origin)
		}
	}
}

func TestIsOriginAllowed_TrailingSlashNormalised(t *testing.T) {
	allowed := []string{"https://iceq.space"}

	for _, origin := range []string{
		"https://iceq.space/",
		"https://iceq.space",
	} {
		req := httptest.NewRequest("GET", "/ws", nil)
		req.Header.Set("Origin", origin)
		if !isOriginAllowed(allowed, req) {
			t.Fatalf("origin %q should match after normalisation", origin)
		}
	}
}

func TestIsOriginAllowed_WhitespaceTrimmed(t *testing.T) {
	allowed := []string{" https://iceq.space "}

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Origin", " https://iceq.space ")

	if !isOriginAllowed(allowed, req) {
		t.Fatal("whitespace-padded origin should match after trimming")
	}
}

func TestIsOriginAllowed_TrailingSlashInAllowlistNormalised(t *testing.T) {
	allowed := []string{"https://iceq.space/"}

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Origin", "https://iceq.space")

	if !isOriginAllowed(allowed, req) {
		t.Fatal("trailing slash in allowlist entry should be normalised")
	}
}
