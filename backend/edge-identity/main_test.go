package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testSecret(ch byte) []byte { return bytes.Repeat([]byte{ch}, 32) }

func TestIdentityIsVersionedHMACAndRotatesDaily(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	got := signIdentity(testSecret('a'), "203.0.113.9", now)
	parts := strings.Split(got, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		t.Fatalf("identity = %q", got)
	}
	mac := hmac.New(sha256.New, testSecret('a'))
	mac.Write([]byte("iceq-edge-identity\x002026-07-16\x00203.0.113.9"))
	if parts[2] != base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) {
		t.Fatal("digest is not the specified HMAC")
	}
	if got == signIdentity(testSecret('a'), "203.0.113.9", now.Add(24*time.Hour)) {
		t.Fatal("identity did not rotate")
	}
	if strings.Contains(got, "203.0.113.9") {
		t.Fatal("identity leaked raw IP")
	}
}

func TestHandlerIgnoresSpoofedClientIdentityAndReturnsRotationOverlap(t *testing.T) {
	h := newHandler(config{current: testSecret('a'), previous: testSecret('b'), now: func() time.Time { return time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC) }})
	req := httptest.NewRequest(http.MethodGet, "/identity", nil)
	req.Header.Set(edgeClientIPHeader, "203.0.113.9")
	req.Header.Set(identityHeader, "attacker-controlled")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rr.Code)
	}
	values := rr.Header().Values(identityHeader)
	if len(values) != 2 {
		t.Fatalf("identity values = %v", values)
	}
	for _, value := range values {
		if value == "attacker-controlled" || !strings.HasPrefix(value, "v1.") {
			t.Fatalf("unsafe identity = %q", value)
		}
	}
}

func TestHandlerRejectsMissingOrMalformedEdgeIP(t *testing.T) {
	h := newHandler(config{current: testSecret('a'), now: time.Now})
	for _, raw := range []string{"", "not-an-ip", "203.0.113.9, 10.0.0.1", "203.0.113.9:443"} {
		req := httptest.NewRequest(http.MethodGet, "/identity", nil)
		req.Header.Set(edgeClientIPHeader, raw)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("input %q status = %d", raw, rr.Code)
		}
		if rr.Header().Get(identityHeader) != "" {
			t.Fatal("invalid input received an identity")
		}
	}
}

func TestServerAndHandlerDoNotLogNetworkIdentity(t *testing.T) {
	var logs bytes.Buffer
	s := newServer(config{current: testSecret('a'), now: time.Now}, io.Discard)
	req := httptest.NewRequest(http.MethodGet, "/identity", nil)
	req.Header.Set(edgeClientIPHeader, "203.0.113.9")
	rr := httptest.NewRecorder()
	s.Handler.ServeHTTP(rr, req)
	if logs.Len() != 0 {
		t.Fatalf("unexpected logs: %q", logs.String())
	}
	if s.ErrorLog.Writer() != io.Discard {
		t.Fatal("server error logger is not discarded")
	}
}

func TestLoadConfigValidatesSecrets(t *testing.T) {
	t.Setenv("ICEQ_EDGE_IDENTITY_HMAC_SECRET", "short")
	if _, err := loadConfig(); err == nil {
		t.Fatal("accepted short current secret")
	}
	t.Setenv("ICEQ_EDGE_IDENTITY_HMAC_SECRET", strings.Repeat("a", 32))
	t.Setenv("ICEQ_EDGE_IDENTITY_HMAC_PREVIOUS_SECRET", "short")
	if _, err := loadConfig(); err == nil {
		t.Fatal("accepted short previous secret")
	}
}
