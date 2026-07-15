package middleware

import (
	"strings"
	"testing"
	"time"
)

func TestAnonymousRateLimitBucketNeverContainsRawIdentity(t *testing.T) {
	identity := "198.51.100.23|Mozilla/5.0 secret-agent"
	got, err := AnonymousRateLimitBucket([]byte("01234567890123456789012345678901"), identity, "login", time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "198.51.100.23") || strings.Contains(got, "Mozilla") {
		t.Fatalf("bucket leaks raw identity: %q", got)
	}
	if !strings.HasPrefix(got, "anon:login:") {
		t.Fatalf("bucket = %q", got)
	}
}

func TestAnonymousRateLimitBucketRotatesDaily(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	a, _ := AnonymousRateLimitBucket(secret, "edge-token", "register", time.Date(2026, 7, 16, 23, 59, 0, 0, time.UTC))
	b, _ := AnonymousRateLimitBucket(secret, "edge-token", "register", time.Date(2026, 7, 17, 0, 1, 0, 0, time.UTC))
	if a == b {
		t.Fatal("bucket did not rotate across UTC day")
	}
}

func TestAuthenticatedRateLimitKeyUsesUINAndAction(t *testing.T) {
	got, err := AuthenticatedRateLimitKey(123456, "files:download")
	if err != nil {
		t.Fatal(err)
	}
	if got != "auth:123456:files:download" {
		t.Fatalf("key = %q", got)
	}
}

func TestRateLimitKeysRejectMissingInputs(t *testing.T) {
	if _, err := AnonymousRateLimitBucket(nil, "edge", "login", time.Now()); err == nil {
		t.Fatal("accepted empty secret")
	}
	if _, err := AnonymousRateLimitBucket([]byte("short"), "", "login", time.Now()); err == nil {
		t.Fatal("accepted empty identity")
	}
	if _, err := AuthenticatedRateLimitKey(0, "files"); err == nil {
		t.Fatal("accepted invalid uin")
	}
}
