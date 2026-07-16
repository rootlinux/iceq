package middleware

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func validEdgeIdentity() string {
	return "v1.0123456789ab." + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
}

func TestAnonymousRateLimitBucketNeverContainsRawIdentity(t *testing.T) {
	identity := validEdgeIdentity()
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
	a, _ := AnonymousRateLimitBucket(secret, validEdgeIdentity(), "register", time.Date(2026, 7, 16, 23, 59, 0, 0, time.UTC))
	b, _ := AnonymousRateLimitBucket(secret, validEdgeIdentity(), "register", time.Date(2026, 7, 17, 0, 1, 0, 0, time.UTC))
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
	if _, err := AnonymousRateLimitBucket([]byte("01234567890123456789012345678901"), "client-spoof", "login", time.Now()); err == nil {
		t.Fatal("accepted unsigned edge identity")
	}
	if _, err := AuthenticatedRateLimitKey(0, "files"); err == nil {
		t.Fatal("accepted invalid uin")
	}
}

func TestAnonymousRateLimitBucketsEnforcesRotationHeaderContract(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	current := validEdgeIdentity()
	previous := "v1.abcdef012345." + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	buckets, err := AnonymousRateLimitBuckets(secret, []string{current}, []string{previous}, "login", time.Now())
	if err != nil || len(buckets) != 2 || buckets[0] == buckets[1] {
		t.Fatalf("buckets=%v err=%v", buckets, err)
	}
	invalid := []struct{ current, previous []string }{
		{nil, nil}, {[]string{current, current}, nil}, {[]string{current}, []string{previous, previous}}, {[]string{current}, []string{current}},
	}
	for _, tc := range invalid {
		if _, err := AnonymousRateLimitBuckets(secret, tc.current, tc.previous, "login", time.Now()); err == nil {
			t.Fatalf("accepted invalid headers current=%v previous=%v", tc.current, tc.previous)
		}
	}
}

func TestRotationOverlapPreservesOldBucketUntilPreviousIsRetired(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	oldIdentity := validEdgeIdentity()
	newIdentity := "v1.abcdef012345." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	before, err := AnonymousRateLimitBuckets(secret, []string{oldIdentity}, nil, "login", now)
	if err != nil {
		t.Fatal(err)
	}
	during, err := AnonymousRateLimitBuckets(secret, []string{newIdentity}, []string{oldIdentity}, "login", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(during) != 2 || during[1] != before[0] {
		t.Fatalf("old bucket continuity lost: before=%v during=%v", before, during)
	}
	after, err := AnonymousRateLimitBuckets(secret, []string{newIdentity}, nil, "login", now)
	if err != nil || len(after) != 1 || after[0] != during[0] {
		t.Fatalf("retirement contract mismatch: during=%v after=%v err=%v", during, after, err)
	}
}
