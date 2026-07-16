package store

import (
	"testing"
	"time"
)

func TestEffectiveMessageTTLUsesPerMessagePolicyAndGlobalFallback(t *testing.T) {
	if got := effectiveMessageTTL(24*time.Hour, 3600); got != time.Hour {
		t.Fatalf("per-message ttl=%s", got)
	}
	if got := effectiveMessageTTL(24*time.Hour, 0); got != 24*time.Hour {
		t.Fatalf("fallback ttl=%s", got)
	}
	if got := effectiveMessageTTL(0, 0); got != 0 {
		t.Fatalf("off ttl=%s", got)
	}
}

func TestExpiryIsDerivedFromServerCreatedAt(t *testing.T) {
	created := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	if got := expiryAt(created, time.Hour); !got.Equal(created.Add(time.Hour)) {
		t.Fatalf("expiry=%s", got)
	}
	if got := expiryAt(created, 0); !got.IsZero() {
		t.Fatalf("off expiry=%s", got)
	}
}
