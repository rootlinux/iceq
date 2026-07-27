package store

import (
	"testing"
	"time"
)

func TestEffectiveMessageTTLUsesExplicitPerMessagePolicy(t *testing.T) {
	if got := effectiveMessageTTL(3600); got != time.Hour {
		t.Fatalf("per-message ttl=%s", got)
	}
	if got := effectiveMessageTTL(0); got != defaultMessageTTL {
		t.Fatalf("unset ttl should fall back to the bounded default, got=%s", got)
	}
	if got := effectiveMessageTTL(-1); got != defaultMessageTTL {
		t.Fatalf("negative ttl should fall back to the bounded default, got=%s", got)
	}
}

func TestEffectiveMessageTTLHasNoIndefiniteRetentionPath(t *testing.T) {
	if got := effectiveMessageTTL(int64(maxMessageTTL/time.Second) + 1); got != maxMessageTTL {
		t.Fatalf("above-max ttl must clamp to maxMessageTTL, got=%s", got)
	}
	if got := effectiveMessageTTL(1 << 40); got != maxMessageTTL {
		t.Fatalf("a modified client requesting an unbounded ttl must still clamp to maxMessageTTL, got=%s", got)
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
