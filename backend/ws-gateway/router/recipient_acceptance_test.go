package router

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRecipientAcceptanceDirectIsAtomicAndStableAcrossRestart(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	scope, err := DirectRecipientScope(42)
	if err != nil {
		t.Fatal(err)
	}

	first := NewRecipientAcceptanceStore(client)
	accepted, err := first.Accept(ctx, RecipientAcceptance{
		Scope: scope, MessageID: "stable-message-id", Envelope: []byte(`{"id":"stable-message-id"}`),
		ExpiresAt: expiresAtPtr(time.Now().Add(72 * time.Hour)),
	})
	if err != nil || !accepted {
		t.Fatalf("first Accept = (%v, %v), want (true, nil)", accepted, err)
	}

	// Reconstructing the store models a gateway/browser crash and restart. Redis
	// is the only state carried across the boundary.
	restarted := NewRecipientAcceptanceStore(client)
	accepted, err = restarted.Accept(ctx, RecipientAcceptance{
		Scope: scope, MessageID: "stable-message-id", Envelope: []byte(`{"id":"stable-message-id"}`),
		ExpiresAt: expiresAtPtr(time.Now().Add(72 * time.Hour)),
	})
	if err != nil || accepted {
		t.Fatalf("replay Accept = (%v, %v), want (false, nil)", accepted, err)
	}

	items, err := restarted.ReadAccepted(ctx, scope, "-", "+", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || string(items[0].Envelope) != `{"id":"stable-message-id"}` {
		t.Fatalf("queue = %q, want one stable message", items)
	}
}

func TestRecipientAcceptanceReplayAfterMoreThan24HoursDoesNotDuplicate(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	scope, _ := DirectRecipientScope(42)
	store := NewRecipientAcceptanceStore(client)
	expiresAt := time.Now().Add(72 * time.Hour)
	message := RecipientAcceptance{Scope: scope, MessageID: "long-lived", Envelope: []byte("wire"), ExpiresAt: &expiresAt}

	if accepted, err := store.Accept(ctx, message); err != nil || !accepted {
		t.Fatalf("first Accept = (%v, %v)", accepted, err)
	}
	server.FastForward(25 * time.Hour)
	if accepted, err := store.Accept(ctx, message); err != nil || accepted {
		t.Fatalf("25h replay Accept = (%v, %v), want (false, nil)", accepted, err)
	}
	got, err := server.Stream(AcceptanceQueueKey(scope))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("stream length = %d, want 1", len(got))
	}
}

func TestRecipientAcceptanceGroupMemberScopesQueuePerMember(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	store := NewRecipientAcceptanceStore(client)
	a, _ := GroupMemberScope("group-a", 42)
	b, _ := GroupMemberScope("group-a", 43)

	for _, scope := range []RecipientAcceptanceScope{a, b} {
		accepted, err := store.Accept(ctx, RecipientAcceptance{Scope: scope, MessageID: "group-message", Envelope: []byte("wire")})
		if err != nil || !accepted {
			t.Fatalf("Accept(%v) = (%v, %v)", scope, accepted, err)
		}
	}
	if AcceptanceQueueKey(a) == AcceptanceQueueKey(b) {
		t.Fatal("group members unexpectedly share an acceptance queue")
	}
}

func TestRecipientAcceptanceTTLMatchesRemainingExpiryAndOffIsPersistent(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	store := NewRecipientAcceptanceStore(client)
	timed, _ := DirectRecipientScope(42)
	expiresAt := time.Now().Add(48 * time.Hour)
	if _, err := store.Accept(ctx, RecipientAcceptance{Scope: timed, MessageID: "timed", Envelope: []byte("wire"), ExpiresAt: &expiresAt}); err != nil {
		t.Fatal(err)
	}
	ttl := server.TTL(AcceptanceQueueKey(timed))
	if ttl < 47*time.Hour+59*time.Minute || ttl > 48*time.Hour {
		t.Fatalf("queue TTL = %s, want remaining expires_at near 48h", ttl)
	}

	persistent, _ := DirectRecipientScope(43)
	if _, err := store.Accept(ctx, RecipientAcceptance{Scope: persistent, MessageID: "off", Envelope: []byte("wire")}); err != nil {
		t.Fatal(err)
	}
	if ttl := server.TTL(AcceptanceQueueKey(persistent)); ttl != 0 {
		t.Fatalf("TTL-off queue TTL = %s, want persistent", ttl)
	}
}

func TestRecipientAcceptanceMixedTTLNeverShortensOrExpiresOffStream(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	store := NewRecipientAcceptanceStore(client)
	scope, _ := DirectRecipientScope(42)
	long := time.Now().Add(72 * time.Hour)
	short := time.Now().Add(2 * time.Hour)

	_, _ = store.Accept(ctx, RecipientAcceptance{Scope: scope, MessageID: "long", Envelope: []byte("long"), ExpiresAt: &long})
	_, _ = store.Accept(ctx, RecipientAcceptance{Scope: scope, MessageID: "short", Envelope: []byte("short"), ExpiresAt: &short})
	if ttl := server.TTL(AcceptanceQueueKey(scope)); ttl < 71*time.Hour+59*time.Minute {
		t.Fatalf("short-lived entry shortened stream TTL to %s", ttl)
	}
	_, _ = store.Accept(ctx, RecipientAcceptance{Scope: scope, MessageID: "off", Envelope: []byte("off")})
	if ttl := server.TTL(AcceptanceQueueKey(scope)); ttl != 0 {
		t.Fatalf("TTL-off entry left stream expiring in %s", ttl)
	}
	later := time.Now().Add(time.Hour)
	_, _ = store.Accept(ctx, RecipientAcceptance{Scope: scope, MessageID: "later", Envelope: []byte("later"), ExpiresAt: &later})
	if ttl := server.TTL(AcceptanceQueueKey(scope)); ttl != 0 {
		t.Fatalf("expiring entry changed persistent mixed stream TTL to %s", ttl)
	}
}

func TestRecipientAcceptanceRejectsExpiredWithoutQueueing(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	scope, _ := DirectRecipientScope(42)
	expiresAt := time.Now().Add(-time.Second)
	_, err := NewRecipientAcceptanceStore(client).Accept(context.Background(), RecipientAcceptance{
		Scope: scope, MessageID: "expired", Envelope: []byte("wire"), ExpiresAt: &expiresAt,
	})
	if !errors.Is(err, ErrAcceptanceExpired) {
		t.Fatalf("Accept error = %v, want ErrAcceptanceExpired", err)
	}
	if server.Exists(AcceptanceQueueKey(scope)) {
		t.Fatal("expired acceptance created a queue")
	}
}

func expiresAtPtr(value time.Time) *time.Time { return &value }
