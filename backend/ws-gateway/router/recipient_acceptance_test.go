package router

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func acceptanceTestStore(t *testing.T) (*miniredis.Miniredis, *RecipientAcceptanceStore, RecipientAcceptanceScope) {
	t.Helper()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	scope, err := DirectRecipientScope(42)
	if err != nil {
		t.Fatal(err)
	}
	return server, NewRecipientAcceptanceStore(client), scope
}

func TestRecipientAcceptanceMixedOffAndExpiringRecordsExpireIndependently(t *testing.T) {
	server, store, scope := acceptanceTestStore(t)
	ctx := context.Background()
	expires := time.Now().Add(time.Hour)
	if ok, err := store.Accept(ctx, RecipientAcceptance{Scope: scope, MessageID: "hour", Envelope: []byte("hour-wire"), ExpiresAt: &expires}); err != nil || !ok {
		t.Fatalf("timed Accept = (%v, %v)", ok, err)
	}
	if ok, err := store.Accept(ctx, RecipientAcceptance{Scope: scope, MessageID: "off", Envelope: []byte("off-wire")}); err != nil || !ok {
		t.Fatalf("off Accept = (%v, %v)", ok, err)
	}

	server.FastForward(time.Hour + time.Millisecond)
	items, err := store.ReadAcceptedAfter(ctx, scope, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].MessageID != "off" || string(items[0].Envelope) != "off-wire" {
		t.Fatalf("items after expiry = %#v, want only off", items)
	}
	if ttl := server.TTL(acceptanceRecordKey(scope, "off")); ttl != 0 {
		t.Fatalf("off record TTL = %s, want persistent", ttl)
	}
}

func TestAckRecipientRemovesPayloadAndFreesCapacityButKeepsDedupe(t *testing.T) {
	_, store, scope := acceptanceTestStore(t)
	ctx := context.Background()
	if ok, err := store.Accept(ctx, RecipientAcceptance{Scope: scope, MessageID: "ack-me", Envelope: []byte("wire")}); err != nil || !ok {
		t.Fatalf("accept=(%v,%v)", ok, err)
	}
	removed, err := store.AckRecipient(ctx, 42, []string{"ack-me"})
	if err != nil || removed != 1 {
		t.Fatalf("ack=(%d,%v)", removed, err)
	}
	items, err := store.ReadAcceptedAfter(ctx, scope, "", 10)
	if err != nil || len(items) != 0 {
		t.Fatalf("items=%#v err=%v", items, err)
	}
	if ok, err := store.Accept(ctx, RecipientAcceptance{Scope: scope, MessageID: "ack-me", Envelope: []byte("wire")}); err != nil || ok {
		t.Fatalf("dedupe after ack=(%v,%v)", ok, err)
	}
}

func TestRecipientAcceptanceExpiresWithoutPollOrBackgroundWorker(t *testing.T) {
	server, store, scope := acceptanceTestStore(t)
	expires := time.Now().Add(time.Hour)
	if _, err := store.Accept(context.Background(), RecipientAcceptance{Scope: scope, MessageID: "timed", Envelope: []byte("secret"), ExpiresAt: &expires}); err != nil {
		t.Fatal(err)
	}
	recordKey := acceptanceRecordKey(scope, "timed")
	if !server.Exists(recordKey) {
		t.Fatal("record not created")
	}
	server.FastForward(time.Hour + time.Millisecond)
	if server.Exists(recordKey) {
		t.Fatal("ciphertext record survived expires_at without a poll")
	}
}

func TestRecipientAcceptanceFullReturnsBackpressureThenRecoversAfterDrain(t *testing.T) {
	_, store, scope := acceptanceTestStore(t)
	ctx := context.Background()
	for i := 0; i < recipientAcceptanceMaxActive; i++ {
		id := "m-" + strconv.Itoa(i)
		if ok, err := store.Accept(ctx, RecipientAcceptance{Scope: scope, MessageID: id, Envelope: []byte(id)}); err != nil || !ok {
			t.Fatalf("Accept %d = (%v, %v)", i, ok, err)
		}
	}
	if ok, err := store.Accept(ctx, RecipientAcceptance{Scope: scope, MessageID: "overflow", Envelope: []byte("wire")}); ok || !errors.Is(err, ErrAcceptanceQueueFull) {
		t.Fatalf("overflow Accept = (%v, %v), want queue full", ok, err)
	}
	drained, err := store.DrainAccepted(ctx, scope, "", 1)
	if err != nil || len(drained) != 1 {
		t.Fatalf("DrainAccepted = (%d, %v)", len(drained), err)
	}
	if ok, err := store.Accept(ctx, RecipientAcceptance{Scope: scope, MessageID: "after-drain", Envelope: []byte("wire")}); err != nil || !ok {
		t.Fatalf("after drain Accept = (%v, %v)", ok, err)
	}
}

func TestRecipientAcceptanceCrashRestartReplaysUntilDrain(t *testing.T) {
	_, first, scope := acceptanceTestStore(t)
	ctx := context.Background()
	if ok, err := first.Accept(ctx, RecipientAcceptance{Scope: scope, MessageID: "stable", Envelope: []byte("wire")}); err != nil || !ok {
		t.Fatalf("Accept = (%v, %v)", ok, err)
	}
	restarted := NewRecipientAcceptanceStore(first.rdb)
	items, err := restarted.ReadAcceptedAfter(ctx, scope, "", 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("restart read = (%d, %v)", len(items), err)
	}
	cursor := items[0].StreamID
	items, err = restarted.ReadAcceptedAfter(ctx, scope, cursor, 10)
	if err != nil || len(items) != 0 {
		t.Fatalf("read after cursor = (%d, %v)", len(items), err)
	}
	drained, err := restarted.DrainAccepted(ctx, scope, "", 10)
	if err != nil || len(drained) != 1 {
		t.Fatalf("drain = (%d, %v)", len(drained), err)
	}
	items, err = restarted.ReadAcceptedAfter(ctx, scope, "", 10)
	if err != nil || len(items) != 0 {
		t.Fatalf("post-drain replay = (%d, %v)", len(items), err)
	}
}

func TestRecipientAcceptanceReplayIsDeduplicated(t *testing.T) {
	_, store, scope := acceptanceTestStore(t)
	ctx := context.Background()
	a := RecipientAcceptance{Scope: scope, MessageID: "same", Envelope: []byte("wire")}
	if ok, err := store.Accept(ctx, a); err != nil || !ok {
		t.Fatalf("first = (%v, %v)", ok, err)
	}
	if ok, err := store.Accept(ctx, a); err != nil || ok {
		t.Fatalf("replay = (%v, %v)", ok, err)
	}
}

func TestRecipientAcceptanceRejectsExpiredWithoutQueueing(t *testing.T) {
	server, store, scope := acceptanceTestStore(t)
	expires := time.Now().Add(-time.Second)
	_, err := store.Accept(context.Background(), RecipientAcceptance{Scope: scope, MessageID: "expired", Envelope: []byte("wire"), ExpiresAt: &expires})
	if !errors.Is(err, ErrAcceptanceExpired) {
		t.Fatalf("Accept error = %v", err)
	}
	if server.Exists(AcceptanceQueueKey(scope)) {
		t.Fatal("expired acceptance created an index")
	}
}
