package router

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

type deduperStub struct {
	prior          string
	duplicate      bool
	reservedSender int64
	reservedClient string
	commits        int
}

func (d *deduperStub) Reserve(_ context.Context, sender int64, clientID, serverID string) (string, bool, error) {
	d.reservedSender, d.reservedClient = sender, clientID
	if d.duplicate {
		return d.prior, true, nil
	}
	return serverID, false, nil
}
func (d *deduperStub) Release(context.Context, int64, string, string) error { return nil }
func (d *deduperStub) Commit(context.Context, int64, string, string) error  { d.commits++; return nil }

func TestIdempotencyIsScopedToAuthenticatedSenderAndClientMessageID(t *testing.T) {
	d := &deduperStub{}
	got, duplicate, err := reserveMessageID(context.Background(), d, 42, "client-1", "server-1")
	if err != nil || duplicate || got != "server-1" {
		t.Fatalf("got=%q duplicate=%v err=%v", got, duplicate, err)
	}
	if d.reservedSender != 42 || d.reservedClient != "client-1" {
		t.Fatalf("scope=%d/%q", d.reservedSender, d.reservedClient)
	}
}

func TestIdempotencyReplayReturnsPriorServerID(t *testing.T) {
	d := &deduperStub{prior: "server-original", duplicate: true}
	got, duplicate, err := reserveMessageID(context.Background(), d, 42, "client-1", "server-new")
	if err != nil || !duplicate || got != "server-original" {
		t.Fatalf("got=%q duplicate=%v err=%v", got, duplicate, err)
	}
}

func TestRedisLeaseOnlyReplaysCommittedAndReleaseTransfersOwnership(t *testing.T) {
	m := miniredis.RunT(t)
	d := NewRedisMessageDeduper(redis.NewClient(&redis.Options{Addr: m.Addr()}))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if id, dup, err := d.Reserve(ctx, 7, "client", "server-a"); err != nil || dup || id != "server-a" {
		t.Fatalf("reserve=%q/%v/%v", id, dup, err)
	}
	type result struct {
		id  string
		dup bool
		err error
	}
	wait := make(chan result, 1)
	go func() { id, dup, err := d.Reserve(ctx, 7, "client", "server-b"); wait <- result{id, dup, err} }()
	select {
	case got := <-wait:
		t.Fatalf("pending lease acknowledged early: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}
	if err := d.Commit(ctx, 7, "client", "server-a"); err != nil {
		t.Fatal(err)
	}
	got := <-wait
	if got.err != nil || !got.dup || got.id != "server-a" {
		t.Fatalf("committed replay=%+v", got)
	}
	if _, _, err := d.Reserve(ctx, 7, "other", "server-c"); err != nil {
		t.Fatal(err)
	}
	wait = make(chan result, 1)
	go func() { id, dup, err := d.Reserve(ctx, 7, "other", "server-d"); wait <- result{id, dup, err} }()
	time.Sleep(30 * time.Millisecond)
	if err := d.Release(ctx, 7, "other", "server-c"); err != nil {
		t.Fatal(err)
	}
	got = <-wait
	if got.err != nil || got.dup || got.id != "server-d" {
		t.Fatalf("transferred=%+v", got)
	}
}
