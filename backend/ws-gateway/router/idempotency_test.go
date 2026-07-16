package router

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/iceq/iceq/shared/models"
	"github.com/redis/go-redis/v9"
)

type leaseDeduper struct {
	mu            sync.Mutex
	state, server string
	changed       chan struct{}
}

func newLeaseDeduper() *leaseDeduper { return &leaseDeduper{changed: make(chan struct{})} }
func (d *leaseDeduper) notify()      { close(d.changed); d.changed = make(chan struct{}) }
func (d *leaseDeduper) Reserve(ctx context.Context, _ int64, _ string, server string) (string, bool, error) {
	for {
		d.mu.Lock()
		switch d.state {
		case "":
			d.state = "pending"
			d.server = server
			d.mu.Unlock()
			return server, false, nil
		case "committed":
			prior := d.server
			d.mu.Unlock()
			return prior, true, nil
		default:
			ch := d.changed
			d.mu.Unlock()
			select {
			case <-ctx.Done():
				return "", false, ctx.Err()
			case <-ch:
			}
		}
	}
}
func (d *leaseDeduper) Commit(_ context.Context, _ int64, _ string, server string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state != "pending" || d.server != server {
		return errors.New("lost")
	}
	d.state = "committed"
	d.notify()
	return nil
}
func (d *leaseDeduper) Release(_ context.Context, _ int64, _ string, server string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state == "pending" && d.server == server {
		d.state = ""
		d.server = ""
		d.notify()
	}
	return nil
}

type failFirstPublisher struct {
	mu             sync.Mutex
	calls, success int
	started        chan struct{}
	allowFailure   chan struct{}
}

func (p *failFirstPublisher) Publish(_ string, _ []byte) error {
	p.mu.Lock()
	p.calls++
	call := p.calls
	p.mu.Unlock()
	if call == 1 {
		close(p.started)
		<-p.allowFailure
		return errors.New("publish failed")
	}
	p.mu.Lock()
	p.success++
	p.mu.Unlock()
	return nil
}

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

func TestPendingDuplicateWaitsAndOwnerFailureTransfersWithoutFalseAck(t *testing.T) {
	d := newLeaseDeduper()
	pub := &failFirstPublisher{started: make(chan struct{}), allowFailure: make(chan struct{})}
	deps := SendDeps{Publisher: pub, Deduper: d}
	raw := json.RawMessage(`{"conversation_id":"dm:7:42","to_uin":42,"ciphertext":"YQ","msg_type":"signal_message","client_id":"same"}`)
	env := models.Envelope{Type: models.EnvelopeTypeDirect, Payload: raw}
	results := make(chan error, 2)
	go func() { _, err := processHTTPSend(context.Background(), 7, env, deps); results <- err }()
	<-pub.started
	go func() { _, err := processHTTPSend(context.Background(), 7, env, deps); results <- err }()
	close(pub.allowFailure)
	err1, err2 := <-results, <-results
	if (err1 == nil) == (err2 == nil) {
		t.Fatalf("want one failure and one committed ack: %v / %v", err1, err2)
	}
	if pub.success != 1 {
		t.Fatalf("successful publishes=%d", pub.success)
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
