package router

import (
	"context"
	"testing"
)

type deduperStub struct {
	prior          string
	duplicate      bool
	reservedSender int64
	reservedClient string
}

func (d *deduperStub) Reserve(_ context.Context, sender int64, clientID, serverID string) (string, bool, error) {
	d.reservedSender, d.reservedClient = sender, clientID
	if d.duplicate {
		return d.prior, true, nil
	}
	return serverID, false, nil
}
func (d *deduperStub) Release(context.Context, int64, string, string) error { return nil }

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
