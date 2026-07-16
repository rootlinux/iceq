package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iceq/iceq/ws-gateway/router"
)

type memoryAccepter struct {
	mu    sync.Mutex
	seen  map[string]struct{}
	queue map[string]router.AcceptedEnvelope
	items int
}

func (a *memoryAccepter) Accept(_ context.Context, in router.RecipientAcceptance) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.seen == nil {
		a.seen = make(map[string]struct{})
	}
	key := router.AcceptanceQueueKey(in.Scope) + ":" + in.MessageID
	if _, ok := a.seen[key]; ok {
		return false, nil
	}
	a.seen[key] = struct{}{}
	if a.queue == nil {
		a.queue = make(map[string]router.AcceptedEnvelope)
	}
	a.queue[key] = router.AcceptedEnvelope{StreamID: fmt.Sprint(a.items + 1), MessageID: in.MessageID, Envelope: append([]byte(nil), in.Envelope...)}
	a.items++
	return true, nil
}

func (a *memoryAccepter) ReadAcceptedAfter(_ context.Context, scope router.RecipientAcceptanceScope, _ string, _ int64) ([]router.AcceptedEnvelope, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	prefix := router.AcceptanceQueueKey(scope) + ":"
	out := make([]router.AcceptedEnvelope, 0)
	for key, item := range a.queue {
		if strings.HasPrefix(key, prefix) {
			out = append(out, item)
		}
	}
	return out, nil
}

type liveCounter struct{ calls int }

func (l *liveCounter) SendLive(int64, []byte) { l.calls++ }

type receiptStub struct {
	calls     int
	failFirst bool
}

func (r *receiptStub) Request(_ string, _ []byte, _ time.Duration) ([]byte, error) {
	r.calls++
	if r.failFirst && r.calls == 1 {
		return nil, errors.New("receipt unavailable")
	}
	return []byte(`{"status":"accepted"}`), nil
}

func directDeliveryBody(id string) []byte {
	return []byte(fmt.Sprintf(`{"type":"message","id":%q,"ts":1700000000000,"payload":{"conversation_id":"dm:7:42","sender_uin":7,"receiver_uin":42,"ciphertext":%q,"msg_type":"signal_message","client_id":"client-1"}}`, id, base64.RawURLEncoding.EncodeToString([]byte("opaque"))))
}

func groupDeliveryBody(id, groupID string) []byte {
	return []byte(fmt.Sprintf(`{"type":"group_msg","id":%q,"ts":1700000000000,"payload":{"group_id":%q,"sender_uin":7,"ciphertext":%q,"msg_type":"group_ciphertext","crypto_version":1,"crypto_epoch":2,"client_id":"group-client","recipient_uins":[7,42,99]}}`, id, groupID, base64.RawURLEncoding.EncodeToString([]byte("opaque"))))
}

func TestCrashAfterDurableAcceptanceRedeliversWithoutSecondQueueItem(t *testing.T) {
	accept := &memoryAccepter{}
	live := &liveCounter{}
	receipts := &receiptStub{failFirst: true}
	body := directDeliveryBody("00000000-0000-5000-8000-000000000001")
	if err := acceptDelivery(context.Background(), accept, live, receipts, "msg.direct.42", body); err == nil {
		t.Fatal("first receipt failure must keep JetStream message unacked")
	}
	if err := acceptDelivery(context.Background(), accept, live, receipts, "msg.direct.42", body); err != nil {
		t.Fatal(err)
	}
	if accept.items != 1 || live.calls != 2 || receipts.calls != 2 {
		t.Fatalf("queue=%d live=%d receipts=%d", accept.items, live.calls, receipts.calls)
	}
}

func TestGatewayAbsentThenConsumerDurablyAcceptsPublishedMessageOnce(t *testing.T) {
	accept := &memoryAccepter{}
	live := &liveCounter{}
	receipts := &receiptStub{}
	body := directDeliveryBody("00000000-0000-5000-8000-000000000002")
	// The durable stream may hold this body while no gateway process exists.
	if err := acceptDelivery(context.Background(), accept, live, receipts, "msg.direct.42", body); err != nil {
		t.Fatal(err)
	}
	if err := acceptDelivery(context.Background(), accept, live, receipts, "msg.direct.42", body); err != nil {
		t.Fatal(err)
	}
	if accept.items != 1 || live.calls != 2 {
		t.Fatalf("queue=%d live=%d", accept.items, live.calls)
	}
}

func TestGroupDeliveryRequiresEveryMemberAcceptanceBeforeReceipt(t *testing.T) {
	accept := &memoryAccepter{}
	live := &liveCounter{}
	receipts := &receiptStub{}
	groupID := "7f0300f2-0494-4f61-9f41-7c198f73b2fa"
	body := groupDeliveryBody("00000000-0000-5000-8000-000000000003", groupID)
	if err := acceptDelivery(context.Background(), accept, live, receipts, "msg.group."+groupID, body); err != nil {
		t.Fatal(err)
	}
	if accept.items != 3 || live.calls != 3 || receipts.calls != 1 {
		t.Fatalf("queue=%d live=%d receipts=%d", accept.items, live.calls, receipts.calls)
	}
}
