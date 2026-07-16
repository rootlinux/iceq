package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gocql/gocql"
	"github.com/iceq/iceq/message-service/store"
	"github.com/iceq/iceq/shared/models"
)

type ingestMemoryBackend struct {
	mu     sync.Mutex
	record store.IngestRecord
	has    bool
}

func (b *ingestMemoryBackend) Claim(_ context.Context, proposed store.IngestRecord, now time.Time) (store.IngestRecord, store.ClaimDisposition, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.has {
		b.record, b.has = proposed, true
		return b.record, store.ClaimAcquired, nil
	}
	if b.record.EnvelopeHash != proposed.EnvelopeHash {
		return b.record, 0, store.ErrIngestConflict
	}
	if b.record.State == store.IngestStored || b.record.State == store.IngestDelivered {
		return b.record, store.ClaimCommitted, nil
	}
	if b.record.LeaseUntil.After(now) {
		return b.record, store.ClaimBusy, nil
	}
	b.record.OwnerToken, b.record.LeaseUntil = proposed.OwnerToken, proposed.LeaseUntil
	return b.record, store.ClaimAcquired, nil
}
func (b *ingestMemoryBackend) MarkStored(_ context.Context, _ store.IngestKey, owner gocql.UUID, lease, _ time.Time) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.record.OwnerToken != owner || !b.record.LeaseUntil.Equal(lease) {
		return false, nil
	}
	b.record.State = store.IngestStored
	return true, nil
}
func (b *ingestMemoryBackend) MarkDelivered(_ context.Context, _ store.IngestKey, id gocql.UUID) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.record.MessageID != id {
		return false, nil
	}
	b.record.State = store.IngestDelivered
	return true, nil
}

type countingDirectWriter struct{ writes int }

func (w *countingDirectWriter) WriteDirect(context.Context, store.DurableDirectWrite) error {
	w.writes++
	return nil
}

type countingDelivery struct {
	calls     int
	failFirst bool
	visible   int
	seen      map[string]struct{}
}

type fixedOutboxReader struct{ entries []store.OutboxEntry }

func (r fixedOutboxReader) FetchPending(context.Context, int) ([]store.OutboxEntry, error) {
	return r.entries, nil
}

type blockFirstDelivery struct {
	calls     int
	completed []string
}

func (d *blockFirstDelivery) PublishDelivery(ctx context.Context, _ string, _ []byte, id string) error {
	d.calls++
	if d.calls == 1 {
		<-ctx.Done()
		return ctx.Err()
	}
	d.completed = append(d.completed, id)
	return nil
}

func (d *countingDelivery) PublishDelivery(_ context.Context, _ string, _ []byte, id string) error {
	d.calls++
	if d.failFirst && d.calls == 1 {
		return errors.New("jetstream unavailable")
	}
	if d.seen == nil {
		d.seen = make(map[string]struct{})
	}
	if _, ok := d.seen[id]; !ok {
		d.seen[id] = struct{}{}
		d.visible++
	}
	return nil
}

func directIngestBody(t *testing.T) []byte {
	t.Helper()
	payload := `{"conversation_id":"dm:7:42","sender_uin":7,"receiver_uin":42,"ciphertext":"` + base64.RawURLEncoding.EncodeToString([]byte("opaque")) + `","msg_type":"signal_message","client_id":"client-durable"}`
	return []byte(`{"type":"message","payload":` + payload + `}`)
}

func TestDurableIngestReplayNeverStoresOrDeliversTwice(t *testing.T) {
	backend := &ingestMemoryBackend{}
	writer := &countingDirectWriter{}
	delivery := &countingDelivery{}
	ingester := store.NewDurableIngestStore(backend, writer, time.Now, time.Second)
	for i := 0; i < 2; i++ {
		ack, err := processDurableIngest(context.Background(), ingester, delivery, nil, directIngestBody(t))
		if err != nil {
			t.Fatal(err)
		}
		var p models.AckPayload
		if err := json.Unmarshal(ack.Payload, &p); err != nil || p.State != models.AckStatePersisted {
			t.Fatalf("ack=%+v err=%v", p, err)
		}
	}
	if writer.writes != 1 || delivery.visible != 1 {
		t.Fatalf("writes=%d attempts=%d visible deliveries=%d", writer.writes, delivery.calls, delivery.visible)
	}
}

func TestDurableOutboxRetriesAfterStoreThenDeliveryFailure(t *testing.T) {
	backend := &ingestMemoryBackend{}
	writer := &countingDirectWriter{}
	delivery := &countingDelivery{failFirst: true}
	ingester := store.NewDurableIngestStore(backend, writer, time.Now, time.Second)
	if _, err := processDurableIngest(context.Background(), ingester, delivery, nil, directIngestBody(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := processDurableIngest(context.Background(), ingester, delivery, nil, directIngestBody(t)); err != nil {
		t.Fatal(err)
	}
	if writer.writes != 1 || delivery.calls != 2 || backend.record.State != store.IngestStored {
		t.Fatalf("writes=%d attempts=%d state=%s", writer.writes, delivery.calls, backend.record.State)
	}
}

func TestRecoveredOutboxUsesStableMessageIDButWaitsForAcceptanceReceipt(t *testing.T) {
	backend := &ingestMemoryBackend{}
	writer := &countingDirectWriter{}
	ingester := store.NewDurableIngestStore(backend, writer, time.Now, time.Second)
	if _, err := processDurableIngest(context.Background(), ingester, &countingDelivery{failFirst: true}, nil, directIngestBody(t)); err != nil {
		t.Fatal(err)
	}
	entry := store.OutboxEntry{
		Kind: store.IngestKindDirect, Key: backend.record.Key, MessageID: backend.record.MessageID,
		CreatedAt: backend.record.CreatedAt, ReceiverUIN: backend.record.ReceiverUIN, Envelope: directIngestBody(t),
	}
	delivery := &countingDelivery{}
	if err := deliverOutboxEntry(context.Background(), delivery, entry); err != nil {
		t.Fatal(err)
	}
	if delivery.calls != 1 || backend.record.State != store.IngestStored {
		t.Fatalf("delivery calls=%d state=%s", delivery.calls, backend.record.State)
	}
}

func TestDeliveryReceiptDeletesOutboxOnlyAfterDurableRecipientAcceptance(t *testing.T) {
	backend := &ingestMemoryBackend{}
	writer := &countingDirectWriter{}
	ingester := store.NewDurableIngestStore(backend, writer, time.Now, time.Second)
	if _, err := processDurableIngest(context.Background(), ingester, &countingDelivery{}, nil, directIngestBody(t)); err != nil {
		t.Fatal(err)
	}
	if backend.record.State != store.IngestStored {
		t.Fatalf("producer PubAck prematurely marked %s", backend.record.State)
	}
	receipt, _ := json.Marshal(deliveryAcceptedPayload{SenderUIN: 7, ClientID: "client-durable", MessageID: backend.record.MessageID.String()})
	if err := processDeliveryAccepted(context.Background(), ingester, receipt); err != nil {
		t.Fatal(err)
	}
	if backend.record.State != store.IngestDelivered {
		t.Fatalf("receipt did not mark delivered: %s", backend.record.State)
	}
}

func TestBlockedOutboxPublishTimesOutWithoutStarvingLaterEntry(t *testing.T) {
	first, second := gocql.TimeUUID(), gocql.TimeUUID()
	reader := fixedOutboxReader{entries: []store.OutboxEntry{
		{Kind: store.IngestKindDirect, MessageID: first, ReceiverUIN: 42, Envelope: directIngestBody(t)},
		{Kind: store.IngestKindDirect, MessageID: second, ReceiverUIN: 42, Envelope: directIngestBody(t)},
	}}
	delivery := &blockFirstDelivery{}
	drainPendingOutboxWithTimeout(context.Background(), reader, delivery, 10*time.Millisecond)
	if delivery.calls != 2 || len(delivery.completed) != 1 || delivery.completed[0] != second.String() {
		t.Fatalf("calls=%d completed=%v", delivery.calls, delivery.completed)
	}
}
