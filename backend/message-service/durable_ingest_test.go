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
}

func (d *countingDelivery) PublishDelivery(context.Context, string, []byte, string) error {
	d.calls++
	if d.failFirst && d.calls == 1 {
		return errors.New("jetstream unavailable")
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
	if writer.writes != 1 || delivery.calls != 1 {
		t.Fatalf("writes=%d visible deliveries=%d", writer.writes, delivery.calls)
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
	if writer.writes != 1 || delivery.calls != 2 || backend.record.State != store.IngestDelivered {
		t.Fatalf("writes=%d attempts=%d state=%s", writer.writes, delivery.calls, backend.record.State)
	}
}

func TestRecoveredOutboxUsesStableMessageIDAndMarksDelivered(t *testing.T) {
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
	if err := deliverOutboxEntry(context.Background(), ingester, delivery, entry); err != nil {
		t.Fatal(err)
	}
	if delivery.calls != 1 || backend.record.State != store.IngestDelivered {
		t.Fatalf("delivery calls=%d state=%s", delivery.calls, backend.record.State)
	}
}
