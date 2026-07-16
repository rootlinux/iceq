package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gocql/gocql"
)

type memoryIngestBackend struct {
	mu      sync.Mutex
	records map[IngestKey]IngestRecord
}

func newMemoryIngestBackend() *memoryIngestBackend {
	return &memoryIngestBackend{records: make(map[IngestKey]IngestRecord)}
}

func (m *memoryIngestBackend) Claim(_ context.Context, proposed IngestRecord, now time.Time) (IngestRecord, ClaimDisposition, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.records[proposed.Key]
	if !ok {
		m.records[proposed.Key] = proposed
		return proposed, ClaimAcquired, nil
	}
	if current.EnvelopeHash != proposed.EnvelopeHash {
		return IngestRecord{}, 0, ErrIngestConflict
	}
	if current.State == IngestStored || current.State == IngestDelivered {
		return current, ClaimCommitted, nil
	}
	if current.State == IngestPending && !current.LeaseUntil.After(now) {
		current.OwnerToken = proposed.OwnerToken
		current.LeaseUntil = proposed.LeaseUntil
		m.records[proposed.Key] = current
		return current, ClaimAcquired, nil
	}
	return current, ClaimBusy, nil
}

func (m *memoryIngestBackend) MarkStored(_ context.Context, key IngestKey, owner gocql.UUID, leaseUntil time.Time, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.records[key]
	if r.State != IngestPending || r.OwnerToken != owner || !r.LeaseUntil.Equal(leaseUntil) || !r.LeaseUntil.After(now) {
		return false, nil
	}
	r.State = IngestStored
	m.records[key] = r
	return true, nil
}

func (m *memoryIngestBackend) MarkDelivered(_ context.Context, key IngestKey, messageID gocql.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.records[key]
	if r.MessageID != messageID || r.State != IngestStored {
		return false, nil
	}
	r.State = IngestDelivered
	m.records[key] = r
	return true, nil
}

type recordingDurableWriter struct {
	mu       sync.Mutex
	failures int
	writes   []DurableDirectWrite
}

func (w *recordingDurableWriter) WriteDirect(_ context.Context, write DurableDirectWrite) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes = append(w.writes, write)
	if w.failures > 0 {
		w.failures--
		return errors.New("scylla unavailable")
	}
	return nil
}

func TestDurableIngestStoreFailureThenReplayUsesOneDeterministicRow(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	backend := newMemoryIngestBackend()
	writer := &recordingDurableWriter{failures: 1}
	store := NewDurableIngestStore(backend, writer, func() time.Time { return now }, time.Second)
	req := DurableDirectRequest{SenderUIN: 41, ClientID: "client-1", ReceiverUIN: 52, ConversationID: "dm:41:52", Envelope: []byte(`{"ciphertext":"opaque"}`), Ciphertext: []byte("opaque"), MsgType: "signal_message"}

	if _, err := store.PersistDirect(context.Background(), req); err == nil {
		t.Fatal("first write should surface storage failure")
	}
	now = now.Add(2 * time.Second)
	result, err := store.PersistDirect(context.Background(), req)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !result.Committed {
		t.Fatal("replay should commit")
	}
	if len(writer.writes) != 2 {
		t.Fatalf("writes = %d, want 2 attempts", len(writer.writes))
	}
	if writer.writes[0].Message.ID != writer.writes[1].Message.ID || !writer.writes[0].Message.CreatedAt.Equal(writer.writes[1].Message.CreatedAt) {
		t.Fatal("retry changed deterministic message primary key")
	}
	if writer.writes[0].EnvelopeHash != sha256.Sum256(req.Envelope) {
		t.Fatal("writer did not receive immutable envelope hash")
	}
}

func TestExpiredLeaseOwnerCannotTransitionAfterTakeover(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	backend := newMemoryIngestBackend()
	hash := sha256.Sum256([]byte("opaque"))
	first := newIngestRecord(IngestKey{SenderUIN: 41, ClientID: "client-1"}, []byte("opaque"), hash, now, time.Second)
	claimed, disposition, err := backend.Claim(context.Background(), first, now)
	if err != nil || disposition != ClaimAcquired {
		t.Fatalf("first claim = %v, %v", disposition, err)
	}
	now = now.Add(2 * time.Second)
	second := newIngestRecord(first.Key, []byte("opaque"), hash, now, time.Second)
	_, disposition, err = backend.Claim(context.Background(), second, now)
	if err != nil || disposition != ClaimAcquired {
		t.Fatalf("takeover = %v, %v", disposition, err)
	}
	applied, err := backend.MarkStored(context.Background(), first.Key, claimed.OwnerToken, claimed.LeaseUntil, now)
	if err != nil {
		t.Fatal(err)
	}
	if applied {
		t.Fatal("expired owner transitioned state after takeover")
	}
}

func TestCrashAfterStoredReturnsCommittedWithoutSecondWrite(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	backend := newMemoryIngestBackend()
	writer := &recordingDurableWriter{}
	store := NewDurableIngestStore(backend, writer, func() time.Time { return now }, time.Second)
	req := DurableDirectRequest{SenderUIN: 41, ClientID: "client-1", ReceiverUIN: 52, ConversationID: "dm:41:52", Envelope: []byte("opaque-envelope"), Ciphertext: []byte("opaque"), MsgType: "signal_message"}

	first, err := store.PersistDirect(context.Background(), req)
	if err != nil || !first.Committed {
		t.Fatalf("first persist = %+v, %v", first, err)
	}
	second, err := store.PersistDirect(context.Background(), req)
	if err != nil || !second.Committed {
		t.Fatalf("replay = %+v, %v", second, err)
	}
	if first.MessageID != second.MessageID || !first.CreatedAt.Equal(second.CreatedAt) {
		t.Fatal("committed replay changed identity")
	}
	if len(writer.writes) != 1 {
		t.Fatalf("durable writes = %d, want 1", len(writer.writes))
	}
}

func TestExpiryPolicyKeepsOffRowsTTLlessAndAlignsExpiringWrites(t *testing.T) {
	if ttl := durableTTL(0); ttl != 0 {
		t.Fatalf("off TTL = %v, want zero", ttl)
	}
	if ttl := durableTTL(3600); ttl != time.Hour {
		t.Fatalf("expiring TTL = %v, want 1h", ttl)
	}
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	writer := &recordingDurableWriter{}
	store := NewDurableIngestStore(newMemoryIngestBackend(), writer, func() time.Time { return now }, 5*time.Second)
	result, err := store.PersistDirect(context.Background(), DurableDirectRequest{
		SenderUIN: 41, ClientID: "expiring", ReceiverUIN: 52, ConversationID: "dm:41:52",
		Envelope: []byte("opaque-envelope"), Ciphertext: []byte("opaque"), MsgType: "signal_message", ExpiresInSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := writer.writes[0].ExpiresAt, result.CreatedAt.Add(time.Hour); !got.Equal(want) {
		t.Fatalf("write expiry = %v, want %v", got, want)
	}
}

func TestMessageIDIsDeterministicForAuthenticatedIdempotencyKey(t *testing.T) {
	key := IngestKey{SenderUIN: 41, ClientID: "client-1"}
	if deterministicMessageID(key) != deterministicMessageID(key) {
		t.Fatal("same authenticated key produced different ids")
	}
	if deterministicMessageID(key) == deterministicMessageID(IngestKey{SenderUIN: 42, ClientID: key.ClientID}) {
		t.Fatal("message id was not sender-bound")
	}
}
