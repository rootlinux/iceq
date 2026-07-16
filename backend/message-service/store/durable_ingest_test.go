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
	if current.EnvelopeHash != proposed.EnvelopeHash || current.Kind != proposed.Kind || current.GroupID != proposed.GroupID || current.CryptoEpoch != proposed.CryptoEpoch || current.ReceiverUIN != proposed.ReceiverUIN || !sameRecipientSnapshot(current.RecipientUINs, proposed.RecipientUINs) {
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

type recordingDurableGroupWriter struct {
	mu       sync.Mutex
	failures int
	writes   []DurableGroupWrite
}

func (w *recordingDurableGroupWriter) WriteGroup(_ context.Context, write DurableGroupWrite) error {
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

func TestDurableGroupFailureThenReplayUsesOneDeterministicRow(t *testing.T) {
	now := time.Date(2026, 7, 16, 13, 0, 0, 0, time.UTC)
	backend := newMemoryIngestBackend()
	directWriter := &recordingDurableWriter{}
	groupWriter := &recordingDurableGroupWriter{failures: 1}
	store := NewDurableIngestStoreWithGroup(backend, directWriter, groupWriter, func() time.Time { return now }, time.Second)
	groupID := gocql.TimeUUID()
	req := DurableGroupRequest{
		SenderUIN: 41, ClientID: "group-client-1", GroupID: groupID, CryptoEpoch: 7,
		RecipientUINs: []int64{52, 63},
		Envelope:      []byte(`{"group_id":"opaque"}`), Ciphertext: []byte("opaque"), MsgType: "sender_key_message", ExpiresInSeconds: 3600,
	}

	if _, err := store.PersistGroup(context.Background(), req); err == nil {
		t.Fatal("first group write should surface storage failure")
	}
	now = now.Add(2 * time.Second)
	result, err := store.PersistGroup(context.Background(), req)
	if err != nil || !result.Committed {
		t.Fatalf("group replay = %+v, %v", result, err)
	}
	if len(groupWriter.writes) != 2 {
		t.Fatalf("group writes = %d, want 2 attempts", len(groupWriter.writes))
	}
	first, second := groupWriter.writes[0], groupWriter.writes[1]
	if first.Message.ID != second.Message.ID || !first.Message.CreatedAt.Equal(second.Message.CreatedAt) {
		t.Fatal("group retry changed deterministic primary key")
	}
	if first.Message.GroupID != groupID || first.Message.CryptoEpoch != 7 {
		t.Fatal("group write lost authenticated group metadata")
	}
	if got, want := first.ExpiresAt, result.CreatedAt.Add(time.Hour); !got.Equal(want) {
		t.Fatalf("group expiry = %v, want %v", got, want)
	}
}

func TestStoredGroupReplayReturnsCommittedWithoutSecondWrite(t *testing.T) {
	now := time.Date(2026, 7, 16, 13, 0, 0, 0, time.UTC)
	backend := newMemoryIngestBackend()
	groupWriter := &recordingDurableGroupWriter{}
	store := NewDurableIngestStoreWithGroup(backend, &recordingDurableWriter{}, groupWriter, func() time.Time { return now }, time.Second)
	req := DurableGroupRequest{SenderUIN: 41, ClientID: "group-client-1", GroupID: gocql.TimeUUID(), CryptoEpoch: 3, RecipientUINs: []int64{52, 63}, Envelope: []byte("opaque-envelope"), Ciphertext: []byte("opaque"), MsgType: "sender_key_message"}

	first, err := store.PersistGroup(context.Background(), req)
	if err != nil || !first.Committed {
		t.Fatalf("first group persist = %+v, %v", first, err)
	}
	second, err := store.PersistGroup(context.Background(), req)
	if err != nil || !second.Committed {
		t.Fatalf("stored group replay = %+v, %v", second, err)
	}
	if first.MessageID != second.MessageID || !first.CreatedAt.Equal(second.CreatedAt) {
		t.Fatal("stored group replay changed identity")
	}
	if len(groupWriter.writes) != 1 {
		t.Fatalf("group durable writes = %d, want 1", len(groupWriter.writes))
	}
}

func TestDurableGroupRecipientSnapshotIsImmutableAcrossReplay(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	backend := newMemoryIngestBackend()
	groupWriter := &recordingDurableGroupWriter{failures: 1}
	store := NewDurableIngestStoreWithGroup(backend, &recordingDurableWriter{}, groupWriter, func() time.Time { return now }, time.Second)
	recipients := []int64{52, 63}
	req := DurableGroupRequest{SenderUIN: 41, ClientID: "snapshot-1", GroupID: gocql.TimeUUID(), CryptoEpoch: 7, RecipientUINs: recipients, Envelope: []byte("opaque-envelope"), Ciphertext: []byte("opaque"), MsgType: "sender_key_message"}
	if _, err := store.PersistGroup(context.Background(), req); err == nil {
		t.Fatal("first write should fail")
	}
	recipients[0] = 999
	req.RecipientUINs = []int64{52, 63, 74}
	now = now.Add(2 * time.Second)
	if _, err := store.PersistGroup(context.Background(), req); !errors.Is(err, ErrIngestConflict) {
		t.Fatalf("changed membership snapshot = %v, want conflict", err)
	}
	if got := groupWriter.writes[0].RecipientUINs; len(got) != 2 || got[0] != 52 || got[1] != 63 {
		t.Fatalf("stored recipient snapshot mutated: %v", got)
	}
}

type fakeOutboxBucketReader struct {
	direct map[int8][]OutboxEntry
	group  map[int8][]OutboxEntry
}

func rowsAfter(rows []OutboxEntry, after outboxPageCursor, limit int) []OutboxEntry {
	start := 0
	if after.Valid {
		for start < len(rows) && (rows[start].CreatedAt.Before(after.CreatedAt) || rows[start].CreatedAt.Equal(after.CreatedAt) && rows[start].MessageID.String() <= after.MessageID.String()) {
			start++
		}
	}
	rows = rows[start:]
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

func (f *fakeOutboxBucketReader) fetchDirectBucket(_ context.Context, bucket int8, after outboxPageCursor, limit int) ([]OutboxEntry, error) {
	return rowsAfter(f.direct[bucket], after, limit), nil
}

func (f *fakeOutboxBucketReader) fetchGroupBucket(_ context.Context, bucket int8, after outboxPageCursor, limit int) ([]OutboxEntry, error) {
	return rowsAfter(f.group[bucket], after, limit), nil
}

func TestFetchPendingIsBoundedAndIncludesDirectAndGroupBuckets(t *testing.T) {
	reader := &fakeOutboxBucketReader{direct: map[int8][]OutboxEntry{}, group: map[int8][]OutboxEntry{}}
	reader.direct[0] = []OutboxEntry{{Kind: IngestKindDirect}, {Kind: IngestKindDirect}}
	reader.group[1] = []OutboxEntry{{Kind: IngestKindGroup}, {Kind: IngestKindGroup}}

	rows, err := fetchPendingOutbox(context.Background(), reader, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) > 3 {
		t.Fatalf("rows = %d, want at most 3", len(rows))
	}
	seenDirect, seenGroup := false, false
	for _, row := range rows {
		seenDirect = seenDirect || row.Kind == IngestKindDirect
		seenGroup = seenGroup || row.Kind == IngestKindGroup
	}
	if !seenDirect || !seenGroup {
		t.Fatalf("pending recovery omitted a kind: direct=%v group=%v", seenDirect, seenGroup)
	}
}

func TestFetchPendingRotatesStartingBucketAcrossCalls(t *testing.T) {
	reader := &fakeOutboxBucketReader{direct: map[int8][]OutboxEntry{}, group: map[int8][]OutboxEntry{}}
	for bucket := int8(0); bucket < outboxBucketCount; bucket++ {
		reader.direct[bucket] = []OutboxEntry{{ReceiverUIN: int64(bucket)}}
	}
	cursor := &outboxFetchCursor{}

	first, err := cursor.fetch(context.Background(), reader, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cursor.fetch(context.Background(), reader, 1)
	if err != nil {
		t.Fatal(err)
	}
	if first[0].ReceiverUIN != 0 || second[0].ReceiverUIN != 1 {
		t.Fatalf("starting buckets = %d, %d; want 0, 1", first[0].ReceiverUIN, second[0].ReceiverUIN)
	}
}

func TestFetchPendingReservesQuotaForLaterBucketsAndCapsAtOneHundred(t *testing.T) {
	reader := &fakeOutboxBucketReader{direct: map[int8][]OutboxEntry{}, group: map[int8][]OutboxEntry{}}
	for i := 0; i < 200; i++ {
		reader.direct[0] = append(reader.direct[0], OutboxEntry{ReceiverUIN: 1000})
	}
	reader.direct[15] = []OutboxEntry{{ReceiverUIN: 15}}

	rows, err := (&outboxFetchCursor{}).fetch(context.Background(), reader, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) > maxPendingOutboxFetch {
		t.Fatalf("rows = %d, want hard cap %d", len(rows), maxPendingOutboxFetch)
	}
	foundLateBucket := false
	for _, row := range rows {
		foundLateBucket = foundLateBucket || row.ReceiverUIN == 15
	}
	if !foundLateBucket {
		t.Fatal("hot bucket 0 starved bucket 15")
	}
}

func TestFetchPendingAdvancesPastSameBucketPoisonPrefix(t *testing.T) {
	reader := &fakeOutboxBucketReader{direct: map[int8][]OutboxEntry{}, group: map[int8][]OutboxEntry{}}
	base := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 12; i++ {
		reader.direct[0] = append(reader.direct[0], OutboxEntry{CreatedAt: base.Add(time.Duration(i) * time.Second), MessageID: gocql.TimeUUID(), ReceiverUIN: int64(i + 1)})
	}
	cursor := &outboxFetchCursor{}
	for i := 0; i < outboxBucketCount; i++ { // rotate start back to bucket zero
		if _, err := cursor.fetch(context.Background(), reader, 16); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := cursor.fetch(context.Background(), reader, 16)
	if err != nil {
		t.Fatal(err)
	}
	foundLater := false
	for _, row := range rows {
		foundLater = foundLater || row.ReceiverUIN > 1
	}
	if !foundLater {
		t.Fatal("permanent earliest row starved later rows in the same bucket")
	}
}
