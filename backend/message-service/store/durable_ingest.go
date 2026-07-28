package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/gocql/gocql"
)

type IngestState string
type IngestKind string

const (
	IngestPending    IngestState = "pending"
	IngestStored     IngestState = "stored"
	IngestDelivered  IngestState = "delivered"
	IngestKindDirect IngestKind  = "direct"
	IngestKindGroup  IngestKind  = "group"

	// IngestRecipientErased marks an ingest row with no live recipient left
	// to deliver to, because a panic wipe erased the last (or only) one. The
	// row is never deleted outright in this case -- that would destroy the
	// SENDER's idempotency receipt, and a legitimate retry (the sender's
	// client has no way to know the recipient was wiped) would then look
	// like a brand new claim and re-process the message from scratch.
	// Instead the row is converted to a sanitized tombstone: state flips to
	// this value and every field that could identify the wiped recipient(s)
	// or the message content (receiver_uin, conversation_id, recipient_uins,
	// envelope, envelope_hash) is cleared -- see
	// auth-service/handlers/scyllastore.go's deleteIngestReceipts, which is
	// the only writer of this state. Claim() recognizes it and returns
	// ClaimRecipientErased deterministically instead of a generic conflict.
	//
	// Applies to two cases:
	//   - DIRECT: the single receiver was erased.
	//   - GROUP: every recipient has been erased (recipient_uins reduced to
	//     empty). A group row with SOME recipients still live instead stays
	//     in its normal state with recipient_uins reduced in place and
	//     RecipientSetSanitized set -- see recipientSnapshotCompatible.
	IngestRecipientErased IngestState = "recipient_erased"
)

type ClaimDisposition uint8

const (
	ClaimAcquired ClaimDisposition = iota + 1
	ClaimBusy
	ClaimCommitted
	// ClaimRecipientErased is returned when the stored row has been
	// converted to a recipient-erased tombstone (see IngestRecipientErased).
	// It is terminal: the caller must not write message content or
	// re-attempt delivery, since the recipient no longer exists.
	ClaimRecipientErased
)

var (
	ErrIngestConflict         = errors.New("store: client id reused with a different envelope")
	ErrIngestBusy             = errors.New("store: ingest is owned by another worker")
	ErrIngestLeaseLost        = errors.New("store: ingest lease was lost")
	ErrInvalidIngest          = errors.New("store: invalid durable ingest request")
	ErrIngestRecipientErased  = errors.New("store: recipient was erased by a panic wipe; message cannot be delivered")
)

type IngestKey struct {
	SenderUIN int64
	ClientID  string
}

type IngestRecord struct {
	Key              IngestKey
	Kind             IngestKind
	ReceiverUIN      int64
	ConversationID   string
	GroupID          gocql.UUID
	CryptoEpoch      int64
	RecipientUINs    []int64
	Envelope         []byte
	EnvelopeHash     [sha256.Size]byte
	MessageID        gocql.UUID
	CreatedAt        time.Time
	ExpiresAt        time.Time
	State                 IngestState
	OwnerToken            gocql.UUID
	LeaseUntil            time.Time
	StoredAt              time.Time
	DeliveredAt           time.Time
	ExpiresInSeconds      int64
	// RecipientSetSanitized is true once a panic wipe has removed one or
	// more (but not necessarily all) recipients from RecipientUINs on a
	// GROUP row. It never identifies who was removed. When set, Claim()
	// stops comparing RecipientUINs against what a retry proposes -- a
	// retry's proposed list is always the sender's stale original and is
	// expected to differ from the sanitized one. See recipientSnapshotCompatible.
	RecipientSetSanitized bool
}

type DurableDirectRequest struct {
	SenderUIN        int64
	ClientID         string
	ReceiverUIN      int64
	ConversationID   string
	Envelope         []byte
	Ciphertext       []byte
	MsgType          string
	ExpiresInSeconds int64
}

type DurableDirectWrite struct {
	Key          IngestKey
	Envelope     []byte
	EnvelopeHash [sha256.Size]byte
	ExpiresAt    time.Time
	Message      SaveRequest
}

type DurableGroupRequest struct {
	SenderUIN        int64
	ClientID         string
	GroupID          gocql.UUID
	CryptoEpoch      int64
	RecipientUINs    []int64
	Envelope         []byte
	Ciphertext       []byte
	MsgType          string
	ExpiresInSeconds int64
}

type DurableGroupWrite struct {
	Key           IngestKey
	Envelope      []byte
	EnvelopeHash  [sha256.Size]byte
	ExpiresAt     time.Time
	RecipientUINs []int64
	Message       SaveGroupRequest
}

type DurableIngestResult struct {
	MessageID gocql.UUID
	CreatedAt time.Time
	State     IngestState
	Committed bool
}

type IngestBackend interface {
	Claim(context.Context, IngestRecord, time.Time) (IngestRecord, ClaimDisposition, error)
	MarkStored(context.Context, IngestKey, gocql.UUID, time.Time, time.Time) (bool, error)
	MarkDelivered(context.Context, IngestKey, gocql.UUID) (bool, error)
}

type DurableDirectWriter interface {
	WriteDirect(context.Context, DurableDirectWrite) error
}

type DurableGroupWriter interface {
	WriteGroup(context.Context, DurableGroupWrite) error
}

type DurableIngestStore struct {
	backend     IngestBackend
	writer      DurableDirectWriter
	groupWriter DurableGroupWriter
	now         func() time.Time
	lease       time.Duration
}

func NewDurableIngestStoreWithGroup(backend IngestBackend, directWriter DurableDirectWriter, groupWriter DurableGroupWriter, now func() time.Time, lease time.Duration) *DurableIngestStore {
	if groupWriter == nil {
		panic("store.NewDurableIngestStoreWithGroup: nil group writer")
	}
	store := NewDurableIngestStore(backend, directWriter, now, lease)
	store.groupWriter = groupWriter
	return store
}

func NewDurableIngestStore(backend IngestBackend, writer DurableDirectWriter, now func() time.Time, lease time.Duration) *DurableIngestStore {
	if backend == nil || writer == nil {
		panic("store.NewDurableIngestStore: nil dependency")
	}
	if now == nil {
		now = time.Now
	}
	if lease <= 0 {
		panic("store.NewDurableIngestStore: lease must be positive")
	}
	store := &DurableIngestStore{backend: backend, writer: writer, now: now, lease: lease}
	if groupWriter, ok := writer.(DurableGroupWriter); ok {
		store.groupWriter = groupWriter
	}
	return store
}

// durableTTL shares the same bounded-retention policy as effectiveMessageTTL
// (messagestore.go): an unset/zero request gets defaultMessageTTL, and any
// request above maxMessageTTL is clamped down. There is no "keep forever"
// path — a modified client cannot request indefinite retention.
func durableTTL(seconds int64) time.Duration {
	return effectiveMessageTTL(seconds)
}

func newIngestRecord(key IngestKey, envelope []byte, hash [sha256.Size]byte, now time.Time, lease time.Duration) IngestRecord {
	created := now.UTC().Truncate(time.Millisecond)
	return IngestRecord{
		Key:          key,
		Envelope:     append([]byte(nil), envelope...),
		EnvelopeHash: hash,
		MessageID:    deterministicMessageID(key),
		CreatedAt:    created,
		State:        IngestPending,
		OwnerToken:   gocql.TimeUUID(),
		LeaseUntil:   created.Add(lease),
	}
}

func deterministicMessageID(key IngestKey) gocql.UUID {
	digest := sha256.Sum256([]byte(fmt.Sprintf("iceq:durable-message:v1:%d:%s", key.SenderUIN, key.ClientID)))
	digest[6] = (digest[6] & 0x0f) | 0x50
	digest[8] = (digest[8] & 0x3f) | 0x80
	id, err := gocql.UUIDFromBytes(digest[:16])
	if err != nil {
		panic("store: deterministic UUID construction failed")
	}
	return id
}

// recipientSnapshotCompatible reports whether the stored recipient snapshot
// exactly matches what's being proposed. Kept as an exact, order-sensitive
// comparison deliberately: see
// TestDurableGroupRecipientSnapshotIsImmutableAcrossReplay, which proves a
// client cannot use a client_id replay with an expanded recipient list to
// smuggle a new recipient into an already-claimed group message. A looser
// (e.g. subset-tolerant) comparison cannot distinguish that attack from
// legitimate wipe-driven shrinkage -- both produce a "stored list is a
// subset of proposed" shape.
//
// This is why panic wipe does NOT rely on this comparison tolerating a
// shrunk list: instead, once a wipe has reduced recipient_uins,
// IngestRecord.RecipientSetSanitized is set on the row and Claim() skips
// calling this function entirely for that row (see durable_ingest_scylla.go).
// The exact-equality invariant this function enforces therefore stays intact
// for every row that has NOT been sanitized -- a replay attack still cannot
// smuggle in a new recipient by proposing an expanded list, because an
// unsanitized row always requires an exact match.
func recipientSnapshotCompatible(current, proposed []int64) bool {
	return slices.Equal(current, proposed)
}

func (s *DurableIngestStore) PersistDirect(ctx context.Context, req DurableDirectRequest) (DurableIngestResult, error) {
	if req.SenderUIN <= 0 || req.ReceiverUIN <= 0 || req.ClientID == "" || req.ConversationID == "" || len(req.Envelope) == 0 || len(req.Ciphertext) == 0 || req.ExpiresInSeconds < 0 {
		return DurableIngestResult{}, ErrInvalidIngest
	}
	now := s.now().UTC()
	hash := sha256.Sum256(req.Envelope)
	proposed := newIngestRecord(IngestKey{SenderUIN: req.SenderUIN, ClientID: req.ClientID}, req.Envelope, hash, now, s.lease)
	proposed.ReceiverUIN = req.ReceiverUIN
	proposed.ConversationID = req.ConversationID
	proposed.Kind = IngestKindDirect
	proposed.ExpiresInSeconds = req.ExpiresInSeconds
	if ttl := durableTTL(req.ExpiresInSeconds); ttl > 0 {
		proposed.ExpiresAt = proposed.CreatedAt.Add(ttl)
		if proposed.LeaseUntil.After(proposed.ExpiresAt) {
			proposed.LeaseUntil = proposed.ExpiresAt
		}
	}
	record, disposition, err := s.backend.Claim(ctx, proposed, now)
	if err != nil {
		return DurableIngestResult{}, err
	}
	result := DurableIngestResult{MessageID: record.MessageID, CreatedAt: record.CreatedAt, State: record.State}
	switch disposition {
	case ClaimCommitted:
		result.Committed = true
		return result, nil
	case ClaimBusy:
		return result, ErrIngestBusy
	case ClaimRecipientErased:
		// The receiver was permanently erased by a panic wipe after this
		// claim was accepted (possibly before this exact retry). This is
		// terminal and deterministic: never write message content, never
		// re-attempt delivery -- the recipient no longer exists.
		result.State = IngestRecipientErased
		return result, ErrIngestRecipientErased
	case ClaimAcquired:
	default:
		return DurableIngestResult{}, fmt.Errorf("store: unknown claim disposition %d", disposition)
	}

	write := DurableDirectWrite{
		Key:          record.Key,
		Envelope:     append([]byte(nil), record.Envelope...),
		EnvelopeHash: record.EnvelopeHash,
		ExpiresAt:    record.ExpiresAt,
		Message: SaveRequest{
			ConversationID:   req.ConversationID,
			ID:               record.MessageID,
			SenderUIN:        req.SenderUIN,
			ReceiverUIN:      req.ReceiverUIN,
			Ciphertext:       append([]byte(nil), req.Ciphertext...),
			MsgType:          req.MsgType,
			CreatedAt:        record.CreatedAt,
			ExpiresInSeconds: req.ExpiresInSeconds,
		},
	}
	if err := s.writer.WriteDirect(ctx, write); err != nil {
		return result, fmt.Errorf("store: durable message/outbox write: %w", err)
	}
	applied, err := s.backend.MarkStored(ctx, record.Key, record.OwnerToken, record.LeaseUntil, s.now().UTC())
	if err != nil {
		return result, fmt.Errorf("store: mark ingest stored: %w", err)
	}
	if !applied {
		return result, ErrIngestLeaseLost
	}
	result.State = IngestStored
	result.Committed = true
	return result, nil
}

func (s *DurableIngestStore) PersistGroup(ctx context.Context, req DurableGroupRequest) (DurableIngestResult, error) {
	if s.groupWriter == nil {
		return DurableIngestResult{}, errors.New("store: durable group writer is not configured")
	}
	if req.SenderUIN <= 0 || req.ClientID == "" || req.GroupID == (gocql.UUID{}) || len(req.RecipientUINs) == 0 || len(req.Envelope) == 0 || len(req.Ciphertext) == 0 || req.MsgType == "" || req.CryptoEpoch <= 0 || req.ExpiresInSeconds < 0 {
		return DurableIngestResult{}, ErrInvalidIngest
	}
	for _, uin := range req.RecipientUINs {
		if uin <= 0 {
			return DurableIngestResult{}, ErrInvalidIngest
		}
	}
	now := s.now().UTC()
	hash := sha256.Sum256(req.Envelope)
	proposed := newIngestRecord(IngestKey{SenderUIN: req.SenderUIN, ClientID: req.ClientID}, req.Envelope, hash, now, s.lease)
	proposed.Kind = IngestKindGroup
	proposed.GroupID = req.GroupID
	proposed.CryptoEpoch = req.CryptoEpoch
	proposed.RecipientUINs = append([]int64(nil), req.RecipientUINs...)
	proposed.ExpiresInSeconds = req.ExpiresInSeconds
	if ttl := durableTTL(req.ExpiresInSeconds); ttl > 0 {
		proposed.ExpiresAt = proposed.CreatedAt.Add(ttl)
		if proposed.LeaseUntil.After(proposed.ExpiresAt) {
			proposed.LeaseUntil = proposed.ExpiresAt
		}
	}
	record, disposition, err := s.backend.Claim(ctx, proposed, now)
	if err != nil {
		return DurableIngestResult{}, err
	}
	result := DurableIngestResult{MessageID: record.MessageID, CreatedAt: record.CreatedAt, State: record.State}
	if disposition == ClaimCommitted {
		result.Committed = true
		return result, nil
	}
	if disposition == ClaimBusy {
		return result, ErrIngestBusy
	}
	if disposition == ClaimRecipientErased {
		// Every recipient in this group send has been erased by a panic
		// wipe (recipient_uins reduced to empty). Terminal and
		// deterministic, same contract as the direct case: never write
		// message content, never re-attempt delivery.
		result.State = IngestRecipientErased
		return result, ErrIngestRecipientErased
	}
	if disposition != ClaimAcquired {
		return DurableIngestResult{}, fmt.Errorf("store: unknown claim disposition %d", disposition)
	}
	write := DurableGroupWrite{
		Key: record.Key, Envelope: append([]byte(nil), record.Envelope...), EnvelopeHash: record.EnvelopeHash, ExpiresAt: record.ExpiresAt, RecipientUINs: append([]int64(nil), record.RecipientUINs...),
		Message: SaveGroupRequest{GroupID: record.GroupID, ID: record.MessageID, SenderUIN: req.SenderUIN, CryptoEpoch: record.CryptoEpoch, Ciphertext: append([]byte(nil), req.Ciphertext...), MsgType: req.MsgType, CreatedAt: record.CreatedAt, ExpiresInSeconds: req.ExpiresInSeconds},
	}
	if err := s.groupWriter.WriteGroup(ctx, write); err != nil {
		return result, fmt.Errorf("store: durable group/outbox write: %w", err)
	}
	applied, err := s.backend.MarkStored(ctx, record.Key, record.OwnerToken, record.LeaseUntil, s.now().UTC())
	if err != nil {
		return result, fmt.Errorf("store: mark group ingest stored: %w", err)
	}
	if !applied {
		return result, ErrIngestLeaseLost
	}
	result.State, result.Committed = IngestStored, true
	return result, nil
}

func (s *DurableIngestStore) MarkDelivered(ctx context.Context, key IngestKey, messageID gocql.UUID) error {
	applied, err := s.backend.MarkDelivered(ctx, key, messageID)
	if err != nil {
		return err
	}
	if !applied {
		return ErrIngestConflict
	}
	return nil
}
