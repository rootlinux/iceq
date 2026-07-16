package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/gocql/gocql"
)

type IngestState string

const (
	IngestPending   IngestState = "pending"
	IngestStored    IngestState = "stored"
	IngestDelivered IngestState = "delivered"
)

type ClaimDisposition uint8

const (
	ClaimAcquired ClaimDisposition = iota + 1
	ClaimBusy
	ClaimCommitted
)

var (
	ErrIngestConflict  = errors.New("store: client id reused with a different envelope")
	ErrIngestBusy      = errors.New("store: ingest is owned by another worker")
	ErrIngestLeaseLost = errors.New("store: ingest lease was lost")
	ErrInvalidIngest   = errors.New("store: invalid durable ingest request")
)

type IngestKey struct {
	SenderUIN int64
	ClientID  string
}

type IngestRecord struct {
	Key              IngestKey
	ReceiverUIN      int64
	ConversationID   string
	Envelope         []byte
	EnvelopeHash     [sha256.Size]byte
	MessageID        gocql.UUID
	CreatedAt        time.Time
	ExpiresAt        time.Time
	State            IngestState
	OwnerToken       gocql.UUID
	LeaseUntil       time.Time
	StoredAt         time.Time
	DeliveredAt      time.Time
	ExpiresInSeconds int64
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

type DurableIngestStore struct {
	backend IngestBackend
	writer  DurableDirectWriter
	now     func() time.Time
	lease   time.Duration
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
	return &DurableIngestStore{backend: backend, writer: writer, now: now, lease: lease}
}

func durableTTL(seconds int64) time.Duration {
	if seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
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

func (s *DurableIngestStore) PersistDirect(ctx context.Context, req DurableDirectRequest) (DurableIngestResult, error) {
	if req.SenderUIN <= 0 || req.ReceiverUIN <= 0 || req.ClientID == "" || req.ConversationID == "" || len(req.Envelope) == 0 || len(req.Ciphertext) == 0 || req.ExpiresInSeconds < 0 {
		return DurableIngestResult{}, ErrInvalidIngest
	}
	now := s.now().UTC()
	hash := sha256.Sum256(req.Envelope)
	proposed := newIngestRecord(IngestKey{SenderUIN: req.SenderUIN, ClientID: req.ClientID}, req.Envelope, hash, now, s.lease)
	proposed.ReceiverUIN = req.ReceiverUIN
	proposed.ConversationID = req.ConversationID
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
