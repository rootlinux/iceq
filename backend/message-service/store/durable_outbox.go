package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/gocql/gocql"
)

const maxPendingOutboxFetch = 100

var ErrInvalidOutboxLimit = errors.New("store: outbox limit must be positive")

type OutboxEntry struct {
	Kind           IngestKind
	Key            IngestKey
	MessageID      gocql.UUID
	CreatedAt      time.Time
	ExpiresAt      time.Time
	ReceiverUIN    int64
	ConversationID string
	GroupID        gocql.UUID
	CryptoEpoch    int64
	Envelope       []byte
	EnvelopeHash   [sha256.Size]byte
}

type outboxBucketReader interface {
	fetchDirectBucket(context.Context, int8, int) ([]OutboxEntry, error)
	fetchGroupBucket(context.Context, int8, int) ([]OutboxEntry, error)
}

func fetchPendingOutbox(ctx context.Context, reader outboxBucketReader, limit int) ([]OutboxEntry, error) {
	if limit <= 0 {
		return nil, ErrInvalidOutboxLimit
	}
	if limit > maxPendingOutboxFetch {
		limit = maxPendingOutboxFetch
	}
	result := make([]OutboxEntry, 0, limit)
	for rawBucket := 0; rawBucket < outboxBucketCount && len(result) < limit; rawBucket++ {
		bucket := int8(rawBucket)
		fetchers := []func(context.Context, int8, int) ([]OutboxEntry, error){reader.fetchDirectBucket, reader.fetchGroupBucket}
		if rawBucket%2 == 1 {
			fetchers[0], fetchers[1] = fetchers[1], fetchers[0]
		}
		for _, fetch := range fetchers {
			rows, err := fetch(ctx, bucket, limit-len(result))
			if err != nil {
				return nil, err
			}
			result = append(result, rows...)
			if len(result) == limit {
				break
			}
		}
	}
	return result, nil
}

// FetchPending returns a bounded recovery batch across the fixed outbox
// buckets. Rows remain until the matching durable ingest receipt is marked
// delivered, so a worker crash only causes an idempotent replay.
func (w *ScyllaDurableDirectWriter) FetchPending(ctx context.Context, limit int) ([]OutboxEntry, error) {
	return fetchPendingOutbox(ctx, w, limit)
}

func (w *ScyllaDurableDirectWriter) fetchDirectBucket(ctx context.Context, bucket int8, limit int) ([]OutboxEntry, error) {
	const query = `SELECT created_at, message_id, receiver_uin, sender_uin, client_id, conversation_id, envelope, envelope_hash, expires_at
	  FROM iceq.message_outbox WHERE bucket = ? LIMIT ?`
	iter := w.session.Query(query, bucket, limit).WithContext(ctx).Consistency(gocql.Quorum).Iter()
	rows := make([]OutboxEntry, 0, limit)
	for {
		row := OutboxEntry{Kind: IngestKindDirect}
		var hash []byte
		if !iter.Scan(&row.CreatedAt, &row.MessageID, &row.ReceiverUIN, &row.Key.SenderUIN, &row.Key.ClientID, &row.ConversationID, &row.Envelope, &hash, &row.ExpiresAt) {
			break
		}
		if err := finishOutboxRow(&row, hash); err != nil {
			_ = iter.Close()
			return nil, err
		}
		if row.ExpiresAt.IsZero() || row.ExpiresAt.After(time.Now()) {
			rows = append(rows, row)
		}
	}
	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("store: direct outbox iteration: %w", err)
	}
	return rows, nil
}

func (w *ScyllaDurableDirectWriter) fetchGroupBucket(ctx context.Context, bucket int8, limit int) ([]OutboxEntry, error) {
	const query = `SELECT created_at, message_id, group_id, sender_uin, client_id, crypto_epoch, envelope, envelope_hash, expires_at
	  FROM iceq.group_message_outbox WHERE bucket = ? LIMIT ?`
	iter := w.session.Query(query, bucket, limit).WithContext(ctx).Consistency(gocql.Quorum).Iter()
	rows := make([]OutboxEntry, 0, limit)
	for {
		row := OutboxEntry{Kind: IngestKindGroup}
		var hash []byte
		if !iter.Scan(&row.CreatedAt, &row.MessageID, &row.GroupID, &row.Key.SenderUIN, &row.Key.ClientID, &row.CryptoEpoch, &row.Envelope, &hash, &row.ExpiresAt) {
			break
		}
		if err := finishOutboxRow(&row, hash); err != nil {
			_ = iter.Close()
			return nil, err
		}
		if row.ExpiresAt.IsZero() || row.ExpiresAt.After(time.Now()) {
			rows = append(rows, row)
		}
	}
	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("store: group outbox iteration: %w", err)
	}
	return rows, nil
}

func finishOutboxRow(row *OutboxEntry, hash []byte) error {
	if len(hash) != sha256.Size {
		return fmt.Errorf("store: invalid outbox envelope hash length %d", len(hash))
	}
	copy(row.EnvelopeHash[:], hash)
	return nil
}
