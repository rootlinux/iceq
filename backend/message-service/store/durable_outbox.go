package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
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
	RecipientUINs  []int64
	Envelope       []byte
	EnvelopeHash   [sha256.Size]byte
}

type outboxBucketReader interface {
	fetchDirectBucket(context.Context, int8, outboxPageCursor, int) ([]OutboxEntry, error)
	fetchGroupBucket(context.Context, int8, outboxPageCursor, int) ([]OutboxEntry, error)
}

type outboxPageCursor struct {
	CreatedAt time.Time
	MessageID gocql.UUID
	Valid     bool
}

type outboxFetchCursor struct {
	next  atomic.Uint32
	mu    sync.Mutex
	pages [outboxBucketCount * 2]outboxPageCursor
}

var pendingOutboxCursor outboxFetchCursor

func (c *outboxFetchCursor) fetch(ctx context.Context, reader outboxBucketReader, limit int) ([]OutboxEntry, error) {
	if limit <= 0 {
		return nil, ErrInvalidOutboxLimit
	}
	if limit > maxPendingOutboxFetch {
		limit = maxPendingOutboxFetch
	}
	start := int(c.next.Add(1)-1) % outboxBucketCount
	perBucket := (limit + outboxBucketCount - 1) / outboxBucketCount
	result := make([]OutboxEntry, 0, limit)
	for offset := 0; offset < outboxBucketCount && len(result) < limit; offset++ {
		rawBucket := (start + offset) % outboxBucketCount
		bucket := int8(rawBucket)
		bucketRemaining := perBucket
		fetchers := []func(context.Context, int8, outboxPageCursor, int) ([]OutboxEntry, error){reader.fetchDirectBucket, reader.fetchGroupBucket}
		kinds := []int{0, 1}
		if rawBucket%2 == 1 {
			fetchers[0], fetchers[1] = fetchers[1], fetchers[0]
			kinds[0], kinds[1] = kinds[1], kinds[0]
		}
		for index, fetch := range fetchers {
			fetchLimit := min(bucketRemaining, limit-len(result))
			if fetchLimit == 0 {
				break
			}
			pageIndex := rawBucket*2 + kinds[index]
			c.mu.Lock()
			after := c.pages[pageIndex]
			c.mu.Unlock()
			rows, err := fetch(ctx, bucket, after, fetchLimit)
			if err != nil {
				return nil, err
			}
			if len(rows) > fetchLimit {
				rows = rows[:fetchLimit]
			}
			result = append(result, rows...)
			c.mu.Lock()
			if len(rows) == 0 {
				c.pages[pageIndex] = outboxPageCursor{}
			} else {
				last := rows[len(rows)-1]
				c.pages[pageIndex] = outboxPageCursor{CreatedAt: last.CreatedAt, MessageID: last.MessageID, Valid: true}
			}
			c.mu.Unlock()
			bucketRemaining -= len(rows)
		}
	}
	return result, nil
}

func fetchPendingOutbox(ctx context.Context, reader outboxBucketReader, limit int) ([]OutboxEntry, error) {
	return pendingOutboxCursor.fetch(ctx, reader, limit)
}

// FetchPending returns a bounded recovery batch across the fixed outbox
// buckets. Rows remain until the matching durable ingest receipt is marked
// delivered, so a worker crash only causes an idempotent replay.
func (w *ScyllaDurableDirectWriter) FetchPending(ctx context.Context, limit int) ([]OutboxEntry, error) {
	return fetchPendingOutbox(ctx, w, limit)
}

func (w *ScyllaDurableDirectWriter) fetchDirectBucket(ctx context.Context, bucket int8, after outboxPageCursor, limit int) ([]OutboxEntry, error) {
	query := `SELECT created_at, message_id, receiver_uin, sender_uin, client_id, conversation_id, envelope, envelope_hash, expires_at FROM iceq.message_outbox WHERE bucket = ? LIMIT ?`
	args := []any{bucket, limit}
	if after.Valid {
		query = `SELECT created_at, message_id, receiver_uin, sender_uin, client_id, conversation_id, envelope, envelope_hash, expires_at FROM iceq.message_outbox WHERE bucket = ? AND (created_at, message_id) > (?, ?) LIMIT ?`
		args = []any{bucket, after.CreatedAt, after.MessageID, limit}
	}
	iter := w.session.Query(query, args...).WithContext(ctx).Consistency(gocql.Quorum).Iter()
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

func (w *ScyllaDurableDirectWriter) fetchGroupBucket(ctx context.Context, bucket int8, after outboxPageCursor, limit int) ([]OutboxEntry, error) {
	query := `SELECT created_at, message_id, group_id, sender_uin, client_id, crypto_epoch, recipient_uins, envelope, envelope_hash, expires_at FROM iceq.group_message_outbox WHERE bucket = ? LIMIT ?`
	args := []any{bucket, limit}
	if after.Valid {
		query = `SELECT created_at, message_id, group_id, sender_uin, client_id, crypto_epoch, recipient_uins, envelope, envelope_hash, expires_at FROM iceq.group_message_outbox WHERE bucket = ? AND (created_at, message_id) > (?, ?) LIMIT ?`
		args = []any{bucket, after.CreatedAt, after.MessageID, limit}
	}
	iter := w.session.Query(query, args...).WithContext(ctx).Consistency(gocql.Quorum).Iter()
	rows := make([]OutboxEntry, 0, limit)
	for {
		row := OutboxEntry{Kind: IngestKindGroup}
		var hash []byte
		if !iter.Scan(&row.CreatedAt, &row.MessageID, &row.GroupID, &row.Key.SenderUIN, &row.Key.ClientID, &row.CryptoEpoch, &row.RecipientUINs, &row.Envelope, &hash, &row.ExpiresAt) {
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
