package store

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"time"

	"github.com/gocql/gocql"
)

type ScyllaIngestBackend struct {
	session *gocql.Session
}

func NewScyllaIngestBackend(session *gocql.Session) *ScyllaIngestBackend {
	if session == nil {
		panic("store.NewScyllaIngestBackend: nil session")
	}
	return &ScyllaIngestBackend{session: session}
}

func (b *ScyllaIngestBackend) Claim(ctx context.Context, proposed IngestRecord, now time.Time) (IngestRecord, ClaimDisposition, error) {
	const insert = `INSERT INTO iceq.message_ingest
	  (sender_uin, client_id, message_kind, receiver_uin, conversation_id, group_id, crypto_epoch, recipient_uins, envelope, envelope_hash, message_id, created_at, expires_at, state, owner_token, lease_until)
	  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) IF NOT EXISTS`
	const insertTTL = `INSERT INTO iceq.message_ingest
	  (sender_uin, client_id, message_kind, receiver_uin, conversation_id, group_id, crypto_epoch, recipient_uins, envelope, envelope_hash, message_id, created_at, expires_at, state, owner_token, lease_until)
	  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) IF NOT EXISTS USING TTL ?`
	args := []any{proposed.Key.SenderUIN, proposed.Key.ClientID, proposed.Kind, proposed.ReceiverUIN, proposed.ConversationID, nullableUUID(proposed.GroupID), proposed.CryptoEpoch, proposed.RecipientUINs, proposed.Envelope, proposed.EnvelopeHash[:], proposed.MessageID, proposed.CreatedAt, nullableTime(proposed.ExpiresAt), proposed.State, proposed.OwnerToken, proposed.LeaseUntil}
	query := insert
	if proposed.ExpiresInSeconds > 0 {
		query = insertTTL
		args = append(args, proposed.ExpiresInSeconds)
	}
	applied, err := b.session.Query(query, args...).WithContext(ctx).Consistency(gocql.Quorum).SerialConsistency(gocql.Serial).MapScanCAS(map[string]any{})
	if err != nil {
		return IngestRecord{}, 0, fmt.Errorf("store: claim ingest: %w", err)
	}
	if applied {
		// Write the erasure index so panic-wipe can find this ingest row
		// without ALLOW FILTERING -- for EVERY uin that appears in it: the
		// sender, plus the receiver (direct) or every recipient (group),
		// not just the sender. Without this, a wiped receiver/recipient's
		// UIN would never surface in a wipe scan and this row would persist
		// referencing them until its own TTL (see erasureIndexUINs). The
		// erasure index is idempotent (same PK, same values — Scylla
		// INSERT is an upsert).
		for _, uin := range erasureIndexUINs(proposed) {
			if err := b.session.Query(
				`INSERT INTO iceq.message_ingest_erasure_index (uin, sender_uin, client_id) VALUES (?, ?, ?)`,
				uin, proposed.Key.SenderUIN, proposed.Key.ClientID,
			).WithContext(ctx).Consistency(gocql.Quorum).Exec(); err != nil {
				return IngestRecord{}, 0, fmt.Errorf("store: write ingest erasure index: %w", err)
			}
		}
		return proposed, ClaimAcquired, nil
	}
	current, err := b.load(ctx, proposed.Key)
	if err != nil {
		return IngestRecord{}, 0, err
	}
	if current.State == IngestRecipientErased {
		// The receiver (direct) or every recipient (group) was permanently
		// erased by a panic wipe. This check MUST run before the mismatch
		// comparison below: the tombstone has its identifying fields cleared
		// (see scyllastore.go's deleteIngestReceipts), which would otherwise
		// look like a client_id collision with a different message and
		// incorrectly return ErrIngestConflict instead of a deterministic,
		// terminal result.
		return current, ClaimRecipientErased, nil
	}
	recipientsMatch := recipientSnapshotCompatible(current.RecipientUINs, proposed.RecipientUINs)
	if current.RecipientSetSanitized {
		// A panic wipe has removed one or more (but not all -- that case is
		// IngestRecipientErased above) recipients from this GROUP row's
		// recipient_uins. A retry's proposed list is the sender's stale
		// original and is EXPECTED to differ from the sanitized one now
		// stored; comparing them would incorrectly reject a legitimate retry
		// as a conflict. Every OTHER field is still compared below --
		// sanitization only ever touches recipient_uins, so any other
		// mismatch remains a genuine conflict (e.g. a client_id collision
		// with a different message).
		recipientsMatch = true
	}
	if current.EnvelopeHash != proposed.EnvelopeHash || current.Kind != proposed.Kind || current.ReceiverUIN != proposed.ReceiverUIN || current.ConversationID != proposed.ConversationID || current.GroupID != proposed.GroupID || current.CryptoEpoch != proposed.CryptoEpoch || !recipientsMatch {
		return IngestRecord{}, 0, ErrIngestConflict
	}
	if current.State == IngestStored || current.State == IngestDelivered {
		return current, ClaimCommitted, nil
	}
	if !current.ExpiresAt.IsZero() && !current.ExpiresAt.After(now) {
		return current, ClaimBusy, nil
	}
	if current.State != IngestPending || current.LeaseUntil.After(now) {
		return current, ClaimBusy, nil
	}

	const takeover = `UPDATE iceq.message_ingest SET owner_token = ?, lease_until = ?
	  WHERE sender_uin = ? AND client_id = ?
	  IF state = ? AND owner_token = ? AND lease_until = ?`
	const takeoverTTL = `UPDATE iceq.message_ingest USING TTL ? SET owner_token = ?, lease_until = ?
	  WHERE sender_uin = ? AND client_id = ?
	  IF state = ? AND owner_token = ? AND lease_until = ?`
	takeoverArgs := []any{proposed.OwnerToken, proposed.LeaseUntil, proposed.Key.SenderUIN, proposed.Key.ClientID, IngestPending, current.OwnerToken, current.LeaseUntil}
	takeoverQuery := takeover
	if remaining := remainingTTLSeconds(current.ExpiresAt, now); remaining > 0 {
		takeoverQuery = takeoverTTL
		takeoverArgs = append([]any{remaining}, takeoverArgs...)
	}
	applied, err = b.session.Query(takeoverQuery, takeoverArgs...).WithContext(ctx).Consistency(gocql.Quorum).SerialConsistency(gocql.Serial).MapScanCAS(map[string]any{})
	if err != nil {
		return IngestRecord{}, 0, fmt.Errorf("store: take over ingest: %w", err)
	}
	if !applied {
		latest, loadErr := b.load(ctx, proposed.Key)
		if loadErr != nil {
			return IngestRecord{}, 0, loadErr
		}
		return latest, ClaimBusy, nil
	}
	current.OwnerToken = proposed.OwnerToken
	current.LeaseUntil = proposed.LeaseUntil
	return current, ClaimAcquired, nil
}

func (b *ScyllaIngestBackend) MarkStored(ctx context.Context, key IngestKey, owner gocql.UUID, leaseUntil time.Time, now time.Time) (bool, error) {
	record, err := b.load(ctx, key)
	if err != nil {
		return false, err
	}
	if record.State != IngestPending || record.OwnerToken != owner || !record.LeaseUntil.Equal(leaseUntil) || !leaseUntil.After(now) || (!record.ExpiresAt.IsZero() && !record.ExpiresAt.After(now)) {
		return false, nil
	}
	const update = `UPDATE iceq.message_ingest SET state = ?, stored_at = ?
	  WHERE sender_uin = ? AND client_id = ? IF state = ? AND owner_token = ? AND lease_until = ?`
	const updateTTL = `UPDATE iceq.message_ingest USING TTL ? SET state = ?, stored_at = ?
	  WHERE sender_uin = ? AND client_id = ? IF state = ? AND owner_token = ? AND lease_until = ?`
	args := []any{IngestStored, now, key.SenderUIN, key.ClientID, IngestPending, owner, leaseUntil}
	query := update
	if remaining := remainingTTLSeconds(record.ExpiresAt, now); remaining > 0 {
		query = updateTTL
		args = append([]any{remaining}, args...)
	}
	applied, err := b.session.Query(query, args...).WithContext(ctx).Consistency(gocql.Quorum).SerialConsistency(gocql.Serial).MapScanCAS(map[string]any{})
	if err != nil {
		return false, fmt.Errorf("store: mark stored CAS: %w", err)
	}
	return applied, nil
}

func (b *ScyllaIngestBackend) MarkDelivered(ctx context.Context, key IngestKey, messageID gocql.UUID) (bool, error) {
	now := time.Now().UTC()
	record, err := b.load(ctx, key)
	if err != nil {
		return false, err
	}
	if record.MessageID != messageID || record.State == IngestDelivered {
		if record.MessageID != messageID || record.State != IngestDelivered {
			return false, nil
		}
		return true, b.deleteOutbox(ctx, record)
	}
	if !record.ExpiresAt.IsZero() && !record.ExpiresAt.After(now) {
		return false, nil
	}
	const update = `UPDATE iceq.message_ingest SET state = ?, delivered_at = ?
	  WHERE sender_uin = ? AND client_id = ? IF state = ? AND message_id = ?`
	const updateTTL = `UPDATE iceq.message_ingest USING TTL ? SET state = ?, delivered_at = ?
	  WHERE sender_uin = ? AND client_id = ? IF state = ? AND message_id = ?`
	args := []any{IngestDelivered, now, key.SenderUIN, key.ClientID, IngestStored, messageID}
	query := update
	if remaining := remainingTTLSeconds(record.ExpiresAt, now); remaining > 0 {
		query = updateTTL
		args = append([]any{remaining}, args...)
	}
	applied, err := b.session.Query(query, args...).WithContext(ctx).Consistency(gocql.Quorum).SerialConsistency(gocql.Serial).MapScanCAS(map[string]any{})
	if err != nil {
		return false, fmt.Errorf("store: mark delivered CAS: %w", err)
	}
	if !applied {
		return false, nil
	}
	if err := b.deleteOutbox(ctx, record); err != nil {
		return false, err
	}
	return true, nil
}

func (b *ScyllaIngestBackend) load(ctx context.Context, key IngestKey) (IngestRecord, error) {
	const query = `SELECT message_kind, receiver_uin, conversation_id, group_id, crypto_epoch, recipient_uins, envelope, envelope_hash, message_id, created_at, expires_at, state, owner_token, lease_until, stored_at, delivered_at, recipient_set_sanitized
	  FROM iceq.message_ingest WHERE sender_uin = ? AND client_id = ?`
	var record IngestRecord
	var hash []byte
	record.Key = key
	err := b.session.Query(query, key.SenderUIN, key.ClientID).WithContext(ctx).Consistency(gocql.Quorum).Scan(
		&record.Kind, &record.ReceiverUIN, &record.ConversationID, &record.GroupID, &record.CryptoEpoch, &record.RecipientUINs, &record.Envelope, &hash, &record.MessageID, &record.CreatedAt, &record.ExpiresAt, &record.State,
		&record.OwnerToken, &record.LeaseUntil, &record.StoredAt, &record.DeliveredAt, &record.RecipientSetSanitized,
	)
	if err != nil {
		return IngestRecord{}, fmt.Errorf("store: load ingest: %w", err)
	}
	if len(hash) != sha256.Size {
		return IngestRecord{}, fmt.Errorf("store: invalid persisted envelope hash length %d", len(hash))
	}
	copy(record.EnvelopeHash[:], hash)
	if !record.ExpiresAt.IsZero() {
		record.ExpiresInSeconds = int64(record.ExpiresAt.Sub(record.CreatedAt) / time.Second)
	}
	return record, nil
}

func (b *ScyllaIngestBackend) deleteOutbox(ctx context.Context, record IngestRecord) error {
	query := `DELETE FROM iceq.message_outbox WHERE bucket = ? AND created_at = ? AND message_id = ?`
	if record.Kind == IngestKindGroup {
		query = `DELETE FROM iceq.group_message_outbox WHERE bucket = ? AND created_at = ? AND message_id = ?`
	}
	if err := b.session.Query(query, outboxBucket(record.MessageID), record.CreatedAt, record.MessageID).WithContext(ctx).Consistency(gocql.Quorum).Exec(); err != nil {
		return fmt.Errorf("store: delete delivered outbox row: %w", err)
	}
	return nil
}

type ScyllaDurableDirectWriter struct {
	session *gocql.Session
}

func NewScyllaDurableDirectWriter(session *gocql.Session) *ScyllaDurableDirectWriter {
	if session == nil {
		panic("store.NewScyllaDurableDirectWriter: nil session")
	}
	return &ScyllaDurableDirectWriter{session: session}
}

func (w *ScyllaDurableDirectWriter) WriteDirect(ctx context.Context, write DurableDirectWrite) error {
	req := write.Message
	ttl := durableTTL(req.ExpiresInSeconds)
	expiresAt := write.ExpiresAt
	batch := w.session.NewBatch(gocql.LoggedBatch).WithContext(ctx)
	batch.SetConsistency(gocql.Quorum)
	if ttl > 0 {
		seconds := int(remainingTTLSeconds(expiresAt, time.Now().UTC()))
		if seconds <= 0 {
			return fmt.Errorf("store: durable write expired before commit")
		}
		batch.Query(`INSERT INTO iceq.messages
		  (conversation_id, created_at, id, sender_uin, receiver_uin, ciphertext, msg_type, status, expires_at)
		  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) USING TTL ?`, req.ConversationID, req.CreatedAt, req.ID, req.SenderUIN, req.ReceiverUIN, req.Ciphertext, req.MsgType, "", expiresAt, seconds)
		batch.Query(`INSERT INTO iceq.message_deletion_index (uin, conversation_id, created_at, id) VALUES (?, ?, ?, ?) USING TTL ?`, req.SenderUIN, req.ConversationID, req.CreatedAt, req.ID, seconds)
		if req.ReceiverUIN != req.SenderUIN {
			batch.Query(`INSERT INTO iceq.message_deletion_index (uin, conversation_id, created_at, id) VALUES (?, ?, ?, ?) USING TTL ?`, req.ReceiverUIN, req.ConversationID, req.CreatedAt, req.ID, seconds)
		}
		batch.Query(`INSERT INTO iceq.message_outbox
		  (bucket, created_at, message_id, receiver_uin, sender_uin, client_id, conversation_id, envelope, envelope_hash, state, expires_at)
		  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) USING TTL ?`, outboxBucket(req.ID), req.CreatedAt, req.ID, req.ReceiverUIN, req.SenderUIN, write.Key.ClientID, req.ConversationID, write.Envelope, write.EnvelopeHash[:], "pending", expiresAt, seconds)
		batch.Query(`INSERT INTO iceq.message_outbox_erasure_index (uin, bucket, created_at, message_id) VALUES (?, ?, ?, ?) USING TTL ?`, req.SenderUIN, outboxBucket(req.ID), req.CreatedAt, req.ID, seconds)
		if req.ReceiverUIN != req.SenderUIN {
			batch.Query(`INSERT INTO iceq.message_outbox_erasure_index (uin, bucket, created_at, message_id) VALUES (?, ?, ?, ?) USING TTL ?`, req.ReceiverUIN, outboxBucket(req.ID), req.CreatedAt, req.ID, seconds)
		}
	} else {
		batch.Query(`INSERT INTO iceq.messages
		  (conversation_id, created_at, id, sender_uin, receiver_uin, ciphertext, msg_type, status)
		  VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, req.ConversationID, req.CreatedAt, req.ID, req.SenderUIN, req.ReceiverUIN, req.Ciphertext, req.MsgType, "")
		batch.Query(`INSERT INTO iceq.message_deletion_index (uin, conversation_id, created_at, id) VALUES (?, ?, ?, ?)`, req.SenderUIN, req.ConversationID, req.CreatedAt, req.ID)
		if req.ReceiverUIN != req.SenderUIN {
			batch.Query(`INSERT INTO iceq.message_deletion_index (uin, conversation_id, created_at, id) VALUES (?, ?, ?, ?)`, req.ReceiverUIN, req.ConversationID, req.CreatedAt, req.ID)
		}
		batch.Query(`INSERT INTO iceq.message_outbox
		  (bucket, created_at, message_id, receiver_uin, sender_uin, client_id, conversation_id, envelope, envelope_hash, state)
		  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, outboxBucket(req.ID), req.CreatedAt, req.ID, req.ReceiverUIN, req.SenderUIN, write.Key.ClientID, req.ConversationID, write.Envelope, write.EnvelopeHash[:], "pending")
		batch.Query(`INSERT INTO iceq.message_outbox_erasure_index (uin, bucket, created_at, message_id) VALUES (?, ?, ?, ?)`, req.SenderUIN, outboxBucket(req.ID), req.CreatedAt, req.ID)
		if req.ReceiverUIN != req.SenderUIN {
			batch.Query(`INSERT INTO iceq.message_outbox_erasure_index (uin, bucket, created_at, message_id) VALUES (?, ?, ?, ?)`, req.ReceiverUIN, outboxBucket(req.ID), req.CreatedAt, req.ID)
		}
	}
	if err := w.session.ExecuteBatch(batch); err != nil {
		return fmt.Errorf("store: execute durable direct batch: %w", err)
	}
	return nil
}

func (w *ScyllaDurableDirectWriter) WriteGroup(ctx context.Context, write DurableGroupWrite) error {
	req := write.Message
	batch := w.session.NewBatch(gocql.LoggedBatch).WithContext(ctx)
	batch.SetConsistency(gocql.Quorum)

	ob := outboxBucket(req.ID)
	erasureInsert := func(uin int64, role string) {
		// Group outbox erasure index entries must be committed in the same
		// batch as the outbox row so the index is always consistent with
		// the data. Sender uses role='sender'; every recipient uses
		// role='recipient'.
		if req.ExpiresInSeconds > 0 {
			seconds := int(remainingTTLSeconds(write.ExpiresAt, time.Now().UTC()))
			if seconds <= 0 {
				return
			}
			batch.Query(`INSERT INTO iceq.group_message_outbox_erasure_index (uin, bucket, created_at, message_id, role) VALUES (?, ?, ?, ?, ?) USING TTL ?`,
				uin, ob, req.CreatedAt, req.ID, role, seconds)
		} else {
			batch.Query(`INSERT INTO iceq.group_message_outbox_erasure_index (uin, bucket, created_at, message_id, role) VALUES (?, ?, ?, ?, ?)`,
				uin, ob, req.CreatedAt, req.ID, role)
		}
	}

	if req.ExpiresInSeconds > 0 {
		seconds := int(remainingTTLSeconds(write.ExpiresAt, time.Now().UTC()))
		if seconds <= 0 {
			return fmt.Errorf("store: durable group write expired before commit")
		}
		batch.Query(`INSERT INTO iceq.group_messages (group_id, created_at, id, sender_uin, crypto_epoch, ciphertext, msg_type, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) USING TTL ?`, req.GroupID, req.CreatedAt, req.ID, req.SenderUIN, req.CryptoEpoch, req.Ciphertext, req.MsgType, write.ExpiresAt, seconds)
		batch.Query(`INSERT INTO iceq.group_message_deletion_index (uin, group_id, created_at, id) VALUES (?, ?, ?, ?) USING TTL ?`, req.SenderUIN, req.GroupID, req.CreatedAt, req.ID, seconds)
		batch.Query(`INSERT INTO iceq.group_message_outbox (bucket, created_at, message_id, group_id, sender_uin, client_id, crypto_epoch, recipient_uins, envelope, envelope_hash, state, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) USING TTL ?`, ob, req.CreatedAt, req.ID, req.GroupID, req.SenderUIN, write.Key.ClientID, req.CryptoEpoch, write.RecipientUINs, write.Envelope, write.EnvelopeHash[:], "pending", write.ExpiresAt, seconds)
	} else {
		batch.Query(`INSERT INTO iceq.group_messages (group_id, created_at, id, sender_uin, crypto_epoch, ciphertext, msg_type) VALUES (?, ?, ?, ?, ?, ?, ?)`, req.GroupID, req.CreatedAt, req.ID, req.SenderUIN, req.CryptoEpoch, req.Ciphertext, req.MsgType)
		batch.Query(`INSERT INTO iceq.group_message_deletion_index (uin, group_id, created_at, id) VALUES (?, ?, ?, ?)`, req.SenderUIN, req.GroupID, req.CreatedAt, req.ID)
		batch.Query(`INSERT INTO iceq.group_message_outbox (bucket, created_at, message_id, group_id, sender_uin, client_id, crypto_epoch, recipient_uins, envelope, envelope_hash, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, ob, req.CreatedAt, req.ID, req.GroupID, req.SenderUIN, write.Key.ClientID, req.CryptoEpoch, write.RecipientUINs, write.Envelope, write.EnvelopeHash[:], "pending")
	}

	// Index the sender.
	erasureInsert(req.SenderUIN, "sender")
	// Index every recipient so that a wiped recipient can be removed from
	// the recipient_uins snapshot without affecting other recipients.
	for _, recipientUIN := range write.RecipientUINs {
		if recipientUIN != req.SenderUIN {
			erasureInsert(recipientUIN, "recipient")
		}
	}

	if err := w.session.ExecuteBatch(batch); err != nil {
		return fmt.Errorf("store: execute durable group batch: %w", err)
	}
	return nil
}

// erasureIndexUINs returns every uin that must be able to discover this
// ingest row via message_ingest_erasure_index without ALLOW FILTERING: the
// sender always, plus the receiver (direct) or every recipient (group),
// each deduplicated against the sender's own uin.
func erasureIndexUINs(record IngestRecord) []int64 {
	uins := []int64{record.Key.SenderUIN}
	switch record.Kind {
	case IngestKindGroup:
		for _, uin := range record.RecipientUINs {
			if uin != record.Key.SenderUIN {
				uins = append(uins, uin)
			}
		}
	default:
		if record.ReceiverUIN != 0 && record.ReceiverUIN != record.Key.SenderUIN {
			uins = append(uins, record.ReceiverUIN)
		}
	}
	return uins
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

func nullableUUID(value gocql.UUID) any {
	if value == (gocql.UUID{}) {
		return nil
	}
	return value
}

const outboxBucketCount = 16

func outboxBucket(id gocql.UUID) int8 {
	return int8(id[0] & (outboxBucketCount - 1))
}

func remainingTTLSeconds(expiresAt, now time.Time) int64 {
	if expiresAt.IsZero() || !expiresAt.After(now) {
		return 0
	}
	return int64(math.Ceil(expiresAt.Sub(now).Seconds()))
}
