package handlers

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/gocql/gocql"
)

// ScyllaMessageStore removes every durable Scylla footprint associated with
// the wiped user. The chat tables are partitioned by conversation/group rather
// than sender, so the store uses deletion/erasure indexes to discover full
// primary keys and then deletes those exact rows.
//
// Tables cleaned:
//   - messages + message_deletion_index         (direct ciphertext + index)
//   - group_messages + group_message_deletion_index (group ciphertext + index)
//   - message_ingest + message_ingest_erasure_index  (durable idempotency receipts)
//   - message_outbox + message_outbox_erasure_index  (direct outbox entries)
//   - group_message_outbox + group_message_outbox_erasure_index (group outbox entries)
//
// Every table is cleaned via its erasure or deletion index — no
// full-table scans, no unbounded scans.
type ScyllaMessageStore struct {
	session *gocql.Session
}

func NewScyllaMessageStore(session *gocql.Session) (*ScyllaMessageStore, error) {
	if session == nil {
		return nil, fmt.Errorf("panicwipe: scylla session is nil")
	}
	return &ScyllaMessageStore{session: session}, nil
}

// DeleteUserMessages removes every direct-message footprint for the given UIN:
// messages ciphertext rows, message_deletion_index entries (both this user's
// own and the counterpart's now-orphaned mirror), message_ingest receipts,
// message_outbox entries, and all associated erasure indexes.
func (s *ScyllaMessageStore) DeleteUserMessages(ctx context.Context, uin int64) error {
	// 1. Direct ciphertext rows via deletion index. message_deletion_index
	// holds one pointer row per DM participant (see messagestore.go's
	// SaveMessage and durable_ingest_scylla.go's WriteDirect), both pointing
	// at the SAME messages row. Deleting that shared row via this user's own
	// index entry would otherwise orphan the counterpart's mirror entry: it
	// would keep pointing at a row that no longer exists, and its
	// conversation_id clustering key embeds this wiped UIN as plaintext on
	// the counterpart's own partition. The counterpart UIN is derived from
	// conversation_id -- already in hand from this same scan, no extra read
	// -- and its mirror row is captured and deleted alongside the shared
	// row, before it can be orphaned. A plain unconditional DELETE (not a
	// CAS) is sufficient here: unlike the group_message_outbox/message_ingest
	// recipient lists, no two writers ever race to mutate the SAME row's
	// contents, so a concurrent wipe of both DM participants just makes each
	// DELETE redundant with the other's, never conflicting.
	iter := s.session.Query(`SELECT conversation_id, created_at, id FROM message_deletion_index WHERE uin = ?`, uin).WithContext(ctx).Iter()
	var conversationID string
	var createdAt time.Time
	var id gocql.UUID
	for iter.Scan(&conversationID, &createdAt, &id) {
		if err := s.session.Query(`DELETE FROM messages WHERE conversation_id = ? AND created_at = ? AND id = ?`, conversationID, createdAt, id).WithContext(ctx).Exec(); err != nil {
			_ = iter.Close()
			return fmt.Errorf("delete sent message: %w", err)
		}
		if counterpartUIN, ok := dmCounterpartUIN(conversationID, uin); ok {
			if err := s.session.Query(`DELETE FROM message_deletion_index WHERE uin = ? AND conversation_id = ? AND created_at = ? AND id = ?`, counterpartUIN, conversationID, createdAt, id).WithContext(ctx).Exec(); err != nil {
				_ = iter.Close()
				return fmt.Errorf("delete counterpart deletion index: %w", err)
			}
		}
	}
	if err := iter.Close(); err != nil {
		return fmt.Errorf("scan message deletion index: %w", err)
	}

	// Delete this user's own deletion index rows.
	if err := s.session.Query(`DELETE FROM message_deletion_index WHERE uin = ?`, uin).WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("delete message deletion index: %w", err)
	}

	// 2. Durable ingest receipts via erasure index.
	if err := s.deleteIngestReceipts(ctx, uin); err != nil {
		return err
	}

	// 3. Direct outbox entries via erasure index.
	if err := s.deleteDirectOutboxEntries(ctx, uin); err != nil {
		return err
	}

	return nil
}

// dmCounterpartUIN parses a "dm:<min>:<max>" conversation_id and returns the
// participant that is NOT knownUIN. Mirrors message-service/handlers'
// parseDMMembers validation exactly (canonical form, min < max, both
// positive) -- auth-service and message-service are independently
// deployable and do not share Go types across the module boundary, only the
// wire format both sides must agree on. ok is false when the format is
// invalid or knownUIN is not one of the two parsed participants (e.g. a
// group conversation_id, or a row that doesn't belong to this uin).
func dmCounterpartUIN(conversationID string, knownUIN int64) (int64, bool) {
	parts := strings.Split(conversationID, ":")
	if len(parts) != 3 || parts[0] != "dm" {
		return 0, false
	}
	a, errA := strconv.ParseInt(parts[1], 10, 64)
	b, errB := strconv.ParseInt(parts[2], 10, 64)
	if errA != nil || errB != nil || a <= 0 || b <= 0 || a >= b {
		return 0, false
	}
	switch knownUIN {
	case a:
		return b, true
	case b:
		return a, true
	default:
		return 0, false
	}
}

// DeleteUserGroupMessages removes every group-message footprint for the given UIN:
// group_messages ciphertext rows, group_message_deletion_index entries,
// group_message_outbox entries, and all associated erasure indexes.
//
// Group ciphertext is shared across members. When one member triggers a panic
// wipe, only the deletion index for that member is removed. The underlying
// group_messages row is NOT deleted if other members still reference it through
// their own indexes. The ciphertext is unreadable without the wiped member's
// keys, which are destroyed by the PostgreSQL portion of the wipe.
func (s *ScyllaMessageStore) DeleteUserGroupMessages(ctx context.Context, uin int64) error {
	// 1. Group ciphertext rows via deletion index.
	iter := s.session.Query(`SELECT group_id, created_at, id FROM group_message_deletion_index WHERE uin = ?`, uin).WithContext(ctx).Iter()
	var groupID gocql.UUID
	var createdAt time.Time
	var id gocql.UUID
	for iter.Scan(&groupID, &createdAt, &id) {
		// Delete the specific group message only if this user was the sender.
		// For messages sent by other members, the ciphertext is shared and
		// cannot be safely deleted for one member without affecting others.
		// The deletion index entry for this UIN is removed below regardless.
		if err := s.session.Query(`DELETE FROM group_messages WHERE group_id = ? AND created_at = ? AND id = ? IF sender_uin = ?`, groupID, createdAt, id, uin).WithContext(ctx).Exec(); err != nil {
			_ = iter.Close()
			return fmt.Errorf("delete group message: %w", err)
		}
	}
	if err := iter.Close(); err != nil {
		return fmt.Errorf("scan group message deletion index: %w", err)
	}

	// Delete the deletion index itself.
	if err := s.session.Query(`DELETE FROM group_message_deletion_index WHERE uin = ?`, uin).WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("delete group message deletion index: %w", err)
	}

	// 2. Group outbox entries via erasure index.
	if err := s.deleteGroupOutboxEntries(ctx, uin); err != nil {
		return err
	}

	return nil
}

// ingestRecipientErasedState mirrors message-service/store's
// IngestRecipientErased state value. auth-service and message-service are
// independently deployable and deliberately do not share Go types across
// the module boundary -- the message_ingest schema (this value included) is
// their contract instead. Keep in sync with
// message-service/store/durable_ingest.go's IngestRecipientErased.
const ingestRecipientErasedState = "recipient_erased"

// maxRecipientSanitizeCASAttempts bounds the read-compute-CAS retry loop
// used to remove a wiped uin from a group recipient list shared with other
// live recipients (message_ingest.recipient_uins,
// group_message_outbox.recipient_uins). Two wipe workers can legitimately
// process different recipients of the same group message concurrently (see
// wipejob.go's FOR UPDATE SKIP LOCKED), so a single compare-and-set attempt
// conditioned on a stale read can lose the race to a concurrent writer. On
// loss the caller re-reads and retries. Exhausting this bound returns an
// error instead of reporting false success, so the wipe job is retried
// later by the durable wipe-job worker rather than silently leaving the uin
// in the list.
const maxRecipientSanitizeCASAttempts = 8

// deleteIngestReceipts removes or sanitizes durable ingest idempotency
// receipts for the given UIN. The message_ingest table is partitioned by
// (sender_uin, client_id); we use the erasure index to discover the
// complete primary keys.
//
// The wiped uin can appear in a receipt in one of three roles, and each is
// handled differently by sanitizeIngestReceipt:
//   - sender: the whole receipt belongs to the wiped user and nobody will
//     ever retry its client_id again. Delete it outright.
//   - direct receiver: the receipt still belongs to a live sender. Convert
//     it to a sanitized terminal tombstone instead of deleting it, so a
//     sender retry gets a deterministic terminal result (see
//     message-service/store's IngestRecipientErased) instead of silently
//     re-creating and re-delivering the message to a uin that no longer
//     exists.
//   - group recipient: remove only the wiped uin from recipient_uins.
//     Delivery to any other live recipients continues unaffected. If no
//     recipients remain, the receipt is terminalized the same way as a
//     direct tombstone.
//
// The wiped uin itself is never written into any field, table, log, hash,
// or other provenance column -- sanitizeIngestReceipt only ever removes it
// or records a non-identifying recipient_set_sanitized marker.
func (s *ScyllaMessageStore) deleteIngestReceipts(ctx context.Context, uin int64) error {
	iter := s.session.Query(`SELECT sender_uin, client_id FROM message_ingest_erasure_index WHERE uin = ?`, uin).WithContext(ctx).Iter()
	var senderUIN int64
	var clientID string
	for iter.Scan(&senderUIN, &clientID) {
		if err := s.sanitizeIngestReceipt(ctx, senderUIN, clientID, uin); err != nil {
			_ = iter.Close()
			return fmt.Errorf("sanitize ingest receipt: %w", err)
		}
	}
	if err := iter.Close(); err != nil {
		return fmt.Errorf("scan ingest erasure index: %w", err)
	}
	if err := s.session.Query(`DELETE FROM message_ingest_erasure_index WHERE uin = ?`, uin).WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("delete ingest erasure index: %w", err)
	}
	return nil
}

// boundedCASRetry runs attempt up to maxAttempts times, stopping as soon as
// attempt reports applied=true or returns a non-nil error. ctx is checked
// for cancellation before every attempt, including the first -- a
// cancelled context is reported without ever calling attempt. Exhausting
// maxAttempts without attempt ever reporting applied=true returns
// exhaustedErr(maxAttempts) instead of silently giving up, so a caller can
// tell "safe to treat as done" apart from "must be retried later." The
// exhaustion/cancellation errors are returned unwrapped so each call site
// can attach its own context-specific message, matching what
// sanitizeIngestReceipt did inline before this was extracted.
func boundedCASRetry(ctx context.Context, maxAttempts int, exhaustedErr func(attempts int) error, attempt func(ctx context.Context) (applied bool, err error)) error {
	for i := 0; ; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if i >= maxAttempts {
			return exhaustedErr(maxAttempts)
		}
		applied, err := attempt(ctx)
		if err != nil {
			return err
		}
		if applied {
			return nil
		}
	}
}

// sanitizeIngestReceipt applies role-aware cleanup to a single message_ingest
// row for a wiped uin. Safe to call more than once for the same row (repeated
// wipe-worker retries, or two different recipients of the same group message
// wiped in separate operations): every branch either no-ops on a row that's
// already gone, already terminal, or no longer references the uin.
//
// The group branch is a bounded read-compute-CAS retry loop (boundedCASRetry),
// not a single read-modify-write: two wipe workers processing different
// recipients of the SAME group row can run concurrently (see wipejob.go's
// FOR UPDATE SKIP LOCKED), and a plain "UPDATE ... IF EXISTS" only guards
// row existence, not the recipient_uins value each worker read. Without the
// CAS condition, the second writer's UPDATE can silently overwrite the
// first's removal with a stale list, resurrecting an already-wiped
// recipient with no future retry to catch it -- see
// sanitizeGroupIngestRecipients.
func (s *ScyllaMessageStore) sanitizeIngestReceipt(ctx context.Context, senderUIN int64, clientID string, wipedUIN int64) error {
	if senderUIN == wipedUIN {
		if err := s.session.Query(`DELETE FROM message_ingest WHERE sender_uin = ? AND client_id = ?`, senderUIN, clientID).WithContext(ctx).Exec(); err != nil {
			return fmt.Errorf("delete sender ingest receipt: %w", err)
		}
		return nil
	}

	err := boundedCASRetry(ctx, maxRecipientSanitizeCASAttempts, func(attempts int) error {
		return fmt.Errorf("sanitize ingest receipt: exhausted %d CAS attempts under contention for sender_uin=%d client_id=%s -- caller must retry this wipe job later", attempts, senderUIN, clientID)
	}, func(ctx context.Context) (bool, error) {
		var kind, state string
		var receiverUIN int64
		var recipientUINs []int64
		var expiresAt time.Time
		readIter := s.session.Query(`SELECT message_kind, receiver_uin, recipient_uins, state, expires_at FROM message_ingest WHERE sender_uin = ? AND client_id = ?`, senderUIN, clientID).WithContext(ctx).Iter()
		found := readIter.Scan(&kind, &receiverUIN, &recipientUINs, &state, &expiresAt)
		if err := readIter.Close(); err != nil {
			return false, fmt.Errorf("read ingest receipt: %w", err)
		}
		if !found {
			// Already gone -- delivered and cleaned up, or a previous wipe pass
			// already handled it. Safe to repeat.
			return true, nil
		}
		if state == ingestRecipientErasedState {
			// Already terminalized by an earlier wipe pass. Idempotent no-op.
			return true, nil
		}

		now := time.Now().UTC()
		remaining := remainingIngestTTLSeconds(expiresAt, now)
		if !expiresAt.IsZero() && remaining <= 0 {
			// Already past its own expiry -- let it expire naturally rather
			// than writing a fresh TTL that would resurrect it.
			return true, nil
		}

		switch kind {
		case "direct":
			if receiverUIN != wipedUIN {
				// This uin isn't referenced by this receipt in a role we
				// recognize; leave it untouched.
				return true, nil
			}
			// A direct receipt has exactly one receiver_uin, so no two
			// concurrent wipes can ever target the same row here -- a plain
			// IF EXISTS is sufficient, no CAS/retry needed.
			return true, s.terminalizeIngestReceipt(ctx, senderUIN, clientID, remaining)
		case "group":
			// Lost the race to a concurrent wipe of a different recipient
			// on this same row when applied=false: boundedCASRetry re-reads
			// the current state (this closure runs again) and retries.
			return s.sanitizeGroupIngestRecipients(ctx, senderUIN, clientID, wipedUIN, recipientUINs, remaining)
		default:
			return false, fmt.Errorf("sanitize ingest receipt: unrecognized message_kind %q for sender_uin=%d client_id=%s", kind, senderUIN, clientID)
		}
	})
	if err != nil && err == ctx.Err() {
		return fmt.Errorf("sanitize ingest receipt: %w", err)
	}
	return err
}

// sanitizeGroupIngestRecipients performs ONE compare-and-set attempt that
// removes wipedUIN from a group message_ingest row's recipient_uins,
// conditioned on the exact list previousRecipients (the value the caller just
// read). Returns applied=false -- not an error -- when a concurrent wipe of a
// different recipient on the same row committed first; the caller re-reads
// and retries. recipient_set_sanitized is written in the same CAS statement
// as recipient_uins so the two are never observed out of sync.
func (s *ScyllaMessageStore) sanitizeGroupIngestRecipients(ctx context.Context, senderUIN int64, clientID string, wipedUIN int64, previousRecipients []int64, remaining int64) (bool, error) {
	filtered := make([]int64, 0, len(previousRecipients))
	removed := false
	for _, r := range previousRecipients {
		if r == wipedUIN {
			removed = true
			continue
		}
		filtered = append(filtered, r)
	}
	if !removed {
		// Already absent from the list this attempt read -- a concurrent
		// wipe already removed it. Idempotent success.
		return true, nil
	}

	var query string
	var args []any
	if len(filtered) == 0 {
		query = `UPDATE message_ingest SET state = ?, receiver_uin = ?, conversation_id = ?, recipient_uins = ?, envelope = ?, envelope_hash = ?, recipient_set_sanitized = ? WHERE sender_uin = ? AND client_id = ? IF recipient_uins = ?`
		args = []any{ingestRecipientErasedState, nil, nil, nil, nil, nil, true, senderUIN, clientID, previousRecipients}
		if remaining > 0 {
			query = `UPDATE message_ingest USING TTL ? SET state = ?, receiver_uin = ?, conversation_id = ?, recipient_uins = ?, envelope = ?, envelope_hash = ?, recipient_set_sanitized = ? WHERE sender_uin = ? AND client_id = ? IF recipient_uins = ?`
			args = []any{remaining, ingestRecipientErasedState, nil, nil, nil, nil, nil, true, senderUIN, clientID, previousRecipients}
		}
	} else {
		query = `UPDATE message_ingest SET recipient_uins = ?, recipient_set_sanitized = ? WHERE sender_uin = ? AND client_id = ? IF recipient_uins = ?`
		args = []any{filtered, true, senderUIN, clientID, previousRecipients}
		if remaining > 0 {
			query = `UPDATE message_ingest USING TTL ? SET recipient_uins = ?, recipient_set_sanitized = ? WHERE sender_uin = ? AND client_id = ? IF recipient_uins = ?`
			args = []any{remaining, filtered, true, senderUIN, clientID, previousRecipients}
		}
	}

	applied, err := s.session.Query(query, args...).WithContext(ctx).Consistency(gocql.Quorum).SerialConsistency(gocql.Serial).MapScanCAS(map[string]any{})
	if err != nil {
		return false, fmt.Errorf("sanitize group recipient_uins CAS: %w", err)
	}
	return applied, nil
}

// terminalizeIngestReceipt converts a receipt to the same sanitized terminal
// shape message-service/store's Claim() recognizes as IngestRecipientErased:
// state flips and every field that could identify a recipient or the
// message content is cleared. Used both when a direct receiver is wiped and
// when the last live recipient of a group send is wiped. Guarded by IF
// EXISTS so a concurrent MarkDelivered cleanup (which deletes the row) does
// not race into resurrecting it.
func (s *ScyllaMessageStore) terminalizeIngestReceipt(ctx context.Context, senderUIN int64, clientID string, remaining int64) error {
	query := `UPDATE message_ingest SET state = ?, receiver_uin = ?, conversation_id = ?, recipient_uins = ?, envelope = ?, envelope_hash = ?, recipient_set_sanitized = ? WHERE sender_uin = ? AND client_id = ? IF EXISTS`
	args := []any{ingestRecipientErasedState, nil, nil, nil, nil, nil, true, senderUIN, clientID}
	if remaining > 0 {
		query = `UPDATE message_ingest USING TTL ? SET state = ?, receiver_uin = ?, conversation_id = ?, recipient_uins = ?, envelope = ?, envelope_hash = ?, recipient_set_sanitized = ? WHERE sender_uin = ? AND client_id = ? IF EXISTS`
		args = append([]any{remaining}, args...)
	}
	if err := s.session.Query(query, args...).WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("terminalize ingest receipt: %w", err)
	}
	return nil
}

// remainingIngestTTLSeconds mirrors message-service/store's
// remainingTTLSeconds. Duplicated rather than imported across the
// auth-service/message-service module boundary (see ingestRecipientErasedState).
func remainingIngestTTLSeconds(expiresAt, now time.Time) int64 {
	if expiresAt.IsZero() || !expiresAt.After(now) {
		return 0
	}
	return int64(math.Ceil(expiresAt.Sub(now).Seconds()))
}

// deleteDirectOutboxEntries removes direct outbox rows for the given UIN
// (appears as either sender or receiver). The message_outbox table is
// partitioned by bucket; we use the erasure index to discover the complete
// primary keys.
func (s *ScyllaMessageStore) deleteDirectOutboxEntries(ctx context.Context, uin int64) error {
	iter := s.session.Query(`SELECT bucket, created_at, message_id FROM message_outbox_erasure_index WHERE uin = ?`, uin).WithContext(ctx).Iter()
	var bucket int8
	var createdAt time.Time
	var messageID gocql.UUID
	for iter.Scan(&bucket, &createdAt, &messageID) {
		if err := s.session.Query(`DELETE FROM message_outbox WHERE bucket = ? AND created_at = ? AND message_id = ?`, bucket, createdAt, messageID).WithContext(ctx).Exec(); err != nil {
			_ = iter.Close()
			return fmt.Errorf("delete direct outbox: %w", err)
		}
	}
	if err := iter.Close(); err != nil {
		return fmt.Errorf("scan direct outbox erasure index: %w", err)
	}
	if err := s.session.Query(`DELETE FROM message_outbox_erasure_index WHERE uin = ?`, uin).WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("delete direct outbox erasure index: %w", err)
	}
	return nil
}

// deleteGroupOutboxEntries removes the wiped user from every group outbox row
// indexed for them. The behaviour depends on the erasure-index role:
//
//   - role='sender': the wiped user authored the message. Delete the entire
//     shared pending outbox row. No other user can meaningfully receive a
//     message whose sender no longer exists.
//
//   - role='recipient': the wiped user is one of several recipients. Remove
//     only that UIN from the recipient_uins snapshot. If no valid recipients
//     remain after removal, delete the row. Otherwise UPDATE the row with the
//     reduced list, using an explicit USING TTL that preserves the row's
//     remaining lifetime (a bare UPDATE would write its touched cells with
//     no TTL, silently turning an expiring row permanent). A row already
//     past its own expiry is left untouched rather than resurrected with a
//     fresh TTL. Uses an IF EXISTS lightweight transaction so a concurrent
//     delivery (which deletes the row) does not race with the UPDATE.
//
// Safe to call more than once for the same row: an already-gone row, an
// already-expired row, and a UIN already absent from recipient_uins are all
// detected and no-opped.
//
// After the outbox mutation, every erasure-index row for this UIN is deleted.
// The final DELETE FROM erasure index removes all entries regardless of role
// because the per-outbox-row cleanup has already been completed above.
func (s *ScyllaMessageStore) deleteGroupOutboxEntries(ctx context.Context, uin int64) error {
	iter := s.session.Query(`SELECT bucket, created_at, message_id, role FROM group_message_outbox_erasure_index WHERE uin = ?`, uin).WithContext(ctx).Iter()
	var bucket int8
	var createdAt time.Time
	var messageID gocql.UUID
	var role string
	for iter.Scan(&bucket, &createdAt, &messageID, &role) {
		switch role {
		case "sender":
			// Delete the entire outbox row — the sender no longer exists.
			if err := s.session.Query(`DELETE FROM group_message_outbox WHERE bucket = ? AND created_at = ? AND message_id = ?`, bucket, createdAt, messageID).WithContext(ctx).Exec(); err != nil {
				_ = iter.Close()
				return fmt.Errorf("delete group outbox (sender): %w", err)
			}
		case "recipient":
			// Bounded read-compute-CAS retry loop, not a single
			// read-modify-write: two wipe workers processing different
			// recipients of the SAME group outbox row can run concurrently
			// (see wipejob.go's FOR UPDATE SKIP LOCKED), and a plain
			// "UPDATE ... IF EXISTS" only guards row existence, not the
			// recipient_uins value each worker read. Without the CAS
			// condition, the second writer's UPDATE can silently overwrite
			// the first's removal with a stale list, resurrecting an
			// already-wiped recipient -- see sanitizeGroupOutboxRecipients.
			for attempt := 0; ; attempt++ {
				if err := ctx.Err(); err != nil {
					_ = iter.Close()
					return fmt.Errorf("group outbox recipient sanitize: %w", err)
				}
				if attempt >= maxRecipientSanitizeCASAttempts {
					_ = iter.Close()
					return fmt.Errorf("group outbox recipient sanitize: exhausted %d CAS attempts under contention for bucket=%d created_at=%v message_id=%s -- caller must retry this wipe job later", maxRecipientSanitizeCASAttempts, bucket, createdAt, messageID)
				}

				// Read the current recipient_uins list and expires_at.
				// expires_at is read so the CAS write below can carry an
				// explicit USING TTL -- an UPDATE without one writes its
				// touched cells with NO ttl, silently turning an expiring
				// row permanent (group_message_outbox has no table-level
				// default_time_to_live).
				var currentRecipients []int64
				var expiresAt time.Time
				readIter := s.session.Query(`SELECT recipient_uins, expires_at FROM group_message_outbox WHERE bucket = ? AND created_at = ? AND message_id = ?`, bucket, createdAt, messageID).WithContext(ctx).Iter()
				found := readIter.Scan(&currentRecipients, &expiresAt)
				if err := readIter.Close(); err != nil {
					_ = iter.Close()
					return fmt.Errorf("read group outbox recipients: %w", err)
				}
				if !found {
					// Already gone -- delivered and cleaned up, or a
					// previous wipe pass (ours or a concurrent one) already
					// removed it. Safe to repeat.
					break
				}

				now := time.Now().UTC()
				remaining := remainingIngestTTLSeconds(expiresAt, now)
				if !expiresAt.IsZero() && remaining <= 0 {
					// Already past its own expiry -- let it expire naturally
					// rather than writing a fresh TTL that would resurrect it.
					break
				}

				applied, err := s.sanitizeGroupOutboxRecipients(ctx, bucket, createdAt, messageID, uin, currentRecipients, remaining)
				if err != nil {
					_ = iter.Close()
					return err
				}
				if applied {
					break
				}
				// Lost the race to a concurrent wipe of a different
				// recipient on this same row. Re-read and retry.
			}
		default:
			// Unknown role — delete the index entry but leave the data row
			// alone. This handles forward compatibility with future roles.
		}
	}
	if err := iter.Close(); err != nil {
		return fmt.Errorf("scan group outbox erasure index: %w", err)
	}
	// Delete all erasure-index entries for this UIN — the per-row cleanup
	// above has already handled each outbox row according to its role.
	if err := s.session.Query(`DELETE FROM group_message_outbox_erasure_index WHERE uin = ?`, uin).WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("delete group outbox erasure index: %w", err)
	}
	return nil
}

// sanitizeGroupOutboxRecipients performs ONE compare-and-set attempt that
// removes uin from a group_message_outbox row's recipient_uins, conditioned
// on the exact list previousRecipients (the value the caller just read).
// Returns applied=false -- not an error -- when a concurrent wipe of a
// different recipient on the same row committed first; the caller re-reads
// and retries.
//
// The empty-list branch deletes the row outright instead of CAS-conditioning
// on recipient_uins: a DELETE has no partial state to lose, so IF EXISTS is
// sufficient there -- if it doesn't apply, the row is already gone (a
// concurrent delivery cleanup or another wipe worker's own delete), which is
// exactly the desired end state, not contention to retry.
func (s *ScyllaMessageStore) sanitizeGroupOutboxRecipients(ctx context.Context, bucket int8, createdAt time.Time, messageID gocql.UUID, uin int64, previousRecipients []int64, remaining int64) (bool, error) {
	filtered := make([]int64, 0, len(previousRecipients))
	removed := false
	for _, r := range previousRecipients {
		if r == uin {
			removed = true
			continue
		}
		filtered = append(filtered, r)
	}
	if !removed {
		// Already absent from the list this attempt read -- a concurrent
		// wipe already removed it. Idempotent success.
		return true, nil
	}

	if len(filtered) == 0 {
		if err := s.session.Query(`DELETE FROM group_message_outbox WHERE bucket = ? AND created_at = ? AND message_id = ? IF EXISTS`, bucket, createdAt, messageID).WithContext(ctx).Exec(); err != nil {
			return false, fmt.Errorf("delete empty group outbox: %w", err)
		}
		return true, nil
	}

	query := `UPDATE group_message_outbox SET recipient_uins = ? WHERE bucket = ? AND created_at = ? AND message_id = ? IF recipient_uins = ?`
	args := []any{filtered, bucket, createdAt, messageID, previousRecipients}
	if remaining > 0 {
		query = `UPDATE group_message_outbox USING TTL ? SET recipient_uins = ? WHERE bucket = ? AND created_at = ? AND message_id = ? IF recipient_uins = ?`
		args = []any{remaining, filtered, bucket, createdAt, messageID, previousRecipients}
	}
	applied, err := s.session.Query(query, args...).WithContext(ctx).Consistency(gocql.Quorum).SerialConsistency(gocql.Serial).MapScanCAS(map[string]any{})
	if err != nil {
		return false, fmt.Errorf("update group outbox recipients CAS: %w", err)
	}
	return applied, nil
}
