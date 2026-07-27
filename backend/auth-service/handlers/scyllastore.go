package handlers

import (
	"context"
	"fmt"
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
// messages ciphertext rows, message_deletion_index entries, message_ingest
// receipts, message_outbox entries, and all associated erasure indexes.
func (s *ScyllaMessageStore) DeleteUserMessages(ctx context.Context, uin int64) error {
	// 1. Direct ciphertext rows via deletion index.
	iter := s.session.Query(`SELECT conversation_id, created_at, id FROM message_deletion_index WHERE uin = ?`, uin).WithContext(ctx).Iter()
	var conversationID string
	var createdAt time.Time
	var id gocql.UUID
	for iter.Scan(&conversationID, &createdAt, &id) {
		if err := s.session.Query(`DELETE FROM messages WHERE conversation_id = ? AND created_at = ? AND id = ?`, conversationID, createdAt, id).WithContext(ctx).Exec(); err != nil {
			_ = iter.Close()
			return fmt.Errorf("delete sent message: %w", err)
		}
	}
	if err := iter.Close(); err != nil {
		return fmt.Errorf("scan message deletion index: %w", err)
	}

	// Delete the deletion index itself.
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

// deleteIngestReceipts removes durable ingest idempotency receipts for the
// given UIN. The message_ingest table is partitioned by (sender_uin, client_id);
// we use the erasure index to discover the complete primary keys.
func (s *ScyllaMessageStore) deleteIngestReceipts(ctx context.Context, uin int64) error {
	iter := s.session.Query(`SELECT sender_uin, client_id FROM message_ingest_erasure_index WHERE uin = ?`, uin).WithContext(ctx).Iter()
	var senderUIN int64
	var clientID string
	for iter.Scan(&senderUIN, &clientID) {
		if err := s.session.Query(`DELETE FROM message_ingest WHERE sender_uin = ? AND client_id = ?`, senderUIN, clientID).WithContext(ctx).Exec(); err != nil {
			_ = iter.Close()
			return fmt.Errorf("delete ingest receipt: %w", err)
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
//     reduced list. Uses an IF EXISTS lightweight transaction so a concurrent
//     delivery (which deletes the row) does not race with the UPDATE.
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
			// Read the current recipient_uins list, remove this UIN, and
			// UPDATE or DELETE the row. Use IF EXISTS so a concurrent
			// delivery (which deletes the row entirely) does not race.
			var currentRecipients []int64
			readIter := s.session.Query(`SELECT recipient_uins FROM group_message_outbox WHERE bucket = ? AND created_at = ? AND message_id = ?`, bucket, createdAt, messageID).WithContext(ctx).Iter()
			readIter.Scan(&currentRecipients)
			if err := readIter.Close(); err != nil {
				_ = iter.Close()
				return fmt.Errorf("read group outbox recipients: %w", err)
			}

			// Remove the wiped UIN from the list.
			filtered := make([]int64, 0, len(currentRecipients))
			for _, r := range currentRecipients {
				if r != uin {
					filtered = append(filtered, r)
				}
			}

			if len(filtered) == 0 {
				// No valid recipients remain — delete the row.
				if err := s.session.Query(`DELETE FROM group_message_outbox WHERE bucket = ? AND created_at = ? AND message_id = ? IF EXISTS`, bucket, createdAt, messageID).WithContext(ctx).Exec(); err != nil {
					_ = iter.Close()
					return fmt.Errorf("delete empty group outbox: %w", err)
				}
			} else {
				// Other recipients remain — UPDATE with the reduced list.
				// IF EXISTS guards against concurrent delivery.
				if err := s.session.Query(`UPDATE group_message_outbox SET recipient_uins = ? WHERE bucket = ? AND created_at = ? AND message_id = ? IF EXISTS`, filtered, bucket, createdAt, messageID).WithContext(ctx).Exec(); err != nil {
					_ = iter.Close()
					return fmt.Errorf("update group outbox recipients: %w", err)
				}
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
