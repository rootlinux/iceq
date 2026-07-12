package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/gocql/gocql"
)

// ScyllaMessageStore removes only rows involving the wiped user. Because the
// chat tables are partitioned by conversation/group rather than sender, the
// store first discovers full primary keys and then deletes those exact rows.
type ScyllaMessageStore struct {
	session *gocql.Session
}

func NewScyllaMessageStore(session *gocql.Session) (*ScyllaMessageStore, error) {
	if session == nil {
		return nil, fmt.Errorf("panicwipe: scylla session is nil")
	}
	return &ScyllaMessageStore{session: session}, nil
}

func (s *ScyllaMessageStore) DeleteUserMessages(ctx context.Context, uin int64) error {
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
	if err := s.session.Query(`DELETE FROM message_deletion_index WHERE uin = ?`, uin).WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("delete message index: %w", err)
	}
	return nil
}

func (s *ScyllaMessageStore) DeleteUserGroupMessages(ctx context.Context, uin int64) error {
	iter := s.session.Query(`SELECT group_id, created_at, id FROM group_message_deletion_index WHERE uin = ?`, uin).WithContext(ctx).Iter()
	var groupID gocql.UUID
	var createdAt interface{}
	var id gocql.UUID
	for iter.Scan(&groupID, &createdAt, &id) {
		if err := s.session.Query(`DELETE FROM group_messages WHERE group_id = ? AND created_at = ? AND id = ?`, groupID, createdAt, id).WithContext(ctx).Exec(); err != nil {
			_ = iter.Close()
			return fmt.Errorf("delete group message: %w", err)
		}
	}
	if err := iter.Close(); err != nil {
		return fmt.Errorf("scan group message deletion index: %w", err)
	}
	if err := s.session.Query(`DELETE FROM group_message_deletion_index WHERE uin = ?`, uin).WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("delete group message index: %w", err)
	}
	return nil
}
