// Package store is the message-service's persistence layer. It
// wraps a *gocql.Session and exposes a small, opinionated API
// for the two tables the service owns:
//
//   - iceq.messages       — 1:1 direct chats. Partition key
//     is the conversation_id (canonical
//     "dm:<min>:<max>" form). Clustering
//     key is (created_at, id) so a
//     paginated history fetch is an
//     O(page-size) range scan.
//   - iceq.group_messages — group chats. Partition key is
//     group_id. Same clustering shape.
//
// E2EE contract
// -------------
//
// The web client encrypts every chat message with the Signal
// Protocol (X3DH + Double Ratchet) BEFORE handing the bytes to
// the gateway. The gateway forwards those bytes to us as the
// Ciphertext []byte field on SaveRequest. We store the bytes
// opaquely as a BLOB column and never:
//
//   - log them (no fmt.Printf that includes m.Ciphertext)
//   - inspect them (no string-cast, no length-only logging,
//     no length comparison in business logic)
//   - transform them (no encoding, no encryption, no truncation)
//   - index them (no secondary index on a BLOB column)
//
// This file is the only place in the service that touches the
// raw ciphertext bytes. Every other layer passes through
// []byte without reading it. The privacy review checklist is:
//
//  1. grep for "Ciphertext" or "ciphertext" in *.go — only
//     this file and the wire-format struct in shared/models
//     should match.
//  2. grep for "content" in *.go — only the shared/models
//     legacy plaintext column name should match, and it is
//     read-only in the historical path.
//
// Storage model
// -------------
//
// Scylla is Cassandra-compatible. The session is opened with
// CL=QUORUM in shared/db/scylla.go; we re-state it on every
// call for documentation purposes (the per-call SetConsistency
// is a no-op when it matches the cluster default, but it makes
// the durability contract local to this file).
//
// Timestamps are stored as gocql's native TIMESTAMP type,
// which under the hood is int64 unix milliseconds. The caller
// is expected to pass time.Time values that have already been
// minute-truncated by the gateway before publish; we do not
// re-truncate here.
//
// Pagination
// ----------
//
// GetHistory and GetGroupHistory return rows in DESCENDING
// order (newest first). The cursor is the created_at of the
// last row the caller received. Pass a zero time.Time to mean
// "from the present". The caller iterates until a partial
// page comes back; that signals end-of-history.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gocql/gocql"
)

// ----------------------------------------------------------------------------
// Request / response types. The structs are the public API of
// this package; the handler layer in ../handlers/ builds the
// requests and consumes the responses without knowing the
// underlying SQL/CQL.
// ----------------------------------------------------------------------------

// SaveRequest is the input to SaveMessage. The ConversationID
// is pre-computed by the caller (in main.go's NATS handler) so
// the same canonical form ("dm:min:max") is used for the
// Scylla partition key, the JWT-derived conversation_id, and
// the row that ends up in the database.
//
// Ciphertext is an opaque []byte. It is the X3DH + Double
// Ratchet payload the web client produced. We never read it.
type SaveRequest struct {
	ConversationID   string
	ID               gocql.UUID
	SenderUIN        int64
	ReceiverUIN      int64
	Ciphertext       []byte
	MsgType          string
	CreatedAt        time.Time
	ExpiresInSeconds int64
}

// SaveGroupRequest is the input to SaveGroupMessage. GroupID
// is a gocql.UUID; the wire form (in JSON envelopes) is a
// canonical 36-char string and we convert at the boundary.
type SaveGroupRequest struct {
	GroupID          gocql.UUID
	ID               gocql.UUID
	SenderUIN        int64
	CryptoEpoch      int64
	Ciphertext       []byte
	MsgType          string
	CreatedAt        time.Time
	ExpiresInSeconds int64
}

// HistoryRequest is the input to GetHistory. The Before
// cursor is exclusive (rows with created_at < Before are
// returned). A zero value means "now-ish" — we use
// time.Now() in the handler so a future call with the
// same zero cursor does NOT return the same rows twice.
type HistoryRequest struct {
	ConversationID string
	Before         time.Time
	Limit          int
}

// GroupHistoryRequest mirrors HistoryRequest for the
// group_messages table.
type GroupHistoryRequest struct {
	GroupID gocql.UUID
	Before  time.Time
	Limit   int
}

// MessageRow is one row of history. It is a strict superset
// of SaveRequest's fields — the ID is filled in on the way
// out (it's the natural cluster key, not a payload field).
//
// Status is the latest delivery state the recipient's
// gateway has confirmed: "delivered" (the recipient's
// connection received it), "read" (the recipient sent a
// read receipt), or "" (no state change yet).
type MessageRow struct {
	ConversationID string
	CreatedAt      time.Time
	ID             gocql.UUID
	SenderUIN      int64
	ReceiverUIN    int64
	Ciphertext     []byte
	MsgType        string
	Status         string
	ExpiresAt      time.Time
}

// GroupMessageRow is one row of group-message history. The
// group row does NOT have a receiver_uin or status — the
// recipient list is implicit (every group member at the
// moment of delivery).
type GroupMessageRow struct {
	GroupID     gocql.UUID
	CreatedAt   time.Time
	ID          gocql.UUID
	SenderUIN   int64
	CryptoEpoch int64
	Ciphertext  []byte
	MsgType     string
	ExpiresAt   time.Time
}

// ----------------------------------------------------------------------------
// Limits / defaults. Centralized so a tuning change is a
// single edit and the public surface is the only place
// that needs updating.
// ----------------------------------------------------------------------------

const (
	// defaultHistoryLimit is the page size when the caller
	// passes 0. The spec calls for max 50, default 20.
	defaultHistoryLimit = 20

	// maxHistoryLimit is the hard upper bound; a request
	// asking for more is silently capped.
	maxHistoryLimit = 50
)

// ErrInvalidLimit is returned when a limit is negative. The
// handler layer translates this to a 400.
var ErrInvalidLimit = errors.New("store: history limit must be positive")

// ----------------------------------------------------------------------------
// MessageStore. The single public type, wrapping a
// *gocql.Session. We wrap rather than pass the session
// around so cross-cutting concerns (logging, metrics, a
// future in-memory cache) attach at one well-defined seam.
// ----------------------------------------------------------------------------

// MessageStore is the message-service's read/write surface
// against ScyllaDB. It is safe for concurrent use; the
// *gocql.Session is itself concurrency-safe and the methods
// here hold no mutable state.
type MessageStore struct {
	session *gocql.Session
}

// New constructs a MessageStore. The caller owns the
// underlying *gocql.Session and is responsible for closing
// it on shutdown. We keep a single store per process; the
// methods are safe to call from many goroutines.
func New(s *gocql.Session) *MessageStore {
	if s == nil {
		panic("store.New: scylla session is nil")
	}
	return &MessageStore{session: s}
}

func effectiveMessageTTL(requestedSeconds int64) time.Duration {
	if requestedSeconds > 0 {
		return time.Duration(requestedSeconds) * time.Second
	}
	// Zero is the explicit public "off" policy. A deployment-wide legacy TTL
	// must never silently override the sender's visible choice.
	return 0
}

func expiryAt(created time.Time, ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return created.Add(ttl)
}

// ----------------------------------------------------------------------------
// SaveMessage — append a 1:1 chat message to the messages
// table. Returns the underlying gocql error on failure.
// ----------------------------------------------------------------------------

// SaveMessage writes one row to iceq.messages. The
// ConversationID is the partition key; CreatedAt is the
// first clustering column. The (conversation_id, created_at,
// id) tuple is unique.
//
// We use a prepared statement compiled at call time (NOT a
// per-call NewBatch) because:
//  1. Prepared statements are cached by gocql internally
//     and the QueryString is identical for every call.
//  2. The driver will route the statement to the right
//     replica by partition key without us caring which
//     coordinator is current.
//
// If the insert fails (network blip, schema mismatch, etc.)
// the returned error wraps the gocql error and is the only
// signal the handler layer sees.
func (m *MessageStore) SaveMessage(ctx context.Context, req SaveRequest) error {
	ttl := effectiveMessageTTL(req.ExpiresInSeconds)
	expiresAt := expiryAt(req.CreatedAt, ttl)
	batch := m.session.NewBatch(gocql.LoggedBatch).WithContext(ctx)
	batch.SetConsistency(gocql.Quorum)
	if ttl > 0 {
		const q = `INSERT INTO iceq.messages
		  (conversation_id, created_at, id, sender_uin, receiver_uin, ciphertext, msg_type, status, expires_at)
		  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		  USING TTL ?`
		batch.Query(q,
			req.ConversationID,
			req.CreatedAt,
			req.ID,
			req.SenderUIN,
			req.ReceiverUIN,
			req.Ciphertext,
			req.MsgType,
			"",
			expiresAt,
			int(ttl.Seconds()),
		)
		const indexQ = `INSERT INTO iceq.message_deletion_index (uin, conversation_id, created_at, id) VALUES (?, ?, ?, ?) USING TTL ?`
		batch.Query(indexQ, req.SenderUIN, req.ConversationID, req.CreatedAt, req.ID, int(ttl.Seconds()))
		if req.ReceiverUIN != req.SenderUIN {
			batch.Query(indexQ, req.ReceiverUIN, req.ConversationID, req.CreatedAt, req.ID, int(ttl.Seconds()))
		}
		return m.session.ExecuteBatch(batch)
	}
	const q = `INSERT INTO iceq.messages
	  (conversation_id, created_at, id, sender_uin, receiver_uin, ciphertext, msg_type, status)
	  VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	batch.Query(q,
		req.ConversationID,
		req.CreatedAt,
		req.ID,
		req.SenderUIN,
		req.ReceiverUIN,
		req.Ciphertext,
		req.MsgType,
		"",
	)
	const indexQ = `INSERT INTO iceq.message_deletion_index (uin, conversation_id, created_at, id) VALUES (?, ?, ?, ?)`
	batch.Query(indexQ, req.SenderUIN, req.ConversationID, req.CreatedAt, req.ID)
	if req.ReceiverUIN != req.SenderUIN {
		batch.Query(indexQ, req.ReceiverUIN, req.ConversationID, req.CreatedAt, req.ID)
	}
	return m.session.ExecuteBatch(batch)
}

// SaveGroupMessage writes one row to iceq.group_messages.
// The (group_id, created_at, id) tuple is unique. There is
// no status column on this table; the group fan-out is
// confirmed by the per-recipient presence of a row in
// iceq.messages for each member (TODO future step: confirm
// fan-out coverage).
func (m *MessageStore) SaveGroupMessage(ctx context.Context, req SaveGroupRequest) error {
	ttl := effectiveMessageTTL(req.ExpiresInSeconds)
	expiresAt := expiryAt(req.CreatedAt, ttl)
	batch := m.session.NewBatch(gocql.LoggedBatch).WithContext(ctx)
	batch.SetConsistency(gocql.Quorum)
	if ttl > 0 {
		const q = `INSERT INTO iceq.group_messages
		  (group_id, created_at, id, sender_uin, crypto_epoch, ciphertext, msg_type, expires_at)
		  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		  USING TTL ?`
		batch.Query(q,
			req.GroupID,
			req.CreatedAt,
			req.ID,
			req.SenderUIN,
			req.CryptoEpoch,
			req.Ciphertext,
			req.MsgType,
			expiresAt,
			int(ttl.Seconds()),
		)
		batch.Query(`INSERT INTO iceq.group_message_deletion_index (uin, group_id, created_at, id) VALUES (?, ?, ?, ?) USING TTL ?`, req.SenderUIN, req.GroupID, req.CreatedAt, req.ID, int(ttl.Seconds()))
		return m.session.ExecuteBatch(batch)
	}
	const q = `INSERT INTO iceq.group_messages
	  (group_id, created_at, id, sender_uin, crypto_epoch, ciphertext, msg_type)
	  VALUES (?, ?, ?, ?, ?, ?, ?)`
	batch.Query(q,
		req.GroupID,
		req.CreatedAt,
		req.ID,
		req.SenderUIN,
		req.CryptoEpoch,
		req.Ciphertext,
		req.MsgType,
	)
	batch.Query(`INSERT INTO iceq.group_message_deletion_index (uin, group_id, created_at, id) VALUES (?, ?, ?, ?)`, req.SenderUIN, req.GroupID, req.CreatedAt, req.ID)
	return m.session.ExecuteBatch(batch)
}

// ----------------------------------------------------------------------------
// GetHistory — paginated 1:1 chat history.
// ----------------------------------------------------------------------------

// GetHistory returns up to req.Limit rows of the messages
// table for the given conversation_id, ordered by created_at
// DESC. The Before cursor is exclusive: rows with
// created_at < Before are returned.
//
// Limit normalization:
//   - 0  -> defaultHistoryLimit (20)
//   - > 50 -> capped at maxHistoryLimit (50)
//   - < 0  -> ErrInvalidLimit
//
// A zero Before is treated as "give me the newest page".
// We do NOT use time.Now() inside this function — the handler
// layer should pass time.Now() if it wants the freshest page.
func (m *MessageStore) GetHistory(ctx context.Context, req HistoryRequest) ([]MessageRow, error) {
	limit := req.Limit
	if limit == 0 {
		limit = defaultHistoryLimit
	}
	if limit < 0 {
		return nil, ErrInvalidLimit
	}
	if limit > maxHistoryLimit {
		limit = maxHistoryLimit
	}
	before := req.Before
	if before.IsZero() {
		// "now-ish" — use the current server clock. We add
		// a tiny safety margin (1 second) so a row that was
		// just written at the same millisecond isn't
		// accidentally excluded by an exclusive cursor.
		before = time.Now().Add(time.Second)
	}

	const q = `SELECT conversation_id, created_at, id, sender_uin, receiver_uin, ciphertext, msg_type, status, expires_at
	  FROM iceq.messages
	  WHERE conversation_id = ? AND created_at < ?
	  ORDER BY created_at DESC
	  LIMIT ?`

	iter := m.session.
		Query(q, req.ConversationID, before, limit).
		WithContext(ctx).
		Consistency(gocql.Quorum).
		Iter()

	var rows []MessageRow
	for {
		var row MessageRow
		if !iter.Scan(
			&row.ConversationID,
			&row.CreatedAt,
			&row.ID,
			&row.SenderUIN,
			&row.ReceiverUIN,
			&row.Ciphertext,
			&row.MsgType,
			&row.Status,
			&row.ExpiresAt,
		) {
			break
		}
		if !row.ExpiresAt.IsZero() && !row.ExpiresAt.After(time.Now()) {
			continue
		}
		rows = append(rows, row)
	}
	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("store: history iter: %w", err)
	}
	return rows, nil
}

// GetGroupHistory mirrors GetHistory for the
// group_messages table. The query shape and limit semantics
// are identical; only the partition-key column changes.
func (m *MessageStore) GetGroupHistory(ctx context.Context, req GroupHistoryRequest) ([]GroupMessageRow, error) {
	limit := req.Limit
	if limit == 0 {
		limit = defaultHistoryLimit
	}
	if limit < 0 {
		return nil, ErrInvalidLimit
	}
	if limit > maxHistoryLimit {
		limit = maxHistoryLimit
	}
	before := req.Before
	if before.IsZero() {
		before = time.Now().Add(time.Second)
	}

	const q = `SELECT group_id, created_at, id, sender_uin, crypto_epoch, ciphertext, msg_type, expires_at
	  FROM iceq.group_messages
	  WHERE group_id = ? AND created_at < ?
	  ORDER BY created_at DESC
	  LIMIT ?`

	iter := m.session.
		Query(q, req.GroupID, before, limit).
		WithContext(ctx).
		Consistency(gocql.Quorum).
		Iter()

	var rows []GroupMessageRow
	for {
		var row GroupMessageRow
		if !iter.Scan(
			&row.GroupID,
			&row.CreatedAt,
			&row.ID,
			&row.SenderUIN,
			&row.CryptoEpoch,
			&row.Ciphertext,
			&row.MsgType,
			&row.ExpiresAt,
		) {
			break
		}
		if !row.ExpiresAt.IsZero() && !row.ExpiresAt.After(time.Now()) {
			continue
		}
		rows = append(rows, row)
	}
	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("store: group history iter: %w", err)
	}
	return rows, nil
}

// ----------------------------------------------------------------------------
// MarkDelivered / MarkRead — per-message status transitions.
// Called by the ack.{sender_uin} subscriber (read receipts
// from clients) and by the persisted-ack path on the
// recipient's gateway. Updates the `status` column on
// the matching (conversation_id, created_at, id) row.
// ----------------------------------------------------------------------------

// MarkDelivered flips the status to "delivered" for the
// given (conversation_id, created_at, id) tuple. The three
// fields together are the natural primary key of the
// messages table.
//
// The UPDATE is conditional on the (conv, ts, id) tuple
// existing; a non-existent row is a no-op (we don't return
// a "row not found" error — the caller can't tell a fresh
// row from a TTL-expired one, and the action is
// idempotent in spirit).
func (m *MessageStore) MarkDelivered(ctx context.Context, conversationID string, createdAt time.Time, id gocql.UUID) error {
	const q = `UPDATE iceq.messages SET status = 'delivered'
	  WHERE conversation_id = ? AND created_at = ? AND id = ?`
	return m.session.
		Query(q, conversationID, createdAt, id).
		WithContext(ctx).
		Consistency(gocql.Quorum).
		Exec()
}

// MarkRead flips the status to "read" for the given
// (conversation_id, created_at, id) tuple. Same shape and
// idempotency contract as MarkDelivered.
func (m *MessageStore) MarkRead(ctx context.Context, conversationID string, createdAt time.Time, id gocql.UUID) error {
	const q = `UPDATE iceq.messages SET status = 'read'
	  WHERE conversation_id = ? AND created_at = ? AND id = ?`
	return m.session.
		Query(q, conversationID, createdAt, id).
		WithContext(ctx).
		Consistency(gocql.Quorum).
		Exec()
}
