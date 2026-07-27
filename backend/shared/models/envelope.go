// Package models defines the wire-format types shared by every IceQ
// backend service and the web client. Two responsibilities live here:
//
//  1. The Envelope struct — the single envelope shape that wraps every
//     message flowing over a WebSocket, regardless of whether that
//     message is a chat send, a typing indicator, a read receipt, or a
//     presence update. Using a single envelope means the WebSocket
//     transport layer can route / log / sequence uniformly; the
//     per-message-type payload is parsed lazily by consumers.
//
//  2. The per-type payload structs. They are intentionally small
//     (mostly just the fields a given message needs) and live next to
//     the Envelope so the spec is easy to read end-to-end. Adding a
//     new message type is a matter of adding a Type constant, a
//     payload struct, and a switch case in the consumer; the
//     transport layer does not need to change.
//
// Everything in this package is JSON-tagged and (de)serializes with
// encoding/json. Time fields are int64 unix milliseconds on the wire
// for the smallest possible payload and unambiguous cross-platform
// parsing; we convert to time.Time only at the consumer boundary when
// real time arithmetic is needed.
package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// nowFunc is the clock source used by every time-related helper in this
// package. Exposed as a package-level variable so tests can substitute
// a deterministic clock without touching the rest of the code.
var nowFunc = time.Now

// ----------------------------------------------------------------------------
// Envelope type constants. These string values are part of the public
// contract with the web client — never rename without a coordinated
// versioned rollout. The strings are short on the wire (chat is
// high-frequency) but verbose enough to be self-documenting in logs.
// ----------------------------------------------------------------------------

const (
	// EnvelopeTypeDirect is a 1:1 chat message (sender -> receiver).
	EnvelopeTypeDirect = "message"

	// EnvelopeTypeGroup is a group chat message.
	EnvelopeTypeGroup = "group_msg"

	// EnvelopeTypeTyping is a transient typing indicator. Not
	// persisted.
	EnvelopeTypeTyping = "typing"

	// EnvelopeTypeRead is a read-receipt acknowledging that a
	// message has been displayed.
	EnvelopeTypeRead = "read"

	// EnvelopeTypePresence is a presence-state change (online /
	// away / dnd / offline). Not persisted; broadcast on the
	// presence NATS subject.
	EnvelopeTypePresence = "presence"

	// EnvelopeTypeAck is the client-or-server acknowledgement for a
	// previously-sent message. Carries the original message ID and
	// its delivery state (delivered, persisted, read).
	EnvelopeTypeAck = "ack"

	// EnvelopeTypeTransportAck confirms the authenticated recipient has
	// durably committed received envelope IDs locally.
	EnvelopeTypeTransportAck = "transport_ack"

	// EnvelopeTypeError is a server-to-client error message. The
	// client should display it and increment any retry counters.
	EnvelopeTypeError = "error"

	// EnvelopeTypeNotification is a server-originated user-visible
	// event that is NOT a chat message — typically a "you have a new
	// contact request" or "you've been added to group X" prompt.
	// The web client subscribes to `notification.<uin>` and surfaces
	// these in a toast / notification list.
	EnvelopeTypeNotification = "notification"
)

// ----------------------------------------------------------------------------
// Notification kinds. Discriminator inside NotificationPayload.Kind.
// Adding a new kind is a non-breaking change for the client; the
// client just renders an unknown kind with a generic "you have a new
// event" line.
// ----------------------------------------------------------------------------

const (
	// NotificationKindContactRequest is fired when someone adds the
	// recipient to their contact list with status=pending.
	NotificationKindContactRequest = "contact_request"

	// NotificationKindGroupInvite is fired when someone adds the
	// recipient to a group with role=member.
	NotificationKindGroupInvite = "group_invite"

	// NotificationKindContactAccepted is fired when a pending contact
	// request is accepted so the original requester sees the accepted
	// relationship without reloading.
	NotificationKindContactAccepted = "contact_accepted"
)

// ----------------------------------------------------------------------------
// Content-type and presence-status constants. Same versioning rule as
// the envelope types — string values are a public contract.
// ----------------------------------------------------------------------------

// ContentType is the discriminator for what kind of payload `content`
// carries. The chat side can carry inline text, a file URL, or an
// image URL — all three are valid but the client renders them
// differently. The numeric / unknown values are intentionally absent:
// a new content type should be added here as a constant so the
// consumer has an exhaustive switch.
const (
	ContentTypeText  = "text"
	ContentTypeImage = "image"
	ContentTypeFile  = "file"
)

// PresenceStatus is the user's availability state. offline is a
// derived state (we know a user is offline if their last heartbeat is
// older than the presence TTL); the others are explicit user-set
// states.
const (
	PresenceStatusOnline  = "online"
	PresenceStatusAway    = "away"
	PresenceStatusDND     = "dnd"
	PresenceStatusOffline = "offline"
)

// ----------------------------------------------------------------------------
// AckState. Used inside AckPayload to convey what kind of
// acknowledgement the server is sending to the original sender.
// ----------------------------------------------------------------------------

// AckState values describe the lifecycle of a message: from "the
// server received and persisted it" through "the recipient is
// online and saw it" to "the recipient explicitly marked it read".
const (
	AckStatePersisted = "persisted" // Scylla write succeeded
	AckStateDelivered = "delivered" // recipient's ws-gateway received
	AckStateRead      = "read"      // recipient sent a read receipt
)

// ----------------------------------------------------------------------------
// Envelope. The single wrapper used for every WebSocket message. Payloads
// are stored as raw JSON so consumers can decode into a type-specific
// struct only when they need to.
// ----------------------------------------------------------------------------

// Envelope is the wire-level wrapper for every IceQ WebSocket message.
// It is deliberately a flat struct with json.RawMessage for the
// payload: the alternative (interface{} / map[string]any) loses type
// safety at the boundary and forces every consumer to re-validate
// field shapes.
//
// Field rationale:
//
//   - Type is the discriminator. Consumers switch on it and Unmarshal
//     Payload into a type-specific struct.
//   - ID is a server-assigned UUID. Clients can use it to dedupe
//     messages received on multiple paths (e.g. via the WebSocket and
//     via the /api/messages REST history endpoint).
//   - TS is the server time at which the envelope was created, in
//     unix milliseconds. We use milliseconds rather than seconds so
//     rapid message bursts retain their relative ordering without
//     needing a separate sequence number.
//   - Payload is the type-specific body. It is left as raw JSON to
//     keep Envelope transport-agnostic.
type Envelope struct {
	Type    string          `json:"type"`
	ID      string          `json:"id"`
	TS      int64           `json:"ts"`
	Payload json.RawMessage `json:"payload"`
}

// NewEnvelope constructs a server-side envelope with a fresh UUID and
// the current unix-millisecond timestamp. The payload is captured as
// raw JSON; the caller is responsible for producing a value that
// json.Marshal understands (struct, map, or json.RawMessage).
func NewEnvelope(envelopeType string, payload any) (Envelope, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{
		Type:    envelopeType,
		ID:      uuid.NewString(),
		TS:      nowUnixMilli(),
		Payload: raw,
	}, nil
}

// ----------------------------------------------------------------------------
// Payload structs. One per EnvelopeType. Keep them small and additive:
// adding an optional field is a non-breaking change; renaming or
// removing a field requires a coordinated client/server rollout.
// ----------------------------------------------------------------------------

type TransportAckPayload struct {
	MessageIDs []string `json:"message_ids"`
}

// DirectMessagePayload is the body of a 1:1 chat message. ToUIN is the
// public client contract; ReceiverUIN is kept as the persisted/server
// alias for older clients and service-internal records.
//
// ReceiverUIN
// is set by the server from the auth context, not trusted from the
// client, so a tampered client cannot impersonate other users.
//
// ConversationID is the same value the message service uses as the
// Scylla partition key. Setting it server-side keeps the partition
// consistent regardless of who initiates the message.
//
// Ciphertext is the E2EE payload the client produced with the Signal
// Protocol. The server stores it as an opaque byte slice and never
// inspects, transforms, or logs it.
//
// MsgType names the Signal payload shape: "signal_message" (a Double
// Ratchet message) or "prekey_message" (an X3DH initial message
// that bootstraps a session). The web client picks one of the two;
// the value is stored alongside the ciphertext so the recipient
// can route it to the right Signal sub-protocol on decrypt.
type DirectMessagePayload struct {
	ConversationID   string `json:"conversation_id"`
	SenderUIN        int64  `json:"sender_uin"`
	ToUIN            int64  `json:"to_uin,omitempty"`
	ReceiverUIN      int64  `json:"receiver_uin"`
	Content          string `json:"content"`
	ContentType      string `json:"content_type"`
	FileURL          string `json:"file_url,omitempty"`
	ClientID         string `json:"client_id,omitempty"`
	Ciphertext       []byte `json:"ciphertext,omitempty"`
	MsgType          string `json:"msg_type,omitempty"`
	ExpiresInSeconds int64  `json:"expires_in_seconds,omitempty"`
}

// GroupMessagePayload is the body of a group chat message. The
// recipient list is implicit (every group member), so the payload
// carries only the group ID, ciphertext, and metadata.
//
// MsgType follows the same X3DH / Double Ratchet discriminator
// convention as DirectMessagePayload; see that type's docs.
type GroupMessagePayload struct {
	GroupID          string `json:"group_id"`
	SenderUIN        int64  `json:"sender_uin"`
	Content          string `json:"content"`
	ContentType      string `json:"content_type"`
	FileURL          string `json:"file_url,omitempty"`
	ClientID         string `json:"client_id,omitempty"`
	Ciphertext       []byte `json:"ciphertext,omitempty"`
	MsgType          string `json:"msg_type,omitempty"`
	CryptoVersion    int    `json:"crypto_version"`
	CryptoEpoch      int64  `json:"crypto_epoch"`
	ExpiresInSeconds int64  `json:"expires_in_seconds,omitempty"`
	// RecipientUINs is a server-generated immutable membership snapshot for
	// the exact crypto epoch. Gateways must never trust a client-supplied list.
	RecipientUINs []int64 `json:"recipient_uins,omitempty"`
}

// TypingPayload is a transient indicator. The server-side presence
// service uses it to update typing TTLs but does not persist it.
type TypingPayload struct {
	ConversationID string `json:"conversation_id"`
	SenderUIN      int64  `json:"sender_uin"`
	IsGroup        bool   `json:"is_group"`
	GroupID        string `json:"group_id,omitempty"`
}

// ReadPayload is a read receipt. The client marks a specific
// message as read by naming its (conversation_id, message_id,
// created_at) triple; the created_at is needed because the
// message-service stores rows keyed on
// (conversation_id, created_at, id) and an UPDATE without
// created_at is a full-cluster scan.
//
// SenderUIN is the original SENDER's UIN — i.e. the user
// who should be notified that their message was read. The
// ws-gateway uses it as the NATS subject suffix on
// `ack.<sender_uin>` so the message-service can route
// per-sender. The reader's own UIN is taken from the
// authenticated connection (server-side fill) — we never
// trust a client-claimed reader_uin.
type ReadPayload struct {
	ConversationID string    `json:"conversation_id"`
	ReaderUIN      int64     `json:"reader_uin"`
	SenderUIN      int64     `json:"sender_uin"`
	MessageID      string    `json:"message_id"`
	CreatedAt      time.Time `json:"created_at"`
	IsGroup        bool      `json:"is_group"`
	GroupID        string    `json:"group_id,omitempty"`
}

// PresencePayload is broadcast on the presence NATS subject. UIN is
// the user whose state changed. The presence service derives
// "offline" by TTL expiry; the rest are explicit.
type PresencePayload struct {
	UIN    int64  `json:"uin"`
	Status string `json:"status"`
	TS     int64  `json:"ts"`
}

// AckPayload is a server-to-original-sender acknowledgement.
// MessageID is the ID of the message being acked. State is one of
// the AckState* constants. RecipientUIN is the UIN of the user
// whose action produced the ack (the person who read or received).
type AckPayload struct {
	MessageID    string `json:"message_id"`
	State        string `json:"state"`
	RecipientUIN int64  `json:"recipient_uin"`
}

// ErrorPayload is a server-to-client error message. The Code is a
// stable string identifier (e.g. "rate_limited", "invalid_payload")
// for the client to switch on; Message is the human-readable
// description shown in the UI.
type ErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// NotificationPayload is the body of a server-originated
// user-visible event. Kind is one of the NotificationKind*
// constants. Title and Body are pre-formatted, human-readable
// strings safe to render directly in the UI. Data carries
// kind-specific context (e.g. a group_id for a group_invite)
// so the client can navigate to the right place when the user
// clicks through. The UIN of the recipient is NOT in the
// payload — the recipient is implicit from the NATS subject
// (`notification.<uin>`) so we don't echo it back.
type NotificationPayload struct {
	Kind  string         `json:"kind"`
	Title string         `json:"title"`
	Body  string         `json:"body"`
	Data  map[string]any `json:"data,omitempty"`
}

// ----------------------------------------------------------------------------
// Time helper. Centralized so every envelope in the system uses the
// same clock source; replacing this with a mocked clock in tests is
// a one-line change.
// ----------------------------------------------------------------------------

// nowUnixMilli returns the current time in unix milliseconds. The
// name is a free function rather than a constant so the dependency
// on time.Now() is localized to this one helper — every other call
// site reads as a value, not as a clock query.
func nowUnixMilli() int64 {
	return nowFunc().UnixMilli()
}
