// Package router inspects every inbound WebSocket envelope and
// routes it to the correct downstream action. The router is
// *transport-only*: it never reads the ciphertext, never
// inspects content, never persists anything. It only switches
// on the Envelope.Type discriminator and decides:
//
//   - For "message": validate the target, mint a server ID,
//     publish to msg.direct.{receiver_uin} on NATS, ACK the
//     sender.
//   - For "group_msg": verify the sender is a member of the
//     group, publish to msg.group.{group_id}, ACK.
//   - For "typing": forward to msg.direct.{receiver_uin} or
//     msg.group.{group_id}. No ACK, no storage.
//   - For "read": publish to ack.{original_sender_uin}. No
//     storage at the gateway level.
//   - For "presence": validate the status, publish to
//     presence.update.
//   - For "ping": respond with pong. No NATS.
//
// Unknown types produce an error frame; the connection stays
// open. The router never closes a connection on its own — the
// readLoop owns close decisions (wipe, rate limit, etc.).
//
// The router is package-level (no struct, just functions) so
// the readLoop can call it as a one-liner. The stateful
// dependencies (Hub, NATS, PG) are passed through Client.Deps
// at call time.
package router

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/iceq/iceq/shared/models"
	"github.com/iceq/iceq/ws-gateway/client"
	"github.com/jackc/pgx/v5"
)

// ----------------------------------------------------------------------------
// Dispatch. The single entry point from the readLoop. The switch
// is exhaustive on the type strings the spec defines; anything
// else produces an error frame.
// ----------------------------------------------------------------------------

// Dispatch is the per-frame router entry. It is intentionally
// a free function (not a method on a Router struct) because
// the router has no per-instance state — every dependency
// lives in the passed-in client.
//
// The function is a single switch on env.Type. Each case
// delegates to a typed handler; an unknown type produces an
// error frame and returns.
func Dispatch(c *client.Client, env models.Envelope) {
	deps := c.Deps()
	switch env.Type {
	case models.EnvelopeTypeDirect:
		handleDirect(c, deps, env)
	case models.EnvelopeTypeGroup:
		handleGroup(c, deps, env)
	case models.EnvelopeTypeTyping:
		handleTyping(deps, env)
	case models.EnvelopeTypeRead:
		handleRead(c, deps, env)
	case models.EnvelopeTypePresence:
		handlePresence(deps, env)
	case "ping":
		handlePing(c, env)
	default:
		// Unknown type: send an error frame, do NOT close.
		// The spec is explicit: a misbehaving client should
		// be told it misbehaved, not kicked.
		errEnv, _ := models.NewEnvelope(models.EnvelopeTypeError, models.ErrorPayload{
			Code:    "UNKNOWN_TYPE",
			Message: "envelope type not recognized",
		})
		c.TrySend(mustMarshal(errEnv))
	}
}

// ----------------------------------------------------------------------------
// "message" → DirectMessagePayload
// ----------------------------------------------------------------------------

// handleDirect processes a 1:1 chat message. Validates the
// payload, mints a server-side ID, publishes to NATS, and
// ACKs the sender. The router does NOT touch ciphertext; the
// payload's `content` field is treated as opaque and is
// included in the NATS envelope byte-for-byte.
//
// Validation rules (from the spec):
//   - receiver_uin != 0
//   - len(content) > 0
//   - msg_type ∈ {"signal_message", "prekey_message"}
//
// The msg_type field is the Signal Protocol envelope type
// (whisper, prekey, etc.). We pass it through on the wire so
// the message-service can persist it, but we never inspect
// it ourselves — the gateway is a transport router, not a
// Signal Protocol participant.
func handleDirect(c *client.Client, deps client.Deps, env models.Envelope) {
	p, err := parseDirectPayload(env.Payload)
	if err != nil {
		sendErrorFrame(c, "INVALID_PAYLOAD", "message payload malformed")
		return
	}
	if err := validateDirectPayload(p); err != nil {
		sendErrorFrame(c, "INVALID_PAYLOAD", err.Error())
		return
	}
	// Server-side fill: the sender is the authenticated
	// user, NEVER the client-claimed sender_uin. A tampered
	// client cannot impersonate another user.
	p.SenderUIN = c.UIN()

	// Truncate timestamp to the minute. The spec mandates
	// this; it (a) makes timing-correlation attacks against
	// the log harder and (b) is the right granularity for
	// the chat's per-minute sort key.
	ts := time.Now().UTC().Truncate(time.Minute).UnixMilli()

	// Mint a server-side message ID. We use a UUID v4; the
	// spec asks for a UUID.
	msgID := uuid.NewString()

	// Build the on-wire envelope. The router includes the
	// message_id so the recipient's message-service can
	// dedupe on retried publishes.
	out := models.Envelope{
		Type:    models.EnvelopeTypeDirect,
		ID:      msgID,
		TS:      ts,
		Payload: mustMarshalRaw(forwardDirectPayload(p, c.UIN())),
	}
	data, err := json.Marshal(out)
	if err != nil {
		log.Printf("[ws-gateway] marshal direct: %v", err)
		return
	}

	// Publish on the per-receiver subject. The Hub's
	// NATS subscriber (in main.go) listens on
	// msg.direct.* and routes to the recipient's local
	// connections. Subjects are uin-as-string; using a
	// wildcard here would defeat the gateway's per-
	// receiver fan-out.
	if err := deps.NATS.Publish(
		"msg.direct."+itoa(p.ReceiverUIN),
		data,
	); err != nil {
		// The publish failed (NATS down, server closing,
		// etc.). The send ACKs we are about to emit would
		// be misleading because the recipient won't see
		// the message. We log and skip the ACK; the
		// client will retry.
		log.Printf("[ws-gateway] publish direct: %v", err)
		return
	}

	// ACK the sender. The AckPayload.State is "persisted"
	// from the gateway's perspective: we have accepted
	// the message and handed it to the bus. The
	// message-service will publish a follow-up ACK with
	// State="delivered" once it has written to Scylla.
	ack, _ := models.NewEnvelope(models.EnvelopeTypeAck, models.AckPayload{
		MessageID:    ackMessageID(msgID, p.ClientID),
		State:        models.AckStatePersisted,
		RecipientUIN: p.ReceiverUIN,
	})
	c.TrySend(mustMarshal(ack))
}

type directMessageWirePayload struct {
	ConversationID string `json:"conversation_id"`
	SenderUIN      int64  `json:"sender_uin"`
	ToUIN          int64  `json:"to_uin,omitempty"`
	ReceiverUIN    int64  `json:"receiver_uin"`
	Content        string `json:"content"`
	ContentType    string `json:"content_type"`
	FileURL        string `json:"file_url,omitempty"`
	ClientID       string `json:"client_id,omitempty"`
	Ciphertext     string `json:"ciphertext,omitempty"`
	MsgType        string `json:"msg_type,omitempty"`
}

func parseDirectPayload(raw json.RawMessage) (models.DirectMessagePayload, error) {
	var wire directMessageWirePayload
	if err := json.Unmarshal(raw, &wire); err != nil {
		return models.DirectMessagePayload{}, err
	}
	ciphertext, err := decodeWireCiphertext(wire.Ciphertext)
	if err != nil {
		return models.DirectMessagePayload{}, err
	}
	receiverUIN := wire.ReceiverUIN
	if receiverUIN == 0 {
		receiverUIN = wire.ToUIN
	}
	return models.DirectMessagePayload{
		ConversationID: wire.ConversationID,
		SenderUIN:      wire.SenderUIN,
		ToUIN:          receiverUIN,
		ReceiverUIN:    receiverUIN,
		Content:        wire.Content,
		ContentType:    wire.ContentType,
		FileURL:        wire.FileURL,
		ClientID:       wire.ClientID,
		Ciphertext:     ciphertext,
		MsgType:        wire.MsgType,
	}, nil
}

func decodeWireCiphertext(ciphertext string) ([]byte, error) {
	if ciphertext == "" {
		return nil, nil
	}
	decoders := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	var lastErr error
	for _, enc := range decoders {
		out, err := enc.DecodeString(ciphertext)
		if err == nil {
			return out, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("ciphertext is not valid base64: %w", lastErr)
}

func validateDirectPayload(p models.DirectMessagePayload) error {
	if p.ReceiverUIN == 0 {
		return fmt.Errorf("receiver_uin is required")
	}
	if len(p.Content) == 0 && len(p.Ciphertext) == 0 {
		return fmt.Errorf("content or ciphertext is required")
	}
	if len(p.Ciphertext) > 0 && !isValidMessageType(p.MsgType) {
		return fmt.Errorf("msg_type must be prekey_message or signal_message")
	}
	return nil
}

func isValidMessageType(msgType string) bool {
	return msgType == "signal_message" || msgType == "prekey_message"
}

func forwardDirectPayload(p models.DirectMessagePayload, senderUIN int64) models.DirectMessagePayload {
	return models.DirectMessagePayload{
		ConversationID: p.ConversationID,
		SenderUIN:      senderUIN,
		ToUIN:          p.ReceiverUIN,
		ReceiverUIN:    p.ReceiverUIN,
		Content:        p.Content,
		ContentType:    p.ContentType,
		FileURL:        p.FileURL,
		ClientID:       p.ClientID,
		Ciphertext:     p.Ciphertext,
		MsgType:        p.MsgType,
	}
}

// ----------------------------------------------------------------------------
// "group_msg" → GroupMessagePayload
// ----------------------------------------------------------------------------

// handleGroup processes a group chat message. Verifies the
// sender is a member of the group, mints a server ID,
// publishes to msg.group.{group_id}, and ACKs the sender.
// The recipient list is implicit (every group member); the
// group's NATS subscriber fans out to each member's UIN.
func handleGroup(c *client.Client, deps client.Deps, env models.Envelope) {
	p, err := parseGroupPayload(env.Payload)
	if err != nil {
		sendErrorFrame(c, "INVALID_PAYLOAD", "group payload malformed")
		return
	}
	if err := validateGroupPayload(p); err != nil {
		sendErrorFrame(c, "INVALID_PAYLOAD", err.Error())
		return
	}
	// Server-side fill: sender is the authenticated user.
	p.SenderUIN = c.UIN()

	// Membership check. The spec requires a 403-equivalent
	// for non-members. We use a single PG query that
	// returns 0 rows if the user is not a member; the
	// error path emits an error frame and skips the
	// publish.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	const q = `SELECT 1 FROM group_members WHERE group_id = $1 AND uin = $2`
	var probe int
	if err := deps.PG.QueryRow(ctx, q, p.GroupID, c.UIN()).Scan(&probe); err != nil {
		if err == pgx.ErrNoRows {
			// Not a member. 403 in error-frame form.
			// We do NOT distinguish "group doesn't exist"
			// from "you're not in it" — that would let an
			// attacker enumerate group IDs.
			sendErrorFrame(c, "NOT_A_MEMBER", "sender is not a member of this group")
			return
		}
		// Real DB error: log, send a generic error frame.
		log.Printf("[ws-gateway] group membership: %v", err)
		sendErrorFrame(c, "INTERNAL", "membership check failed")
		return
	}

	ts := time.Now().UTC().Truncate(time.Minute).UnixMilli()
	msgID := uuid.NewString()

	out := models.Envelope{
		Type: models.EnvelopeTypeGroup,
		ID:   msgID,
		TS:   ts,
		Payload: mustMarshalRaw(models.GroupMessagePayload{
			GroupID:     p.GroupID,
			SenderUIN:   p.SenderUIN,
			Content:     p.Content,
			ContentType: p.ContentType,
			FileURL:     p.FileURL,
			ClientID:    p.ClientID,
			Ciphertext:  p.Ciphertext,
			MsgType:     p.MsgType,
		}),
	}
	data, err := json.Marshal(out)
	if err != nil {
		log.Printf("[ws-gateway] marshal group: %v", err)
		return
	}
	if err := deps.NATS.Publish(
		"msg.group."+p.GroupID,
		data,
	); err != nil {
		log.Printf("[ws-gateway] publish group: %v", err)
		return
	}
	ack, _ := models.NewEnvelope(models.EnvelopeTypeAck, models.AckPayload{
		MessageID: ackMessageID(msgID, p.ClientID),
		State:     models.AckStatePersisted,
		// RecipientUIN is the GROUP, encoded as 0 for
		// "group ack". Recipients are the individual
		// members; the message-service will fan out
		// per-member ACKs as they are delivered.
		RecipientUIN: 0,
	})
	c.TrySend(mustMarshal(ack))
}

func ackMessageID(serverID, clientID string) string {
	if clientID != "" {
		return clientID
	}
	return serverID
}

type groupMessageWirePayload struct {
	GroupID     string `json:"group_id"`
	SenderUIN   int64  `json:"sender_uin"`
	Content     string `json:"content"`
	ContentType string `json:"content_type"`
	FileURL     string `json:"file_url,omitempty"`
	ClientID    string `json:"client_id,omitempty"`
	Ciphertext  string `json:"ciphertext,omitempty"`
	MsgType     string `json:"msg_type,omitempty"`
}

func parseGroupPayload(raw json.RawMessage) (models.GroupMessagePayload, error) {
	var wire groupMessageWirePayload
	if err := json.Unmarshal(raw, &wire); err != nil {
		return models.GroupMessagePayload{}, err
	}
	ciphertext, err := decodeWireCiphertext(wire.Ciphertext)
	if err != nil {
		return models.GroupMessagePayload{}, err
	}
	return models.GroupMessagePayload{
		GroupID:     wire.GroupID,
		SenderUIN:   wire.SenderUIN,
		Content:     wire.Content,
		ContentType: wire.ContentType,
		FileURL:     wire.FileURL,
		ClientID:    wire.ClientID,
		Ciphertext:  ciphertext,
		MsgType:     wire.MsgType,
	}, nil
}

func validateGroupPayload(p models.GroupMessagePayload) error {
	if p.GroupID == "" {
		return fmt.Errorf("group_id is required")
	}
	if len(p.Content) == 0 && len(p.Ciphertext) == 0 {
		return fmt.Errorf("content or ciphertext is required")
	}
	if len(p.Ciphertext) > 0 && !isValidMessageType(p.MsgType) {
		return fmt.Errorf("msg_type must be prekey_message or signal_message")
	}
	return nil
}

// ----------------------------------------------------------------------------
// "typing" → TypingPayload
// ----------------------------------------------------------------------------

// handleTyping forwards a typing indicator. No ACK, no
// storage, no timestamp truncation. The presence service
// uses the indicator to update a per-conversation typing
// TTL; once the TTL expires the indicator is implicitly
// retracted.
func handleTyping(deps client.Deps, env models.Envelope) {
	var p models.TypingPayload
	if err := json.Unmarshal(env.Payload, &p); err != nil {
		// Typing indicators are best-effort; an
		// unparseable indicator is dropped without
		// notification to the sender.
		return
	}
	data, err := json.Marshal(env)
	if err != nil {
		return
	}
	if p.IsGroup && p.GroupID != "" {
		_ = deps.NATS.Publish("msg.group."+p.GroupID, data)
		return
	}
	if p.ConversationID != "" {
		// ConversationID is the same value used as the
		// Scylla partition key; we re-derive the
		// receiver from it for the NATS subject. The
		// gateway is intentionally not parsing the
		// conversation_id into (sender, receiver) — the
		// message-service does that. For typing we just
		// forward the envelope as-is.
		_ = deps.NATS.Publish("msg.direct."+p.ConversationID, data)
	}
}

// ----------------------------------------------------------------------------
// "read" → ReadPayload
// ----------------------------------------------------------------------------

// handleRead forwards a read receipt. The receipt's
// SenderUIN is the ORIGINAL sender of the message being
// marked read — i.e. the user the read-receipt flows
// back to. The message-service subscribes to
// `ack.<sender_uin>` and uses that to UPDATE the right
// row's status column.
//
// The client must include CreatedAt (the original
// message's minute-truncated timestamp) on the wire; the
// message-service's UPDATE statement requires it because
// the natural key is (conversation_id, created_at, id).
// A zero CreatedAt is rejected on the receiving side.
func handleRead(c *client.Client, deps client.Deps, env models.Envelope) {
	var p models.ReadPayload
	if err := json.Unmarshal(env.Payload, &p); err != nil {
		return
	}
	// Server-side fill: the reader is the authenticated
	// user. We do not trust a client-claimed reader_uin.
	p.ReaderUIN = c.UIN()
	// SenderUIN comes from the wire — the client
	// knows which message it's marking read, and
	// the original sender's UIN is on the message
	// envelope. We do not look it up; a missing
	// value (0) is rejected by the message-service
	// via the subject-tail check.
	// CreatedAt likewise comes from the wire
	// unchanged — it must match the minute-
	// truncated timestamp the gateway emitted at
	// original-send time. We do NOT re-truncate
	// here, because re-truncating a misaligned
	// value would silently produce a missed
	// UPDATE.
	// Rebuild the envelope with the corrected payload so
	// downstream consumers see the right reader.
	env.Payload = mustMarshalRaw(p)
	data, err := json.Marshal(env)
	if err != nil {
		return
	}
	// Publish to ack.<sender_uin> so the message-
	// service's `ack.*` subscriber lands on the
	// right routing. The message-service uses the
	// subject tail as a sanity check against the
	// payload's SenderUIN.
	if p.SenderUIN <= 0 {
		// No original sender — drop rather than
		// publish to ack.0 (which the message-
		// service would also drop, but logging
		// once is friendlier).
		return
	}
	subject := "ack." + itoa(p.SenderUIN)
	if p.IsGroup && p.GroupID != "" {
		// Group receipts carry the same per-row
		// state; the group_id is informational
		// for the message-service and used by
		// future fan-out paths.
		_ = deps.NATS.Publish(subject, data)
		return
	}
	_ = deps.NATS.Publish(subject, data)
}

// ----------------------------------------------------------------------------
// "presence" → PresencePayload
// ----------------------------------------------------------------------------

// handlePresence processes a presence update from a connected
// client. Validates the status, republishes to
// presence.update. The presence service's subscribers (in
// the gateway's main.go NATS handler block) then fan out to
// every accepted contact of the user.
func handlePresence(deps client.Deps, env models.Envelope) {
	var p models.PresencePayload
	if err := json.Unmarshal(env.Payload, &p); err != nil {
		return
	}
	switch p.Status {
	case models.PresenceStatusOnline,
		models.PresenceStatusAway,
		models.PresenceStatusDND,
		models.PresenceStatusOffline:
		// OK
	default:
		// Invalid status: drop without notification.
		// (Presence is fire-and-forget; the client can
		// observe its own state in the next frame.)
		return
	}
	p.TS = time.Now().UTC().Truncate(time.Minute).UnixMilli()
	data, err := json.Marshal(models.Envelope{
		Type:    models.EnvelopeTypePresence,
		ID:      uuid.NewString(),
		TS:      p.TS,
		Payload: mustMarshalRaw(p),
	})
	if err != nil {
		return
	}
	if err := deps.NATS.Publish("presence.update", data); err != nil {
		log.Printf("[ws-gateway] presence publish: %v", err)
	}
}

// ----------------------------------------------------------------------------
// "ping" → Pong
// ----------------------------------------------------------------------------

// handlePing responds to a client-initiated ping with a
// matching-id pong. No NATS, no storage. The ping/pong
// channel is the gateway's local keepalive: a client that
// wants to know the connection is still alive sends
// {type:"ping", id:"<uuid>"} and gets {type:"pong", id:
// "<same uuid>"} back. The gateway's readLoop also
// resets the read deadline on every frame, so a chatty
// client never gets kicked for idleness.
func handlePing(c *client.Client, env models.Envelope) {
	c.TrySend(mustMarshal(buildPongEnvelope(env.ID)))
}

func buildPongEnvelope(id string) models.Envelope {
	return models.Envelope{
		Type:    "pong",
		ID:      id,
		TS:      time.Now().UTC().UnixMilli(),
		Payload: mustMarshalRaw(map[string]any{}),
	}
}

// ----------------------------------------------------------------------------
// Small helpers. Kept local so the router file is the only
// place these idioms appear in the gateway.
// ----------------------------------------------------------------------------

// sendErrorFrame builds and pushes an error envelope to the
// client. The router never closes the connection on a bad
// frame; it tells the client it misbehaved and continues.
func sendErrorFrame(c *client.Client, code, message string) {
	env, _ := models.NewEnvelope(models.EnvelopeTypeError, models.ErrorPayload{
		Code:    code,
		Message: message,
	})
	c.TrySend(mustMarshal(env))
}

// mustMarshal is the router's local copy of the same helper
// in client.go. We duplicate it (rather than export from
// client) to keep the package boundary minimal: the router
// uses Client.TrySend but doesn't otherwise share internals.
func mustMarshal(env models.Envelope) []byte {
	b, err := json.Marshal(env)
	if err != nil {
		log.Printf("[ws-gateway] router: marshal: %v", err)
		return nil
	}
	return b
}

// mustMarshalRaw marshals a payload value to raw JSON.
// Used when we are building an Envelope manually (with a
// pre-minted ID) and don't want a second wrapping pass.
func mustMarshalRaw(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		log.Printf("[ws-gateway] router: marshal raw: %v", err)
		return json.RawMessage(`null`)
	}
	return b
}

// itoa is the local copy of the hub's int64-to-string helper.
// Kept local to avoid a circular import (the router does
// not import the hub package).
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
