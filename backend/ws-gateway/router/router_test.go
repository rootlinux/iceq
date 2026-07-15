package router

import (
	"encoding/base64"
	"testing"

	"github.com/iceq/iceq/shared/models"
)

func TestDecodeWireCiphertextAcceptsBase64URL(t *testing.T) {
	raw := []byte{0xff, 0xee, 0xdd, 0x00, 0x01}
	wire := base64.RawURLEncoding.EncodeToString(raw)

	got, err := decodeWireCiphertext(wire)
	if err != nil {
		t.Fatalf("decodeWireCiphertext returned error: %v", err)
	}
	if string(got) != string(raw) {
		t.Fatalf("decodeWireCiphertext mismatch: got %v want %v", got, raw)
	}
}

func TestValidateDirectPayloadAllowsCiphertextOnlyE2EEMessage(t *testing.T) {
	err := validateDirectPayload(models.DirectMessagePayload{
		ReceiverUIN: 99,
		Ciphertext:  []byte("ciphertext"),
		MsgType:     "prekey_message",
	})
	if err != nil {
		t.Fatalf("validateDirectPayload rejected ciphertext-only message: %v", err)
	}
}

func TestParseGroupPayloadAcceptsPlaintextContent(t *testing.T) {
	raw := []byte(`{"group_id":"7f0300f2-0494-4f61-9f41-7c198f73b2fa","sender_uin":7,"content":"hello group","content_type":"text","client_id":"c1"}`)

	got, err := parseGroupPayload(raw)
	if err != nil {
		t.Fatalf("parseGroupPayload returned error: %v", err)
	}
	if got.GroupID != "7f0300f2-0494-4f61-9f41-7c198f73b2fa" {
		t.Fatalf("GroupID mismatch: got %q", got.GroupID)
	}
	if got.Content != "hello group" {
		t.Fatalf("Content mismatch: got %q", got.Content)
	}
	if got.ClientID != "c1" {
		t.Fatalf("ClientID mismatch: got %q", got.ClientID)
	}
}

func TestParseGroupPayloadAcceptsCiphertextOnlyE2EEMessage(t *testing.T) {
	raw := []byte(`{"group_id":"7f0300f2-0494-4f61-9f41-7c198f73b2fa","content":"","content_type":"text","client_id":"c1","ciphertext":"Y2lwaGVy","msg_type":"prekey_message"}`)

	got, err := parseGroupPayload(raw)
	if err != nil {
		t.Fatalf("parseGroupPayload returned error: %v", err)
	}
	if string(got.Ciphertext) != "cipher" {
		t.Fatalf("Ciphertext mismatch: got %q", string(got.Ciphertext))
	}
	if got.MsgType != "prekey_message" {
		t.Fatalf("MsgType mismatch: got %q", got.MsgType)
	}
}

func TestValidateGroupPayloadRequiresContentOrCiphertext(t *testing.T) {
	err := validateGroupPayload(models.GroupMessagePayload{
		GroupID:     "7f0300f2-0494-4f61-9f41-7c198f73b2fa",
		ContentType: "text",
	})
	if err == nil || err.Error() != "content or ciphertext is required" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseDirectPayloadAcceptsToUINWireContract(t *testing.T) {
	raw := []byte(`{"conversation_id":"dm:7:42","sender_uin":7,"to_uin":42,"content":"","content_type":"text","client_id":"c1","ciphertext":"Y2lwaGVy","msg_type":"prekey_message"}`)

	got, err := parseDirectPayload(raw)
	if err != nil {
		t.Fatalf("parseDirectPayload returned error: %v", err)
	}
	if got.ReceiverUIN != 42 {
		t.Fatalf("ReceiverUIN mismatch: got %d want 42", got.ReceiverUIN)
	}
	if got.ToUIN != 42 {
		t.Fatalf("ToUIN mismatch: got %d want 42", got.ToUIN)
	}
	if string(got.Ciphertext) != "cipher" {
		t.Fatalf("Ciphertext mismatch: got %q", string(got.Ciphertext))
	}
}

func TestValidateDirectPayloadRejectsMissingBody(t *testing.T) {
	err := validateDirectPayload(models.DirectMessagePayload{ReceiverUIN: 99})
	if err == nil || err.Error() != "content or ciphertext is required" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthorizeDirectConversationRejectsForeignOrMismatchedObject(t *testing.T) {
	tests := []models.DirectMessagePayload{
		{ConversationID: "dm:7:99", ReceiverUIN: 42},
		{ConversationID: "dm:42:99", ReceiverUIN: 42},
		{ConversationID: "dm:42:7", ReceiverUIN: 42},
	}
	for _, payload := range tests {
		if authorizeDirectConversation(payload, 7) == nil {
			t.Fatalf("authorized mismatched payload: %+v", payload)
		}
	}
}

func TestAuthorizeDirectConversationAcceptsCanonicalTwoUserObject(t *testing.T) {
	if err := authorizeDirectConversation(models.DirectMessagePayload{
		ConversationID: "dm:7:42",
		ReceiverUIN:    42,
	}, 7); err != nil {
		t.Fatalf("canonical conversation rejected: %v", err)
	}
}

func TestForwardDirectPayloadPreservesCiphertextAndMsgType(t *testing.T) {
	in := models.DirectMessagePayload{
		ConversationID: "dm:7:42",
		ReceiverUIN:    42,
		ContentType:    "text",
		ClientID:       "optimistic-id",
		Ciphertext:     []byte("ciphertext"),
		MsgType:        "signal_message",
	}

	got := forwardDirectPayload(in, 7)

	if got.SenderUIN != 7 {
		t.Fatalf("SenderUIN mismatch: got %d want 7", got.SenderUIN)
	}
	if got.ClientID != "optimistic-id" {
		t.Fatalf("ClientID mismatch: got %q", got.ClientID)
	}
	if string(got.Ciphertext) != "ciphertext" {
		t.Fatalf("Ciphertext mismatch: got %q", string(got.Ciphertext))
	}
	if got.MsgType != "signal_message" {
		t.Fatalf("MsgType mismatch: got %q", got.MsgType)
	}
}

func TestAckMessageIDPrefersClientIDForOptimisticUI(t *testing.T) {
	if got := ackMessageID("server-id", "optimistic-id"); got != "optimistic-id" {
		t.Fatalf("ackMessageID mismatch: got %q want %q", got, "optimistic-id")
	}
}

func TestAckMessageIDFallsBackToServerID(t *testing.T) {
	if got := ackMessageID("server-id", ""); got != "server-id" {
		t.Fatalf("ackMessageID mismatch: got %q want %q", got, "server-id")
	}
}

func TestEnvelopeTypesMatchWebWireContract(t *testing.T) {
	if models.EnvelopeTypeDirect != "message" {
		t.Fatalf("EnvelopeTypeDirect mismatch: got %q want %q", models.EnvelopeTypeDirect, "message")
	}
	if models.EnvelopeTypeGroup != "group_msg" {
		t.Fatalf("EnvelopeTypeGroup mismatch: got %q want %q", models.EnvelopeTypeGroup, "group_msg")
	}
}

func TestBuildPongEnvelopeUsesPongTypeAndEchoesID(t *testing.T) {
	got := buildPongEnvelope("ping-123")

	if got.Type != "pong" {
		t.Fatalf("pong type mismatch: got %q want %q", got.Type, "pong")
	}
	if got.ID != "ping-123" {
		t.Fatalf("pong id mismatch: got %q want %q", got.ID, "ping-123")
	}
	if got.TS == 0 {
		t.Fatal("pong timestamp was not populated")
	}
}
