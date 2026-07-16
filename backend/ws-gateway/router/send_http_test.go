package router

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/iceq/iceq/shared/middleware"
	"github.com/iceq/iceq/shared/models"
)

type publisherStub struct {
	calls   int
	subject string
	body    []byte
	err     error
	reply   []byte
}

func (p *publisherStub) Publish(subject string, body []byte) error {
	p.calls++
	p.subject = subject
	p.body = body
	return nil
}
func (p *publisherStub) Request(subject string, body []byte, _ time.Duration) ([]byte, error) {
	p.calls++
	p.subject = subject
	p.body = body
	if p.err != nil {
		return nil, p.err
	}
	if p.reply != nil {
		return p.reply, nil
	}
	var env models.Envelope
	_ = json.Unmarshal(body, &env)
	var clientID string
	recipient := int64(0)
	if env.Type == models.EnvelopeTypeDirect {
		var payload models.DirectMessagePayload
		_ = json.Unmarshal(env.Payload, &payload)
		clientID, recipient = payload.ClientID, payload.ReceiverUIN
	} else {
		var payload models.GroupMessagePayload
		_ = json.Unmarshal(env.Payload, &payload)
		clientID = payload.ClientID
	}
	ack, _ := models.NewEnvelope(models.EnvelopeTypeAck, models.AckPayload{MessageID: clientID, State: models.AckStatePersisted, RecipientUIN: recipient})
	return json.Marshal(ack)
}

func TestHTTPSendDoesNotDependOnGatewayRedisCommit(t *testing.T) {
	// There is deliberately no Redis/deduper dependency here: a persisted ACK
	// comes only from the durable message-service request/reply boundary.
	ingest := &publisherStub{}
	body := `{"type":"message","payload":{"conversation_id":"dm:7:42","to_uin":42,"ciphertext":"YQ","msg_type":"signal_message","client_id":"durable-client"}}`
	req := httptest.NewRequest(http.MethodPost, "/send", strings.NewReader(body))
	req = req.WithContext(middleware.WithUIN(req.Context(), 7))
	rr := httptest.NewRecorder()
	NewSendHandler(SendDeps{Ingester: ingest}).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || ingest.calls != 1 {
		t.Fatalf("status=%d requests=%d body=%s", rr.Code, ingest.calls, rr.Body.String())
	}
}

func TestHTTPSendRejectsNonDurableIngestReply(t *testing.T) {
	bad, _ := models.NewEnvelope(models.EnvelopeTypeAck, models.AckPayload{MessageID: "c", State: models.AckStateDelivered})
	reply, _ := json.Marshal(bad)
	ingest := &publisherStub{reply: reply}
	body := `{"type":"message","payload":{"conversation_id":"dm:7:42","to_uin":42,"ciphertext":"YQ","msg_type":"signal_message","client_id":"c"}}`
	req := httptest.NewRequest(http.MethodPost, "/send", strings.NewReader(body))
	req = req.WithContext(middleware.WithUIN(req.Context(), 7))
	rr := httptest.NewRecorder()
	NewSendHandler(SendDeps{Ingester: ingest}).ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHTTPSendBindsActorAndPublishesOpaqueEnvelopeOnce(t *testing.T) {
	pub := &publisherStub{}
	payload := `{"conversation_id":"dm:7:42","sender_uin":999,"to_uin":42,"ciphertext":"` + base64.RawURLEncoding.EncodeToString([]byte("opaque")) + `","msg_type":"signal_message","client_id":"client-1"}`
	body := `{"type":"message","id":"wire-id","ts":1,"payload":` + payload + `}`
	req := httptest.NewRequest(http.MethodPost, "/send", strings.NewReader(body))
	req = req.WithContext(middleware.WithUIN(req.Context(), 7))
	rr := httptest.NewRecorder()
	NewSendHandler(SendDeps{Ingester: pub}).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if pub.calls != 1 || pub.subject != durableIngestSubject {
		t.Fatalf("publish=%d subject=%q", pub.calls, pub.subject)
	}
	var forwarded models.Envelope
	if err := json.Unmarshal(pub.body, &forwarded); err != nil {
		t.Fatal(err)
	}
	var got models.DirectMessagePayload
	if err := json.Unmarshal(forwarded.Payload, &got); err != nil {
		t.Fatal(err)
	}
	if got.SenderUIN != 7 {
		t.Fatalf("trusted sender=%d", got.SenderUIN)
	}
	if string(got.Ciphertext) != "opaque" {
		t.Fatal("ciphertext changed")
	}
}

func TestHTTPSendReturnsOnlyDurableIngestAck(t *testing.T) {
	pub := &publisherStub{}
	body := `{"type":"message","id":"wire-id","ts":1,"payload":{"conversation_id":"dm:7:42","to_uin":42,"ciphertext":"b3BhcXVl","msg_type":"signal_message","client_id":"client-1"}}`
	req := httptest.NewRequest(http.MethodPost, "/send", strings.NewReader(body))
	req = req.WithContext(middleware.WithUIN(context.Background(), 7))
	rr := httptest.NewRecorder()
	NewSendHandler(SendDeps{Ingester: pub}).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || pub.calls != 1 {
		t.Fatalf("status=%d publish=%d", rr.Code, pub.calls)
	}
}

func TestHTTPSendRequiresAuthAndRejectsPlaintext(t *testing.T) {
	for _, tc := range []struct {
		auth bool
		want int
	}{{false, http.StatusUnauthorized}, {true, http.StatusBadRequest}} {
		req := httptest.NewRequest(http.MethodPost, "/send", strings.NewReader(`{"type":"message","id":"x","ts":1,"payload":{"conversation_id":"dm:7:42","to_uin":42,"content":"plaintext","client_id":"c"}}`))
		if tc.auth {
			req = req.WithContext(middleware.WithUIN(req.Context(), 7))
		}
		rr := httptest.NewRecorder()
		NewSendHandler(SendDeps{Ingester: &publisherStub{}}).ServeHTTP(rr, req)
		if rr.Code != tc.want {
			t.Fatalf("auth=%v status=%d", tc.auth, rr.Code)
		}
	}
}

func TestHTTPSendRejectsTrailingJSONValues(t *testing.T) {
	body := `{"type":"message","id":"x","ts":1,"payload":{"conversation_id":"dm:7:42","to_uin":42,"ciphertext":"YQ","msg_type":"signal_message","client_id":"c"}} {}`
	req := httptest.NewRequest(http.MethodPost, "/send", strings.NewReader(body))
	req = req.WithContext(middleware.WithUIN(req.Context(), 7))
	rr := httptest.NewRecorder()
	NewSendHandler(SendDeps{Ingester: &publisherStub{}}).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rr.Code)
	}
}
