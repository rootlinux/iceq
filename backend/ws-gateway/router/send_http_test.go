package router

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/iceq/iceq/shared/middleware"
	"github.com/iceq/iceq/shared/models"
)

type publisherStub struct {
	calls   int
	subject string
	body    []byte
}

func (p *publisherStub) Publish(subject string, body []byte) error {
	p.calls++
	p.subject = subject
	p.body = body
	return nil
}

func TestHTTPSendBindsActorAndPublishesOpaqueEnvelopeOnce(t *testing.T) {
	pub := &publisherStub{}
	dedupe := &deduperStub{}
	payload := `{"conversation_id":"dm:7:42","sender_uin":999,"to_uin":42,"ciphertext":"` + base64.RawURLEncoding.EncodeToString([]byte("opaque")) + `","msg_type":"signal_message","client_id":"client-1"}`
	body := `{"type":"message","id":"wire-id","ts":1,"payload":` + payload + `}`
	req := httptest.NewRequest(http.MethodPost, "/send", strings.NewReader(body))
	req = req.WithContext(middleware.WithUIN(req.Context(), 7))
	rr := httptest.NewRecorder()
	NewSendHandler(SendDeps{Publisher: pub, Deduper: dedupe}).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if pub.calls != 1 || pub.subject != "msg.direct.42" {
		t.Fatalf("publish=%d subject=%q", pub.calls, pub.subject)
	}
	if dedupe.commits != 1 {
		t.Fatalf("ack returned before idempotency commit; commits=%d", dedupe.commits)
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

func TestHTTPSendReplayReturnsAckWithoutSecondPublish(t *testing.T) {
	pub := &publisherStub{}
	dedupe := &deduperStub{prior: "server-original", duplicate: true}
	body := `{"type":"message","id":"wire-id","ts":1,"payload":{"conversation_id":"dm:7:42","to_uin":42,"ciphertext":"b3BhcXVl","msg_type":"signal_message","client_id":"client-1"}}`
	req := httptest.NewRequest(http.MethodPost, "/send", strings.NewReader(body))
	req = req.WithContext(middleware.WithUIN(context.Background(), 7))
	rr := httptest.NewRecorder()
	NewSendHandler(SendDeps{Publisher: pub, Deduper: dedupe}).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || pub.calls != 0 {
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
		NewSendHandler(SendDeps{Publisher: &publisherStub{}, Deduper: &deduperStub{}}).ServeHTTP(rr, req)
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
	NewSendHandler(SendDeps{Publisher: &publisherStub{}, Deduper: &deduperStub{}}).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rr.Code)
	}
}
