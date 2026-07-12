package client

import "testing"

func TestParseAuthToken_AcceptsLegacyFrame(t *testing.T) {
	token, err := parseAuthToken([]byte(`{"type":"auth","token":"legacy-token"}`))
	if err != nil {
		t.Fatalf("parseAuthToken() error = %v, want nil", err)
	}
	if token != "legacy-token" {
		t.Fatalf("parseAuthToken() token = %q, want %q", token, "legacy-token")
	}
}

func TestParseAuthToken_AcceptsEnvelopePayload(t *testing.T) {
	token, err := parseAuthToken([]byte(`{"type":"auth","id":"1","ts":123,"payload":{"access_token":"payload-token"}}`))
	if err != nil {
		t.Fatalf("parseAuthToken() error = %v, want nil", err)
	}
	if token != "payload-token" {
		t.Fatalf("parseAuthToken() token = %q, want %q", token, "payload-token")
	}
}

func TestParseAuthToken_RejectsMissingToken(t *testing.T) {
	if _, err := parseAuthToken([]byte(`{"type":"auth","payload":{}}`)); err == nil {
		t.Fatal("parseAuthToken() error = nil, want non-nil")
	}
}
