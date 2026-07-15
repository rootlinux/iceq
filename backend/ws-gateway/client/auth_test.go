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

func TestParseAuthToken_RejectsConflictingAuthObjects(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"type":"auth","token":"one","payload":{"access_token":"two"}}`),
		[]byte(`{"type":"auth","payload":{"access_token":"one","token":"two"}}`),
	} {
		if _, err := parseAuthToken(raw); err == nil {
			t.Fatalf("parseAuthToken(%s) accepted conflicting token sources", raw)
		}
	}
}

func TestParseAuthToken_RejectsNonAuthObject(t *testing.T) {
	if _, err := parseAuthToken([]byte(`{"type":"message","token":"token"}`)); err == nil {
		t.Fatal("parseAuthToken accepted non-auth object")
	}
}
