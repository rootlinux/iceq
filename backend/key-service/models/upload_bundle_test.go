package models

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	validKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	validSig = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

func TestUploadBundleRequestAcceptsFrontendBundleShape(t *testing.T) {
	body := `{
		"identity_key":"` + validKey + `",
		"signed_pre_key":{"id":1,"public_key":"` + validKey + `","signature":"` + validSig + `"},
		"one_time_pre_keys":[{"id":2,"public_key":"` + validKey + `"}],
		"registration_id":77
	}`

	dec := json.NewDecoder(strings.NewReader(body))
	dec.DisallowUnknownFields()

	var req UploadBundleRequest
	if err := dec.Decode(&req); err != nil {
		t.Fatalf("decode frontend bundle shape: %v", err)
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("validate frontend bundle shape: %v", err)
	}
	if got := len(req.OneTimePrekeys); got != 1 {
		t.Fatalf("one-time prekey count = %d, want 1", got)
	}
	if req.RegistrationID != 77 {
		t.Fatalf("registration_id = %d, want 77", req.RegistrationID)
	}
}

func TestBundleResponseUsesFrontendFieldNames(t *testing.T) {
	resp := BundleResponse{
		UIN:         1001,
		IdentityKey: validKey,
		SignedPrekey: SignedPrekey{
			ID:        1,
			PublicKey: validKey,
			Signature: validSig,
		},
		OneTimePrekey:  &OneTimePrekey{ID: 2, PublicKey: validKey},
		RegistrationID: 77,
	}

	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal bundle response: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal bundle response: %v", err)
	}

	for _, key := range []string{"signed_pre_key", "pre_key", "registration_id"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("response missing %q: %s", key, raw)
		}
	}
	for _, key := range []string{"signed_prekey", "one_time_prekey"} {
		if _, ok := got[key]; ok {
			t.Fatalf("response unexpectedly contains %q: %s", key, raw)
		}
	}
}
