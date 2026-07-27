package router

import (
	"github.com/iceq/iceq/shared/models"
	"testing"
)

func TestGroupCiphertextRequiresVersionedCurrentEpochFields(t *testing.T) {
	good := models.GroupMessagePayload{GroupID: "7f0300f2-0494-4f61-9f41-7c198f73b2fa", ClientID: "client-1", CryptoVersion: 1, CryptoEpoch: 4, Ciphertext: []byte("opaque"), MsgType: "group_ciphertext", ContentType: "text", ExpiresInSeconds: 3600}
	if err := validateGroupPayload(good); err != nil {
		t.Fatalf("valid sender key payload rejected: %v", err)
	}
	for _, mutate := range []func(*models.GroupMessagePayload){func(p *models.GroupMessagePayload) { p.CryptoVersion = 0 }, func(p *models.GroupMessagePayload) { p.CryptoEpoch = 0 }, func(p *models.GroupMessagePayload) { p.MsgType = "signal_message" }, func(p *models.GroupMessagePayload) { p.Content = "plaintext" }} {
		p := good
		mutate(&p)
		if validateGroupPayload(p) == nil {
			t.Fatalf("invalid group crypto payload accepted: %+v", p)
		}
	}
}
