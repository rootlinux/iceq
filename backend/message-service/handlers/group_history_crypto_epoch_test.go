package handlers

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/gocql/gocql"
	"github.com/iceq/iceq/message-service/store"
)

func TestGroupHistoryExposesPersistedCryptoEpoch(t *testing.T) {
	row := store.GroupMessageRow{
		GroupID: gocql.TimeUUID(), ID: gocql.TimeUUID(), SenderUIN: 42,
		CryptoEpoch: 7, Ciphertext: []byte("opaque"), MsgType: "group_ciphertext", CreatedAt: time.Now(),
	}
	wire := groupRowToMessage("", row.GroupID.String(), row)
	if wire.CryptoEpoch == nil || *wire.CryptoEpoch != 7 {
		t.Fatalf("crypto_epoch=%v, want 7", wire.CryptoEpoch)
	}
	b, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["crypto_epoch"] != float64(7) {
		t.Fatalf("history JSON crypto_epoch=%v, want 7", decoded["crypto_epoch"])
	}
}

func TestDirectHistoryDoesNotExposeGroupCryptoEpoch(t *testing.T) {
	row := store.MessageRow{ID: gocql.TimeUUID()}
	b, err := json.Marshal(dmRowToMessage("dm:1:2", "", row))
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, present := decoded["crypto_epoch"]; present {
		t.Fatalf("direct history must not expose group-only crypto_epoch: %s", b)
	}
}

func TestGroupHistoryMakesLegacyZeroEpochExplicitForFailClosedClient(t *testing.T) {
	row := store.GroupMessageRow{GroupID: gocql.TimeUUID(), ID: gocql.TimeUUID(), SenderUIN: 42}
	b, err := json.Marshal(groupRowToMessage("", row.GroupID.String(), row))
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	epoch, present := decoded["crypto_epoch"]
	if !present || epoch != float64(0) {
		t.Fatalf("legacy row must expose crypto_epoch=0, got present=%v value=%v", present, epoch)
	}
}
