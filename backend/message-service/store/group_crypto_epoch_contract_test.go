package store

import (
	"os"
	"strings"
	"testing"
)

func TestGroupMessageCryptoEpochPersistenceContract(t *testing.T) {
	src, err := os.ReadFile("messagestore.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	for _, want := range []string{
		"CryptoEpoch int64",
		"sender_uin, crypto_epoch, ciphertext, msg_type",
		"req.CryptoEpoch",
		"sender_uin, crypto_epoch, ciphertext, msg_type, expires_at\n\t  FROM iceq.group_messages",
		"&row.CryptoEpoch",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("group crypto epoch persistence contract missing %q", want)
		}
	}
}

func TestScyllaGroupCryptoEpochMigrationIsNonCollidingAndWired(t *testing.T) {
	migration, err := os.ReadFile("../../../deploy/init/migrations/010_group_message_crypto_epoch.cql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(migration), "ADD IF NOT EXISTS crypto_epoch BIGINT") {
		t.Fatal("migration must idempotently add group_messages.crypto_epoch")
	}

	initSchema, err := os.ReadFile("../../../deploy/init/scylla-init.cql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(initSchema), "crypto_epoch     BIGINT") {
		t.Fatal("fresh Scylla schema must define group_messages.crypto_epoch")
	}

	compose, err := os.ReadFile("../../../deploy/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"010_group_message_crypto_epoch.cql", "010-group-message-crypto-epoch.cql"} {
		if !strings.Contains(string(compose), want) {
			t.Fatalf("compose does not wire migration %q", want)
		}
	}
}
