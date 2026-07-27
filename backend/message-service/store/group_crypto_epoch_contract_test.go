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

// Scylla 5.4's CQL parser rejects "ALTER TABLE ... ADD IF NOT EXISTS col
// type" (confirmed against a live 5.4.9 node: "no viable alternative at
// input 'IF'"), unlike CREATE TABLE IF NOT EXISTS, which it does support.
// These migrations therefore use plain ADD, and retry-safety across
// restarts/redeploys is handled by the docker-compose.yml scylla-init
// wrapper, which tolerates the resulting "conflicts with an existing
// column" error instead of relying on CQL-level idempotency.
func TestScyllaGroupCryptoEpochMigrationIsNonCollidingAndWired(t *testing.T) {
	migration, err := os.ReadFile("../../../deploy/init/migrations/010_group_message_crypto_epoch.cql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(migration), "ADD crypto_epoch BIGINT") {
		t.Fatal("migration must add group_messages.crypto_epoch")
	}
	if strings.Contains(string(migration), "IF NOT EXISTS crypto_epoch") {
		t.Fatal("Scylla 5.4 does not support ALTER TABLE ADD IF NOT EXISTS; retry-safety must come from the scylla-init wrapper, not this clause")
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
	for _, want := range []string{"010_group_message_crypto_epoch.cql", "010-group-message-crypto-epoch.cql", "apply_tolerant_alter 010-group-message-crypto-epoch"} {
		if !strings.Contains(string(compose), want) {
			t.Fatalf("compose does not wire migration %q", want)
		}
	}
}

func TestGroupRecipientSnapshotMigrationIsRetrySafe(t *testing.T) {
	raw, err := os.ReadFile("../../../deploy/init/migrations/013_group_recipient_snapshot.cql")
	if err != nil {
		t.Fatal(err)
	}
	migration := string(raw)
	for _, statement := range []string{
		"ALTER TABLE iceq.message_ingest ADD recipient_uins LIST<BIGINT>;",
		"ALTER TABLE iceq.group_message_outbox ADD recipient_uins LIST<BIGINT>;",
	} {
		if !strings.Contains(migration, statement) {
			t.Fatalf("migration 013 missing statement %q", statement)
		}
	}
	if strings.Contains(migration, "IF NOT EXISTS") {
		t.Fatal("Scylla 5.4 does not support ALTER TABLE ADD IF NOT EXISTS")
	}

	compose, err := os.ReadFile("../../../deploy/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(compose), "apply_tolerant_alter 013-group-recipient-snapshot") {
		t.Fatal("compose must run migration 013 through the tolerant-retry wrapper for idempotency")
	}
}
