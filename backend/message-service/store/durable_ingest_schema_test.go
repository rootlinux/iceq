package store

import (
	"os"
	"strings"
	"testing"
)

func TestDurableIngestMigrationDefinesAuthenticatedReceiptAndOutbox(t *testing.T) {
	raw, err := os.ReadFile("../../../deploy/init/migrations/012_durable_message_ingest.cql")
	if err != nil {
		t.Fatal(err)
	}
	schema := string(raw)
	normalized := strings.Join(strings.Fields(schema), " ")
	for _, required := range []string{
		"CREATE TABLE IF NOT EXISTS iceq.message_ingest",
		"PRIMARY KEY ((sender_uin, client_id))",
		"receiver_uin BIGINT",
		"conversation_id TEXT",
		"envelope BLOB",
		"envelope_hash BLOB",
		"owner_token UUID",
		"lease_until TIMESTAMP",
		"state TEXT",
		"CREATE TABLE IF NOT EXISTS iceq.message_outbox",
		"PRIMARY KEY ((bucket), created_at, message_id)",
		"CREATE TABLE IF NOT EXISTS iceq.group_message_outbox",
		"bucket TINYINT",
	} {
		if !strings.Contains(normalized, required) {
			t.Errorf("migration missing %q", required)
		}
	}
	if strings.Contains(strings.ToUpper(schema), "DEFAULT_TIME_TO_LIVE") {
		t.Fatal("schema-level TTL would make the explicit off policy impossible")
	}
}

func TestScyllaDurableStoreUsesOwnerCASAndLoggedOutboxBatch(t *testing.T) {
	raw, err := os.ReadFile("durable_ingest_scylla.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, required := range []string{
		"IF state = ? AND owner_token = ? AND lease_until = ?",
		"gocql.LoggedBatch",
		"INSERT INTO iceq.message_outbox",
		"INSERT INTO iceq.group_message_outbox",
		"DELETE FROM iceq.message_outbox",
		"DELETE FROM iceq.group_message_outbox",
		"USING TTL ?",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("Scylla implementation missing %q", required)
		}
	}
	outboxRaw, err := os.ReadFile("durable_outbox.go")
	if err != nil {
		t.Fatal(err)
	}
	outboxSource := string(outboxRaw)
	for _, required := range []string{"FetchPending", "WHERE bucket = ? LIMIT ?", "maxPendingOutboxFetch = 100"} {
		if !strings.Contains(outboxSource, required) {
			t.Errorf("outbox recovery implementation missing %q", required)
		}
	}
}
