// Package handlers — shared PostgreSQL schema bootstrap for tests.
//
// Unlike applyAcceptanceSchema (panicwipe_acceptance_test.go, gated behind
// the "integration" build tag), this file carries no build tag: it is
// visible to every test in the package, tagged or not. That matters because
// Go compiles a package's test binary from all applicable files together —
// an untagged file that referenced a symbol defined only in a
// tagged file would fail to compile whenever that tag is absent. Any test
// helper that must work under plain `go test ./...` (no -tags=integration)
// has to live here instead.
package handlers

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// pgMigrationFiles lists the production PostgreSQL migrations (relative to
// deploy/init/migrations) in application order. Scylla-only *.cql migrations
// are intentionally excluded.
var pgMigrationFiles = []string{
	"001_session_epoch.sql",
	"002_prekey_bundle_registration_id.sql",
	"003_contacts_requested_by.sql",
	"005_wiped_accounts.sql",
	"006_file_object_owners.sql",
	"007_file_object_grants.sql",
	"008_group_crypto_epoch.sql",
	"009_sender_key_distribution_inbox.sql",
	"014_panic_wipe_pin.sql",
	"015_wipe_public_key.sql",
	"016_wipe_jobs.sql",
}

// ensurePostgresSchema applies the real production base schema
// (deploy/init/postgres-init.sql) and migration files against pool if they
// are not already present. Matches the production fresh-volume bootstrap
// order: the base schema runs first, then migrations, exactly as a real
// deployment applies them.
//
// Safe to call repeatedly against the same live connection: the base schema
// is guarded by a users-table existence check, and every file in
// pgMigrationFiles uses idempotent DDL (IF NOT EXISTS / duplicate_object
// guards) — confirmed by inspection of all eleven files. This function does
// not delete or modify any existing rows.
func ensurePostgresSchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var usersTable *string
	if err := pool.QueryRow(ctx, `SELECT to_regclass('public.users')::text`).Scan(&usersTable); err != nil {
		t.Fatalf("inspect PG base schema: %v", err)
	}
	if usersTable == nil {
		basePath := "../../../deploy/init/postgres-init.sql"
		baseRaw, err := os.ReadFile(basePath)
		if err != nil {
			t.Fatalf("read PG base schema %s: %v", basePath, err)
		}
		if _, err := pool.Exec(ctx, string(baseRaw)); err != nil {
			t.Fatalf("apply PG base schema %s: %v", basePath, err)
		}
	}

	migrationDir := "../../../deploy/init/migrations"
	for _, filename := range pgMigrationFiles {
		path := migrationDir + "/" + filename
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read PG migration %s: %v", path, err)
		}
		if _, err := pool.Exec(ctx, string(raw)); err != nil {
			t.Fatalf("apply PG migration %s: %v", filename, err)
		}
	}
	t.Log("PostgreSQL schema ready (base + migrations)")
}
