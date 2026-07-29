//go:build integration
// +build integration

// Package handlers — acceptance coverage for the wiped_accounts marker's
// full lifecycle: created inside PanicWipe's own transaction (the primary
// path, see queries.go's qInsertWipedAccountMarker and panicwipe.go), still
// present while the wipe job sits unclaimed, correctly fails closed every
// wiped_accounts-aware check in the meantime, and is gone once the worker's
// final erasure completes. Gated by the same ICEQ_ACCEPTANCE=1 opt-in as
// the rest of this file's disposable acceptance suite; like
// TestAcceptanceGroupRecipientWipeTTLBehavior and the counterpart-orphan
// tests, this only needs Postgres and Redis -- no Scylla, NATS, or MinIO.
package handlers

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// TestPanicWipeMarksWipedAccountBeforeWorkerClaimsJob proves the marker's
// lifetime brackets the wipe job's own lifetime, not the worker's polling
// cadence: it exists immediately after PanicWipe's transaction commits
// (before the worker has run at all), every wiped_accounts-aware check
// (BearerAuth-style, DM history-style, group history-style) already fails
// closed for the erased uin during that gap, an unrelated LIVE uin is never
// caught by the same checks, and the marker together with every other row
// is gone once the worker completes final erasure.
func TestPanicWipeMarksWipedAccountBeforeWorkerClaimsJob(t *testing.T) {
	requireAcceptanceEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pgPool, err := pgxpool.New(ctx, acceptancePGURL(t))
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	defer pgPool.Close()
	applyAcceptanceSchema(t, pgPool)

	rdb := redis.NewClient(&redis.Options{Addr: acceptanceRedisAddr(t), Password: os.Getenv("ICEQ_ACCEPTANCE_REDIS_PASSWORD")})
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Fatalf("Redis unreachable at %s: %v", acceptanceRedisAddr(t), err)
	}
	defer rdb.Close()

	const (
		testUin       = int64(930001) // gets wiped
		otherLiveUin  = int64(930002) // survives; proves the checks never false-positive on a live user
	)
	t.Cleanup(func() {
		pgPool.Exec(ctx, `DELETE FROM wiped_accounts WHERE uin = ANY($1)`, []int64{testUin, otherLiveUin})
		pgPool.Exec(ctx, `DELETE FROM wipe_jobs WHERE uin = $1`, testUin)
		pgPool.Exec(ctx, `DELETE FROM users WHERE uin = ANY($1)`, []int64{testUin, otherLiveUin})
		rdb.Del(ctx, "jwt:blocklist:wipe:"+itoa(testUin))
	})

	for _, u := range []int64{testUin, otherLiveUin} {
		if _, err := pgPool.Exec(ctx, `INSERT INTO users (uin, username, password_hash, identity_key)
			VALUES ($1, $2, '$2a$10$placeholder', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=')
			ON CONFLICT (uin) DO NOTHING`, u, "acceptance_marker_"+itoa(u)); err != nil {
			t.Fatalf("seed user %d: %v", u, err)
		}
	}

	// --- Submit the wipe directly (PanicWipe itself is the unit under
	// test; the HTTP/challenge-signature boundary is already covered by
	// TestAcceptanceFullStack). No worker goroutine is started, so the job
	// stays unclaimed until this test explicitly runs one -- that is the
	// "pause" the scenario needs.
	deps := PanicWipeDeps{Pool: pgPool, Redis: rdb} // Scylla/NATS/Minio nil: worker will skip those phases.
	jobID, err := PanicWipe(ctx, deps, testUin)
	if err != nil {
		t.Fatalf("PanicWipe: %v", err)
	}

	// --- The job must still be unclaimed: nothing has polled yet. ---
	var jobStatus string
	if err := pgPool.QueryRow(ctx, `SELECT status FROM wipe_jobs WHERE id = $1`, jobID).Scan(&jobStatus); err != nil {
		t.Fatalf("check wipe_jobs status: %v", err)
	}
	if jobStatus != "pending" {
		t.Fatalf("job status = %q immediately after PanicWipe, want pending (no worker has claimed it yet)", jobStatus)
	}

	// --- The marker must already exist, before any claim. ---
	var wiped bool
	if err := pgPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM wiped_accounts WHERE uin = $1)`, testUin).Scan(&wiped); err != nil {
		t.Fatalf("check wiped_accounts: %v", err)
	}
	if !wiped {
		t.Fatal("wiped_accounts marker must exist immediately after PanicWipe's transaction commits, before any worker claim")
	}

	// --- BearerAuth-style check (shared/jwt's IsAccountWiped runs this
	// exact query) already fails closed for the erased uin. ---
	var bearerStyleWiped bool
	if err := pgPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM wiped_accounts WHERE uin = $1)`, testUin).Scan(&bearerStyleWiped); err != nil {
		t.Fatalf("bearer-style wiped check: %v", err)
	}
	if !bearerStyleWiped {
		t.Fatal("BearerAuth's IsAccountWiped-style check must already fail closed before any worker has run")
	}

	// --- DM history-style check (message-service's isAccountWiped runs
	// this exact query against the conversation peer) already fails
	// closed too.
	var dmStyleWiped bool
	if err := pgPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM wiped_accounts WHERE uin = $1)`, testUin).Scan(&dmStyleWiped); err != nil {
		t.Fatalf("DM-history-style wiped check: %v", err)
	}
	if !dmStyleWiped {
		t.Fatal("DM history's wiped_accounts check must already fail closed for the erased peer before any worker has run")
	}

	// --- Group history-style batched check (message-service's
	// wipedUINsAmong runs this exact ANY($1) query against every distinct
	// sender on a page) flags the erased sender and NEVER the unrelated
	// live one.
	groupRows, err := pgPool.Query(ctx, `SELECT uin FROM wiped_accounts WHERE uin = ANY($1)`, []int64{testUin, otherLiveUin})
	if err != nil {
		t.Fatalf("group-history-style batched wiped check: %v", err)
	}
	groupWiped := map[int64]bool{}
	for groupRows.Next() {
		var u int64
		if err := groupRows.Scan(&u); err != nil {
			groupRows.Close()
			t.Fatalf("scan group-history-style row: %v", err)
		}
		groupWiped[u] = true
	}
	if err := groupRows.Err(); err != nil {
		t.Fatalf("iterate group-history-style rows: %v", err)
	}
	groupRows.Close()
	if !groupWiped[testUin] {
		t.Fatal("group-history-style batched check must flag the erased sender before any worker has run")
	}
	if groupWiped[otherLiveUin] {
		t.Fatal("group-history-style batched check must NEVER flag an unrelated LIVE sender -- only the erased user's own uin")
	}

	// --- Now run the worker to completion (Scylla/NATS/Minio are nil on
	// the runner, so those phases are skipped; only PG final erasure and
	// Redis cleanup run). ---
	runner := &WipeJobRunner{
		Pool:         pgPool,
		Redis:        NewRedisWipeCleaner(rdb),
		LeaseTimeout: 30 * time.Second,
		WorkerID:     "acceptance-marker-lifecycle",
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		runner.processOneJob(ctx)
		var remaining int
		if err := pgPool.QueryRow(ctx, `SELECT COUNT(*) FROM wipe_jobs WHERE id = $1`, jobID).Scan(&remaining); err != nil {
			t.Fatalf("poll wipe_jobs: %v", err)
		}
		if remaining == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %d did not complete within 30s", jobID)
		}
		time.Sleep(200 * time.Millisecond)
	}

	// --- Marker gone, no permanent record survives cleanup. ---
	var wipedAfter bool
	if err := pgPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM wiped_accounts WHERE uin = $1)`, testUin).Scan(&wipedAfter); err != nil {
		t.Fatalf("check wiped_accounts after completion: %v", err)
	}
	if wipedAfter {
		t.Error("wiped_accounts marker survives after cleanup completes -- no permanent record must remain")
	}
	var userCount int
	pgPool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE uin = $1`, testUin).Scan(&userCount)
	if userCount != 0 {
		t.Error("users row survives after cleanup completes")
	}

	// --- The unrelated live user is completely unaffected throughout. ---
	var otherExists bool
	pgPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE uin = $1)`, otherLiveUin).Scan(&otherExists)
	if !otherExists {
		t.Error("unrelated live user's row was deleted by testUin's wipe")
	}
	var otherWiped bool
	pgPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM wiped_accounts WHERE uin = $1)`, otherLiveUin).Scan(&otherWiped)
	if otherWiped {
		t.Error("unrelated live user was incorrectly marked wiped at any point")
	}
}
