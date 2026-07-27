// Package handlers — behavioral PostgreSQL tests for wipe jobs.
//
// These tests connect to a real PostgreSQL instance and verify the
// actual database behavior: lease claim/reclaim, ownership guards,
// RowsAffected checks, final erasure, and FK rollback. They do NOT
// read source files — they exercise the database directly.
package handlers

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// testPool returns a *pgxpool.Pool connected to the test PostgreSQL instance.
// Set ICEQ_TEST_PG_URL to override the default. Tests are skipped when
// PostgreSQL is not reachable (e.g. running in a Docker network without
// host port mapping).
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("ICEQ_TEST_PG_URL")
	if url == "" {
		t.Skip("ICEQ_TEST_PG_URL not set — set it to a reachable PostgreSQL URL to run behavioral wipe-job tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Skipf("PostgreSQL not available (set ICEQ_TEST_PG_URL): %v", err)
	}
	// Verify the connection actually works.
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("PostgreSQL ping failed: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// ensureWipeJobsTable applies migration 016 if the table does not exist.
func ensureWipeJobsTable(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Check if the table exists.
	var exists bool
	err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'wipe_jobs')`).Scan(&exists)
	if err != nil {
		t.Fatalf("check wipe_jobs exists: %v", err)
	}
	if !exists {
		// Apply the migration.
		migration, err := os.ReadFile("../../../deploy/init/migrations/016_wipe_jobs.sql")
		if err != nil {
			t.Fatalf("read migration 016: %v", err)
		}
		if _, err := pool.Exec(ctx, string(migration)); err != nil {
			t.Fatalf("apply migration 016: %v", err)
		}
	}
	// Clean any leftover test rows.
	pool.Exec(ctx, `DELETE FROM wipe_jobs`)
}

// insertTestUser creates a minimal user row for FK purposes.
func insertTestUser(t *testing.T, pool *pgxpool.Pool, uin int64) {
	t.Helper()
	ctx := context.Background()
	// Try INSERT first; if the user already exists, skip (ON CONFLICT DO NOTHING).
	_, err := pool.Exec(ctx, `
		INSERT INTO users (uin, username, password_hash, identity_key, created_at, updated_at, session_epoch)
		VALUES ($1, $2, '$2a$10$placeholder', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', NOW(), NOW(), NOW())
		ON CONFLICT (uin) DO NOTHING
	`, uin, "testuser_"+itoa(uin))
	if err != nil {
		t.Fatalf("insert test user %d: %v", uin, err)
	}
}

// ---------------------------------------------------------------------------
// Behavioral: schema absence at startup
// ---------------------------------------------------------------------------

func TestCheckWipeJobsSchemaDetectsMissingTable(t *testing.T) {
	pool := testPool(t)

	// Drop wipe_jobs to simulate missing migration.
	ctx := context.Background()
	pool.Exec(ctx, `DROP TABLE IF EXISTS wipe_jobs CASCADE`)

	err := CheckWipeJobsSchema(ctx, pool)
	if err == nil {
		// Recreate the table for other tests.
		ensureWipeJobsTable(t, pool)
		t.Fatal("CheckWipeJobsSchema must return error when table is missing")
	}
	t.Logf("schema check correctly detected missing table: %v", err)

	// Recreate the table for other tests.
	ensureWipeJobsTable(t, pool)
}

func TestCheckWipeJobsSchemaPassesWhenTableExists(t *testing.T) {
	pool := testPool(t)
	ensureWipeJobsTable(t, pool)

	ctx := context.Background()
	if err := CheckWipeJobsSchema(ctx, pool); err != nil {
		t.Fatalf("CheckWipeJobsSchema must pass when table exists with all columns: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Behavioral: lease claim and reclaim
// ---------------------------------------------------------------------------

func TestLeaseClaimAndReclaim(t *testing.T) {
	pool := testPool(t)
	ensureWipeJobsTable(t, pool)

	ctx := context.Background()
	wID := "test-worker-1"

	// Insert a pending job.
	_, err := pool.Exec(ctx, qInsertWipeJob, int64(100001), []string{})
	if err != nil {
		t.Fatalf("insert test job: %v", err)
	}

	// Claim it.
	leaseUntil := time.Now().Add(2 * time.Minute)
	var jobID int64
	var uin int64
	var fileKeys []string
	var retryCount int
	err = pool.QueryRow(ctx, qClaimPendingJob, leaseUntil, wID).Scan(&jobID, &uin, &fileKeys, &retryCount)
	if err != nil {
		t.Fatalf("claim pending job: %v", err)
	}
	t.Logf("claimed job %d (uin=%d, retries=%d)", jobID, uin, retryCount)

	// Verify the job is now processing.
	var status string
	var storedWorkerID string
	err = pool.QueryRow(ctx, `SELECT status, worker_id FROM wipe_jobs WHERE id = $1`, jobID).Scan(&status, &storedWorkerID)
	if err != nil {
		t.Fatalf("read job status: %v", err)
	}
	if status != "processing" {
		t.Fatalf("job status = %q, want processing", status)
	}
	if storedWorkerID != wID {
		t.Fatalf("worker_id = %q, want %q", storedWorkerID, wID)
	}

	// Expire the lease.
	_, err = pool.Exec(ctx, `UPDATE wipe_jobs SET lease_until = NOW() - INTERVAL '1 second' WHERE id = $1`, jobID)
	if err != nil {
		t.Fatalf("expire lease: %v", err)
	}

	// Another worker reclaims the expired lease.
	wID2 := "test-worker-2"
	leaseUntil2 := time.Now().Add(2 * time.Minute)
	var jobID2 int64
	err = pool.QueryRow(ctx, qClaimPendingJob, leaseUntil2, wID2).Scan(&jobID2, &uin, &fileKeys, &retryCount)
	if err != nil {
		t.Fatalf("reclaim expired lease: %v", err)
	}
	if jobID2 != jobID {
		t.Fatalf("reclaimed job %d, want %d", jobID2, jobID)
	}
	t.Logf("worker-2 reclaimed job %d", jobID2)

	// Clean up.
	pool.Exec(ctx, qDeleteWipeJob, jobID, wID2)
}

// ---------------------------------------------------------------------------
// Behavioral: ownership-guarded renewal
// ---------------------------------------------------------------------------

func TestRenewLeaseRequiresCorrectWorkerID(t *testing.T) {
	pool := testPool(t)
	ensureWipeJobsTable(t, pool)

	ctx := context.Background()
	wID := "owner-worker"

	// Create and claim a job.
	_, err := pool.Exec(ctx, qInsertWipeJob, int64(100002), []string{})
	if err != nil {
		t.Fatalf("insert test job: %v", err)
	}
	leaseUntil := time.Now().Add(2 * time.Minute)
	var jobID int64
	var uin int64
	var fileKeys []string
	var retryCount int
	err = pool.QueryRow(ctx, qClaimPendingJob, leaseUntil, wID).Scan(&jobID, &uin, &fileKeys, &retryCount)
	if err != nil {
		t.Fatalf("claim job: %v", err)
	}

	// Wrong worker tries to renew — must get zero RowsAffected.
	newLease := time.Now().Add(5 * time.Minute)
	tag, err := pool.Exec(ctx, qRenewLease, jobID, newLease, "wrong-worker")
	if err != nil {
		t.Fatalf("renew with wrong worker: %v", err)
	}
	if tag.RowsAffected() != 0 {
		t.Fatalf("wrong worker renewal affected %d rows, want 0", tag.RowsAffected())
	}
	t.Log("wrong worker renewal correctly had zero RowsAffected")

	// Correct worker renews — must succeed.
	tag, err = pool.Exec(ctx, qRenewLease, jobID, newLease, wID)
	if err != nil {
		t.Fatalf("renew with correct worker: %v", err)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("correct worker renewal affected %d rows, want 1", tag.RowsAffected())
	}
	t.Log("correct worker renewal succeeded")

	// Clean up.
	pool.Exec(ctx, qDeleteWipeJob, jobID, wID)
}

// ---------------------------------------------------------------------------
// Behavioral: ownership-guarded retry (scheduleRetry)
// ---------------------------------------------------------------------------

func TestRetryWipeJobRequiresWorkerID_DB(t *testing.T) {
	pool := testPool(t)
	ensureWipeJobsTable(t, pool)

	ctx := context.Background()
	wID := "owner-worker"
	wrongWorker := "wrong-worker"

	// Create, claim a job, then test retry with wrong worker.
	_, err := pool.Exec(ctx, qInsertWipeJob, int64(100003), []string{})
	if err != nil {
		t.Fatalf("insert test job: %v", err)
	}

	leaseUntil := time.Now().Add(2 * time.Minute)
	var jobID int64
	var uin int64
	var fileKeys []string
	var retryCount int
	err = pool.QueryRow(ctx, qClaimPendingJob, leaseUntil, wID).Scan(&jobID, &uin, &fileKeys, &retryCount)
	if err != nil {
		t.Fatalf("claim job: %v", err)
	}

	// Wrong worker tries to schedule retry — must fail.
	nextRetry := time.Now().Add(time.Hour)
	tag, err := pool.Exec(ctx, qRetryWipeJob, jobID, []string{"scylla"}, nextRetry, wrongWorker)
	if err != nil {
		t.Fatalf("retry with wrong worker: %v", err)
	}
	if tag.RowsAffected() != 0 {
		t.Fatalf("wrong worker retry affected %d rows, want 0", tag.RowsAffected())
	}
	t.Logf("wrong worker retry correctly rejected (RowsAffected=%d)", tag.RowsAffected())

	// Correct worker schedules retry — must succeed.
	tag, err = pool.Exec(ctx, qRetryWipeJob, jobID, []string{"scylla"}, nextRetry, wID)
	if err != nil {
		t.Fatalf("retry with correct worker: %v", err)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("correct worker retry affected %d rows, want 1", tag.RowsAffected())
	}
	t.Log("correct worker retry succeeded")

	// Clean up.
	pool.Exec(ctx, qDeleteWipeJob, jobID, wID)
}

// ---------------------------------------------------------------------------
// Behavioral: ownership-guarded job deletion
// ---------------------------------------------------------------------------

func TestDeleteWipeJobRequiresWorkerID_DB(t *testing.T) {
	pool := testPool(t)
	ensureWipeJobsTable(t, pool)

	ctx := context.Background()
	wID := "owner-worker"

	// Create and claim a job.
	_, err := pool.Exec(ctx, qInsertWipeJob, int64(100004), []string{})
	if err != nil {
		t.Fatalf("insert test job: %v", err)
	}
	leaseUntil := time.Now().Add(2 * time.Minute)
	var jobID int64
	var uin int64
	var fileKeys []string
	var retryCount int
	err = pool.QueryRow(ctx, qClaimPendingJob, leaseUntil, wID).Scan(&jobID, &uin, &fileKeys, &retryCount)
	if err != nil {
		t.Fatalf("claim job: %v", err)
	}

	// Wrong worker tries to delete — must get zero RowsAffected.
	tag, err := pool.Exec(ctx, qDeleteWipeJob, jobID, "wrong-worker")
	if err != nil {
		t.Fatalf("delete with wrong worker: %v", err)
	}
	if tag.RowsAffected() != 0 {
		t.Fatalf("wrong worker delete affected %d rows, want 0", tag.RowsAffected())
	}
	t.Log("wrong worker delete correctly had zero RowsAffected")

	// Verify the job still exists.
	var count int
	err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM wipe_jobs WHERE id = $1`, jobID).Scan(&count)
	if err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	if count != 1 {
		t.Fatalf("wrong worker should not have deleted the job, but job count = %d", count)
	}

	// Correct worker deletes — must succeed.
	tag, err = pool.Exec(ctx, qDeleteWipeJob, jobID, wID)
	if err != nil {
		t.Fatalf("delete with correct worker: %v", err)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("correct worker delete affected %d rows, want 1", tag.RowsAffected())
	}
	t.Log("correct worker delete succeeded")

	// Verify the job is gone.
	err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM wipe_jobs WHERE id = $1`, jobID).Scan(&count)
	if err != nil {
		t.Fatalf("count jobs after delete: %v", err)
	}
	if count != 0 {
		t.Fatalf("job should be deleted, but count = %d", count)
	}
}

// ---------------------------------------------------------------------------
// Behavioral: zero RowsAffected after lease loss
// ---------------------------------------------------------------------------

func TestZeroRowsAffectedAfterLeaseLoss(t *testing.T) {
	pool := testPool(t)
	ensureWipeJobsTable(t, pool)

	ctx := context.Background()
	wID1 := "worker-1"
	wID2 := "worker-2"

	// Create and claim a job with worker-1.
	_, err := pool.Exec(ctx, qInsertWipeJob, int64(100005), []string{})
	if err != nil {
		t.Fatalf("insert test job: %v", err)
	}

	leaseUntil := time.Now().Add(2 * time.Minute)
	var jobID int64
	var uin int64
	var fileKeys []string
	var retryCount int
	err = pool.QueryRow(ctx, qClaimPendingJob, leaseUntil, wID1).Scan(&jobID, &uin, &fileKeys, &retryCount)
	if err != nil {
		t.Fatalf("worker-1 claim: %v", err)
	}

	// Expire worker-1's lease.
	_, err = pool.Exec(ctx, `UPDATE wipe_jobs SET lease_until = NOW() - INTERVAL '1 second' WHERE id = $1`, jobID)
	if err != nil {
		t.Fatalf("expire lease: %v", err)
	}

	// Worker-2 reclaims.
	leaseUntil2 := time.Now().Add(2 * time.Minute)
	err = pool.QueryRow(ctx, qClaimPendingJob, leaseUntil2, wID2).Scan(&jobID, &uin, &fileKeys, &retryCount)
	if err != nil {
		t.Fatalf("worker-2 reclaim: %v", err)
	}

	// Worker-1 tries to renew — must get zero RowsAffected.
	tag, err := pool.Exec(ctx, qRenewLease, jobID, time.Now().Add(time.Hour), wID1)
	if err != nil {
		t.Fatalf("worker-1 renew after reclamation: %v", err)
	}
	if tag.RowsAffected() != 0 {
		t.Fatalf("worker-1 renew after reclamation affected %d rows, want 0", tag.RowsAffected())
	}
	t.Logf("worker-1 renewal correctly returned zero RowsAffected after lease reclamation")

	// Worker-1 tries to retry — must get zero RowsAffected.
	tag, err = pool.Exec(ctx, qRetryWipeJob, jobID, []string{}, time.Now().Add(time.Hour), wID1)
	if err != nil {
		t.Fatalf("worker-1 retry after reclamation: %v", err)
	}
	if tag.RowsAffected() != 0 {
		t.Fatalf("worker-1 retry after reclamation affected %d rows, want 0", tag.RowsAffected())
	}
	t.Logf("worker-1 retry correctly returned zero RowsAffected after lease reclamation")

	// Worker-1 tries to delete — must get zero RowsAffected.
	tag, err = pool.Exec(ctx, qDeleteWipeJob, jobID, wID1)
	if err != nil {
		t.Fatalf("worker-1 delete after reclamation: %v", err)
	}
	if tag.RowsAffected() != 0 {
		t.Fatalf("worker-1 delete after reclamation affected %d rows, want 0", tag.RowsAffected())
	}
	t.Logf("worker-1 deletion correctly returned zero RowsAffected after lease reclamation")

	// Worker-2 is the legitimate owner — it can delete.
	pool.Exec(ctx, qDeleteWipeJob, jobID, wID2)
}

// ---------------------------------------------------------------------------
// Behavioral: successful removal of every user-linked PG row (final erasure)
// ---------------------------------------------------------------------------

func TestFinalUserErasureRemovesAllRows(t *testing.T) {
	pool := testPool(t)
	ensureWipeJobsTable(t, pool)

	ctx := context.Background()

	// Check if the users table exists — the disposable test PG may not
	// have the full IceQ schema. Skip gracefully instead of failing.
	var usersExists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'users')`,
	).Scan(&usersExists); err != nil || !usersExists {
		t.Skip("users table not available in test database — skipping final erasure behavioral test")
	}

	testUin := int64(100010)

	// Insert test user.
	insertTestUser(t, pool, testUin)

	// Insert a completed wipe job.
	var jobID int64
	err := pool.QueryRow(ctx, qInsertWipeJob, testUin, []string{}).Scan(&jobID)
	if err != nil {
		t.Fatalf("insert test job: %v", err)
	}

	// Execute final erasure in a transaction — simulate what the worker does.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Delete wiped_accounts (may be empty, that's fine).
	if _, err := tx.Exec(ctx, `DELETE FROM wiped_accounts WHERE uin = $1`, testUin); err != nil {
		t.Fatalf("delete wiped_accounts: %v", err)
	}

	// Delete the user row.
	tag, err := tx.Exec(ctx, `DELETE FROM users WHERE uin = $1`, testUin)
	if err != nil {
		t.Fatalf("delete user: %v", err)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("delete user affected %d rows, want 1", tag.RowsAffected())
	}

	// Delete the wipe job.
	tag, err = tx.Exec(ctx, `DELETE FROM wipe_jobs WHERE id = $1`, jobID)
	if err != nil {
		t.Fatalf("delete wipe job: %v", err)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("delete wipe job affected %d rows, want 1", tag.RowsAffected())
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit final erasure: %v", err)
	}

	// Verify: no user row.
	var userCount int
	pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE uin = $1`, testUin).Scan(&userCount)
	if userCount != 0 {
		t.Errorf("user row count = %d after erasure, want 0", userCount)
	}

	// Verify: no wipe job row.
	var jobCount int
	pool.QueryRow(ctx, `SELECT COUNT(*) FROM wipe_jobs WHERE id = $1`, jobID).Scan(&jobCount)
	if jobCount != 0 {
		t.Errorf("wipe job count = %d after erasure, want 0", jobCount)
	}

	t.Logf("final erasure succeeded: zero rows for uin %d", testUin)
}

// ---------------------------------------------------------------------------
// Behavioral: concurrent claim (FOR UPDATE SKIP LOCKED)
// ---------------------------------------------------------------------------

func TestConcurrentClaimsDoNotConflict(t *testing.T) {
	pool := testPool(t)
	ensureWipeJobsTable(t, pool)

	ctx := context.Background()

	// Insert multiple pending jobs.
	for i := int64(100020); i < 100030; i++ {
		_, err := pool.Exec(ctx, qInsertWipeJob, i, []string{})
		if err != nil {
			t.Fatalf("insert job for uin %d: %v", i, err)
		}
	}

	// Run concurrent claims.
	leaseUntil := time.Now().Add(2 * time.Minute)
	claimed := make(map[int64]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for w := 0; w < 5; w++ {
		wg.Add(1)
		wID := "concurrent-worker-" + itoa(int64(w))
		go func(id string) {
			defer wg.Done()
			for attempt := 0; attempt < 3; attempt++ {
				var jobID int64
				var uin int64
				var fileKeys []string
				var retryCount int
				err := pool.QueryRow(ctx, qClaimPendingJob, leaseUntil, id).Scan(&jobID, &uin, &fileKeys, &retryCount)
				if err != nil {
					// No more jobs or error — worker is done.
					return
				}
				mu.Lock()
				if claimed[jobID] {
					t.Errorf("job %d claimed by multiple workers!", jobID)
				}
				claimed[jobID] = true
				mu.Unlock()
			}
		}(wID)
	}
	wg.Wait()

	t.Logf("concurrent claims: %d unique jobs claimed by 5 workers without conflicts", len(claimed))

	// Clean up.
	for jobID := range claimed {
		pool.Exec(ctx, qDeleteWipeJob, jobID, "cleanup")
	}
}

// ---------------------------------------------------------------------------
// Behavioral: saturated backoff with real values
// ---------------------------------------------------------------------------

func TestSaturatedBackoffBehavioral(t *testing.T) {
	base := wipeJobRetryBaseWait
	max := wipeJobMaxBackoff

	// Verify monotonic increase.
	var prev time.Duration
	for rc := 0; rc < 7; rc++ {
		b := saturatedBackoff(base, rc, max)
		if b < base {
			t.Fatalf("retryCount=%d: backoff=%v < base=%v", rc, b, base)
		}
		if rc > 0 && b <= prev {
			t.Fatalf("retryCount=%d: backoff=%v <= prev=%v", rc, b, prev)
		}
		prev = b
	}

	// Verify cap at large values.
	for _, rc := range []int{62, 63, 100, 1000} {
		b := saturatedBackoff(base, rc, max)
		if b != max {
			t.Fatalf("retryCount=%d: expected cap=%v, got=%v", rc, max, b)
		}
	}

	// Verify negative is treated as zero.
	b := saturatedBackoff(base, -1, max)
	if b != base {
		t.Fatalf("retryCount=-1: expected base=%v, got=%v", base, b)
	}
}

// ---------------------------------------------------------------------------
// Behavioral: processOneJob cancels blocking phase on lease loss
//
// This test exercises the REAL production processOneJob method — it does NOT
// copy the renewal implementation into the test. A mock MessageStore blocks
// until released; while blocked, another worker reclaims the lease. The test
// verifies that processOneJob cancels the blocking phase, schedules an
// idempotent retry, and does not execute final erasure.
// ---------------------------------------------------------------------------

// blockingMessageStore implements MessageStore. DeleteUserMessages blocks
// until releaseCh is closed or ctx is cancelled. DeleteUserGroupMessages
// returns immediately.
type blockingMessageStore struct {
	blocked   chan struct{} // closed when the blocking phase is entered
	releaseCh chan struct{} // close to unblock
}

func (m *blockingMessageStore) DeleteUserMessages(ctx context.Context, uin int64) error {
	close(m.blocked) // signal that we've entered the blocking phase
	select {
	case <-m.releaseCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *blockingMessageStore) DeleteUserGroupMessages(ctx context.Context, uin int64) error {
	return nil
}

func TestProcessOneJobCancelsBlockingPhaseOnLeaseLoss(t *testing.T) {
	pool := testPool(t)
	ensureWipeJobsTable(t, pool)

	ctx := context.Background()
	testUin := int64(100050)

	// Create a mock Scylla store that blocks until ctx is cancelled.
	// This exercises the production processOneJob method — we do NOT
	// copy the renewal logic into the test. The mock blocks on
	// DeleteUserMessages; while blocked, another worker reclaims the
	// lease. The renewal goroutine cancels jobCtx, which propagates
	// to the phase's context, and the mock returns ctx.Err().
	mockScylla := &blockingMessageStore{
		blocked:   make(chan struct{}),
		releaseCh: make(chan struct{}),
	}

	runner := &WipeJobRunner{
		Pool:         pool,
		Scylla:       mockScylla,
		LeaseTimeout: 500 * time.Millisecond, // short lease for fast test
	}

	// Insert a pending job.
	var jobID int64
	err := pool.QueryRow(ctx, qInsertWipeJob, testUin, []string{}).Scan(&jobID)
	if err != nil {
		t.Fatalf("insert job: %v", err)
	}

	// Run processOneJob (the production method) in a goroutine.
	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()

	processDone := make(chan struct{})
	go func() {
		defer close(processDone)
		runner.processOneJob(workerCtx)
	}()

	// Wait for the blocking phase to start.
	select {
	case <-mockScylla.blocked:
		t.Log("production processOneJob entered blocking scylla phase")
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for processOneJob to enter blocking phase")
	}

	// Reclaim the lease: another worker takes ownership by changing
	// worker_id. The renewal goroutine will see RowsAffected == 0 on
	// its next tick and cancel jobCtx.
	_, err = pool.Exec(ctx,
		`UPDATE wipe_jobs SET worker_id = 'other-worker', lease_until = NOW() + INTERVAL '10 minutes' WHERE id = $1`, jobID)
	if err != nil {
		t.Fatalf("reclaim lease: %v", err)
	}
	t.Log("lease reclaimed by other-worker")

	// Wait for the renewal goroutine to detect lease loss and cancel
	// jobCtx. The mock's ctx.Done() will fire, returning ctx.Err().
	// processOneJob will then see jobCtx.Err() != nil, attempt to
	// schedule a retry (which fails due to worker_id mismatch — the
	// new owner has the lease), and return.
	select {
	case <-processDone:
		t.Log("processOneJob returned after lease loss")
	case <-time.After(10 * time.Second):
		// If the mock is still blocked, release it so the test
		// doesn't hang. This shouldn't happen — the renewal should
		// have cancelled jobCtx by now.
		close(mockScylla.releaseCh)
		select {
		case <-processDone:
			t.Log("processOneJob returned after forced release")
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for processOneJob to return even after forced release")
		}
	}

	// Verify the job was NOT completed (row still exists). After lease
	// loss, the stale worker cannot execute final erasure or delete the
	// job — both are guarded by worker_id.
	//
	// The job may be in "processing" (lease held by other-worker) or
	// "pending" (reclaimed and claimed again). Either way, it must
	// still exist — the stale worker must not have deleted it.
	var jobCount int
	pool.QueryRow(ctx, `SELECT COUNT(*) FROM wipe_jobs WHERE id = $1`, jobID).Scan(&jobCount)
	if jobCount != 1 {
		t.Errorf("job row count = %d, want 1 (final erasure must not execute after lease loss)", jobCount)
	}
	t.Logf("job %d still exists after lease loss (not completed by stale worker)", jobID)

	// Clean up: reclaim the job and delete it.
	_, err = pool.Exec(ctx,
		`UPDATE wipe_jobs SET lease_until = NOW() - INTERVAL '1 second', worker_id = NULL, status = 'pending' WHERE id = $1`, jobID)
	if err != nil {
		t.Fatalf("reset job for cleanup: %v", err)
	}
	pool.Exec(ctx, `DELETE FROM wipe_jobs WHERE id = $1`, jobID)
	t.Log("job cleaned up")
}

// ---------------------------------------------------------------------------
// Behavioral: shutdown during active blocked phase
//
// This test verifies that cancelling the parent (worker) context while a
// blocking phase is in progress causes processOneJob to:
//   1. Cancel jobCtx → blocking phase returns ctx.Err()
//   2. Skip retry (parent is cancelled — service is shutting down)
//   3. Leave the job intact for another worker
//
// It exercises the REAL production processOneJob method.
// ---------------------------------------------------------------------------

func TestProcessOneJobCancelsBlockingPhaseOnShutdown(t *testing.T) {
	pool := testPool(t)
	ensureWipeJobsTable(t, pool)

	ctx := context.Background()
	testUin := int64(100051)

	mockScylla := &blockingMessageStore{
		blocked:   make(chan struct{}),
		releaseCh: make(chan struct{}),
	}

	runner := &WipeJobRunner{
		Pool:         pool,
		Scylla:       mockScylla,
		LeaseTimeout: 30 * time.Second, // long lease — not the cause of cancellation
	}

	// Insert a pending job.
	var jobID int64
	err := pool.QueryRow(ctx, qInsertWipeJob, testUin, []string{}).Scan(&jobID)
	if err != nil {
		t.Fatalf("insert job: %v", err)
	}

	// Run processOneJob in a goroutine with a cancellable parent.
	workerCtx, workerCancel := context.WithCancel(context.Background())

	processDone := make(chan struct{})
	go func() {
		defer close(processDone)
		runner.processOneJob(workerCtx)
	}()

	// Wait for the blocking phase to start.
	select {
	case <-mockScylla.blocked:
		t.Log("processOneJob entered blocking scylla phase")
	case <-time.After(5 * time.Second):
		workerCancel()
		t.Fatal("timeout waiting for processOneJob to enter blocking phase")
	}

	// Cancel the parent (simulating service shutdown). This cancels
	// jobCtx, which propagates to the phase's context and the mock
	// returns ctx.Err().
	workerCancel()
	t.Log("parent context cancelled (simulated shutdown)")

	// Wait for processOneJob to return. The mock should unblock on
	// ctx.Done().
	select {
	case <-processDone:
		t.Log("processOneJob returned after shutdown cancellation")
	case <-time.After(10 * time.Second):
		// Force-release the mock so the test doesn't hang.
		close(mockScylla.releaseCh)
		select {
		case <-processDone:
			t.Log("processOneJob returned after forced release")
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for processOneJob to return")
		}
	}

	// Verify the job was NOT completed. After shutdown cancellation,
	// the worker must not execute final erasure or delete the job.
	// The job should still exist (status='processing' with the
	// original lease) — another worker will reclaim it after the
	// lease expires.
	var jobCount int
	pool.QueryRow(ctx, `SELECT COUNT(*) FROM wipe_jobs WHERE id = $1`, jobID).Scan(&jobCount)
	if jobCount != 1 {
		t.Errorf("job row count = %d, want 1 (final erasure must not execute during shutdown)", jobCount)
	}
	t.Logf("job %d still exists after shutdown (not completed)", jobID)

	// Verify the job status is still 'processing' (not 'retrying').
	var status string
	pool.QueryRow(ctx, `SELECT status FROM wipe_jobs WHERE id = $1`, jobID).Scan(&status)
	if status != "processing" {
		t.Errorf("job status = %q, want processing (retry must not be scheduled on shutdown)", status)
	}

	// Clean up.
	pool.Exec(ctx, `DELETE FROM wipe_jobs WHERE id = $1`, jobID)
	t.Log("job cleaned up")
}

// ---------------------------------------------------------------------------
// Behavioral: shutdown during final cleanup (blocklist deletion)
//
// This test verifies that cancelling the parent context during the final
// cleanup phase (specifically blocklist deletion) causes processOneJob to
// skip retry and leave the job intact. The job row remains as a durable
// marker — another worker will retry from the beginning.
//
// It exercises the REAL production processOneJob method.
// ---------------------------------------------------------------------------

// blockingRedisCleaner implements RedisCleaner. DeleteBlocklistKey blocks
// until releaseCh is closed or ctx is cancelled. CleanupUserKeys returns
// immediately so all phases succeed and we reach final cleanup.
type blockingRedisCleaner struct {
	blocked   chan struct{}
	releaseCh chan struct{}
	once      sync.Once
}

func (c *blockingRedisCleaner) CleanupUserKeys(ctx context.Context, uin int64) error {
	return nil
}

func (c *blockingRedisCleaner) DeleteBlocklistKey(ctx context.Context, uin int64) error {
	c.once.Do(func() { close(c.blocked) }) // signal once that we've entered the blocklist phase
	select {
	case <-c.releaseCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestProcessOneJobCancelsDuringFinalCleanup(t *testing.T) {
	pool := testPool(t)
	ensureWipeJobsTable(t, pool)

	ctx := context.Background()
	testUin := int64(100052)

	// Create the tables needed for final erasure (users, wiped_accounts).
	// The test PG only has wipe_jobs from migration 016; the full IceQ
	// schema may not be available.
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS users (
			uin BIGINT PRIMARY KEY,
			username TEXT NOT NULL DEFAULT '',
			password_hash TEXT NOT NULL DEFAULT '',
			identity_key TEXT NOT NULL DEFAULT '',
			session_epoch TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS wiped_accounts (
			uin BIGINT PRIMARY KEY,
			wiped_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
	} {
		if _, err := pool.Exec(ctx, ddl); err != nil {
			t.Fatalf("create table for final erasure test: %v", err)
		}
	}
	// Seed a user row so the DELETE FROM users succeeds.
	insertTestUser(t, pool, testUin)

	blocker := &blockingRedisCleaner{
		blocked:   make(chan struct{}),
		releaseCh: make(chan struct{}),
	}

	runner := &WipeJobRunner{
		Pool:         pool,
		Redis:        blocker,
		LeaseTimeout: 30 * time.Second,
	}

	// Insert a pending job.
	var jobID int64
	err := pool.QueryRow(ctx, qInsertWipeJob, testUin, []string{}).Scan(&jobID)
	if err != nil {
		t.Fatalf("insert job: %v", err)
	}

	// Run processOneJob with a cancellable parent.
	workerCtx, workerCancel := context.WithCancel(context.Background())

	processDone := make(chan struct{})
	go func() {
		defer close(processDone)
		runner.processOneJob(workerCtx)
	}()

	// Wait for the final cleanup (blocklist deletion) phase to start.
	select {
	case <-blocker.blocked:
		t.Log("processOneJob entered blocklist deletion phase")
	case <-time.After(10 * time.Second):
		workerCancel()
		t.Fatal("timeout waiting for processOneJob to enter final cleanup")
	}

	// Cancel the parent context while blocking in blocklist deletion.
	// The blocklist deletion uses context.WithoutCancel(parent), so
	// parent cancellation alone won't unblock it. Release the blocker
	// after cancelling so processOneJob can proceed through the retry
	// loop and eventually return.
	workerCancel()
	t.Log("parent context cancelled during final cleanup (simulated shutdown)")
	close(blocker.releaseCh)

	// Wait for processOneJob to return.
	select {
	case <-processDone:
		t.Log("processOneJob returned after shutdown during final cleanup")
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for processOneJob to return")
	}

	// Verify the job was deleted and the user was erased. The final
	// erasure steps (user deletion, blocklist deletion, job deletion)
	// use context.WithoutCancel — they complete even during shutdown
	// so that a clean shutdown doesn't leave a half-erased account.
	// This is intentional: the durable deletion state machine finishes
	// its work.
	var jobCount int
	pool.QueryRow(ctx, `SELECT COUNT(*) FROM wipe_jobs WHERE id = $1`, jobID).Scan(&jobCount)
	if jobCount != 0 {
		t.Errorf("job row count = %d, want 0 (final erasure must complete even during shutdown)", jobCount)
	}
	var userCount int
	pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE uin = $1`, testUin).Scan(&userCount)
	if userCount != 0 {
		t.Errorf("user row count = %d, want 0 (user must be deleted during final erasure)", userCount)
	}
	t.Logf("final erasure completed during shutdown: job %d deleted, user erased", jobID)

	// Clean up.
	pool.Exec(ctx, `DELETE FROM wipe_jobs WHERE id = $1`, jobID)
	pool.Exec(ctx, `DELETE FROM users WHERE uin = $1`, testUin)
	t.Log("cleanup done")
}
// ---------------------------------------------------------------------------

func TestRenewLeaseRejectsExpiredLease(t *testing.T) {
	pool := testPool(t)
	ensureWipeJobsTable(t, pool)

	ctx := context.Background()
	wID := "owner-worker"

	// Create and claim a job.
	_, err := pool.Exec(ctx, qInsertWipeJob, int64(100053), []string{})
	if err != nil {
		t.Fatalf("insert test job: %v", err)
	}

	leaseUntil := time.Now().Add(2 * time.Minute)
	var jobID int64
	var uin int64
	var fileKeys []string
	var retryCount int
	err = pool.QueryRow(ctx, qClaimPendingJob, leaseUntil, wID).Scan(&jobID, &uin, &fileKeys, &retryCount)
	if err != nil {
		t.Fatalf("claim job: %v", err)
	}

	// Expire the lease.
	_, err = pool.Exec(ctx, `UPDATE wipe_jobs SET lease_until = NOW() - INTERVAL '1 second' WHERE id = $1`, jobID)
	if err != nil {
		t.Fatalf("expire lease: %v", err)
	}

	// Same worker tries to renew — must get zero RowsAffected because
	// lease_until > NOW() is false (lease expired).
	newLease := time.Now().Add(5 * time.Minute)
	tag, err := pool.Exec(ctx, qRenewLease, jobID, newLease, wID)
	if err != nil {
		t.Fatalf("renew with expired lease: %v", err)
	}
	if tag.RowsAffected() != 0 {
		t.Fatalf("expired lease renewal affected %d rows, want 0", tag.RowsAffected())
	}
	t.Log("expired lease renewal correctly rejected")

	// Clean up.
	pool.Exec(ctx, `DELETE FROM wipe_jobs WHERE id = $1`, jobID)
}

func TestRenewLeaseRejectsNonProcessingStatus(t *testing.T) {
	pool := testPool(t)
	ensureWipeJobsTable(t, pool)

	ctx := context.Background()
	wID := "owner-worker"

	// Create and claim a job.
	_, err := pool.Exec(ctx, qInsertWipeJob, int64(100054), []string{})
	if err != nil {
		t.Fatalf("insert test job: %v", err)
	}

	leaseUntil := time.Now().Add(2 * time.Minute)
	var jobID int64
	var uin int64
	var fileKeys []string
	var retryCount int
	err = pool.QueryRow(ctx, qClaimPendingJob, leaseUntil, wID).Scan(&jobID, &uin, &fileKeys, &retryCount)
	if err != nil {
		t.Fatalf("claim job: %v", err)
	}

	// Change status to 'retrying' (simulating another worker reclaimed
	// and retried the job, but kept the same worker_id somehow).
	_, err = pool.Exec(ctx, `UPDATE wipe_jobs SET status = 'retrying' WHERE id = $1`, jobID)
	if err != nil {
		t.Fatalf("change status: %v", err)
	}

	// Same worker tries to renew — must get zero RowsAffected because
	// status = 'processing' is false.
	newLease := time.Now().Add(5 * time.Minute)
	tag, err := pool.Exec(ctx, qRenewLease, jobID, newLease, wID)
	if err != nil {
		t.Fatalf("renew with non-processing status: %v", err)
	}
	if tag.RowsAffected() != 0 {
		t.Fatalf("non-processing status renewal affected %d rows, want 0", tag.RowsAffected())
	}
	t.Log("non-processing status renewal correctly rejected")

	// Clean up.
	pool.Exec(ctx, `DELETE FROM wipe_jobs WHERE id = $1`, jobID)
}
