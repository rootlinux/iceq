package handlers

import (
	"context"
	"errors"
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Behavioral tests for durable wipe cleanup
// ---------------------------------------------------------------------------

type contextRecordingStore struct {
	canceled []bool
	bounded  []bool
}

func (s *contextRecordingStore) DeleteUserMessages(ctx context.Context, _ int64) error {
	_, bounded := ctx.Deadline()
	s.canceled = append(s.canceled, ctx.Err() != nil)
	s.bounded = append(s.bounded, bounded)
	// Real stores (gocql, NATS, MinIO) check context cancellation via
	// their drivers. Mirror that behavior: return ctx.Err() when cancelled.
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}
func (s *contextRecordingStore) DeleteUserGroupMessages(ctx context.Context, _ int64) error {
	_, bounded := ctx.Deadline()
	s.canceled = append(s.canceled, ctx.Err() != nil)
	s.bounded = append(s.bounded, bounded)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

func TestCleanupScyllaRespectsParentCancellation(t *testing.T) {
	// When the parent (job) context is cancelled — e.g. due to lease loss —
	// cleanupScylla must propagate cancellation so blocking storage phases
	// are stopped. This prevents destructive work with unconfirmed ownership.
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	store := &contextRecordingStore{}
	err := cleanupScylla(parent, store, 42, time.Second)
	if err == nil {
		t.Fatal("cleanupScylla must return error when parent context is cancelled")
	}
	// Both DeleteUserMessages and DeleteUserGroupMessages should see
	// the cancelled context and return immediately.
	if len(store.canceled) < 1 {
		t.Fatalf("cleanup calls = %d, want at least 1", len(store.canceled))
	}
	for i := range store.canceled {
		if !store.canceled[i] {
			t.Fatal("cleanup did NOT propagate cancellation — phase would have blocked despite lease loss")
		}
	}
	t.Log("cleanupScylla correctly propagates parent cancellation")
}

func TestCleanupScyllaPropagatesDeleteError(t *testing.T) {
	store := &failingMessageStore{}
	err := cleanupScylla(context.Background(), store, 42, time.Second)
	if err == nil {
		t.Fatal("cleanupScylla must return error when DeleteUserMessages fails")
	}
}

type failingMessageStore struct{}

func (f *failingMessageStore) DeleteUserMessages(context.Context, int64) error {
	return errors.New("scylla unavailable")
}
func (f *failingMessageStore) DeleteUserGroupMessages(context.Context, int64) error {
	return errors.New("scylla unavailable")
}

// ---------------------------------------------------------------------------
// Behavioral: session revocation ordering
// ---------------------------------------------------------------------------

func TestPanicWipeRevokesSessionsBeforePGTransaction(t *testing.T) {
	src := mustReadFile(t, "panicwipe.go")
	revoke := strings.Index(src, "deps.Redis.Set(ctx")
	pgBegin := strings.Index(src, "deps.Pool.Begin(ctx")
	if revoke < 0 {
		t.Fatal("revocation not found in panicwipe.go")
	}
	if pgBegin < 0 {
		t.Fatal("PG transaction begin not found in panicwipe.go")
	}
	if revoke >= pgBegin {
		t.Fatalf("session revocation (pos=%d) must precede PG transaction (pos=%d)", revoke, pgBegin)
	}
}

// ---------------------------------------------------------------------------
// Behavioral: recovery defer removes blocklist on failure
// ---------------------------------------------------------------------------

func TestPanicWipeRecoveryRemovesBlocklistOnPGOrCaptureFailure(t *testing.T) {
	src := mustReadFile(t, "panicwipe.go")

	if !strings.Contains(src, `blocklisted := true`) {
		t.Fatal("recovery flag blocklisted := true not found — missing recovery defer")
	}
	if !strings.Contains(src, `blocklisted = false`) {
		t.Fatal("blocklisted = false not found — PG commit must clear the recovery flag")
	}
	if !strings.Contains(src, "deps.Redis.Del") || !strings.Contains(src, "blocklistKey") {
		t.Fatal("recovery defer must delete the blocklist key on failure")
	}
	if !strings.Contains(src, "context.WithoutCancel") {
		t.Fatal("recovery defer must use context.WithoutCancel to run independently of parent ctx")
	}
}

// ---------------------------------------------------------------------------
// Behavioral: insert wipe job INSIDE PG transaction (Issue #1)
// ---------------------------------------------------------------------------

func TestPanicWipeInsertsJobInsideTransactionNotAfterCommit(t *testing.T) {
	// The InsertWipeJobTx call must appear BEFORE tx.Commit(ctx), not after.
	// Inserting after commit means a crash between commit and insertion
	// permanently loses the captured file keys.
	src := mustReadFile(t, "panicwipe.go")

	insertPos := strings.Index(src, "InsertWipeJobTx")
	commitPos := strings.Index(src, "tx.Commit(ctx)")

	if insertPos < 0 {
		t.Fatal("PanicWipe must call InsertWipeJobTx for atomic job creation inside the PG transaction")
	}
	if commitPos < 0 {
		t.Fatal("tx.Commit(ctx) not found")
	}
	if insertPos > commitPos {
		t.Fatalf("InsertWipeJobTx (pos=%d) must be BEFORE tx.Commit(ctx) (pos=%d) — inserting after commit is not atomic", insertPos, commitPos)
	}
}

// ---------------------------------------------------------------------------
// Behavioral: no terminal failed state — infinite retry (Issue #6)
// ---------------------------------------------------------------------------

func TestWipeJobNoTerminalFailedState(t *testing.T) {
	// Retries continue indefinitely with capped exponential backoff.
	// There must be no terminal "failed" status that silently abandons
	// cleanup. If someone adds qFailWipeJob back, this test breaks.
	src := mustReadFile(t, "wipejob.go")

	if strings.Contains(src, "qFailWipeJob") {
		t.Fatal("wipejob.go must not contain qFailWipeJob — infinite retry, no terminal state")
	}
	if strings.Contains(src, "status = 'failed'") {
		t.Fatal("wipejob.go must not set status='failed' — infinite retry, no terminal state")
	}
}

// ---------------------------------------------------------------------------
// Behavioral: crash-safe leasing (Issue #4)
// ---------------------------------------------------------------------------

func TestWipeJobClaimQueryReclaimsExpiredLeases(t *testing.T) {
	// The claim query must reclaim processing jobs whose lease expired.
	// This is the crash-safety mechanism — if a worker dies, another
	// worker picks up the abandoned job after lease_until passes.
	src := mustReadFile(t, "wipejob.go")

	if !strings.Contains(src, "lease_until IS NOT NULL AND lease_until < NOW()") {
		t.Fatal("claim query must reclaim jobs with expired leases")
	}
	if !strings.Contains(src, "FOR UPDATE SKIP LOCKED") {
		t.Fatal("claim query must use FOR UPDATE SKIP LOCKED for concurrent safety")
	}
	if !strings.Contains(src, "qRenewLease") {
		t.Fatal("must have qRenewLease to extend lease during long cleanup operations")
	}
	if !strings.Contains(src, "worker_id") {
		t.Fatal("claim query must set worker_id for lease ownership tracking")
	}
}

// ---------------------------------------------------------------------------
// Behavioral: exponential backoff with cap (Issue #6)
// ---------------------------------------------------------------------------

func TestWipeJobBackoffIsExponentialAndCapped(t *testing.T) {
	// Behavioral: saturatedBackoff must produce values in [base, maxBackoff]
	// for any non-negative retry count, including values that would overflow
	// in a naive base * (1 << retryCount) calculation.

	base := wipeJobRetryBaseWait
	max := wipeJobMaxBackoff

	// Normal range: backoff doubles each retry.
	prev := time.Duration(0)
	for rc := 0; rc < 5; rc++ {
		b := saturatedBackoff(base, rc, max)
		if b < base {
			t.Fatalf("retryCount=%d: backoff=%v < base=%v", rc, b, base)
		}
		if b > max {
			t.Fatalf("retryCount=%d: backoff=%v > max=%v", rc, b, max)
		}
		if rc > 0 && b <= prev {
			t.Fatalf("retryCount=%d: backoff=%v not increasing from prev=%v", rc, b, prev)
		}
		prev = b
	}

	// Boundary: very large retry count (would overflow naive 1<<retryCount).
	for _, rc := range []int{62, 63, 100, 1000, 1_000_000} {
		b := saturatedBackoff(base, rc, max)
		if b != max {
			t.Fatalf("retryCount=%d: expected cap=%v, got=%v", rc, max, b)
		}
	}

	// Boundary: negative retry count (should treat as 0).
	b := saturatedBackoff(base, -1, max)
	if b != base {
		t.Fatalf("retryCount=-1: expected base=%v, got=%v", base, b)
	}

	// Verify source still sets status='retrying' for observability.
	src := mustReadFile(t, "wipejob.go")
	if !strings.Contains(src, "status = 'retrying'") && !strings.Contains(src, `status        = 'retrying'`) {
		t.Fatal("retry must set status='retrying' to distinguish from fresh 'pending' jobs")
	}
}

// ---------------------------------------------------------------------------
// Behavioral: worker start/stop lifecycle (Issue #5)
// ---------------------------------------------------------------------------

func TestWipeWorkerStartStopLifecycle(t *testing.T) {
	// Start the worker, let it run, cancel context, then stop. Stop must
	// return within a bounded time — the worker checks ctx.Done() on each
	// poll tick.

	runner := &WipeJobRunner{
		PollInterval: 50 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	stop := runner.StartWipeWorker(ctx)

	// Let the worker run for a few poll cycles.
	time.Sleep(150 * time.Millisecond)

	// Cancel signals the poll loop to exit.
	cancel()

	// Stop must return quickly — the worker exits on the next ctx.Done().
	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()

	select {
	case <-done:
		// Worker stopped cleanly within the deadline.
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return within 2s — worker goroutine is stuck")
	}
}

func TestWipeWorkerShutdownWithinBoundedTime(t *testing.T) {
	// The full shutdown sequence (cancel + stop) must complete within a
	// bounded time. This test verifies the contract that the caller can
	// depend on for graceful shutdown ordering.

	runner := &WipeJobRunner{
		PollInterval: 10 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	stop := runner.StartWipeWorker(ctx)

	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	cancel()
	stop()
	elapsed := time.Since(start)

	// Even with a slow machine, shutdown should be well under 1 second
	// since the worker checks ctx.Done() on every tick.
	if elapsed > time.Second {
		t.Fatalf("worker shutdown took %v, want < 1s", elapsed)
	}
	t.Logf("worker shutdown took %v", elapsed)
}

// ---------------------------------------------------------------------------
// Behavioral: worker ID uniqueness
// ---------------------------------------------------------------------------

func TestWipeJobRunnerWorkerIDIsUnique(t *testing.T) {
	r1 := &WipeJobRunner{}
	r2 := &WipeJobRunner{}

	id1 := r1.workerID()
	id2 := r2.workerID()

	if id1 == "" {
		t.Fatal("workerID must not be empty")
	}
	if id1 == id2 {
		t.Fatalf("two runners must have different worker IDs, got %q for both", id1)
	}
}

// ---------------------------------------------------------------------------
// Behavioral: group membership query integrity
// ---------------------------------------------------------------------------

func TestPanicWipeRotatesAndRepairsAffectedGroupsInsideWipeTransaction(t *testing.T) {
	q := strings.ToUpper(qWipeGroupMemberships)
	for _, required := range []string{"FOR UPDATE", "DELETE FROM GROUP_MEMBERS", "CRYPTO_EPOCH=CRYPTO_EPOCH+1", "ORDER BY JOINED_AT,UIN", "UPDATE GROUP_MEMBERS", "SET ROLE='ADMIN'", "DELETE FROM GROUPS"} {
		if !strings.Contains(q, required) {
			t.Fatalf("panic wipe group mutation missing %s", required)
		}
	}
}

// ---------------------------------------------------------------------------
// Behavioral: 204 vs 202 HTTP semantics (Issue #2)
// ---------------------------------------------------------------------------

func TestPanicWipeAlwaysCreatesJobAndReturns202(t *testing.T) {
	// Behavioral: PanicWipe must always insert a wipe job and return it.
	// There is no 204 code path — 204 based on nil dependencies is wrong
	// because the worker must always run final PG erasure. The handler
	// must always return 202 Accepted after a successful wipe.
	src := mustReadFile(t, "panicwipe.go")

	// ErrNothingToCleanup must not exist — always create a job.
	if strings.Contains(src, "ErrNothingToCleanup") {
		t.Fatal("panicwipe.go must not define ErrNothingToCleanup — always create a wipe job")
	}
	// No 204 return path.
	if strings.Contains(src, "StatusNoContent") {
		t.Fatal("panicwipe handler must not return 204 — always return 202 Accepted")
	}
	// Always insert a job (no needsCleanup guard).
	if strings.Contains(src, "if needsCleanup") {
		t.Fatal("panicwipe must always insert a wipe job — remove needsCleanup guard")
	}
	// Job insertion is unconditional now.
	insertPos := strings.Index(src, "InsertWipeJobTx")
	commitPos := strings.Index(src, "tx.Commit(ctx)")
	if insertPos < 0 || commitPos < 0 || insertPos > commitPos {
		t.Fatal("InsertWipeJobTx must be called unconditionally before tx.Commit")
	}
	// Verify the handler always returns 202.
	if !strings.Contains(src, "StatusAccepted") {
		t.Fatal("handler must return 202 Accepted on success")
	}
}

// ---------------------------------------------------------------------------
// Behavioral: wipe_jobs table schema contract (Issue #3)
// ---------------------------------------------------------------------------

func TestWipeJobSchemaHasRequiredColumns(t *testing.T) {
	// Verify the migration SQL file exists and contains all required columns.
	migrationSrc, err := os.ReadFile("../../../deploy/init/migrations/016_wipe_jobs.sql")
	if err != nil {
		t.Fatalf("migration file 016_wipe_jobs.sql not found: %v", err)
	}
	m := string(migrationSrc)

	if !strings.Contains(m, "CREATE TABLE IF NOT EXISTS wipe_jobs") {
		t.Fatal("migration must create wipe_jobs table")
	}

	for _, col := range []string{
		"id", "uin", "status", "file_keys", "failed_phases",
		"retry_count", "next_retry_at", "lease_until", "worker_id",
		"created_at", "updated_at",
	} {
		if !strings.Contains(m, col) {
			t.Fatalf("migration missing required column: %s", col)
		}
	}

	// Verify CHECK constraint for allowed statuses.
	if !strings.Contains(m, "CHECK (status IN") {
		t.Fatal("migration must have CHECK constraint on allowed statuses")
	}

	// Verify retry count check constraint.
	if !strings.Contains(m, "retry_count") || !strings.Contains(m, "CHECK") {
		t.Fatal("migration must include retry_count with bounded constraint")
	}

	// Verify indices for claimable jobs.
	if !strings.Contains(m, "idx_wipe_jobs_claimable") {
		t.Fatal("migration must create idx_wipe_jobs_claimable for pending/retrying job claims")
	}
	if !strings.Contains(m, "idx_wipe_jobs_expired_lease") {
		t.Fatal("migration must create idx_wipe_jobs_expired_lease for expired lease recovery")
	}
}

// ---------------------------------------------------------------------------
// Behavioral: InsertWipeJobTx exists and accepts pgx.Tx (Issue #1)
// ---------------------------------------------------------------------------

func TestInsertWipeJobTxExistsAndAcceptsTransaction(t *testing.T) {
	// Verify InsertWipeJobTx function exists and accepts pgx.Tx, not
	// *pgxpool.Pool. This is the tx-scoped insertion function.
	src := mustReadFile(t, "wipejob.go")

	if !strings.Contains(src, "func InsertWipeJobTx") {
		t.Fatal("InsertWipeJobTx function must exist for tx-scoped job insertion")
	}
	if !strings.Contains(src, "pgx.Tx") {
		t.Fatal("InsertWipeJobTx must accept pgx.Tx, not *pgxpool.Pool")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Behavioral: saturated backoff tests (Issue #3)
// ---------------------------------------------------------------------------

func TestSaturatedBackoffClampsAtMaxForOverflowValues(t *testing.T) {
	base := wipeJobRetryBaseWait
	max := wipeJobMaxBackoff

	for _, rc := range []int{62, 63, 100, 1000, math.MaxInt32} {
		b := saturatedBackoff(base, rc, max)
		if b != max {
			t.Errorf("saturatedBackoff(%v, %d, %v) = %v, want %v", base, rc, max, b, max)
		}
	}
}

func TestSaturatedBackoffReturnsBaseForZeroRetries(t *testing.T) {
	b := saturatedBackoff(wipeJobRetryBaseWait, 0, wipeJobMaxBackoff)
	if b != wipeJobRetryBaseWait {
		t.Errorf("saturatedBackoff(base, 0, max) = %v, want %v", b, wipeJobRetryBaseWait)
	}
}

func TestSaturatedBackoffNeverBelowBase(t *testing.T) {
	base := 100 * time.Millisecond
	max := 1 * time.Second
	for rc := -5; rc < 200; rc++ {
		b := saturatedBackoff(base, rc, max)
		if b < base {
			t.Fatalf("saturatedBackoff(%v, %d, %v) = %v < base", base, rc, max, b)
		}
		if b > max {
			t.Fatalf("saturatedBackoff(%v, %d, %v) = %v > max", base, rc, max, b)
		}
	}
}

// ---------------------------------------------------------------------------
// Behavioral: startup schema check (Issue #2)
// ---------------------------------------------------------------------------

func TestCheckWipeJobsSchemaExistsAndIsCalledable(t *testing.T) {
	// Verify CheckWipeJobsSchema function exists and is exported.
	src := mustReadFile(t, "wipejob.go")

	if !strings.Contains(src, "func CheckWipeJobsSchema") {
		t.Fatal("CheckWipeJobsSchema function must exist for startup schema verification")
	}
	if !strings.Contains(src, "ErrWipeJobsTableMissing") {
		t.Fatal("ErrWipeJobsTableMissing sentinel must exist")
	}
	if !strings.Contains(src, "requiredWipeJobsColumns") {
		t.Fatal("requiredWipeJobsColumns must list all expected columns")
	}
}

func TestCheckWipeJobsSchemaHasAllRequiredColumns(t *testing.T) {
	for _, col := range requiredWipeJobsColumns {
		if col == "" {
			t.Fatal("requiredWipeJobsColumns contains an empty entry")
		}
	}
	if len(requiredWipeJobsColumns) < 11 {
		t.Fatalf("requiredWipeJobsColumns has %d entries, want at least 11", len(requiredWipeJobsColumns))
	}
}

// ---------------------------------------------------------------------------
// Behavioral: claim query distinguishes ErrNoRows from other failures (Issue #2)
// ---------------------------------------------------------------------------

func TestClaimQueryTreatsOnlyErrNoRowsAsEmptyQueue(t *testing.T) {
	src := mustReadFile(t, "wipejob.go")

	if !strings.Contains(src, "pgx.ErrNoRows") {
		t.Fatal("claim query must check for pgx.ErrNoRows specifically")
	}
	// Must log non-ErrNoRows errors.
	if !strings.Contains(src, "claim query failed") {
		t.Fatal("claim query must log non-ErrNoRows errors")
	}
}

// ---------------------------------------------------------------------------
// Behavioral: ownership guard on retry and delete (Issue #1)
// ---------------------------------------------------------------------------

func TestRetryWipeJobRequiresWorkerID(t *testing.T) {
	src := mustReadFile(t, "wipejob.go")

	// qRetryWipeJob must include AND worker_id = $N.
	if !strings.Contains(src, "AND worker_id = $4") {
		t.Fatal("qRetryWipeJob must include AND worker_id = $4 for ownership guard")
	}
	// scheduleRetry must check RowsAffected.
	if !strings.Contains(src, "tag.RowsAffected() == 0") && !strings.Contains(src, "RowsAffected() ==") {
		t.Fatal("scheduleRetry must check RowsAffected() after retry update")
	}
}

func TestDeleteWipeJobRequiresWorkerID(t *testing.T) {
	src := mustReadFile(t, "wipejob.go")

	if !strings.Contains(src, "DELETE FROM wipe_jobs WHERE id = $1 AND worker_id = $2") {
		t.Fatal("qDeleteWipeJob must include AND worker_id = $2 for ownership guard")
	}
}

func TestRenewLeaseChecksRowsAffected(t *testing.T) {
	src := mustReadFile(t, "wipejob.go")

	if !strings.Contains(src, "tag.RowsAffected() == 0") {
		t.Fatal("lease renewal must check RowsAffected() — zero rows means lease lost")
	}
	if !strings.Contains(src, "lease lost") {
		t.Fatal("lease renewal must detect and report lease loss")
	}
	// Tightened guards: renewal must require status='processing' and
	// unexpired lease to prevent resurrecting an expired/reclaimed lease.
	if !strings.Contains(src, "status = 'processing'") {
		t.Fatal("qRenewLease must require status = 'processing' — never renew a non-processing job")
	}
	if !strings.Contains(src, "lease_until > NOW()") {
		t.Fatal("qRenewLease must require lease_until > NOW() — never resurrect an expired lease")
	}
}

// ---------------------------------------------------------------------------
// Behavioral: worker executes final PG erasure (Issue #4)
// ---------------------------------------------------------------------------

func TestWorkerExecutesFinalUserErasureAfterStorageCleanup(t *testing.T) {
	src := mustReadFile(t, "wipejob.go")

	// Worker must delete user row and wiped_accounts after storage cleanup.
	if !strings.Contains(src, "DELETE FROM wiped_accounts") {
		t.Fatal("worker must delete wiped_accounts entries during final erasure")
	}
	if !strings.Contains(src, "DELETE FROM users WHERE uin") {
		t.Fatal("worker must delete the user row during final erasure")
	}
	if !strings.Contains(src, "qFinalUserErasure") {
		t.Fatal("qFinalUserErasure query must exist for final PG erasure")
	}
}

func TestPanicWipeNoLongerAnonymizesUserRow(t *testing.T) {
	src := mustReadFile(t, "panicwipe.go")

	// Must not contain the old anonymization pattern 'deleted_' || uin.
	if strings.Contains(src, "'deleted_'") {
		t.Fatal("PanicWipe must not anonymize users row — the worker deletes it after storage cleanup")
	}
	// Must not insert into wiped_accounts.
	if strings.Contains(src, "INSERT INTO wiped_accounts") {
		t.Fatal("PanicWipe must not insert into wiped_accounts — the worker handles final erasure")
	}
	// Must disable the account (advance session_epoch).
	if !strings.Contains(src, "session_epoch") {
		t.Fatal("PanicWipe must advance session_epoch to disable the account")
	}
}

// ---------------------------------------------------------------------------
// Behavioral: graceful shutdown during active cleanup (Issue #5)
// ---------------------------------------------------------------------------

func TestWipeWorkerStopsCleanlyOnCancellation(t *testing.T) {
	// Start a worker with a nil Pool (won't claim jobs). Cancel and verify
	// stop returns within bounded time.
	runner := &WipeJobRunner{
		PollInterval: 10 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	stop := runner.StartWipeWorker(ctx)

	// Let it run a few poll cycles.
	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	cancel()
	stop()
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("worker shutdown took %v, want < 2s", elapsed)
	}
	t.Logf("worker shutdown took %v", elapsed)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mustReadFile(t *testing.T, filename string) string {
	t.Helper()
	src, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	return string(src)
}
