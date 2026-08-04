// Package handlers — wipejob.go
//
// Persisted wipe-job table and background worker for durable async cleanup.
//
// The job row is inserted inside the same PostgreSQL transaction that deletes
// ownership rows and disables the account. If job insertion fails, the
// entire transaction rolls back — the account mutation is never committed
// without a corresponding cleanup job.
//
// After commit, a background poller picks up pending jobs and executes
// Scylla, NATS, and MinIO cleanup independently of any HTTP request budget.
// Only after every external cleanup phase confirms deletion does a final
// PostgreSQL transaction permanently delete the user row, wiped_accounts
// entries, and the completed wipe-job row — leaving zero rows associated
// with the wiped UIN in any PostgreSQL table.
//
// Crash safety: each job claim sets a lease_until timestamp and worker_id.
// If the worker dies before completing the job, another worker reclaims the
// expired lease. Every lease renewal, retry transition, and completed-job
// deletion requires the current worker_id. Zero RowsAffected is treated as
// lease loss — a worker whose lease expired must never alter a job reclaimed
// by another worker.
//
// There is no terminal "failed" status — retries continue indefinitely with
// capped exponential backoff.
//
// IMPORTANT: a pending job temporarily contains deletion targets (file_keys
// and uin). Zero server footprint is achieved only after the job is deleted
// on successful cleanup. Do NOT log uin, file_keys, or other linkable
// identifiers at levels visible in production logs.
package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	wipeJobPollInterval  = 5 * time.Second
	wipeJobLeaseTimeout  = 2 * time.Minute
	wipeJobRetryBaseWait = 10 * time.Second
	wipeJobMaxBackoff    = 10 * time.Minute // cap exponential backoff

	// maxSafeRetryShift is the largest retry_count for which 1 << retryCount
	// fits in an int without overflow on 64-bit systems.
	maxSafeRetryShift = 62
)

// ---------------------------------------------------------------------------
// SQL queries
// ---------------------------------------------------------------------------

// qSchemaCheckWipeJobs verifies the wipe_jobs table exists with the expected
// columns. Used at startup to fail fast if migration 016 has not been applied.
var qSchemaCheckWipeJobs = `
	SELECT column_name
	FROM information_schema.columns
	WHERE table_name = 'wipe_jobs'
	ORDER BY ordinal_position
`

var (
	// qInsertWipeJob creates a pending wipe-job row. Called inside the PG
	// transaction that performs the account mutation so both are durable or
	// neither is.
	qInsertWipeJob = `
		INSERT INTO wipe_jobs (uin, file_keys)
		VALUES ($1, $2)
		RETURNING id
	`

	// qClaimPendingJob atomically claims the next ready job. It matches:
	//   1. pending/retrying jobs whose next_retry_at has arrived, OR
	//   2. processing jobs whose lease has expired (crashed worker).
	// FOR UPDATE SKIP LOCKED prevents multiple workers from grabbing the
	// same row and ensures no blocking on contended rows.
	//
	// The "marked" CTE is now only an idempotent RECOVERY BACKSTOP for the
	// wiped_accounts row, not the primary insertion path: PanicWipe itself
	// (panicwipe.go) inserts the marker inside its own PG transaction,
	// committed atomically with the account mutation and the wipe_job row,
	// so every service's BearerAuth (via jwt.Manager.IsAccountWiped) and
	// the history endpoints' peer/sender checks already see this uin as
	// wiped from the moment PanicWipe's HTTP response is sent -- no gap
	// waiting for a worker to poll. This CTE's insert only does real work
	// if that primary insert is ever somehow missing by the time a job is
	// claimed (there is no known path that causes this; it exists purely
	// so a claim can never be blocked on a missing marker). The marker is
	// guaranteed to be deleted again by processOneJob's final-erasure
	// Phase 1 once all storage cleanup confirms -- see that code for the
	// matching DELETE -- so its lifetime exactly brackets "a wipe job
	// exists for this uin", never longer.
	//
	// ON CONFLICT (uin) DO NOTHING makes the insert idempotent across
	// reclaims of the same job (expired lease, retries). The
	// "WHERE EXISTS (SELECT 1 FROM users ...)" guard handles a narrow
	// crash-recovery case: wiped_accounts.uin has a FOREIGN KEY to
	// users(uin) (migration 005), and a worker can crash after final
	// erasure's Phase 1 already deleted both rows but before Phase 3
	// deletes the wipe_job row (see processOneJob) -- a later reclaim of
	// that same job must not attempt to resurrect a marker for a uin whose
	// user row is permanently gone, which would fail the FK constraint and,
	// because a data-modifying CTE aborts the entire statement on error,
	// would make the claim itself fail and stall the job forever.
	qClaimPendingJob = `
		WITH claimed AS (
			UPDATE wipe_jobs
			SET status      = 'processing',
			    lease_until = $1,
			    worker_id   = $2,
			    updated_at  = NOW()
			WHERE id = (
				SELECT id FROM wipe_jobs
				WHERE (status IN ('pending', 'retrying') AND next_retry_at <= NOW())
				   OR (status = 'processing' AND lease_until IS NOT NULL AND lease_until < NOW())
				ORDER BY next_retry_at, id
				LIMIT 1
				FOR UPDATE SKIP LOCKED
			)
			RETURNING id, uin, file_keys, retry_count
		),
		marked AS (
			INSERT INTO wiped_accounts (uin)
			SELECT c.uin FROM claimed c
			WHERE EXISTS (SELECT 1 FROM users u WHERE u.uin = c.uin)
			ON CONFLICT (uin) DO NOTHING
			RETURNING uin
		)
		SELECT id, uin, file_keys, retry_count FROM claimed
	`

	// qRenewLease extends lease_until for a long-running cleanup so the job
	// is not reclaimed by another worker mid-operation. Requires:
	//   - matching worker_id (ownership guard)
	//   - status = 'processing' (never renew a completed/retrying job)
	//   - lease_until > NOW() (never resurrect an expired lease)
	//
	// Without the lease_until > NOW() guard, a worker whose lease expired
	// and was reclaimed by another worker could still renew — the worker_id
	// would match because the stale worker originally claimed it, but the
	// lease expiration means ownership has been surrendered.
	qRenewLease = `
		UPDATE wipe_jobs
		SET lease_until = $2,
		    updated_at  = NOW()
		WHERE id = $1
		  AND worker_id = $3
		  AND status = 'processing'
		  AND lease_until > NOW()
	`

	// qRetryWipeJob schedules the next retry with exponential backoff.
	// Requires the current worker_id — a worker that lost its lease must
	// not alter a job now owned by another worker.
	qRetryWipeJob = `
		UPDATE wipe_jobs
		SET status        = 'retrying',
		    retry_count    = retry_count + 1,
		    failed_phases  = $2,
		    next_retry_at  = $3,
		    lease_until    = NULL,
		    worker_id      = NULL,
		    updated_at     = NOW()
		WHERE id = $1 AND worker_id = $4
	`

	// qDeleteWipeJob removes the job after all phases confirm deletion.
	// Requires the current worker_id — only the worker that holds the
	// lease may delete the job.
	qDeleteWipeJob = `DELETE FROM wipe_jobs WHERE id = $1 AND worker_id = $2`

	// qFinalUserErasure permanently deletes the user row and related
	// tombstones after all external storage cleanup confirms deletion.
	// Runs in a single transaction inside the worker after Scylla, NATS,
	// and MinIO cleanup all succeed. After this transaction, zero rows
	// associated with the wiped UIN remain in any PostgreSQL table.
	//
	// FK-safe deletion order: refresh_tokens (no CASCADE, and a concurrent
	// login that slips past the serialization boundary could insert a row
	// after PanicWipe's initial DELETE) → wiped_accounts (FK to users) →
	// users. All other FK children were deleted by PanicWipe's own
	// transaction or carry ON DELETE CASCADE.
	qFinalUserErasure = `
		DELETE FROM refresh_tokens WHERE uin = $1;
		DELETE FROM wiped_accounts WHERE uin = $1;
		DELETE FROM users WHERE uin = $1;
	`
)

// ---------------------------------------------------------------------------
// WipeJobRunner
// ---------------------------------------------------------------------------

// WipeJobRunner executes durable storage cleanup for wipe jobs. It is
// created once in main() and runs a background poller goroutine.
type WipeJobRunner struct {
	Pool   *pgxpool.Pool
	Scylla MessageStore
	NATS   NatsCleaner
	Minio  MinioCleaner
	Redis  RedisCleaner

	// PollInterval controls how often the poller checks for pending jobs.
	// Defaults to wipeJobPollInterval (5s).
	PollInterval time.Duration
	// LeaseTimeout bounds a single job's processing time. If a worker
	// exceeds this, another worker may reclaim the job. Defaults to
	// wipeJobLeaseTimeout (2 min).
	LeaseTimeout time.Duration
	// WorkerID uniquely identifies this process for lease ownership.
	// Generated on first use if empty.
	WorkerID string
}

func (r *WipeJobRunner) pollInterval() time.Duration {
	if r.PollInterval <= 0 {
		return wipeJobPollInterval
	}
	return r.PollInterval
}

func (r *WipeJobRunner) leaseTimeout() time.Duration {
	if r.LeaseTimeout <= 0 {
		return wipeJobLeaseTimeout
	}
	return r.LeaseTimeout
}

func (r *WipeJobRunner) workerID() string {
	if r.WorkerID != "" {
		return r.WorkerID
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		r.WorkerID = fmt.Sprintf("w-%d", time.Now().UnixNano())
	} else {
		r.WorkerID = "w-" + hex.EncodeToString(b)
	}
	return r.WorkerID
}

// ErrWipeJobsTableMissing is returned by CheckWipeJobsSchema when the
// wipe_jobs table does not exist or has the wrong schema.
var ErrWipeJobsTableMissing = errors.New("wipe_jobs table is missing or has wrong schema — migration 016 may not have been applied")

// requiredWipeJobsColumns lists every column the wipe_jobs table must have.
// Auth-service startup fails if any column is absent.
var requiredWipeJobsColumns = []string{
	"id", "uin", "status", "file_keys", "failed_phases",
	"retry_count", "next_retry_at", "lease_until", "worker_id",
	"created_at", "updated_at",
}

// CheckWipeJobsSchema verifies the wipe_jobs table exists with all required
// columns. Call during auth-service startup; fail closed if the migration has
// not been applied — a missing table means durable wipe cleanup cannot work.
func CheckWipeJobsSchema(ctx context.Context, pool *pgxpool.Pool) error {
	rows, err := pool.Query(ctx, qSchemaCheckWipeJobs)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWipeJobsTableMissing, err)
	}
	defer rows.Close()

	found := make(map[string]bool)
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			return fmt.Errorf("%w: scan column: %v", ErrWipeJobsTableMissing, err)
		}
		found[col] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: iterate columns: %v", ErrWipeJobsTableMissing, err)
	}

	if len(found) == 0 {
		return fmt.Errorf("%w: no columns returned (table may not exist)", ErrWipeJobsTableMissing)
	}

	var missing []string
	for _, req := range requiredWipeJobsColumns {
		if !found[req] {
			missing = append(missing, req)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: missing columns: %v", ErrWipeJobsTableMissing, missing)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Transaction-scoped insertion
// ---------------------------------------------------------------------------

// InsertWipeJobTx creates a pending wipe-job row inside an existing PG
// transaction. It MUST be called inside the same transaction that performs
// the account mutation. If the INSERT fails, the caller is expected to
// roll back the entire transaction — account mutation and job must be
// durable together.
func InsertWipeJobTx(ctx context.Context, tx pgx.Tx, uin int64, fileKeys []string) (int64, error) {
	if fileKeys == nil {
		fileKeys = []string{}
	}
	var id int64
	err := tx.QueryRow(ctx, qInsertWipeJob, uin, fileKeys).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert wipe job: %w", err)
	}
	return id, nil
}

// ---------------------------------------------------------------------------
// Worker lifecycle
// ---------------------------------------------------------------------------

// StartWipeWorker launches a background goroutine that polls for pending
// wipe jobs and executes durable storage cleanup. The goroutine runs until
// ctx is cancelled.
//
// The returned stop function waits for the worker goroutine to exit. The
// caller MUST cancel ctx before calling stop, otherwise stop blocks
// indefinitely.
//
// Typical usage:
//
//	workerCtx, workerCancel := context.WithCancel(context.Background())
//	defer workerCancel()
//	stop := runner.StartWipeWorker(workerCtx)
//	// ... graceful shutdown ...
//	workerCancel()
//	stop()
func (r *WipeJobRunner) StartWipeWorker(ctx context.Context) (stop func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(r.pollInterval())
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.processOneJob(ctx)
			}
		}
	}()
	return func() { <-done }
}

// ---------------------------------------------------------------------------
// Job processing
// ---------------------------------------------------------------------------

func (r *WipeJobRunner) processOneJob(parent context.Context) {
	if r.Pool == nil {
		return
	}

	// The claim query uses a bounded context (initial lease timeout).
	// The job itself uses an unbounded context — successful lease renewal
	// extends the effective lifetime beyond the initial lease timeout.
	claimCtx, claimCancel := context.WithTimeout(context.WithoutCancel(parent), r.leaseTimeout())
	defer claimCancel()

	wID := r.workerID()
	leaseUntil := time.Now().Add(r.leaseTimeout())

	var jobID int64
	var uin int64
	var fileKeys []string
	var retryCount int

	err := r.Pool.QueryRow(claimCtx, qClaimPendingJob, leaseUntil, wID).Scan(&jobID, &uin, &fileKeys, &retryCount)
	if err != nil {
		// Only pgx.ErrNoRows means "no claimable jobs" — the queue is empty.
		// Every other error is a database failure that must be surfaced.
		if errors.Is(err, pgx.ErrNoRows) {
			return
		}
		log.Printf("[auth-service] wipe-worker: claim query failed: %v", err)
		return
	}

	log.Printf("[auth-service] wipe-worker: claimed job %d (retries=%d, worker=%s)", jobID, retryCount, wID)

	// ---- Job-level lease and cancellation ----------------------------------
	// jobCtx derives from the worker's parent context so service shutdown
	// cancels active cleanup. It is NOT derived from claimCtx — successful
	// lease renewal extends the job's effective lifetime independently of
	// the initial claim timeout.
	//
	// A single lease-renewal goroutine runs for the entire job lifetime.
	// Every renewal DB call has a bounded timeout (renewalDBTimeout) so a
	// stuck database cannot block the goroutine indefinitely.
	//
	// lastConfirmedLease tracks the most recent lease timestamp confirmed
	// by a successful DB write. If a renewal fails and we are past
	// lastConfirmedLease + leaseTimeout, ownership is definitely lost.
	// On ANY renewal error, ownership is unconfirmed — jobCancel is called
	// to prevent destructive work without confirmed ownership.
	//
	// When jobCtx is cancelled mid-execution, an idempotent retry is
	// scheduled (if the worker is not shutting down). The worker_id guard
	// ensures only the legitimate lease-holder updates the job row.
	//
	// cleanup() cancels jobCtx first, then joins the renewal goroutine
	// with a bounded wait (30s safety timer). The order matters: cancel →
	// unblocks <-jobCtx.Done() → goroutine exits → renewWg.Done().
	jobCtx, jobCancel := context.WithCancel(parent)

	var renewWg sync.WaitGroup
	renewWg.Add(1)
	leaseRenewInterval := r.leaseTimeout() / 2
	const renewalDBTimeout = 5 * time.Second

	// lastConfirmedLease tracks the most recent lease timestamp confirmed
	// by a successful DB write. Initialized to the lease_until value from
	// the claim query — the claim itself is a successful DB write that
	// confirms ownership through lease_until. Used to detect definite
	// lease expiry after a renewal error.
	lastConfirmedLease := leaseUntil

	go func() {
		defer renewWg.Done()
		ticker := time.NewTicker(leaseRenewInterval)
		defer ticker.Stop()
		for {
			select {
			case <-jobCtx.Done():
				return
			case <-ticker.C:
				newLease := time.Now().Add(r.leaseTimeout())
				renewCtx, renewCancel := context.WithTimeout(context.WithoutCancel(parent), renewalDBTimeout)
				tag, renewErr := r.Pool.Exec(renewCtx, qRenewLease, jobID, newLease, wID)
				renewCancel()

				if renewErr != nil {
					// Ownership is unconfirmed after a DB error.
					// If we are past the last confirmed lease deadline,
					// ownership is definitely lost. Otherwise we still
					// cancel — destructive work must not continue with
					// unconfirmed ownership.
					if !lastConfirmedLease.IsZero() && time.Now().After(lastConfirmedLease.Add(r.leaseTimeout())) {
						log.Printf("[auth-service] wipe-worker: lease renewal failed for job %d and last confirmed lease expired — cancelling", jobID)
					} else {
						log.Printf("[auth-service] wipe-worker: lease renewal error for job %d — cancelling to prevent destructive work without confirmed ownership: %v", jobID, renewErr)
					}
					jobCancel()
					return
				}
				lastConfirmedLease = newLease

				if tag.RowsAffected() == 0 {
					// Lease was reclaimed by another worker. Cancel the
					// job context — this prevents all remaining phases,
					// the retry path, and final erasure from executing.
					log.Printf("[auth-service] wipe-worker: lease lost for job %d (worker=%s)", jobID, wID)
					jobCancel()
					return
				}
			}
		}
	}()

	// cleanup cancels the job context first, then joins the renewal
	// goroutine with a bounded wait. The order matters: cancel →
	// unblocks <-jobCtx.Done() → goroutine exits → renewWg.Done() →
	// Wait() returns. The safety timer prevents blocking indefinitely
	// even if the renewal goroutine is stuck despite bounded DB timeouts.
	cleanup := func() {
		jobCancel()
		done := make(chan struct{})
		go func() {
			renewWg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			log.Printf("[auth-service] wipe-worker: renewal goroutine did not exit within 30s of cancellation for job %d", jobID)
		}
	}
	defer cleanup()

	// ---- Phase execution --------------------------------------------------
	// failedPhases collects the names of storage layers that did not confirm
	// deletion. If jobCtx is cancelled (lease lost), phases are skipped.
	var failedPhases []string

	// runPhase executes a single storage cleanup phase. It checks jobCtx
	// before starting — if the lease was already lost, the phase is skipped
	// and "lease-lost" is added to failedPhases.
	runPhase := func(name string, fn func(context.Context) error) {
		if jobCtx.Err() != nil {
			// Lease already lost — do not start new work.
			if !containsPhase(failedPhases, "lease-lost") {
				failedPhases = append(failedPhases, "lease-lost")
			}
			return
		}

		phaseCtx, phaseCancel := context.WithTimeout(jobCtx, 30*time.Second)
		defer phaseCancel()

		if err := fn(phaseCtx); err != nil {
			log.Printf("[auth-service] wipe-worker: %s cleanup failed for job %d: %v", name, jobID, err)
			failedPhases = append(failedPhases, name)
		}

		// After the phase completes, check whether the lease was lost
		// during execution (jobCtx cancelled by the renewer).
		if jobCtx.Err() != nil && !containsPhase(failedPhases, "lease-lost") {
			failedPhases = append(failedPhases, "lease-lost")
		}
	}

	if r.Scylla != nil {
		runPhase("scylla", func(ctx context.Context) error {
			return cleanupScylla(ctx, r.Scylla, uin, 8*time.Second)
		})
	}

	if r.NATS != nil {
		runPhase("nats", func(ctx context.Context) error {
			return r.NATS.PurgeUserStreams(ctx, uin)
		})
	}

	if r.Minio != nil {
		runPhase("minio_objects", func(ctx context.Context) error {
			return r.Minio.DeleteUserObjects(ctx, uin, fileKeys)
		})
		runPhase("minio_grants", func(ctx context.Context) error {
			return r.Minio.DeleteUserGrants(ctx, uin)
		})
	}

	if r.Redis != nil {
		runPhase("redis", func(ctx context.Context) error {
			return cleanupRedisKeys(ctx, r.Redis, uin)
		})
	}

	// ---- Completion or retry ----------------------------------------------
	// If jobCtx was cancelled, the lease was lost or ownership became
	// unconfirmed. If the parent (worker) context is still alive, schedule
	// an idempotent retry so the job is not stranded. The worker_id guard
	// in scheduleRetry ensures only the current lease-holder updates the
	// job. If parent is cancelled (service shutdown), skip the retry —
	// another worker will pick up the job on its next poll tick.
	if jobCtx.Err() != nil {
		if parent.Err() == nil {
			// Parent still alive — lease was lost, schedule retry.
			log.Printf("[auth-service] wipe-worker: job %d lease lost during execution — scheduling retry", jobID)
			if !containsPhase(failedPhases, "lease-lost") {
				failedPhases = append(failedPhases, "lease-lost")
			}
			retryCtx, retryCancel := context.WithTimeout(context.WithoutCancel(parent), 10*time.Second)
			defer retryCancel()
			r.scheduleRetry(retryCtx, jobID, failedPhases, retryCount, wID)
		} else {
			log.Printf("[auth-service] wipe-worker: job %d cancelled during shutdown — skipping retry", jobID)
		}
		return
	}

	if len(failedPhases) == 0 {
		// ---- Durable deletion state machine -------------------------------
		//
		// Phase 1: Irreversibly delete the user row. The wipe_job row
		// remains as a durable cleanup marker so a crash after this point
		// does not strand the blocklist key.
		//
		// Phase 2: Retry blocklist deletion until confirmed. The job row
		// is the durable record — if all retries fail, the job is
		// rescheduled and the next attempt resumes from here.
		//
		// Phase 3: Only after blocklist deletion is confirmed, delete the
		// wipe_job row. No success log is emitted while either the
		// blocklist key or job row remains.
		//
		// Every step is idempotent and crash-recoverable.

		finalCtx, finalCancel := context.WithTimeout(context.WithoutCancel(parent), 30*time.Second)
		defer finalCancel()

		// Phase 1: Delete user irreversibly. Keep the wipe_job row as a
		// durable marker so the blocklist deletion is retried on crash.
		tx, txErr := r.Pool.Begin(finalCtx)
		if txErr != nil {
			log.Printf("[auth-service] wipe-worker: final erasure tx begin failed for job %d: %v", jobID, txErr)
			r.scheduleRetry(finalCtx, jobID, []string{"final-erasure"}, retryCount, wID)
			return
		}
		// Rollback is a no-op after commit; safe to defer unconditionally.
		defer func() { _ = tx.Rollback(finalCtx) }()

		// Defense in depth: delete any remaining refresh_tokens before the
		// user row. The FK refresh_tokens.uin → users(uin) has no CASCADE;
		// this also cleans up legacy rows created before login/wipe
		// serialization was enforced.
		if _, txErr = tx.Exec(finalCtx, `DELETE FROM refresh_tokens WHERE uin = $1`, uin); txErr != nil {
			log.Printf("[auth-service] wipe-worker: final erasure refresh_tokens failed for job %d uin %d: %v", jobID, uin, txErr)
			r.scheduleRetry(finalCtx, jobID, []string{"final-erasure"}, retryCount, wID)
			return
		}
		if _, txErr = tx.Exec(finalCtx, `DELETE FROM wiped_accounts WHERE uin = $1`, uin); txErr != nil {
			log.Printf("[auth-service] wipe-worker: final erasure wiped_accounts failed for job %d uin %d: %v", jobID, uin, txErr)
			r.scheduleRetry(finalCtx, jobID, []string{"final-erasure"}, retryCount, wID)
			return
		}
		if _, txErr = tx.Exec(finalCtx, `DELETE FROM users WHERE uin = $1`, uin); txErr != nil {
			log.Printf("[auth-service] wipe-worker: final erasure users failed for job %d uin %d: %v", jobID, uin, txErr)
			r.scheduleRetry(finalCtx, jobID, []string{"final-erasure"}, retryCount, wID)
			return
		}

		// Commit user deletion. The user row is permanently gone.
		// The wipe_job row survives as the durable cleanup marker.
		if txErr = tx.Commit(finalCtx); txErr != nil {
			log.Printf("[auth-service] wipe-worker: user deletion commit failed for job %d: %v", jobID, txErr)
			r.scheduleRetry(finalCtx, jobID, []string{"final-erasure"}, retryCount, wID)
			return
		}

		// Phase 2: Retry blocklist deletion until confirmed.
		// The wipe_job row is the durable record — if we crash here,
		// the next retry will re-run idempotent storage phases and
		// resume from Phase 1 (user already deleted, harmless no-op).
		const maxBlocklistRetries = 5
		var blocklistDeleted bool
		for attempt := 0; attempt < maxBlocklistRetries; attempt++ {
			if r.Redis == nil {
				blocklistDeleted = true
				break
			}
			blockCtx, blockCancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
			err := r.Redis.DeleteBlocklistKey(blockCtx, uin)
			blockCancel()
			if err == nil {
				blocklistDeleted = true
				break
			}
			log.Printf("[auth-service] wipe-worker: blocklist deletion attempt %d/%d failed for job %d uin %d: %v",
				attempt+1, maxBlocklistRetries, jobID, uin, err)
			if attempt < maxBlocklistRetries-1 {
				time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
			}
		}

		if !blocklistDeleted {
			// User is deleted but blocklist key persists. Schedule a
			// retry — the wipe_job row remains as the durable marker.
			// The next attempt re-runs idempotent storage phases and
			// retries blocklist deletion.
			log.Printf("[auth-service] wipe-worker: blocklist deletion failed after %d attempts for job %d — scheduling retry",
				maxBlocklistRetries, jobID)
			r.scheduleRetry(finalCtx, jobID, []string{"blocklist"}, retryCount, wID)
			return
		}

		// Phase 3: Blocklist key confirmed deleted. Now safe to remove
		// the durable wipe_job marker. This runs in a new transaction
		// because the user-deletion transaction already committed.
		//
		// Guarded by worker_id so only the lease-holding worker deletes
		// the job. Zero RowsAffected means another worker reclaimed and
		// completed the job — nothing to do.
		jobTx, jobTxErr := r.Pool.Begin(finalCtx)
		if jobTxErr != nil {
			log.Printf("[auth-service] wipe-worker: job deletion tx begin failed for job %d: %v", jobID, jobTxErr)
			r.scheduleRetry(finalCtx, jobID, []string{"job-deletion"}, retryCount, wID)
			return
		}
		defer func() { _ = jobTx.Rollback(finalCtx) }()

		tag, jobTxErr := jobTx.Exec(finalCtx, qDeleteWipeJob, jobID, wID)
		if jobTxErr != nil {
			log.Printf("[auth-service] wipe-worker: job deletion failed for job %d: %v", jobID, jobTxErr)
			r.scheduleRetry(finalCtx, jobID, []string{"job-deletion"}, retryCount, wID)
			return
		}
		if tag.RowsAffected() == 0 {
			// Another worker reclaimed and completed the job.
			log.Printf("[auth-service] wipe-worker: job %d already completed by another worker", jobID)
			return
		}

		if jobTxErr = jobTx.Commit(finalCtx); jobTxErr != nil {
			log.Printf("[auth-service] wipe-worker: job deletion commit failed for job %d: %v", jobID, jobTxErr)
			r.scheduleRetry(finalCtx, jobID, []string{"job-deletion"}, retryCount, wID)
			return
		}

		// Success: user row deleted, blocklist key deleted, wipe_job
		// row deleted. Zero footprint achieved.
		log.Printf("[auth-service] wipe-worker: job %d completed — user fully erased, blocklist deleted", jobID)
		return
	}

	// Some phases failed. Schedule retry — the worker_id guard in
	// scheduleRetry ensures only the current lease-holder updates the job.
	// Use a short-lived context independent of the claim timeout so the
	// retry update succeeds even if the claim context has expired.
	retryCtx, retryCancel := context.WithTimeout(context.WithoutCancel(parent), 10*time.Second)
	defer retryCancel()
	r.scheduleRetry(retryCtx, jobID, failedPhases, retryCount, wID)
}

// containsPhase reports whether name is present in phases.
func containsPhase(phases []string, name string) bool {
	for _, p := range phases {
		if p == name {
			return true
		}
	}
	return false
}

// scheduleRetry updates the job row for a retry. It requires the current
// worker_id — if the lease was lost (zero RowsAffected), the job is already
// owned by another worker and we must not touch it.
func (r *WipeJobRunner) scheduleRetry(ctx context.Context, jobID int64, failedPhases []string, retryCount int, wID string) {
	backoff := saturatedBackoff(wipeJobRetryBaseWait, retryCount, wipeJobMaxBackoff)
	nextRetry := time.Now().Add(backoff)

	tag, err := r.Pool.Exec(ctx, qRetryWipeJob, jobID, failedPhases, nextRetry, wID)
	if err != nil {
		log.Printf("[auth-service] wipe-worker: retry schedule failed for job %d: %v", jobID, err)
		return
	}
	if tag.RowsAffected() == 0 {
		// Lease was lost — another worker has already reclaimed this job.
		log.Printf("[auth-service] wipe-worker: retry skipped for job %d — lease lost to another worker", jobID)
		return
	}

	log.Printf("[auth-service] wipe-worker: job %d retry %d in %v (phases failed: %v)",
		jobID, retryCount+1, backoff, failedPhases)
}

// ---------------------------------------------------------------------------
// Redis cleanup
// ---------------------------------------------------------------------------
//
// Redis key inventory for a user (UIN-based). Each key pattern below is
// deleted during the "redis" wipe phase. Failure is reported so the job
// retries — Redis cleanup must be confirmed before final PG erasure.
//
// Key                              | Purpose                          | Deleted
// -------------------------------- | -------------------------------- | -------
// jwt:blocklist:wipe:{uin}        | Panic-wipe session revocation    | After final PG erasure (NOT in this phase)
// presence:{uin}                   | Online presence state            | Yes
// undelivered:{uin}                | Undelivered message queue        | Yes
// poll:stream:{uin}                | Poll stream head                 | Yes
// poll:cursors:{uin}               | Poll cursor hash                 | Yes
// poll:cursor-order:{uin}          | Poll cursor ordered set          | Yes
// poll:{{uin}}:*                   | Hash-tag poll keys               | Yes (SCAN + DEL)
// login_attempts:{uin}             | Legacy login counter             | Yes
// ratelimit:auth:{uin}:{action}    | Authenticated rate-limit bucket  | Yes (deterministic DEL, one key per action)
//
// The blocklist key (jwt:blocklist:wipe:{uin}) is INTENTIONALLY excluded
// from this phase. It was set by PanicWipe with a 7-day TTL
// (panicWipeBlocklistTTL = 7 * 24 * time.Hour) to revoke existing sessions.
// Removing it prematurely would let a still-valid token re-attach while
// cleanup is in progress. The worker deletes this key via DeleteBlocklistKey
// only after the final PG erasure transaction commits (user row permanently
// deleted, all connections terminated). If the worker never reaches that
// point (crash, etc.), the key self-expires after 7 days — longer than the
// maximum access-token TTL (15 min) and the maximum practical refresh-token
// lifetime. Zero server footprint is achieved only after the worker
// confirms blocklist key deletion. If Redis is unreachable, the
// wipe_job row remains as a durable retry marker and the key
// self-expires after 7 days.

// redisKeyPatterns lists every deterministic per-user Redis key.
func redisUserKeys(uin int64) []string {
	s := itoa(uin)
	return []string{
		// Presence and undelivered queues.
		"presence:" + s,
		"undelivered:" + s,

		// Poll infrastructure keys.
		"poll:stream:" + s,
		"poll:cursors:" + s,
		"poll:cursor-order:" + s,

		// Legacy login attempt counter.
		"login_attempts:" + s,
	}
}

// redisScanPatterns lists hash-tag poll key patterns requiring SCAN.
func redisScanPatterns(uin int64) []string {
	s := itoa(uin)
	return []string{
		"poll:{" + s + "}:*",
		"poll:{" + s + "}",
	}
}

// cleanupRedisKeys deletes every user-scoped Redis key except the
// blocklist key. It uses DEL for deterministic keys and SCAN+DEL for
// wildcard patterns. The first error encountered is returned; remaining
// keys are still attempted (best-effort within the phase).
func cleanupRedisKeys(ctx context.Context, cleaner RedisCleaner, uin int64) error {
	return cleaner.CleanupUserKeys(ctx, uin)
}

// saturatedBackoff computes capped exponential backoff without overflow.
// For retryCount >= maxSafeRetryShift (62), it returns maxBackoff directly.
// For lower values, it computes base * (1 << retryCount) and clamps to
// maxBackoff. The result is always in [base, maxBackoff] for any non-negative
// retryCount.
func saturatedBackoff(base time.Duration, retryCount int, maxBackoff time.Duration) time.Duration {
	if retryCount < 0 {
		retryCount = 0
	}
	// Guard against overflow: if shifting would overflow int, return cap.
	if retryCount >= maxSafeRetryShift {
		return maxBackoff
	}
	shifted := int64(1) << retryCount
	// Check if multiplication would overflow int64.
	if shifted > math.MaxInt64/int64(base) {
		return maxBackoff
	}
	backoff := time.Duration(int64(base) * shifted)
	if backoff > maxBackoff {
		return maxBackoff
	}
	return backoff
}
