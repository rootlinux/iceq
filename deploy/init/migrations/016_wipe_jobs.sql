-- 016_wipe_jobs.sql
-- Durable asynchronous wipe-job table for the panic-wipe system.
--
-- After the PostgreSQL account mutation commits, a background worker picks up
-- pending jobs and retries Scylla, NATS, and MinIO cleanup independently of
-- any HTTP request budget. The job row is inserted inside the same PG
-- transaction that deletes ownership rows — the captured MinIO object keys are
-- committed atomically with the account mutation.
--
-- Crash safety: processing jobs hold a lease (lease_until). If the worker
-- dies, another worker reclaims the job once the lease expires. There is no
-- terminal "failed" status — retries continue indefinitely with capped
-- exponential backoff so cleanup is never silently abandoned.
--
-- A pending job temporarily contains deletion targets (file_keys). Zero
-- server footprint is achieved only after the job row is deleted on
-- successful cleanup.

CREATE TABLE IF NOT EXISTS wipe_jobs (
    id            BIGSERIAL       PRIMARY KEY,
    uin           BIGINT          NOT NULL,
    status        TEXT            NOT NULL DEFAULT 'pending'
                                  CHECK (status IN ('pending', 'processing', 'retrying')),
    file_keys     TEXT[]          NOT NULL DEFAULT '{}',
    failed_phases TEXT[]          NOT NULL DEFAULT '{}',
    retry_count   INT             NOT NULL DEFAULT 0
                                  CHECK (retry_count >= 0),
    next_retry_at TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    lease_until   TIMESTAMPTZ,
    worker_id     TEXT,
    created_at    TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- Index for claiming pending/retrying jobs ordered by scheduled time.
CREATE INDEX IF NOT EXISTS idx_wipe_jobs_claimable
    ON wipe_jobs (next_retry_at, id)
    WHERE status IN ('pending', 'retrying');

-- Index for reclaiming jobs whose lease expired (worker crashed).
CREATE INDEX IF NOT EXISTS idx_wipe_jobs_expired_lease
    ON wipe_jobs (lease_until, id)
    WHERE status = 'processing';

-- Verification: the table must exist with the correct schema before the
-- auth-service starts its background worker. Run after applying:
--
--   psql $ICEQ_PG_DSN -c "
--     SELECT table_name, column_name, data_type
--     FROM information_schema.columns
--     WHERE table_name = 'wipe_jobs'
--     ORDER BY ordinal_position;
--   "
--
-- Expected columns (12): id, uin, status, file_keys, failed_phases,
-- retry_count, next_retry_at, lease_until, worker_id, created_at, updated_at.
