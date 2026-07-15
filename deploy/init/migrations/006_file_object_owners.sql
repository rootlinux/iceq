-- File download authorization registry. Existing MinIO objects intentionally
-- have no row and therefore fail closed until an operator performs a trusted
-- ownership backfill. Guessing a UUID is never sufficient authorization.
CREATE TABLE IF NOT EXISTS file_objects (
    object_key UUID PRIMARY KEY,
    owner_uin BIGINT NOT NULL REFERENCES users(uin) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_file_objects_owner ON file_objects(owner_uin);
