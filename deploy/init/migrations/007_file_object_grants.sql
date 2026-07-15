CREATE TABLE IF NOT EXISTS file_object_grants (
    object_key UUID NOT NULL REFERENCES file_objects(object_key) ON DELETE CASCADE,
    owner_uin BIGINT NOT NULL REFERENCES users(uin) ON DELETE CASCADE,
    grantee_uin BIGINT NOT NULL REFERENCES users(uin) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (object_key, grantee_uin),
    CHECK (owner_uin <> grantee_uin)
);
CREATE INDEX IF NOT EXISTS idx_file_object_grants_grantee ON file_object_grants(grantee_uin, object_key);
