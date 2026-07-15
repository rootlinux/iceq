CREATE TABLE IF NOT EXISTS file_object_grants (
    object_key UUID NOT NULL,
    owner_uin BIGINT NOT NULL REFERENCES users(uin) ON DELETE CASCADE,
    grantee_uin BIGINT NOT NULL REFERENCES users(uin) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (object_key, grantee_uin),
    CHECK (owner_uin <> grantee_uin),
    FOREIGN KEY (object_key, owner_uin) REFERENCES file_objects(object_key, owner_uin) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_file_object_grants_grantee ON file_object_grants(grantee_uin, object_key);
