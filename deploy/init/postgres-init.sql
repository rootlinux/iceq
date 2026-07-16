-- ============================================================================
-- IceQ — PostgreSQL schema bootstrap.
--
-- This file is mounted into the official postgres image's
-- /docker-entrypoint-initdb.d/ and runs ONCE on a fresh data directory.
-- For an existing deployment that needs to adopt the E2EE columns, the
-- migration commands at the bottom of this file can be run manually:
--
--   ALTER TABLE users ALTER COLUMN email DROP NOT NULL;
--   ALTER TABLE users ADD COLUMN IF NOT EXISTS identity_key TEXT NOT NULL DEFAULT '';
--   CREATE TABLE IF NOT EXISTS prekey_bundles (...);
--   CREATE TABLE IF NOT EXISTS one_time_prekeys (...);
--
-- E2EE columns (added by the architecture update):
--   * users.email       — now NULLABLE. An E2EE user can register with
--                         just a username + identity_key. Two users with
--                         no email are allowed because Postgres UNIQUE
--                         treats NULLs as distinct.
--   * users.identity_key — base64url-encoded X25519 PUBLIC key. The
--                         server stores only the public half; the
--                         private key is generated client-side in the
--                         browser and never leaves the device.
--   * prekey_bundles    — per-user long-term key material: identity key
--                         (copy from users, kept here for atomicity of
--                         the bundle fetch) and signed prekey (rotated
--                         weekly by the client; signature is the
--                         client's identity key signing the SPK pub).
--   * one_time_prekeys  — single-use prekeys consumed during X3DH. The
--                         server returns ONE on each bundle fetch and
--                         marks it used=true. A user can have 0..N
--                         unused keys; when the count hits 0 the
--                         bundle is still valid (X3DH falls back to
--                         using only the signed prekey).
-- ============================================================================

CREATE SEQUENCE uin_seq START 10000000 INCREMENT 1;

CREATE TABLE users (
  uin           BIGINT      DEFAULT nextval('uin_seq') PRIMARY KEY,
  username      TEXT        UNIQUE NOT NULL,
  -- email is now NULLABLE under the E2EE architecture: a user
  -- can register with just a username and identity_key. The
  -- column remains UNIQUE so a non-null email still maps to
  -- exactly one user. The auth-service uses NULLIF($email, '')
  -- in the INSERT to convert "" to NULL.
  email         TEXT        UNIQUE,
  password_hash TEXT        NOT NULL,
  -- identity_key is the base64url X25519 public key. The
  -- private counterpart is generated client-side and is never
  -- transmitted. DEFAULT '' is a safety net for pre-E2EE rows
  -- in a migrated database; the register handler rejects an
  -- empty identity_key at the application layer.
  identity_key  TEXT        NOT NULL DEFAULT '',
  avatar_url    TEXT,
  -- session_epoch: per-user mass-revocation timestamp. Bumped
  -- on logout / refresh-reuse / manual revoke. The JWT Verify
  -- path in shared/jwt/jwt.go rejects any token whose `iat` is
  -- strictly before this value. DEFAULT 1970 is the zero-time
  -- so a fresh install accepts every pre-existing (and every
  -- newly-issued) token without a backfill UPDATE. Migration
  -- 001_session_epoch.sql does the equivalent ADD COLUMN for
  -- databases that were bootstrapped before this column
  -- existed.
  session_epoch TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01 00:00:00+00',
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  updated_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE wiped_accounts (
  uin BIGINT PRIMARY KEY REFERENCES users(uin),
  wiped_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE contacts (
  owner_uin        BIGINT REFERENCES users(uin),
  target_uin       BIGINT REFERENCES users(uin),
  requested_by_uin BIGINT REFERENCES users(uin),
  status           TEXT NOT NULL CHECK (status IN ('pending', 'accepted', 'blocked')),
  created_at       TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (owner_uin, target_uin)
);

CREATE TABLE file_objects (
  object_key UUID PRIMARY KEY,
  owner_uin BIGINT NOT NULL REFERENCES users(uin) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (object_key, owner_uin)
);
CREATE INDEX idx_file_objects_owner ON file_objects(owner_uin);

CREATE TABLE file_object_grants (
  object_key UUID NOT NULL,
  owner_uin BIGINT NOT NULL REFERENCES users(uin) ON DELETE CASCADE,
  grantee_uin BIGINT NOT NULL REFERENCES users(uin) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (object_key, grantee_uin),
  CHECK (owner_uin <> grantee_uin),
  FOREIGN KEY (object_key, owner_uin) REFERENCES file_objects(object_key, owner_uin) ON DELETE CASCADE
);
CREATE INDEX idx_file_object_grants_grantee ON file_object_grants(grantee_uin, object_key);

CREATE TABLE groups (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT        NOT NULL,
  owner_uin   BIGINT      REFERENCES users(uin),
  crypto_epoch BIGINT     NOT NULL DEFAULT 1 CHECK (crypto_epoch > 0),
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE group_members (
  group_id    UUID   REFERENCES groups(id) ON DELETE CASCADE,
  uin         BIGINT REFERENCES users(uin),
  role        TEXT   NOT NULL CHECK (role IN ('admin', 'member')),
  joined_at   TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (group_id, uin)
);

CREATE TABLE sender_key_distributions (
  group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  epoch BIGINT NOT NULL CHECK (epoch > 0), recipient_uin BIGINT NOT NULL REFERENCES users(uin) ON DELETE CASCADE,
  sender_uin BIGINT NOT NULL REFERENCES users(uin) ON DELETE CASCADE, distribution_id TEXT NOT NULL,
  ciphertext TEXT NOT NULL, msg_type TEXT NOT NULL CHECK (msg_type IN ('prekey_message','signal_message')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), retired_at TIMESTAMPTZ,
  PRIMARY KEY (group_id, epoch, recipient_uin, sender_uin, distribution_id)
);
CREATE INDEX idx_sender_key_distributions_recipient ON sender_key_distributions(recipient_uin, group_id, epoch);

CREATE TABLE refresh_tokens (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  uin         BIGINT      REFERENCES users(uin),
  token_hash  TEXT        NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- E2EE key material (added by the architecture update).
-- ============================================================================

-- prekey_bundles: one row per user. Holds the long-term key
-- material that Alice needs in order to start a Signal Protocol
-- session with Bob. The bundle is read-only from the server's
-- perspective — the client uploads it via POST /api/keys/bundle.
--
-- signed_prekey is stored as JSONB rather than three columns
-- because the X3DH wire format expects the three fields
-- together (id, public_key, signature) and the client consumes
-- them as one blob. JSONB gives us indexed access later if we
-- need to look up "who has SPK id=42" (e.g. for a "rotate
-- everyone" admin command), but that's a future concern.
CREATE TABLE prekey_bundles (
  uin              BIGINT      REFERENCES users(uin) PRIMARY KEY,
  identity_key     TEXT        NOT NULL,
  signed_prekey    JSONB       NOT NULL,
  registration_id  INTEGER     NOT NULL DEFAULT 0,
  spk_uploaded_at  TIMESTAMPTZ DEFAULT NOW()
);

-- one_time_prekeys: a pool of single-use prekeys per user.
-- The server picks ONE per /api/keys/bundle/{uin} request
-- (marking it used=true) and returns it to the caller. When
-- the user runs out, the bundle is still served — it just
-- lacks the one_time_prekey field, and X3DH falls back to a
-- signed-prekey-only handshake.
--
-- The (uin, key_id) UNIQUE constraint prevents the client
-- from accidentally uploading the same key_id twice; key_id
-- is the client's own monotonically-increasing counter, not
-- a server-assigned value.
CREATE TABLE one_time_prekeys (
  id         SERIAL       PRIMARY KEY,
  uin        BIGINT       REFERENCES users(uin) ON DELETE CASCADE,
  key_id     INT          NOT NULL,
  public_key TEXT         NOT NULL,
  used       BOOLEAN      DEFAULT FALSE,
  UNIQUE(uin, key_id)
);

-- Index for the consume-one-OPK path: WHERE uin = $1 AND used = false
-- ORDER BY key_id ASC LIMIT 1. The (uin, used) composite covers the
-- filter; the planner uses the key_id sort to satisfy ORDER BY
-- without a sort step. Partial index would be more efficient
-- (WHERE used = false) but Postgres requires a non-partial
-- index to back a UNIQUE constraint, and we want the UNIQUE
-- check on (uin, key_id) regardless of used status. The
-- index below is the best compromise.
CREATE INDEX idx_one_time_prekeys_uin_used
  ON one_time_prekeys (uin, key_id)
  WHERE used = false;

-- Compatibility shell for explicit wipe cleanup. Older deployments stored
-- automatic-wipe configuration in this table; fresh schemas expose no such
-- configuration, while the shared table name keeps explicit wipe idempotent.
CREATE TABLE user_security_settings (
  uin BIGINT REFERENCES users(uin) PRIMARY KEY
);
