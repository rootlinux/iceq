-- Migration 001: add users.session_epoch for per-user mass-revocation.
--
-- Background. The JWT layer had two revocation primitives: a Redis
-- blocklist keyed by JTI (per-token), and nothing else. That made
-- "log this user out of every device" a write-amplification problem:
-- you'd have to know every JTI the user had ever held, write each
-- one to Redis, and trust the JTI generator never to collide.
--
-- This column closes that gap. `users.session_epoch` is a timestamp
-- set to NOW() at issue time and bumped to NOW() whenever ANY of the
-- following happens:
--   - the user logs out (logout handler)
--   - a refresh-token reuse is detected (refresh handler)
--   - an operator force-revokes a user (manual UPDATE)
--
-- The Verify path in shared/jwt/jwt.go reads this column on every
-- request and rejects any token whose `iat` is strictly before it.
-- A bumped epoch therefore invalidates every active session for the
-- user in O(1) writes (one UPDATE) and O(1) reads per request
-- (one indexed lookup on the PK).
--
-- Implementation notes:
--   - TIMESTAMPTZ so we never have to think about the server's local
--     timezone when comparing to the JWT `iat` claim (also TIMESTAMPTZ
--     in the v5 library).
--   - NOT NULL DEFAULT '1970-01-01 00:00:00+00' so the column is
--     usable on every pre-existing row without a separate UPDATE.
--     1970 is the zero-time, so any token issued AFTER the migration
--     has an iat > epoch and is accepted; any token issued before
--     the migration is rejected only if the user has since bumped
--     their epoch (which they would have done by logging in once).
--   - The DEFAULT makes this ADD COLUMN cheap on Postgres 11+: it's
--     a metadata-only operation when the DEFAULT is constant, no
--     table rewrite required.

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS session_epoch TIMESTAMPTZ NOT NULL
  DEFAULT '1970-01-01 00:00:00+00';
