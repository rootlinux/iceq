-- 015_wipe_public_key.sql
-- Adds a dedicated Panic Wipe challenge-signature verification key.
-- This replaces the legacy panic_pin_hash with a key that does NOT
-- permit offline guessing: the client holds the private signing key
-- (protected by the local Security Passphrase vault), the server only
-- stores the corresponding public verification credential.
--
-- The panic_pin_hash column is retained during migration for existing
-- users who have not yet enrolled the new credential through the
-- mandatory first-login security setup. It can be NULLed after
-- successful enrollment.

ALTER TABLE IF EXISTS user_security_settings
  ADD COLUMN IF NOT EXISTS wipe_public_key TEXT;
