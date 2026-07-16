-- 008: 004-007 are already occupied by panic-wipe and file authorization migrations.
-- The epoch is server-visible routing metadata only; sender keys remain client-side.
ALTER TABLE groups ADD COLUMN IF NOT EXISTS crypto_epoch BIGINT NOT NULL DEFAULT 1;
DO $$ BEGIN
  ALTER TABLE groups ADD CONSTRAINT groups_crypto_epoch_positive CHECK (crypto_epoch > 0);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
