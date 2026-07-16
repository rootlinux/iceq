-- Opaque, pairwise-Signal-encrypted Sender Key recovery records.
-- The server sees routing metadata only and never the distribution plaintext.
CREATE TABLE IF NOT EXISTS sender_key_distributions (
  group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  epoch BIGINT NOT NULL CHECK (epoch > 0),
  recipient_uin BIGINT NOT NULL REFERENCES users(uin) ON DELETE CASCADE,
  sender_uin BIGINT NOT NULL REFERENCES users(uin) ON DELETE CASCADE,
  distribution_id TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  msg_type TEXT NOT NULL CHECK (msg_type IN ('prekey_message','signal_message')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  retired_at TIMESTAMPTZ,
  PRIMARY KEY (group_id, epoch, recipient_uin, sender_uin, distribution_id)
);
CREATE INDEX IF NOT EXISTS idx_sender_key_distributions_recipient ON sender_key_distributions(recipient_uin, group_id, epoch);
