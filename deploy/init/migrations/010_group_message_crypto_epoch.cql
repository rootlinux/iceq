-- Persist the authenticated group epoch beside opaque group ciphertext.
-- Existing rows remain null in Scylla and scan as 0 in Go; the history API
-- exposes that 0 explicitly so clients reject legacy rows fail-closed.
ALTER TABLE iceq.group_messages ADD crypto_epoch BIGINT;
