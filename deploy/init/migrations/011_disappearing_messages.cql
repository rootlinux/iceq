-- Per-message expiry metadata. Scylla TTL is applied to every ciphertext and
-- deletion-index cell in the same logged batch; expires_at lets history fail
-- closed during the short interval around TTL compaction.
ALTER TABLE iceq.messages ADD expires_at TIMESTAMP;
ALTER TABLE iceq.group_messages ADD expires_at TIMESTAMP;
