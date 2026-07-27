-- User-erasure indexes for panic-wipe cleanup.
--
-- message_ingest is partitioned by (sender_uin, client_id) — you cannot query it
-- by sender_uin alone without ALLOW FILTERING. This index maps uin to the
-- complete ingest primary key for exact deletion.
CREATE TABLE IF NOT EXISTS iceq.message_ingest_erasure_index (
  uin BIGINT,
  sender_uin BIGINT,
  client_id TEXT,
  PRIMARY KEY ((uin), sender_uin, client_id)
);

-- message_outbox is partitioned by (bucket) and clustered by (created_at, message_id).
-- There is no user-addressable partition key, so panic-wipe cannot delete outbox
-- rows by sender_uin or receiver_uin without a full-table scan. This index maps
-- uin (any user that appears as sender or receiver) to the complete outbox primary key.
CREATE TABLE IF NOT EXISTS iceq.message_outbox_erasure_index (
  uin BIGINT,
  bucket TINYINT,
  created_at TIMESTAMP,
  message_id UUID,
  PRIMARY KEY ((uin), bucket, created_at, message_id)
);

-- group_message_outbox has the same PK shape as message_outbox. This index maps
-- sender_uin and every recipient_uin to the complete outbox primary key for exact
-- deletion. The role column distinguishes sender ownership from recipient membership:
--   'sender'    – the wiped user is the sender; delete the shared pending outbox row.
--   'recipient' – the wiped user is only a recipient; remove only that UIN from the
--                 recipient_uins snapshot; delete the row only when no valid recipients remain.
CREATE TABLE IF NOT EXISTS iceq.group_message_outbox_erasure_index (
  uin BIGINT,
  bucket TINYINT,
  created_at TIMESTAMP,
  message_id UUID,
  role TEXT,
  PRIMARY KEY ((uin), bucket, created_at, message_id)
);
