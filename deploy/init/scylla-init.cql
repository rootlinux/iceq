CREATE KEYSPACE iceq WITH replication = {
  'class': 'SimpleStrategy',
  'replication_factor': 1
};

-- Direct-message store. The base table is a placeholder; the
-- columns required by the message-service (ciphertext BLOB,
-- msg_type TEXT) are added by the ALTER statements below. We
-- add the columns rather than re-creating the table so an
-- existing deployment (with rows in flight) doesn't lose data.
CREATE TABLE iceq.messages (
  conversation_id  TEXT,
  created_at       TIMESTAMP,
  id               UUID,
  sender_uin       BIGINT,
  receiver_uin     BIGINT,
  content          TEXT,
  content_type     TEXT,
  file_url         TEXT,
  status           TEXT,
  PRIMARY KEY ((conversation_id), created_at, id)
) WITH CLUSTERING ORDER BY (created_at DESC, id DESC);

-- E2EE columns. The web client encrypts every chat message
-- with the Signal Protocol (X3DH + Double Ratchet) before
-- handing the bytes to the gateway. The gateway forwards the
-- opaque bytes to us, and we store them as a BLOB. We never
-- log, inspect, transform, or index the ciphertext — it is a
-- black box from the server's perspective.
--
-- msg_type is one of "signal_message" or "prekey_message" (the
-- two shapes X3DH produces). The web client uses this to know
-- whether to start a fresh Double-Ratchet session or extend an
-- existing one.
ALTER TABLE iceq.messages ADD ciphertext BLOB;
ALTER TABLE iceq.messages ADD msg_type   TEXT;

-- Group-message store. Same pattern.
CREATE TABLE iceq.group_messages (
  group_id         UUID,
  created_at       TIMESTAMP,
  id               UUID,
  sender_uin       BIGINT,
  content          TEXT,
  content_type     TEXT,
  file_url         TEXT,
  PRIMARY KEY ((group_id), created_at, id)
) WITH CLUSTERING ORDER BY (created_at DESC, id DESC);

ALTER TABLE iceq.group_messages ADD ciphertext BLOB;
ALTER TABLE iceq.group_messages ADD msg_type   TEXT;

-- Panic-wipe deletion indexes. Each partition belongs to one UIN and carries
-- the complete primary key of the opaque message row; no cluster-wide scan is
-- required during account deletion.
CREATE TABLE iceq.message_deletion_index (
  uin BIGINT, conversation_id TEXT, created_at TIMESTAMP, id UUID,
  PRIMARY KEY ((uin), conversation_id, created_at, id)
);
CREATE TABLE iceq.group_message_deletion_index (
  uin BIGINT, group_id UUID, created_at TIMESTAMP, id UUID,
  PRIMARY KEY ((uin), group_id, created_at, id)
);
