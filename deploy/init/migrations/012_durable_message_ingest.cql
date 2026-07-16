-- Durable idempotency receipt for authenticated message ingress. The complete
-- primary key is the authenticated sender plus the client-generated id; a
-- client id can therefore never collide across accounts. Envelope bytes and
-- their SHA-256 hash are immutable after the initial INSERT IF NOT EXISTS.
--
-- There is deliberately no schema-level default TTL. The writer applies the
-- sender's disappearing-message TTL to the receipt, message row, deletion
-- indexes, and outbox row together. Explicit "off" rows are written without
-- USING TTL and remain durable.
CREATE TABLE IF NOT EXISTS iceq.message_ingest (
  sender_uin       BIGINT,
  client_id        TEXT,
  receiver_uin     BIGINT,
  conversation_id  TEXT,
  envelope         BLOB,
  envelope_hash    BLOB,
  message_id       UUID,
  created_at       TIMESTAMP,
  expires_at       TIMESTAMP,
  state            TEXT,
  owner_token      UUID,
  lease_until      TIMESTAMP,
  stored_at        TIMESTAMP,
  delivered_at     TIMESTAMP,
  PRIMARY KEY ((sender_uin, client_id))
);

-- The opaque delivery outbox is written in the same logged batch as the
-- deterministic message row. Retrying that batch overwrites the same primary
-- keys rather than creating another logical message.
CREATE TABLE IF NOT EXISTS iceq.message_outbox (
  receiver_uin     BIGINT,
  created_at       TIMESTAMP,
  message_id       UUID,
  sender_uin       BIGINT,
  client_id        TEXT,
  conversation_id  TEXT,
  envelope         BLOB,
  envelope_hash    BLOB,
  state            TEXT,
  expires_at       TIMESTAMP,
  PRIMARY KEY ((receiver_uin), created_at, message_id)
) WITH CLUSTERING ORDER BY (created_at ASC, message_id ASC);
