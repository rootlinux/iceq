CREATE TABLE IF NOT EXISTS iceq.message_deletion_index (
  uin BIGINT, conversation_id TEXT, created_at TIMESTAMP, id UUID,
  PRIMARY KEY ((uin), conversation_id, created_at, id)
);
CREATE TABLE IF NOT EXISTS iceq.group_message_deletion_index (
  uin BIGINT, group_id UUID, created_at TIMESTAMP, id UUID,
  PRIMARY KEY ((uin), group_id, created_at, id)
);
