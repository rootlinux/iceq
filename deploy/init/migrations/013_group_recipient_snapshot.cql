-- Immutable fan-out target set captured with the group's crypto epoch at ingest.
ALTER TABLE iceq.message_ingest ADD recipient_uins LIST<BIGINT>;
ALTER TABLE iceq.group_message_outbox ADD recipient_uins LIST<BIGINT>;
