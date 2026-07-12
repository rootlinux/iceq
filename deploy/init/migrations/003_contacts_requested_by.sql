-- Migration 003: record who initiated a pending contact request.
--
-- The contacts table stores two directed rows per request:
--   requester -> target
--   target    -> requester
-- Without a requester marker, the API cannot distinguish incoming
-- from outgoing pending rows, and the requester can accept their own
-- outgoing request. New writes set this explicitly; old rows are
-- backfilled to owner_uin as the safest non-null legacy value.

ALTER TABLE contacts
  ADD COLUMN IF NOT EXISTS requested_by_uin BIGINT REFERENCES users(uin);

UPDATE contacts
SET requested_by_uin = owner_uin
WHERE requested_by_uin IS NULL;

ALTER TABLE contacts
  ALTER COLUMN requested_by_uin SET NOT NULL;
