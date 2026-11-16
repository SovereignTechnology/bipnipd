-- bipnip: bookkeeping for the public lease order event (kind 38735) of each offer.
-- New columns on bipnip's own table only.

-- The `status` the public order event was last brought up to date with; NULL = never.
-- A row whose synced_status differs from its status is behind, and the housekeeping job retries it.
ALTER TABLE lease_offers ADD COLUMN synced_status varchar(12);
-- created_at of the last order event published, so the next one is always newer.
ALTER TABLE lease_offers ADD COLUMN order_event_at integer;
