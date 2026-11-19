-- Per-domain transactional outbox (contract M0 §5.2 rev 2; spec App. E, App. C rule C2, §18.4).
-- Rows are written only through cs_db::outbox::Outbox::append inside the state-change transaction.
-- Sequences are contiguous per (tenant_id, partition): allocated from outbox_counters under a
-- row lock. Domain-level (non-tenant) events use the nil UUID as tenant_id.
CREATE TABLE IF NOT EXISTS outbox (
  tenant_id     uuid        NOT NULL,
  partition     int         NOT NULL CHECK (partition >= 0),
  sequence      bigint      NOT NULL CHECK (sequence >= 1),
  event_id      uuid        NOT NULL,
  event_type    text        NOT NULL,
  event_version int         NOT NULL CHECK (event_version >= 1),
  partition_key uuid        NOT NULL,
  payload       bytea       NOT NULL CHECK (octet_length(payload) <= 65536),
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ((tenant_id, partition) HASH, sequence ASC)
);

-- Counter rows are created on first use by Outbox::append (INSERT ... ON CONFLICT).
CREATE TABLE IF NOT EXISTS outbox_counters (
  tenant_id     uuid   NOT NULL,
  partition     int    NOT NULL CHECK (partition >= 0),
  next_sequence bigint NOT NULL CHECK (next_sequence >= 1),
  PRIMARY KEY ((tenant_id, partition) HASH)
);
