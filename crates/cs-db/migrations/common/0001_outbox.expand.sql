-- Per-domain transactional outbox (contract M0 §5.2; spec App. E, C2, §18.4).
-- Rows are written only through cs_db::outbox::Outbox::append inside the state-change transaction.
-- Sequences are contiguous per partition: allocated from outbox_counters under a row lock.
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
  PRIMARY KEY ((partition) HASH, sequence ASC)
);

CREATE TABLE IF NOT EXISTS outbox_counters (
  partition     int    PRIMARY KEY CHECK (partition >= 0),
  next_sequence bigint NOT NULL CHECK (next_sequence >= 1)
);

-- P is fixed at creation: 16 partitions (design). The partition count is read back from this
-- table, never from code, so it cannot drift.
INSERT INTO outbox_counters (partition, next_sequence)
SELECT p, 1 FROM generate_series(0, 15) AS p
ON CONFLICT (partition) DO NOTHING;
