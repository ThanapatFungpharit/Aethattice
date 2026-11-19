-- Saga step receipts (contract M0 §5.4 rev 2; spec §18.4). Written by the saga framework in
-- the same local transaction as the step's effect; a redelivered step finds its receipt and
-- returns the stored result without re-running. Every domain may participate in sagas, so
-- every domain gets this table.
CREATE TABLE IF NOT EXISTS saga_step_receipts (
  tenant_id    uuid        NOT NULL,
  operation_id uuid        NOT NULL,
  step         text        NOT NULL CHECK (octet_length(step) BETWEEN 1 AND 200),
  result       bytea       NOT NULL CHECK (octet_length(result) <= 65536),
  PRIMARY KEY ((tenant_id, operation_id) HASH, step)
);
