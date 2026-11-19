-- Saga operation records (contract M0 §5.4; spec §18.4, C3). Operations domain.
-- State transitions are enforced by compare-and-set on `version` in cs_ops::saga.
CREATE TABLE IF NOT EXISTS sagas (
  operation_id     uuid        PRIMARY KEY,
  tenant_id        uuid        NOT NULL,
  saga_type        text        NOT NULL,
  protocol_version int         NOT NULL CHECK (protocol_version >= 1),
  actor            uuid        NOT NULL,
  idempotency_key  text        NOT NULL CHECK (octet_length(idempotency_key) BETWEEN 1 AND 255),
  request_digest   bytea       NOT NULL CHECK (octet_length(request_digest) = 32),
  state            text        NOT NULL CHECK (state IN ('created', 'running_pre_pivot', 'pivot_committed', 'completing',
                                                         'completed', 'compensating', 'compensated', 'blocked_for_operator')),
  pivot            text        NOT NULL,
  steps            bytea       NOT NULL CHECK (octet_length(steps) <= 65536),
  deadline         timestamptz NOT NULL,
  result           bytea       CHECK (result IS NULL OR octet_length(result) <= 65536),
  version          bigint      NOT NULL CHECK (version >= 1),
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, saga_type, idempotency_key)
);

-- Reconciler work queue: only non-terminal sagas are indexed.
CREATE INDEX IF NOT EXISTS sagas_state_idx ON sagas (state)
  WHERE state IN ('created', 'running_pre_pivot', 'pivot_committed', 'completing', 'compensating');
