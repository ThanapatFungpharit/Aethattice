-- Client idempotency records (contract M0 §5.3; spec D.3, C4).
CREATE TABLE IF NOT EXISTS idempotency_records (
  tenant_id      uuid        NOT NULL,
  principal_id   uuid        NOT NULL,
  key            text        NOT NULL CHECK (octet_length(key) BETWEEN 1 AND 255),
  request_digest bytea       NOT NULL CHECK (octet_length(request_digest) = 32),
  state          text        NOT NULL CHECK (state IN ('in_progress', 'completed')),
  response       bytea       CHECK (response IS NULL OR octet_length(response) <= 65536),
  expires_at     timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, principal_id, key),
  CHECK ((state = 'completed') = (response IS NOT NULL))
);
