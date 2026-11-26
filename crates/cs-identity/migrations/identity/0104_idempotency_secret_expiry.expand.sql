-- Sealed idempotency replays (M1 contract rev 15/16 P2). `idempotency_records` comes from the
-- common migrations; the identity domain adds, expand-only, the deadline of a sealed
-- secret-bearing response. Past it the identity sweeper overwrites the payload with a
-- tombstone, so no ciphertext outlives the secret it carries. NULL for every response without
-- secrets (and for every row written by other domains or by N-1 nodes).
-- The index avoids a hot spot (App. E, as in 0102): 16 buckets derived from the key's hash,
-- hash-sharded on the bucket and range-ordered on the deadline; partial, so only sealed rows
-- are indexed.
ALTER TABLE idempotency_records ADD COLUMN IF NOT EXISTS secret_expires_at timestamptz;
ALTER TABLE idempotency_records ADD COLUMN IF NOT EXISTS secret_expiry_bucket smallint
  CHECK (secret_expiry_bucket IS NULL OR secret_expiry_bucket BETWEEN 0 AND 15);
CREATE INDEX IF NOT EXISTS idempotency_records_secret_expiry_idx
  ON idempotency_records ((secret_expiry_bucket) HASH, secret_expires_at ASC)
  WHERE secret_expires_at IS NOT NULL;
