-- Expiry indexes without a hot spot (App. E) for the two short-lived tables swept by expiry:
-- `auth_txns` (contract §2.1 rev 6) and `dpop_jti` (§3 [R6]). A plain range index on a
-- monotonic `expires_at` sends every insert to the last tablet, so each table gets an
-- `expiry_bucket` (16 buckets derived from a random value: get_byte(txn_hash, 0) % 16 for
-- auth_txns, the first byte of SHA-256(jti) % 16 for dpop_jti; written by the application)
-- and an index hash-sharded on the bucket and range-ordered on `expires_at` within it. Inserts
-- spread over 16 hash values; the sweeps read each bucket in expiry order.
--
-- Expand step: the columns are nullable because an N-1 node may still insert without them;
-- the sweeps also drain the NULL bucket (the index covers NULL as a hash value). The follow-up
-- contract migration (after the release is finalized) sets NOT NULL and drops the old
-- `auth_txns_expiry_idx`.
ALTER TABLE auth_txns ADD COLUMN IF NOT EXISTS expiry_bucket smallint
  CHECK (expiry_bucket IS NULL OR expiry_bucket BETWEEN 0 AND 15);
CREATE INDEX IF NOT EXISTS auth_txns_expiry_bucket_idx
  ON auth_txns ((expiry_bucket) HASH, expires_at ASC);
ALTER TABLE dpop_jti ADD COLUMN IF NOT EXISTS expiry_bucket smallint
  CHECK (expiry_bucket IS NULL OR expiry_bucket BETWEEN 0 AND 15);
CREATE INDEX IF NOT EXISTS dpop_jti_expiry_bucket_idx
  ON dpop_jti ((expiry_bucket) HASH, expires_at ASC);
