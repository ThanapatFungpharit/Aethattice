-- OPAQUE server-side state (M1 contract rev 6 §2.1).

-- login_txn / registration_txn / reauth_txn records (§2.1; reauth_txn rev 7, bound to the session):
-- 60 s TTL, single use, bound to tenant, login and
-- source. The client-visible txn id uses the rt1 format (§3 [R8]); only SHA-256 of it is
-- stored and the tenant segment selects the partition. `tenant_id` has no foreign key: an
-- unknown tenant runs the same dummy path and writes the same row (§2.1 [R3]).
-- `sealed_state` is the AEAD-encrypted server state (ServerLogin KE2 state, or the registration
-- binding); it is never stored in plaintext because it would let a database reader finish a
-- login. AEAD associated data = tenant_id || txn_hash || kind. `user_id` is NULL on the dummy
-- path. A txn is consumed by DELETE ... RETURNING in the finishing transaction (single use
-- across nodes); expired rows are reclaimed lazily.
CREATE TABLE IF NOT EXISTS auth_txns (
  tenant_id     uuid        NOT NULL,
  txn_hash      bytea       NOT NULL CHECK (octet_length(txn_hash) = 32),
  kind          text        NOT NULL CHECK (kind IN ('login', 'registration', 'reauth')),
  login         text        NOT NULL CHECK (octet_length(login) BETWEEN 1 AND 254),
  source        text        NOT NULL CHECK (octet_length(source) BETWEEN 1 AND 64),
  user_id       uuid,
  session_id    uuid,
  grant_hash    bytea       CHECK (grant_hash IS NULL OR octet_length(grant_hash) = 32),
  key_version   int         NOT NULL CHECK (key_version >= 1),
  sealed_state  bytea       NOT NULL CHECK (octet_length(sealed_state) BETWEEN 1 AND 4096),
  expires_at    timestamptz NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ((tenant_id, txn_hash) HASH),
  CHECK (kind <> 'registration' OR (grant_hash IS NOT NULL AND user_id IS NOT NULL)),
  CHECK (kind <> 'reauth' OR (session_id IS NOT NULL AND user_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS auth_txns_expiry_idx ON auth_txns (expires_at ASC);

-- OPAQUE server key material (§2.1, §5.2): ServerSetup (OPRF seed + AKE key pair), the [R3]
-- PRF key and the txn sealing key, envelope-encrypted: a random data key wrapped by the KMS KEK
-- `identity-opaque@vN` (column `kek_id`), and the material encrypted under the data key with
-- XChaCha20-Poly1305, associated data = key_version || purpose. Unwrapped into
-- memory only. Deployment-wide (no tenant_id): one versioned set shared by every node, created
-- once with INSERT ... ON CONFLICT DO NOTHING.
CREATE TABLE IF NOT EXISTS opaque_server_keys (
  key_version int         NOT NULL CHECK (key_version >= 1),
  kek_id      text        NOT NULL CHECK (octet_length(kek_id) BETWEEN 1 AND 200),
  wrapped_dek bytea       NOT NULL CHECK (octet_length(wrapped_dek) BETWEEN 1 AND 4096),
  nonce       bytea       NOT NULL CHECK (octet_length(nonce) = 24),
  ciphertext  bytea       NOT NULL CHECK (octet_length(ciphertext) BETWEEN 1 AND 4096),
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (key_version ASC)
);
