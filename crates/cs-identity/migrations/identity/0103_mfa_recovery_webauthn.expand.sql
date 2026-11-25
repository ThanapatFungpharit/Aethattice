-- M1 contract rev 10/11: WebAuthn, MFA, recovery-code sets, email recovery, session listing.
-- Expand only: new tables and nullable columns; constraint widenings on auth_txns (no row can
-- violate the wider checks). The unused `recovery_codes` table is dropped by a later contract
-- migration (rev 11).

-- Recovery-code sets (rev 11): 10 codes per set, wire format `<code_id>-<secret>`; lookup by
-- code_id, one Argon2id verification. `set_version` identifies the set; generating a new set
-- deletes the previous one in the same transaction.
CREATE TABLE IF NOT EXISTS recovery_code_entries (
  tenant_id   uuid        NOT NULL,
  user_id     uuid        NOT NULL,
  code_id     text        NOT NULL CHECK (code_id ~ '^[A-Z2-7]{8}$'),
  code_hash   text        NOT NULL CHECK (octet_length(code_hash) BETWEEN 1 AND 512),
  set_version bigint      NOT NULL CHECK (set_version >= 1),
  used_at     timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ((tenant_id, user_id) HASH, code_id ASC),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, user_id)
);

-- Verified email (rev 11), set only by `cs admin user set-email --verified` in M1.
ALTER TABLE users ADD COLUMN IF NOT EXISTS email text
  CHECK (email IS NULL OR octet_length(email) BETWEEN 3 AND 254);
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified_at timestamptz;

-- Session listing (rev 10/11) and the enrolment-only scope (rev 11: `scp` claim kept across
-- refresh).
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_seen_at timestamptz;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_agent text
  CHECK (user_agent IS NULL OR char_length(user_agent) <= 200);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS scope text
  CHECK (scope IS NULL OR scope IN ('mfa_enrolment'));

-- Passkeys (rev 10/11). `passkey_state` is the serialized webauthn-rs credential (public key,
-- counter, flags); `public_key` keeps the COSE key for inspection.
ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS label text
  CHECK (label IS NULL OR char_length(label) BETWEEN 1 AND 100);
ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS last_used_at timestamptz;
ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS passkey_state bytea
  CHECK (passkey_state IS NULL OR octet_length(passkey_state) BETWEEN 1 AND 16384);

-- Ceremony state for MFA and WebAuthn (contract §2.2, §2.3, rev 10/11), stored like the
-- OPAQUE txns of `auth_txns` (rev 6): the client-visible id uses the rt1 format and only its
-- SHA-256 is stored; the state is AEAD-sealed under the txn-sealing key with associated data
-- tenant_id || txn_hash || kind; each row is consumed by DELETE ... RETURNING in the finishing
-- transaction (single use across nodes); expired rows are swept in bounded batches.
-- A separate table rather than new `auth_txns` kinds: widening the `auth_txns` CHECKs would
-- need DROP CONSTRAINT, which only a contract migration may do; WebAuthn state with several
-- allowed credentials also exceeds the 4 KiB `auth_txns` limit.
-- Kinds: `mfa` (auth_txn after OPAQUE, 5 min, rev 11), `webauthn_reg` (bound to the session),
-- `webauthn_login` (discoverable, bound to tenant and source), `webauthn_assert` (MFA: bound
-- to the user and the consumed auth_txn's source; step-up: bound to the session).
CREATE TABLE IF NOT EXISTS auth_ceremonies (
  tenant_id     uuid        NOT NULL,
  txn_hash      bytea       NOT NULL CHECK (octet_length(txn_hash) = 32),
  kind          text        NOT NULL CHECK (kind IN ('mfa', 'webauthn_reg', 'webauthn_login', 'webauthn_assert')),
  source        text        NOT NULL CHECK (octet_length(source) BETWEEN 1 AND 64),
  user_id       uuid,
  session_id    uuid,
  key_version   int         NOT NULL CHECK (key_version >= 1),
  sealed_state  bytea       NOT NULL CHECK (octet_length(sealed_state) BETWEEN 1 AND 65536),
  expires_at    timestamptz NOT NULL,
  expiry_bucket smallint    NOT NULL CHECK (expiry_bucket BETWEEN 0 AND 15),
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ((tenant_id, txn_hash) HASH),
  CHECK (kind = 'webauthn_login' OR user_id IS NOT NULL),
  CHECK (kind <> 'webauthn_reg' OR session_id IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS auth_ceremonies_expiry_bucket_idx
  ON auth_ceremonies ((expiry_bucket) HASH, expires_at ASC);

-- Recovery requests (rev 10): email link hash, device-approval txn hash, approval time,
-- recovery code to invalidate at completion, requester User-Agent (truncated to 256 bytes).
ALTER TABLE recovery_requests ADD COLUMN IF NOT EXISTS link_hash bytea
  CHECK (link_hash IS NULL OR octet_length(link_hash) = 32);
ALTER TABLE recovery_requests ADD COLUMN IF NOT EXISTS txn_hash bytea
  CHECK (txn_hash IS NULL OR octet_length(txn_hash) = 32);
ALTER TABLE recovery_requests ADD COLUMN IF NOT EXISTS approved_at timestamptz;
ALTER TABLE recovery_requests ADD COLUMN IF NOT EXISTS code_id text
  CHECK (code_id IS NULL OR code_id ~ '^[A-Z2-7]{8}$');
ALTER TABLE recovery_requests ADD COLUMN IF NOT EXISTS requester_user_agent text
  CHECK (requester_user_agent IS NULL OR octet_length(requester_user_agent) <= 256);
CREATE UNIQUE INDEX IF NOT EXISTS recovery_requests_link_hash_idx
  ON recovery_requests ((tenant_id, link_hash) HASH) WHERE link_hash IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS recovery_requests_txn_hash_idx
  ON recovery_requests ((tenant_id, txn_hash) HASH) WHERE txn_hash IS NOT NULL;
