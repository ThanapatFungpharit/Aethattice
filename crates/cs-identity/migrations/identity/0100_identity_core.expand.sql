-- Identity domain schema (M1 contract rev 3 §1; spec §5, App. E).
-- tenant_id first in every key, HASH on the leading key columns, version / state columns for
-- compare-and-set, timestamps set by the database, CHECK-constrained lifecycle states.
-- Foreign keys stay within this domain. outbox, outbox_counters, idempotency_records and
-- saga_step_receipts come from the shared cs-db migrations 0001-0099.

-- Tenants (§5.1). `policy` is the tenant policy document as deterministic CBOR (§5.1).
-- `group_epoch` is the per-tenant serialization point for group membership writes: every
-- membership transaction bumps it before its closure check, so two concurrent writes can never
-- both pass the cycle / limit check against a state that misses the other (§6.4).
CREATE TABLE IF NOT EXISTS tenants (
  tenant_id   uuid        NOT NULL,
  name        text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
  state       text        NOT NULL CHECK (state IN ('active', 'suspended', 'deleting')),
  policy      bytea       NOT NULL CHECK (octet_length(policy) <= 65536),
  group_epoch bigint      NOT NULL DEFAULT 0 CHECK (group_epoch >= 0),
  version     bigint      NOT NULL CHECK (version >= 1),
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ((tenant_id) HASH)
);

-- Users (§5.1, §5.7). `login` is normalized (NFKC + lowercase) by the application.
-- Profile fields: display name, photo (object reference, plain ID), title, department, manager.
-- Presence is realtime state and is not stored here.
CREATE TABLE IF NOT EXISTS users (
  tenant_id       uuid        NOT NULL,
  user_id         uuid        NOT NULL,
  login           text        NOT NULL CHECK (octet_length(login) BETWEEN 1 AND 254),
  status          text        NOT NULL CHECK (status IN ('invited', 'active', 'disabled')),
  kind            text        NOT NULL CHECK (kind IN ('member', 'guest')),
  display_name    text        CHECK (display_name IS NULL OR char_length(display_name) BETWEEN 1 AND 200),
  photo_object_id uuid,
  title           text        CHECK (title IS NULL OR char_length(title) BETWEEN 1 AND 200),
  department      text        CHECK (department IS NULL OR char_length(department) BETWEEN 1 AND 200),
  manager_id      uuid,
  version         bigint      NOT NULL CHECK (version >= 1),
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ((tenant_id, user_id) HASH),
  FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id),
  FOREIGN KEY (tenant_id, manager_id) REFERENCES users (tenant_id, user_id),
  CHECK (manager_id IS NULL OR manager_id <> user_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS users_login_idx ON users ((tenant_id, login) HASH);

-- Groups (§5.1, §6.1, §6.4). `membership_version` is bumped in the same transaction as every
-- change of the group's direct members; it is also the group's compare-and-set column.
CREATE TABLE IF NOT EXISTS groups (
  tenant_id          uuid        NOT NULL,
  group_id           uuid        NOT NULL,
  name               text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
  membership_version bigint      NOT NULL CHECK (membership_version >= 1),
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ((tenant_id, group_id) HASH),
  FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id)
);

-- Direct members (group#member tuples, §6.1), stored with the group. Range on member_id within
-- the hash-sharded (tenant_id, group_id) prefix for member listings.
CREATE TABLE IF NOT EXISTS group_members (
  tenant_id   uuid        NOT NULL,
  group_id    uuid        NOT NULL,
  member_id   uuid        NOT NULL,
  member_kind text        NOT NULL CHECK (member_kind IN ('user', 'group')),
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ((tenant_id, group_id) HASH, member_id ASC),
  FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, group_id),
  CHECK (member_kind <> 'group' OR member_id <> group_id)
);
-- Reverse lookup (which groups contain a principal): closure checks and ancestor walks.
CREATE INDEX IF NOT EXISTS group_members_member_idx ON group_members ((tenant_id, member_id) HASH, group_id ASC);

-- OPAQUE registrations (§5.2; contract §2.1). Argon2id KSF parameters stored per registration.
CREATE TABLE IF NOT EXISTS opaque_registrations (
  tenant_id          uuid        NOT NULL,
  user_id            uuid        NOT NULL,
  password_file      bytea       NOT NULL CHECK (octet_length(password_file) BETWEEN 1 AND 4096),
  ksf_m_kib          int         NOT NULL CHECK (ksf_m_kib >= 1),
  ksf_t              int         NOT NULL CHECK (ksf_t >= 1),
  ksf_p              int         NOT NULL CHECK (ksf_p >= 1),
  server_key_version text        NOT NULL CHECK (octet_length(server_key_version) BETWEEN 1 AND 200),
  version            bigint      NOT NULL CHECK (version >= 1),
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ((tenant_id, user_id) HASH),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, user_id)
);

-- WebAuthn credentials (§5.3; contract §2.2).
CREATE TABLE IF NOT EXISTS webauthn_credentials (
  tenant_id     uuid        NOT NULL,
  user_id       uuid        NOT NULL,
  credential_id bytea       NOT NULL CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
  public_key    bytea       NOT NULL CHECK (octet_length(public_key) BETWEEN 1 AND 16384),
  sign_count    bigint      NOT NULL CHECK (sign_count >= 0),
  transports    text[]      NOT NULL DEFAULT '{}',
  discoverable  boolean     NOT NULL,
  prf_supported boolean     NOT NULL,
  version       bigint      NOT NULL CHECK (version >= 1),
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ((tenant_id, user_id) HASH, credential_id ASC),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, user_id)
);
-- Discoverable (passwordless) sign-in looks the credential up without knowing the user.
CREATE UNIQUE INDEX IF NOT EXISTS webauthn_credentials_credential_id_idx ON webauthn_credentials ((tenant_id, credential_id) HASH);

-- Sessions (§5.5; contract §3). `generation` is bumped on revocation (carried as `sgen`).
CREATE TABLE IF NOT EXISTS sessions (
  tenant_id           uuid        NOT NULL,
  session_id          uuid        NOT NULL,
  user_id             uuid        NOT NULL,
  state               text        NOT NULL CHECK (state IN ('active', 'revoked', 'expired')),
  amr                 text[]      NOT NULL,
  auth_time           timestamptz NOT NULL,
  last_strong_auth_at timestamptz,
  device_key_jkt      bytea       CHECK (device_key_jkt IS NULL OR octet_length(device_key_jkt) = 32),
  idle_expires_at     timestamptz NOT NULL,
  absolute_expires_at timestamptz NOT NULL,
  generation          bigint      NOT NULL CHECK (generation >= 1),
  version             bigint      NOT NULL CHECK (version >= 1),
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ((tenant_id, session_id) HASH),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, user_id)
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions ((tenant_id, user_id) HASH, session_id ASC);

-- Refresh tokens (§5.5; contract §3 [R1] [R8]). token_hash = SHA-256 of the whole
-- `rt1.<tenant>.<random>` string. `successor_hash` links a rotated token to the token that
-- replaced it (lost-response handling, [R1]).
CREATE TABLE IF NOT EXISTS refresh_tokens (
  tenant_id                uuid        NOT NULL,
  token_hash               bytea       NOT NULL CHECK (octet_length(token_hash) = 32),
  session_id               uuid        NOT NULL,
  family_generation        bigint      NOT NULL CHECK (family_generation >= 1),
  state                    text        NOT NULL CHECK (state IN ('active', 'rotated', 'revoked')),
  key_jkt                  bytea       CHECK (key_jkt IS NULL OR octet_length(key_jkt) = 32),
  successor_hash           bytea       CHECK (successor_hash IS NULL OR octet_length(successor_hash) = 32),
  rotated_at               timestamptz,
  rotation_idempotency_key text        CHECK (rotation_idempotency_key IS NULL OR octet_length(rotation_idempotency_key) BETWEEN 1 AND 255),
  created_at               timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ((tenant_id, token_hash) HASH),
  FOREIGN KEY (tenant_id, session_id) REFERENCES sessions (tenant_id, session_id),
  CHECK (state <> 'rotated' OR rotated_at IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS refresh_tokens_session_idx ON refresh_tokens ((tenant_id, session_id) HASH);

-- DPoP replay fallback when Valkey is unavailable (contract §3 [R6]). jkt = SHA-256 JWK
-- thumbprint (RFC 7638). Written with INSERT ... ON CONFLICT DO NOTHING.
CREATE TABLE IF NOT EXISTS dpop_jti (
  tenant_id  uuid        NOT NULL,
  jkt        bytea       NOT NULL CHECK (octet_length(jkt) = 32),
  jti        text        NOT NULL CHECK (octet_length(jti) BETWEEN 1 AND 255),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY ((tenant_id, jkt) HASH, jti ASC)
);

-- Recovery codes (§5.6). `code_hash` is an Argon2id PHC string; shown once, never stored plain.
CREATE TABLE IF NOT EXISTS recovery_codes (
  tenant_id  uuid        NOT NULL,
  user_id    uuid        NOT NULL,
  code_hash  text        NOT NULL CHECK (octet_length(code_hash) BETWEEN 1 AND 512),
  version    bigint      NOT NULL CHECK (version >= 1),
  created_at timestamptz NOT NULL DEFAULT now(),
  used_at    timestamptz,
  PRIMARY KEY ((tenant_id, user_id) HASH),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, user_id)
);

-- Recovery requests (§5.6; contract §4 [R5]). `not_before` ends the waiting period. A granted
-- request carries the SHA-256 of its single-use grant token and the grant expiry.
CREATE TABLE IF NOT EXISTS recovery_requests (
  tenant_id        uuid        NOT NULL,
  request_id       uuid        NOT NULL,
  user_id          uuid        NOT NULL,
  method           text        NOT NULL CHECK (method IN ('recovery_code', 'device_approval', 'passkey_approval', 'email', 'admin')),
  state            text        NOT NULL CHECK (state IN ('pending', 'cancelled', 'granted', 'completed', 'expired')),
  not_before       timestamptz NOT NULL,
  grant_hash       bytea       CHECK (grant_hash IS NULL OR octet_length(grant_hash) = 32),
  grant_expires_at timestamptz,
  version          bigint      NOT NULL CHECK (version >= 1),
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ((tenant_id, request_id) HASH),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, user_id),
  CHECK ((grant_hash IS NULL) = (grant_expires_at IS NULL)),
  CHECK (state NOT IN ('granted', 'completed') OR grant_hash IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS recovery_requests_user_idx ON recovery_requests ((tenant_id, user_id) HASH, request_id ASC);
CREATE UNIQUE INDEX IF NOT EXISTS recovery_requests_grant_hash_idx ON recovery_requests ((tenant_id, grant_hash) HASH)
  WHERE grant_hash IS NOT NULL;

-- One-time first-administrator setup links (J.4 step 4; contract §0, §1 [R8]). token_hash =
-- SHA-256 of the whole `rt1.<tenant>.<random>` string; the tenant comes from the token.
CREATE TABLE IF NOT EXISTS setup_links (
  tenant_id  uuid        NOT NULL,
  token_hash bytea       NOT NULL CHECK (octet_length(token_hash) = 32),
  user_id    uuid        NOT NULL,
  purpose    text        NOT NULL CHECK (purpose IN ('first_admin')),
  state      text        NOT NULL CHECK (state IN ('active', 'used', 'expired', 'revoked')),
  expires_at timestamptz NOT NULL,
  used_at    timestamptz,
  version    bigint      NOT NULL CHECK (version >= 1),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ((tenant_id, token_hash) HASH),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, user_id),
  CHECK ((state = 'used') = (used_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS setup_links_user_idx ON setup_links ((tenant_id, user_id) HASH);
