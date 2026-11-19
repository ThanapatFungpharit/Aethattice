# M1 Contracts: Identity (DRAFT, frozen at M0 gate after review)

- Status: **draft**. It is frozen only once the M0 gate passes and the QA Engineer and project owner have reviewed it.
- Spec: §5 (all), §3.5, §6.8, §15.4, §21.3, App. A, D, E, J.4. Errata: C8.
- Builds on `M0-foundations.md`.

## 0. Ordering issue: admin authorization before M2 (owner decision needed)

Spec §6.8 says administrative actions are authorized through the relationship model. That model, with its tuples on tenant resources in the resources domain and the decision service, arrives in M2. M1 has no compliant way to authorize tenant-admin HTTP APIs.

**Proposal:**
- M1 exposes **no HTTP admin API**. Tenant, user and group administration in M1 happens only through:
  - (a) the `cs admin` CLI on a control-role node, which uses an operator credential read from local config and records an audit-pending outbox entry; and
  - (b) the one-time first-administrator setup link (J.4 step 4).
- The HTTP admin API ships in M2, authorized by the relationship model.
- This avoids a temporary authorization bypass that would later have to be removed.

## 1. Identity domain schema (`cs_identity`)

All tables follow App. E: tenant_id first, CAS version columns, DB-set timestamps, CHECK-constrained states.

| Table | Key | Purpose |
|---|---|---|
| `tenants` | `tenant_id` | name, state (`active`,`suspended`,`deleting`), policy CBOR (§5.1), version |
| `users` | `(tenant_id, user_id)` | login name (normalized, unique per tenant via `users_login_idx`), status (`invited`,`active`,`disabled`), kind (`member`,`guest`), profile fields (§5.7), version |
| `groups` | `(tenant_id, group_id)` | name, `membership_version` bigint |
| `group_members` | `(tenant_id, group_id, member_id)` | member kind (`user`,`group`). Stored with the group, written in the same transaction as the bump of `groups.membership_version` (§6.1) |
| `opaque_registrations` | `(tenant_id, user_id)` | OPAQUE password file, Argon2id params `{m_kib, t, p}`, server key version, version |
| `webauthn_credentials` | `(tenant_id, user_id, credential_id)` | public key, sign count, transports, discoverable flag, prf_supported, created_at |
| `sessions` | `(tenant_id, session_id)` | user_id, state (`active`,`revoked`,`expired`), auth strength (amr list + time of last strong auth), device binding, idle and absolute expiry, `generation` bigint |
| `refresh_tokens` | `(tenant_id, token_hash)` | session_id, family generation, state (`active`,`rotated`,`revoked`), DPoP or device key thumbprint |
| `recovery_codes` | `(tenant_id, user_id)` | Argon2id hash, created_at, used_at |
| `recovery_requests` | `(tenant_id, request_id)` | method, state (`pending`,`cancelled`,`completed`,`expired`), `not_before` (waiting period), version |
| `setup_links` | `token_hash` | one-time first-admin link, state, expiry |
| `outbox`, `outbox_counters`, `idempotency_records` | per M0 | |

Group cycles are rejected at write time by a closure check inside the membership transaction, under the configured depth and cardinality limits. Exceeding a limit returns a typed `invalid_request` with error `group_complexity_limit`. A partial result is never returned (§6.4).

Outbox events: `identity.user.created|updated|disabled`, `identity.group.membership_changed` (carries the new membership_version), `identity.session.revoked` (carries session generation), `identity.credentials.changed`. These are the revocation sources that M2's authz domain consumes (§6.6).

## 2. Authentication protocols

### 2.1 OPAQUE (§5.2)

- Library: `opaque-ke` v3+ with the cipher suite ristretto255 OPRF, ristretto255 3DH key exchange, SHA-512, and Argon2id as the KSF (RFC 9807). The browser runs the **same crate compiled to WASM** (`web/packages/opaque-wasm`), so client and server can't drift apart.
- Argon2id runs on the client. Default `m = 65536 KiB, t = 3, p = 1`. Parameters are stored per registration and upgraded by transparent re-registration after the next successful login.
- **Unknown-account indistinguishability:**
  - `login/start` for an unknown login runs opaque-ke's dummy-record path.
  - The response includes Argon2id params; unknown accounts get the current tenant defaults, so known accounts with default params look identical.
  - Accounts with non-default (legacy) params are a known distinguisher. They are minimized by the upgrade-after-login rule and listed in the threat model notes.
  - Response timing is equalized by always doing the same server-side work.
- The OPRF seed and server key-exchange keys come from the KMS with versioned IDs, held in memory only (§5.2). The registration records which key version it used.
- Endpoints (`/api/v2/auth/opaque/...`):
  - `login/start {tenant, login, credential_request}` → `{login_txn, credential_response, ksf_params}`
  - `login/finish {login_txn, credential_finalization}` → an authentication result (§2.4)
  - `register/start` and `register/finish`: allowed only with a registration grant (setup link, invitation, completed recovery, or step-up session for a password change)
- `login_txn` is a server-side record with a 60 s TTL, single use, bound to tenant, login and source.

### 2.2 WebAuthn (§5.3)

- `webauthn-rs`. Passkeys work as a second factor after OPAQUE, or for passwordless sign-in with discoverable credentials.
- Endpoints: `webauthn/register/{start,finish}` (needs step-up), `webauthn/login/{start,finish}`, `webauthn/assert/{start,finish}` (second factor or step-up).
- PRF support is recorded for the vault M9 work. The PRF output never leaves the client.

### 2.3 MFA and step-up

- When tenant policy requires MFA, a successful OPAQUE login returns `{state: "mfa_required", auth_txn, methods}`, and only `webauthn/assert` or `recovery-code` completes it.
- Step-up: sensitive operations (§5.5 list) require `last_strong_auth_at ≥ now() − 5 min` (policy, range 1–60 min). Otherwise they get `unauthenticated` with problem extension `step_up_required: true`.

### 2.4 Authentication result

```json
{ "state": "authenticated", "access_token": "<JWS>", "expires_in": 600, "session_id": "<uuid>" }
```

The refresh token is set as a cookie: `__Secure-cs_rt` (not `__Host-`: that prefix forces Path=/, conflicting with the endpoint scoping §5.5 requires), Secure, HttpOnly, SameSite=Strict, Path=`/api/v2/auth/token`. Native clients get it in the body, bound to the device key (§5.5).

## 3. Tokens (§5.5, C8)

- **Access token:** JWS compact, `alg: EdDSA`, `typ: at+jwt`, `kid` = KMS key ID with version.
  - Claims: `iss`, `aud` (deployment API audience), `sub`, `tid`, `sid`, `av` (authorization version: the session `generation`), `amr`, `auth_time`, `iat`, `exp` (iat + 600 s, policy range 60–3600), `jti`, plus `cnf.jkt` when DPoP-bound.
  - Verifiers accept only EdDSA and only known `kid`s. `alg: none`, HS*, and `jwk`/`jku`/`x5u` headers are all rejected.
- **DPoP (RFC 9449):** mandatory for third-party OAuth clients (M5) and optional for first-party clients (policy). Proofs are checked for `htm`, `htu`, `iat` within ±60 s, `jti` replay (Valkey, with a local fallback cache sized for the window), `ath`, and key thumbprint against `cnf.jkt`.
- **Refresh:** `POST /api/v2/auth/token/refresh` rotates the token on every use.
  - Values are 256-bit, stored as SHA-256.
  - Reusing a `rotated` token revokes the whole session: `sessions.state = revoked`, generation bumped, outbox `identity.session.revoked`.
  - Concurrent refresh with the same token: exactly one wins and the others get `unauthenticated`. This is CAS on token state, so a network retry can't be mistaken for reuse only if the client retries with the new token. The client SDK serializes refreshes.
- **Sessions:** idle lifetime 14 d, absolute 90 d (policy). Endpoints: `GET /api/v2/me/sessions`, `DELETE /api/v2/me/sessions/{id}`, `POST /api/v2/auth/logout`.
- Signing keys are versioned in the KMS. The JWKS is published at `/api/v2/auth/jwks` with the current and previous keys.

## 4. Account recovery (§5.6)

- Methods:
  - Recovery code: shown once, Argon2id-hashed.
  - Approval from a signed-in device or a passkey.
  - Verified email, with a waiting period of 24 h (policy) that can be cancelled from any session.
  - Administrator-assisted, with the same waiting period. In M1 this is CLI only (see §0).
- Users with MFA must also present a second factor or the recovery code.
- Completion is a single identity-domain transaction:
  - issue the registration grant;
  - after the new OPAQUE registration finishes, revoke all sessions (generation bump on each, plus outbox events);
  - notify all devices.
- Email delivery uses a configured outbound SMTP relay through a `Notifier` trait. The notification service proper is M4; M1 ships the trait plus an SMTP relay implementation and a dev log sink that is clearly labelled as such.
- Account recovery never touches vault keys.

## 5. Rate limiting (§5.2, §18.5, §21.3)

- Per account (tenant+login) and per source (IP prefix), for login, recovery and registration.
- Counters live in Valkey. If Valkey is unavailable, nodes fall back to local buckets at limit/N, where N is the node count from config (cluster membership arrives in M8). It never falls back to unlimited.
- Exceeding a limit returns `rate_limited` (429) with Retry-After. Unknown accounts are rate limited identically.

## 6. Error mapping

| Case | Response |
|---|---|
| Wrong password or unknown account | `unauthenticated` with the same detail and timing |
| Expired or invalid token | `unauthenticated` |
| Step-up needed | `unauthenticated` with `step_up_required` |
| Disabled user | `unauthenticated`; existence is not revealed before authentication |
| Refresh reuse | `unauthenticated`, and the session is revoked |

## 7. Frontend (M1)

- Pages: sign-in (OPAQUE plus a passkey option), MFA challenge, registration from a setup or invitation link, account profile, security (sessions list and revoke, passkeys, recovery codes, password change with step-up), recovery flows.
- The SDK auth client:
  - keeps the access token in memory only, never in localStorage;
  - uses the refresh cookie;
  - serializes refreshes;
  - implements the "unauthenticated → refresh once → retry once" hook from M0.

## Changelog
- 2026-11-19: draft.
