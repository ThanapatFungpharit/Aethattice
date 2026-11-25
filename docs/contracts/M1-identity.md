# M1 Contracts: Identity (FROZEN rev 11)

- Status: **frozen for M1**, revision 3 (owner approval 2026-11-24, after the M0 gate passed and QA reviewed rev 1). Changes require Team Leader approval and a changelog entry at the bottom of this file.
- Spec: §5 (all), §3.5, §6.8, §15.4, §21.3, App. A, D, E, J.4. Errata: C8, C11, C13 (spec v2.4.2).
- Builds on `M0-foundations.md` (rev 6).
- Rev 2 resolves QA review M1-R1 … M1-R14 (`docs/qa/M0-gate.md` §6.1). Each resolution is tagged `[R<n>]`.

## 0. Ordering issue: admin authorization before M2 (owner-approved 2026-11-24)

Spec §6.8 says administrative actions are authorized through the relationship model. That model, with its tuples on tenant resources in the resources domain and the decision service, arrives in M2. M1 has no compliant way to authorize tenant-admin HTTP APIs.

**Decision (owner-approved):**
- M1 exposes **no HTTP admin API**. Tenant, user and group administration in M1 happens only through:
  - (a) the `cs admin` CLI. `[R4]` It is a standalone subcommand, not a server role: it does not start a listener and does not need the `control` role, which stays refused until M8. It connects only to the identity domain with the operator credential from `--config`, runs each action as one identity-domain transaction, and writes an outbox event for each action so M4 audit can consume it; and
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
| `refresh_tokens` | `(tenant_id, token_hash)` | session_id, family generation, state (`active`,`rotated`,`revoked`), DPoP or device key thumbprint, `rotated_at`, `rotation_idempotency_key` (see §3 `[R1]`) |
| `dpop_jti` | `((tenant_id, jkt) HASH, jti)` | `[R6]` shared DPoP replay fallback when Valkey is unavailable; `expires_at`; written with `INSERT … ON CONFLICT DO NOTHING`; expired rows purged by a background task |
| `recovery_codes` | `(tenant_id, user_id)` | Argon2id hash, created_at, used_at |
| `recovery_requests` | `(tenant_id, request_id)` | method, state (`pending`,`cancelled`,`granted`,`completed`,`expired`), `not_before` (waiting period), grant hash and `grant_expires_at`, version |
| `setup_links` | `(tenant_id, token_hash)` | one-time first-admin link, state, expiry. `[R8]` The link token uses the same format as refresh tokens (§3), so the tenant comes from the token |
| `outbox`, `outbox_counters`, `idempotency_records` | per M0 | |

Group cycles are rejected at write time by a closure check inside the membership transaction, under the configured depth and cardinality limits. Exceeding a limit returns a typed `invalid_request` with error `group_complexity_limit`. A partial result is never returned (§6.4). Group writes are CLI-only in M1 (§0); the code is listed in the error catalogue (§6.1) for the M2 HTTP API.

Outbox events: `identity.user.created|updated|disabled`, `identity.group.membership_changed` (carries the new membership_version), `identity.session.revoked` (carries session generation), `identity.credentials.changed`. These are the revocation sources that M2's authz domain consumes (§6.6). (rev 4) Administrative actions without a revocation effect also emit `identity.tenant.created`, `identity.group.created` and `identity.setup_link.issued`, so every `cs admin` action writes an outbox event (§0).

## 2. Authentication protocols

### 2.1 OPAQUE (§5.2)

- Library: `opaque-ke` v3+ with the cipher suite ristretto255 OPRF, ristretto255 3DH key exchange, SHA-512, and Argon2id as the KSF (RFC 9807). The browser runs the **same crate compiled to WASM** (`web/packages/opaque-wasm`), so client and server can't drift apart.
- Argon2id runs on the client. Default `m = 65536 KiB, t = 3, p = 1`. Parameters are stored per registration and upgraded by transparent re-registration after the next successful login.
- **Unknown-account indistinguishability (§5.2) `[R3]`:**
  - `login/start` for an unknown login runs opaque-ke's dummy-record path, with the same server-side work as a known login.
  - KSF parameters for an unknown login are chosen deterministically by a keyed PRF (BLAKE3 keyed with a KMS-held key, input `tenant ‖ normalized login`) from the tenant's *current* distribution of stored parameter sets, weighted by how many registrations use each set. Repeated queries for the same unknown login return the same parameters, and the population of answers matches the population of real accounts. No parameter set is by itself a distinguisher.
  - **Unknown tenant** is indistinguishable from an unknown account in an existing tenant: the same dummy path, with parameters chosen by the same PRF from the deployment default distribution, the same status, body shape and timing. The tenant is never confirmed before authentication.
  - Parameters are still upgraded by transparent re-registration after a successful login, which shrinks legacy sets over time.
  - Residual: an attacker who knows a tenant's exact parameter distribution learns nothing per account beyond that distribution. This is recorded in the threat model notes, not accepted as a deviation.
- The OPRF seed and server key-exchange keys come from the KMS with versioned IDs, held in memory only (§5.2). The registration records which key version it used.
- Endpoints (`/api/v2/auth/opaque/...`):
  - `login/start {tenant, login, credential_request}` → `{login_txn, credential_response, ksf_params}`
  - `login/finish {login_txn, credential_finalization}` → an authentication result (§2.4)
  - `register/start` and `register/finish`: allowed only with a registration grant (setup link, invitation, completed recovery, or step-up session for a password change)
- `login_txn` is a server-side record with a 60 s TTL, single use, bound to tenant, login and source.
- (rev 6) **Storage for transactions and server keys:**
  - `auth_txns ((tenant_id, txn_hash) HASH)` holds `login_txn` and `registration_txn`.
    - The txn id uses the `rt1` format, and only its SHA-256 is stored.
    - The ServerLogin state is AEAD-sealed under the txn-sealing key, with associated data `tenant_id ‖ txn_hash ‖ kind`.
    - Each txn is consumed by a conditional delete or state transition in the finishing transaction, so it is single use even across nodes.
    - Expired rows are reclaimed lazily.
  - `opaque_server_keys (key_version)` is a deployment-wide table, so it has no `tenant_id`. Each row holds an envelope with the OPAQUE ServerSetup, the [R3] PRF key and the txn-sealing key.
    - The envelope is encrypted under the KMS KEK `identity-opaque@vN`, with associated data `key_version ‖ purpose`.
    - It is created once with `INSERT … ON CONFLICT DO NOTHING`, and every node then re-reads the stored row, never using its own candidate.
    - Nodes unwrap it into memory only at startup. It is never logged.
    - Rotation adds a new version, and each registration records its version.
- (rev 9) **Re-registration by a step-up session** (password change and transparent KSF or key-version upgrade):
  - `register/start` and `register/finish` take the session's access token instead of `grant`, using `Authorization: DPoP|Bearer` per rev 8 and a proof when the session is bound.
    - `register/start {purpose, registration_request}`, where `purpose` is `password_change` or `ksf_upgrade`. The login is taken from the session's user; a `login` in the body is refused.
    - The session must satisfy the step-up window, otherwise the response is `unauthenticated` with `step_up_required`. The `registration_txn` is bound to the session's `sid`, user and generation.
  - `register/finish` replaces the user's OPAQUE registration with the current KSF parameters and key version. The user stays active, and no setup link is consumed.
    - It emits `identity.credentials.changed` with reason = `purpose`.
    - In the same identity transaction, it revokes **every other** session and refresh family of the user, keeping the current one.
    - The server cannot tell whether the password changed (OPAQUE hides it), so `purpose` never weakens the revocation. A `ksf_upgrade` therefore also signs out other devices. The trade-off is accepted because upgrades are rare.
  - `login/finish` returns `"reregister": true` (absent otherwise) when the stored KSF parameters are below the current defaults, or the registration's server key version is not current. The web client then runs `ksf_upgrade` immediately, with the same password, while still inside the step-up window.
- (rev 7) **KSF parameter bounds.** Valid `ksf_params` satisfy `65536 ≤ m_kib ≤ 262144`, `3 ≤ t ≤ 10` and `1 ≤ p ≤ 4`.
  - The client refuses anything outside these bounds before running Argon2id. A hostile or broken server cannot make it exhaust memory.
  - The server never stores or offers parameters outside them.
- (rev 7) **Password step-up without a new session.** `opaque/reauth/start {credential_request}` → `{reauth_txn, credential_response, ksf_params}`, then `opaque/reauth/finish {reauth_txn, credential_finalization}` → `204`.
  - Both calls require the current access token (DPoP-bound when the session is). The txn is bound to that session's `sid`.
  - On success, the server sets `last_strong_auth_at` on the *existing* session. It issues no new session or refresh token.
  - Failure returns `unauthenticated`, as for login.
- (rev 7) **`GET /api/v2/me`** (access token) → `{user_id, tenant_id, login, display_name, state, amr, auth_time, sid}`, for the account page.
- (rev 6) Access-token claims: `iss = "https://<deployment domain>"`, `aud = "https://<deployment domain>/api/v2"`.
- (rev 5) **Wire format, binding for client and server:**
  - Crate `opaque-ke` 4.0.1 (RFC 9807 final) with `argon2` 0.5. The cipher suite type is defined once, in a small dependency-free crate `cs-identity-wire`, which server and `web/packages/opaque-wasm` both use. That crate also holds login normalization, so client and server normalize identically.
  - OPAQUE messages are base64url without padding in JSON (as in M0 text transports).
  - `ksf_params = {"algorithm":"argon2id","m_kib":65536,"t":3,"p":1}`. The server rejects parameter sets below the defaults when registering.
  - OPAQUE context is the ASCII string `cs-opaque/v1`. The client identifier is the UTF-8 string `<tenant UUID>/<normalized login>`. The server identifier is the default (the server public key; the registration records the key version).
  - `tenant` is always the tenant UUID in canonical text form. Tenant names, slugs or domains are not resolved in M1.
  - `register/start {grant, login, registration_request}` → `{registration_txn, registration_response, ksf_params}`. `grant` is the full `rt1.` token. The tenant comes from the grant, and `registration_txn` has a 60 s TTL and is single use.
  - `register/finish {registration_txn, registration_upload}` → `204`, consuming the grant. The client then signs in normally, so sessions are issued only by `login/finish`.

### 2.2 WebAuthn (§5.3)

- `webauthn-rs`. Passkeys work as a second factor after OPAQUE, or for passwordless sign-in with discoverable credentials.
- Endpoints: `webauthn/register/{start,finish}` (needs step-up), `webauthn/login/{start,finish}`, `webauthn/assert/{start,finish}` (second factor or step-up).
- PRF support is recorded for the vault M9 work. The PRF output never leaves the client.

### 2.3 MFA and step-up

- When tenant policy requires MFA, a successful OPAQUE login returns `{state: "mfa_required", auth_txn, methods}`, and only `webauthn/assert` or `recovery-code` completes it.
- Step-up: sensitive operations (§5.5 list) require `last_strong_auth_at ≥ now() − 5 min` (policy, range 1–60 min, §8). `[R2]` Otherwise they get `unauthenticated` (401) with an `errors[]` entry `{pointer: "", code: "step_up_required", detail}`. No new problem member is added, so the M0 problem fields stay frozen. The M0 SDK hook "unauthenticated → refresh once → retry once" is amended (M0 contract rev 5): it does **not** refresh when `errors[]` contains `step_up_required`, and the SDK surfaces a typed `StepUpRequired` error so the UI can run `webauthn/assert` or re-enter the password.

### 2.4 Authentication result

```json
{ "state": "authenticated", "access_token": "<JWS>", "expires_in": 600, "session_id": "<uuid>" }
```

The refresh token is set as a cookie: `__Secure-cs_rt` (not `__Host-`: that prefix forces Path=/, conflicting with the endpoint scoping §5.5 requires), Secure, HttpOnly, SameSite=Strict, Path=`/api/v2/auth/token`. Native clients get it in the body, bound to the device key (§5.5).

## 3. Tokens (§5.5, C8)

- **Access token:** JWS compact, `alg: EdDSA`, `typ: at+jwt`, `kid` = KMS key ID with version.
  - Claims: `iss`, `aud` (deployment API audience), `sub`, `tid`, `sid`, `sgen` (session `generation`), `amr`, `auth_time`, `iat`, `exp` (iat + 600 s, policy range 60–3600 s, §8), `jti`, plus `cnf.jkt` when DPoP-bound.
  - `[R9]` The claim name `av` is **reserved** for the authorization version (§5.5) that M2 defines over authz epochs and membership versions. M1 tokens omit it; M2 adds it as a new claim, which is not a breaking change. Verifiers ignore unknown claims.
  - Clock skew `[R12]`: `iat` may be at most 60 s in the future; `exp` is enforced with 0 s leeway on the server and 60 s on the client's proactive refresh.
  - Verifiers accept only EdDSA and only known `kid`s. `alg: none`, HS*, and `jwk`/`jku`/`x5u` headers are all rejected.
- **DPoP (RFC 9449):** mandatory for third-party OAuth clients (M5) and optional for first-party clients (policy). Proofs are checked for `htm`, `htu`, `iat` within ±60 s, `jti` replay, `ath`, and key thumbprint against `cnf.jkt`.
  - (rev 8) **Wire details:**
    - **Proof algorithms:** the server accepts `ES256` (P-256) and `EdDSA` (Ed25519) and refuses every other `alg`. The web client uses `ES256`, because WebCrypto supports it everywhere. `typ` must be `dpop+jwt`. The `jwk` header carries only public members; a `jwk` with private members is refused.
    - **No nonces in M1:** the server never sends `DPoP-Nonce` or `use_dpop_nonce`. A client that receives one retries once with the nonce.
    - **The first-party web client always sends proofs:** on `login/finish`, `token/refresh`, `reauth/*`, and every request carrying an access token.
      - When `login/finish` carries a valid proof, the session, its access tokens (`cnf.jkt`) and the whole refresh family are bound to that key's thumbprint.
      - A bound refresh token must present a proof from the same key. A proof from a different key, or none, is treated like refresh-token theft: the refresh is refused with `unauthenticated` and the session is revoked, exactly as for reuse.
      - A session started without a proof stays unbound (policy `dpop_first_party = optional`). Third-party clients must use DPoP (M5).
    - **Authorization header:** a token carrying `cnf.jkt` must be sent as `Authorization: DPoP <token>` with a matching proof that includes `ath`. Presenting it as `Bearer` is refused.
    - **`htu`:** the absolute request URI as the client sends it, without query or fragment. The server compares it with `https://<deployment domain>` plus the request path, so the web shell and the API share one origin.
    - **Key lifetime:**
      - One key pair per session, created before `login/finish` and stored as a non-extractable CryptoKey in IndexedDB, shared by all tabs.
      - It is deleted on sign-out, and on any `unauthenticated` response that ends the session, such as revocation or reuse.
      - The next sign-in generates a new key.
  - `[R6]` The replay check is shared across nodes. It uses Valkey (`SET NX` with TTL 120 s). If Valkey is unavailable it falls back to the identity-domain `dpop_jti` table, never to a per-node cache. Losing Valkey costs latency only (§18.5). If both are unavailable, DPoP-bound requests fail closed with `unavailable` (503, retryable).
- **Refresh:** `POST /api/v2/auth/token/refresh` rotates the token on every use.
  - Format `[R8]`: `rt1.<tenant_id base64url>.<256-bit random base64url>`. The server stores SHA-256 of the whole string. The tenant segment only selects the partition for the lookup `(tenant_id, token_hash)`; it is not trusted, because a changed tenant segment changes the hash and finds nothing. The same format is used for setup links and recovery grants.
  - Reusing a `rotated` token revokes the whole session: `sessions.state = revoked`, generation bumped, all tokens of the family revoked, outbox `identity.session.revoked`. This rule is not weakened.
  - **Concurrent and retried refreshes `[R1]`:**
    - The SDK serializes refreshes **across tabs** with the Web Locks API (`navigator.locks.request("cs-refresh", …)`) and shares the new access token over `BroadcastChannel`. A tab that waited on the lock sends the cookie the browser now holds, which is already the successor token. Where Web Locks are unavailable, the SDK falls back to a `localStorage` lease with the same effect, and the UI degrades to a single active tab.
    - Every refresh request carries an `Idempotency-Key`. If a `rotated` token is presented again **with the same key that rotated it**, within 30 s of `rotated_at`, it is treated as a lost response, not reuse: the successor, which the client never received, is revoked and a new successor is issued from the same family. Bearer secrets are never stored in idempotency records.
    - Any other presentation of a `rotated` token, whether with a different key, no key, or after 30 s, is reuse and revokes the session.
    - Concurrent requests with the same token and different keys: exactly one wins by CAS on token state; the losers are reuse.
  - Values are 256-bit, stored as SHA-256.
- **Sessions:** idle lifetime 14 d, absolute 90 d (policy). Endpoints: `GET /api/v2/me/sessions`, `DELETE /api/v2/me/sessions/{id}`, `POST /api/v2/auth/logout`.
  - `[R10]` Logout is authenticated by the access token. It revokes the session named by `sid` (generation bump) and every refresh token in its family, in one identity transaction, so a refresh cookie the logout request never saw can no longer be used. The response also clears the cookie with `Set-Cookie: __Secure-cs_rt=; Path=/api/v2/auth/token; Max-Age=0`; cookies can be set from any path.
- Signing keys are versioned in the KMS. The JWKS is published at `/api/v2/auth/jwks` with the current and previous keys.

## 4. Account recovery (§5.6)

- Methods:
  - Recovery code: shown once, Argon2id-hashed.
  - Approval from a signed-in device or a passkey.
  - Verified email, with a waiting period of 24 h (policy) that can be cancelled from any session.
  - Administrator-assisted, with the same waiting period. In M1 this is CLI only (see §0).
- Users with MFA must also present a second factor or the recovery code.
- **Completion `[R5]`:**
  - When the waiting period has passed and every required factor is verified, the request moves `pending → granted` and a **recovery grant** is issued: a single-use token (format of §3), bound to the user, expiring after 15 min. Its hash is stored on the request.
  - `register/finish` presented with the grant performs **one identity-domain transaction** that:
    - replaces the OPAQUE registration;
    - revokes every session of the user (generation bump on each) and every refresh family;
    - invalidates the used recovery code, if any;
    - marks the request `completed` and the grant used;
    - writes outbox events `identity.credentials.changed` and `identity.session.revoked` for each session.
  - There is no state in which the new password exists and old sessions are still valid. Sessions are not revoked before then, so an abandoned recovery leaves the account usable.
  - The request is idempotent with `Idempotency-Key`. Presenting a used or expired grant returns `unauthenticated`. An expired grant returns the request to `expired`, and the user must start over.
  - All devices are notified after commit through the `Notifier` (outbox-driven, outside the transaction).
- (rev 10) **Recovery endpoints.**
  - **Recovery code:** no waiting period, because possessing the code is the proof.
    - `POST /api/v2/auth/recovery/start {tenant, login, method: "recovery_code", code}` returns `{state: "granted", grant, grant_expires_in}` for a valid unused code.
    - Unknown tenant, unknown account, wrong code and used code all return the same `unauthenticated` problem, with the same timing path. Rate limits per §5 apply.
  - **Verified email:**
    - `start {tenant, login, method: "email"}` always returns `202 {state: "pending"}`, with an identical shape for unknown accounts.
    - When the account exists, a request is created, and the `Notifier` sends an `rt1` recovery link to the verified address. It is never returned in the API.
    - `POST /api/v2/auth/recovery/status {token}` (the token from the link) returns `{state, available_at}`. Possessing the link verifies the email.
    - Once `not_before` has passed, the state is `granted` and the response carries `grant` (15 min, single use).
    - Users with MFA must also send `code` (a recovery code) in that `status` call, per §4 "a second factor or the recovery code". A user who still has a passkey signs in passwordless instead and changes the password by step-up.
  - **Approval from a signed-in device:**
    - `start {tenant, login, method: "device_approval"}` returns `202 {state: "pending", recovery_txn}`, also for unknown accounts. `recovery_txn` uses the `rt1` format.
    - The user's session sees the request in `GET /api/v2/me/recovery-requests` and approves it with `POST …/{id}/approve` (step-up required). The requester then polls `status {recovery_txn}` and gets `granted` plus `grant`.
    - Approval counts as the second factor and skips the waiting period.
  - **Administrator-assisted:** `cs admin recovery start` creates an email-method request with the waiting period.
  - **Cancel:** any session of the user can list pending requests (`GET /api/v2/me/recovery-requests`) and cancel one with `DELETE …/{id}`, which sets the state to `cancelled`.
  - **Completion:** unchanged ([R5]). `register/start {grant, login, registration_request}` → `register/finish` → normal sign-in.
- (rev 11) **Schema and policy additions (migration 0103, expand only):**
  - **Recovery codes:**
    - Table `recovery_code_entries ((tenant_id, user_id) HASH, code_id ASC)`, holding an Argon2id PHC hash, `used_at` and `set_version`. Each set has 10 codes.
    - Wire format `<code_id: 8 base32 chars>-<secret: 20 base32 chars>`. The lookup is by `code_id`, and exactly one Argon2id verification runs, with a dummy hash for unknown IDs so timing is the same.
    - The old `recovery_codes` table is unused, and a later contract migration drops it.
  - **Email:** `users.email` and `users.email_verified_at`, set in M1 only by `cs admin user set-email --verified`. An email-method recovery for a user with no verified address behaves like an unknown account.
  - **Sessions and passkeys:**
    - `sessions.last_seen_at` is updated on refresh. `sessions.user_agent` is taken at `login/finish` and truncated to 200 characters.
    - `webauthn_credentials` gains `label` (1–100 characters), `last_used_at` and the serialized `passkey_state`. On the wire, the passkey `id` is the base64url credential ID.
  - **MFA:**
    - A user "has MFA" when policy `mfa_required` = 1 (deployment default, overridable by the tenant through `tenants.policy`) or the user has at least one passkey.
    - `login/finish` then returns `200 {state: "mfa_required", auth_txn, methods}`. `auth_txn` uses the `rt1` format with a **5 min** TTL and single use. Presenting it to the wrong endpoint returns 401 with `mfa_required`.
    - **Enrolment:** when policy requires MFA but the user has no passkey and no unused recovery code, `login/finish` issues an **enrolment-only session**.
      - Its access token carries `scp: "mfa_enrolment"`.
      - It may call only `webauthn/register/*`, `me/recovery-codes`, `GET /me` and logout. Every other endpoint answers 401 with `mfa_required`.
      - Once a factor is enrolled, the user signs in again normally.
  - **`reregister` with MFA:** for MFA users the flag is set on the §2.4 result of `webauthn/assert/finish` (MFA) and `mfa/recovery-code`, never on the `mfa_required` body.
    - The client may keep the password only as bytes (`Uint8Array`), never as a string. It keeps them only while the MFA prompt is open, at most for the `auth_txn` lifetime.
    - It runs `ksf_upgrade` immediately after MFA succeeds, then zeroes the bytes. It also zeroes them on cancel, failure or timeout.
  - **New policy keys** (ranges are provisional until the owner records them in erratum C13):
    - `mfa_required` 0 (0–1);
    - `dpop_first_party_required` 0 (0–1);
    - `rate_limit_source_per_min` 30 (5–1000);
    - `rate_limit_account_per_min` 10 (3–100);
    - `rate_limit_tenant_per_min` 600 (60–100000), all over fixed 60 s windows.
    The rate-limit fallback is local buckets at limit/N per §5, using `[cluster] node_count` (≥ 1, checked by `check-config`).
- (rev 10) **Timestamps and recovery requests.**
  - Every timestamp field in M1 JSON bodies is an RFC 3339 UTC string, for example `created_at`, `last_seen_at`, `last_used_at` and `available_at`. JWT claims and the `auth_time` mirrored from them stay in unix seconds (RFC 7519).
  - `GET /api/v2/me/recovery-requests` → `{items: [{id, method: "email"|"device_approval", state: "pending"|"granted", created_at, available_at, requester_user_agent}]}`. It is bounded and not paginated. `requester_user_agent` may be null; it helps the user tell whether a request is their own.
  - `POST …/{id}/approve` and `DELETE …/{id}` each return `204`.
  - The `status` body is `{token, code?}` (email) or `{recovery_txn}` (device approval). The response is `{state, available_at?, grant?, grant_expires_in?}`.
- (rev 10) **WebAuthn and session wire shapes** (L3 JSON forms, binary as base64url without padding):
  - Passkey registration: `webauthn/register/start {}` (access token, DPoP, step-up) → `{registration_txn, public_key}`; `webauthn/register/finish {registration_txn, credential, label}` → `{id, label, created_at, prf}`.
  - Passwordless sign-in: `webauthn/login/start {tenant}` → `{login_txn, public_key}`, with discoverable credentials and empty `allowCredentials`; `webauthn/login/finish {login_txn, credential}` → §2.4 result, with a DPoP proof as for OPAQUE.
  - MFA after OPAQUE: `webauthn/assert/start {auth_txn}` → `{assert_txn, public_key}`; `webauthn/assert/finish {assert_txn, credential}` → §2.4 result. With a recovery code instead: `POST /api/v2/auth/mfa/recovery-code {auth_txn, code}` → §2.4 result.
  - Step-up: `webauthn/assert/start {}` with the access token → `{assert_txn, public_key}`; `webauthn/assert/finish` → `204` and sets `last_strong_auth_at`.
  - Passkeys: `GET /api/v2/me/passkeys` → `{items: [{id, label, created_at, last_used_at, prf}]}`; `DELETE /api/v2/me/passkeys/{id}` (step-up) → `204`.
  - Sessions: `GET /api/v2/me/sessions` → `{items: [{sid, created_at, last_seen_at, amr, user_agent, current}]}`, bounded per user and not paginated.
  - `DELETE /api/v2/me/sessions/{sid}` → `204`. Revoking another session requires step-up; revoking the current session acts as logout.
  - Recovery codes: `POST /api/v2/me/recovery-codes` (step-up) → `{codes}`, which replaces the previous set; `GET` → `{remaining}`.
- Email delivery uses a configured outbound SMTP relay through a `Notifier` trait. The notification service proper is M4; M1 ships the trait plus an SMTP relay implementation and a dev log sink.
  - `[R7]` The log sink writes bearer secrets (recovery links), so it is refused unless `cs serve` runs with the explicit `--dev` profile. `check-config` rejects it otherwise, and every line it writes is prefixed `DEV-ONLY SECRET`. It is never the default.
- Account recovery never touches vault keys.

## 5. Rate limiting (§5.2, §18.5, §21.3)

- Per account (tenant+login) and per source, for login, recovery and registration. `[R12]` Source is the IPv4 /32 or the IPv6 /64.
- Counters live in Valkey. If Valkey is unavailable, nodes fall back to local buckets at limit/N, where N is the node count from config (cluster membership arrives in M8). `check-config` rejects N < 1. It never falls back to unlimited.
- Exceeding a limit returns `rate_limited` (429) with Retry-After. Unknown accounts are rate limited identically.

## 6. Error mapping

| Case | Response |
|---|---|
| Wrong password or unknown account | `unauthenticated` with the same detail and timing |
| Expired or invalid token | `unauthenticated` |
| Step-up needed | `unauthenticated` with `step_up_required` |
| Disabled user | `unauthenticated`; existence is not revealed before authentication |
| Refresh reuse | `unauthenticated`, and the session is revoked |

### 6.1 Error catalogue `[R13]`

Every M1 endpoint publishes its possible codes in the OpenAPI document (App. G.5). Typed `errors[].code` values introduced by M1:

| errors[].code | Under | Meaning |
|---|---|---|
| `step_up_required` | `unauthenticated` | Recent strong authentication needed (§2.3) |
| `mfa_required` | `unauthenticated` | Second factor needed to finish sign-in |
| `group_complexity_limit` | `invalid_request` | Group depth or cardinality limit (§1) |
| `group_cycle` | `invalid_request` | (rev 4) Membership change would create a group cycle (§1) |
| `registration_grant_required` | `permission_denied` | `register/*` without a valid grant |

## 7. Frontend (M1)

- Pages: sign-in (OPAQUE plus a passkey option), MFA challenge, registration from a setup or invitation link, account profile, security (sessions list and revoke, passkeys, recovery codes, password change with step-up), recovery flows.
- The SDK auth client:
  - keeps the access token in memory only, never in localStorage;
  - uses the refresh cookie;
  - serializes refreshes;
  - implements the "unauthenticated → refresh once → retry once" hook from M0, skipping the refresh for `step_up_required` (§2.3);
  - serializes refreshes across tabs (§3 `[R1]`).

## 8. Policy ranges (owner-approved, erratum C13) `[R11]`

These ranges were not in the spec. The owner approved them on 2026-11-24 together with the M0 policy ranges, and they are now normative as erratum C13 (docs/SPEC_ERRATA.md). `check-config` enforces them.

| Policy | Default | Range |
|---|---|---|
| Step-up window | 5 min | 1–60 min |
| Access-token lifetime | 600 s | 60–3600 s |
| Session idle / absolute | 14 d / 90 d | 1 h–90 d / 1 d–365 d |
| Recovery waiting period | 24 h | 1 h–14 d |
| Recovery grant lifetime | 15 min | fixed |
| Refresh lost-response window | 30 s | fixed |

## 9. M1 gate additions `[R14]`

- The QA negative-test list in `docs/qa/M0-gate.md` §6.1.
- `qa:http_surface::malformed_json_body_returns_400_problem`, moved from M0.
- An automated scan of all log output emitted during the M1 suites: no access token, refresh token, setup link, recovery code or grant, OPAQUE message, DPoP proof or key material may appear (carried over from M0 row CT.M0-28, which is `implemented` but not `tested`).

## Changelog
- 2026-11-19: draft.
- 2026-11-20: draft rev 2: resolves QA review M1-R1 … M1-R14. Pending owner decision: §0 (no HTTP admin API in M1) and §8 policy ranges.
- 2026-11-20: §9: log-secret scan added to the M1 gate (M0 carry-over CT.M0-28).
- 2026-11-24: **rev 3, frozen.** The owner approved §0 (no HTTP admin API in M1: `cs admin` CLI and the first-administrator setup link only; HTTP admin in M2 under the relationship model) and the §8 ranges (erratum C13). Builds on M0 contract rev 6.
- 2026-11-24 rev 4 (TL, from backend slice 1): §6.1 adds `group_cycle` (`errors[]` code on `invalid_request`); §1 adds three non-revocation outbox events. Owner-approved the same day (erratum C13): group nesting depth default 32 (4–64), group closure size default 10,000 (1,000–100,000), setup-link lifetime default 24 h (15 min–7 d); all are policies enforced by `check-config`.
- 2026-11-25 rev 5 (TL, frontend question): §2.1 OPAQUE wire format fixed: crate versions, shared `cs-identity-wire` suite and normalization, base64url encoding, ksf_params shape, context and identifiers, tenant as UUID, register endpoint shapes; register/finish returns 204.
- 2026-11-25 rev 6 (TL, backend question): §2.1 adds the `auth_txns` and `opaque_server_keys` tables (sealed state, KEK envelope, single-use and cross-node creation rules) and fixes `iss` and `aud`.
- 2026-11-25 rev 7 (TL, frontend slice 2): KSF parameter bounds; `opaque/reauth/*` for password step-up on the existing session; `GET /api/v2/me`.
- 2026-11-25 rev 8 (TL, frontend DPoP questions): DPoP wire details (algorithms, no nonce in M1, binding of session and refresh family, `DPoP` auth scheme, `htu`, key lifetime).
- 2026-11-25 rev 9 (TL, backend question): re-registration by a step-up session (password change and KSF/key upgrade), the `reregister` signal, and revocation of the user's other sessions on every re-registration.
- 2026-11-26 rev 10 (TL, frontend proposal): recovery endpoints per method (code without a waiting period; email by link with a waiting period, plus a recovery code for MFA users; device approval; admin-assisted; cancel), and WebAuthn, passkey, session and recovery-code wire shapes.
- 2026-11-26 rev 10 addendum: RFC 3339 timestamps in bodies; `me/recovery-requests` item shape; `status` body and response.
- 2026-11-26 rev 11 (TL, backend proposals): recovery-code sets, user email, session and passkey columns, MFA definition and the enrolment-only session, `mfa_required` response and 5 min `auth_txn`, new policy keys (ranges pending owner approval, C13).
- 2026-11-26 rev 11 addendum: `reregister` on MFA completion, and bounded client-side retention of the password bytes.
