# M1 Contracts: Identity (DRAFT rev 2, frozen at M0 gate after review)

- Status: **draft**. It is frozen only once the M0 gate passes and the QA Engineer and project owner have reviewed it.
- Spec: §5 (all), §3.5, §6.8, §15.4, §21.3, App. A, D, E, J.4. Errata: C8.
- Builds on `M0-foundations.md` (rev 4).
- Rev 2 resolves QA review M1-R1 … M1-R14 (`docs/qa/M0-gate.md` §6.1). Each resolution is tagged `[R<n>]`.

## 0. Ordering issue: admin authorization before M2 (owner decision needed)

Spec §6.8 says administrative actions are authorized through the relationship model. That model, with its tuples on tenant resources in the resources domain and the decision service, arrives in M2. M1 has no compliant way to authorize tenant-admin HTTP APIs.

**Proposal:**
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

Outbox events: `identity.user.created|updated|disabled`, `identity.group.membership_changed` (carries the new membership_version), `identity.session.revoked` (carries session generation), `identity.credentials.changed`. These are the revocation sources that M2's authz domain consumes (§6.6).

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

### 2.2 WebAuthn (§5.3)

- `webauthn-rs`. Passkeys work as a second factor after OPAQUE, or for passwordless sign-in with discoverable credentials.
- Endpoints: `webauthn/register/{start,finish}` (needs step-up), `webauthn/login/{start,finish}`, `webauthn/assert/{start,finish}` (second factor or step-up).
- PRF support is recorded for the vault M9 work. The PRF output never leaves the client.

### 2.3 MFA and step-up

- When tenant policy requires MFA, a successful OPAQUE login returns `{state: "mfa_required", auth_txn, methods}`, and only `webauthn/assert` or `recovery-code` completes it.
- Step-up: sensitive operations (§5.5 list) require `last_strong_auth_at ≥ now() − 5 min` (policy, proposed range 1–60 min, §8). `[R2]` Otherwise they get `unauthenticated` (401) with an `errors[]` entry `{pointer: "", code: "step_up_required", detail}`. No new problem member is added, so the M0 problem fields stay frozen. The M0 SDK hook "unauthenticated → refresh once → retry once" is amended (M0 contract rev 5): it does **not** refresh when `errors[]` contains `step_up_required`, and the SDK surfaces a typed `StepUpRequired` error so the UI can run `webauthn/assert` or re-enter the password.

### 2.4 Authentication result

```json
{ "state": "authenticated", "access_token": "<JWS>", "expires_in": 600, "session_id": "<uuid>" }
```

The refresh token is set as a cookie: `__Secure-cs_rt` (not `__Host-`: that prefix forces Path=/, conflicting with the endpoint scoping §5.5 requires), Secure, HttpOnly, SameSite=Strict, Path=`/api/v2/auth/token`. Native clients get it in the body, bound to the device key (§5.5).

## 3. Tokens (§5.5, C8)

- **Access token:** JWS compact, `alg: EdDSA`, `typ: at+jwt`, `kid` = KMS key ID with version.
  - Claims: `iss`, `aud` (deployment API audience), `sub`, `tid`, `sid`, `sgen` (session `generation`), `amr`, `auth_time`, `iat`, `exp` (iat + 600 s, proposed policy range 60–3600 s, §8), `jti`, plus `cnf.jkt` when DPoP-bound.
  - `[R9]` The claim name `av` is **reserved** for the authorization version (§5.5) that M2 defines over authz epochs and membership versions. M1 tokens omit it; M2 adds it as a new claim, which is not a breaking change. Verifiers ignore unknown claims.
  - Clock skew `[R12]`: `iat` may be at most 60 s in the future; `exp` is enforced with 0 s leeway on the server and 60 s on the client's proactive refresh.
  - Verifiers accept only EdDSA and only known `kid`s. `alg: none`, HS*, and `jwk`/`jku`/`x5u` headers are all rejected.
- **DPoP (RFC 9449):** mandatory for third-party OAuth clients (M5) and optional for first-party clients (policy). Proofs are checked for `htm`, `htu`, `iat` within ±60 s, `jti` replay, `ath`, and key thumbprint against `cnf.jkt`.
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
| `registration_grant_required` | `permission_denied` | `register/*` without a valid grant |

## 7. Frontend (M1)

- Pages: sign-in (OPAQUE plus a passkey option), MFA challenge, registration from a setup or invitation link, account profile, security (sessions list and revoke, passkeys, recovery codes, password change with step-up), recovery flows.
- The SDK auth client:
  - keeps the access token in memory only, never in localStorage;
  - uses the refresh cookie;
  - serializes refreshes;
  - implements the "unauthenticated → refresh once → retry once" hook from M0, skipping the refresh for `step_up_required` (§2.3);
  - serializes refreshes across tabs (§3 `[R1]`).

## 8. Policy ranges (proposed, owner review) `[R11]`

These ranges are not in the spec. They are recorded here for owner review together with the M0 policy ranges (open question OQ-6) and are enforced by `check-config`.

| Policy | Default | Proposed range |
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
