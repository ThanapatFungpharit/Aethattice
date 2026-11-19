# M0 Contracts: Foundations (FROZEN)

- Status: **frozen for M0**, revision 3 (Team Leader, 2026-11-19). Changes require Team Leader approval and a changelog entry at the bottom of this file.
- Spec: v2.4.1. Where this contract adds detail the spec leaves open, it says "(design)".
- Multi-node rule: nothing here may assume a single node, a single database cluster or a single process.

## 1. Identifiers (spec §4.1, App. E)

- Every ID is a UUIDv7 (RFC 9562), stored as YSQL `uuid` and as 16 big-endian bytes in binary formats. Text form is lowercase hyphenated.
- Typed newtypes live in `cs-common::id`: `TenantId`, `PrincipalId`, `UserId`, `GroupId`, `ResourceId`, `SpaceId`, `VersionId`, `SessionId`, `ChunkId`, `SealId`, `ExtentId`, `NodeId`, `OperationId`, `EventId`, `RequestId`. They cannot be converted into one another implicitly.
- Exception (spec §17.1): `ChunkId` and `ExtentId` are **128-bit random**: 16 bytes from the CSPRNG, with no version or variant bits set. They are stored in YSQL `uuid` columns (any 16 bytes are valid there) but are not RFC 9562 UUIDs. Text form uses the same hyphenated hex. (rev 2: UUIDv4 layout gave only 122 random bits.)
- Every random value (IDs, keys, salts, nonces, tokens) comes from the OS CSPRNG through `cs-crypto::rand`. If the CSPRNG fails, the operation fails. There is no fallback (§17.2).
- Resource URN: `cs:{tenant}:{type}:{id}`, where tenant and id are UUID text and `type` matches `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$` (for example `drive.folder`). Spaces use the core type `core.space`.
- `cs-common` provides `Urn::parse` / `Display`. Parsing is strict: no surrounding whitespace, lowercase only, no extra segments.

## 2. Error model (spec App. D): shared by backend and frontend

- The code set is exactly table D.2, as a Rust `enum ErrorCode`. TypeScript mirrors it as a string-literal union in `@cs/sdk`. The wire values are the snake_case strings from D.2.
- HTTP responses are `application/problem+json` with fields `type`, `title`, `status`, `code`, `detail`, `instance`, `request_id`, `retryable`, plus `retry_after_ms`, `errors[]` (`pointer`, `code`, `detail`) and `consistency_token` when applicable.
  - `type` = `https://errors.{deployment_domain}/v1/{code}`.
  - `status` and `retryable` are derived from the code by the table and can never be set independently.
- `Retry-After` header (seconds, rounded up) is sent whenever `retry_after_ms` is present.
- `detail` must never contain data the caller may not see. Internal errors use a generic detail; the cause goes to logs, correlated by `request_id`.
- Existence hiding (D.3) is enforced by the authorization layer in M2. The M0 error type only provides the codes.
- Application codes `app.{application_id}.{code}`: the type must already support them (each maps to a D.2 HTTP status) even though no plugins exist until M5.
- Client retry policy (`@cs/sdk`, D.3): retry only when `retryable` is true. Exponential backoff with full jitter, starting at 200 ms, capped at 30 s, honouring `retry_after_ms`. Bounded attempts (default 5). Writes are retried only with the same `Idempotency-Key`. `unauthenticated` triggers one token refresh and one retry; the hook exists in M0 and is wired up in M1.

## 3. Signing envelope (C8, design)

All Ed25519-signed artifacts except JWS access tokens use this envelope. Access tokens are standard JWS (`alg: EdDSA`), and the M1 contract specifies them.

```text
signed_bytes = "cs-sig/v1" 0x00 context 0x00 payload
signature    = Ed25519(key, signed_bytes)
```

- `context` is an ASCII string from a closed registry in `cs-crypto::sig::Context`. Initial registry: `consistency-context/v1`, `snapshot-handle/v1`, `decision-ticket/v1`, `revocation-record/v1`, `watermark-heartbeat/v1`, `storage-receipt/v1`, `data-plane-token/v1`, `state-attestation/v1`, `test/v1`. Adding a context is a contract change.
- `payload` is the artifact encoded as **deterministic CBOR** (RFC 8949 §4.2.1 core deterministic encoding: preferred integer encoding, definite lengths, map keys sorted bytewise, no floats, no tags except where specified). Verifiers decode the payload and re-encode it, and reject the artifact unless the bytes are identical.
- Envelope on the wire: CBOR array `[1, context, key_id, payload_bstr, signature_bstr]`. Text transports use base64url without padding.
- rev 2:
  - The envelope itself is deterministic CBOR and gets the same re-encode check. Trailing bytes after the envelope are rejected.
  - `key_id` is a text string `<key-name>@v<version>`, at most 128 bytes.
  - The 16 KiB limit applies to the binary envelope. For base64url input it is checked on the encoded length (≤ ceil(16384·4/3)) before decoding.
- `key_id` names a versioned signing key from the KMS. Verifiers resolve keys through a `KeyResolver` trait, never a single global key, so multiple issuers and rotation work across nodes.
- Signatures are verified before any field of the payload is used. Size limits are checked before decoding (max envelope 16 KiB unless the artifact contract says otherwise).
- Test vectors live in `crates/cs-crypto/tests/vectors/`.

## 4. Consistency vectors (App. C, C10; §6.4, §18.4)

- `VectorComponent = { cluster_id: uuid, domain_id: DomainId, partition: u32, position: u64 }`.
- `ConsistencyVector` = a sorted, deduplicated list of components with a hard maximum of 64 entries; more than that is an error, never truncated. (rev 2) Components with the same `(cluster_id, domain_id, partition)` merge to the maximum position, because the stronger requirement wins. The 64 limit applies after merging. Comparison is per component (`dominates`). There is no global or timestamp ordering, and HLC or wall-clock values are never part of it.
- `DomainId` is an enum of the domains in §18.1 (`identity`, `resources`, `authz`, `objects`, `cluster`, `operations`, `collab`, `events`, `accounting`, `plugins`, `audit`) plus `App(application_id)`.
- In M0 the vector is only a type with serialization and dominance tests. The signed consistency context is built on it in M2.

## 5. Databases and domains (§18.1, App. E, §8.3.1)

- One logical YSQL database per domain: `cs_identity`, `cs_resources`, `cs_authz`, `cs_objects`, `cs_cluster`, `cs_operations`, `cs_collab`, `cs_events`, `cs_accounting`, `cs_plugins`, `cs_audit`.
- **Each domain has its own connection configuration** (URL, pool size, timeouts). They may point to the same cluster in development, but code must never assume they do. One `DomainPool` handle is bound to exactly one domain, and the API makes opening a transaction across two domains impossible: `DomainPool::transaction` borrows only that pool.
- Postgres client: `sqlx` against YSQL (design; replaceable).
- Retry: SQLSTATE `40001` and `40P01` are retried as whole transactions, with exponential backoff and jitter, bounded (default 10 attempts or 5 s). Retried closures must be idempotent. The type signature takes a re-runnable closure.
- No network calls inside transactions (§18.2). This is enforced by review and by a lint test that checks transaction closures receive only the transaction handle.
- Isolation: READ COMMITTED by default. A REPEATABLE READ helper exists only for journal reads (§19.2). There is no SERIALIZABLE API.

### 5.1 Migrations (§7.5, §24, App. E)

- Files: `crates/<crate>/migrations/<domain>/<NNNN>_<name>.<class>.sql`, where `class` ∈ `expand | migrate | contract`.
- Runner table in each domain: `schema_migrations(version int primary key, name text, class text check (...), checksum bytea, applied_at timestamptz default now())`.
- Rules:
  - Migrations are idempotent and resumable.
  - A checksum mismatch on an applied migration is a hard error.
  - A `contract` migration is refused unless the matching `expand` was applied in an earlier finalized release; in M0 this is enforced through a `requires_finalized` header comment checked against the runner's finalized-release table.
  - Runtime DDL outside the runner is forbidden.
- Every table follows App. E:
  - `tenant_id` is the first primary-key column for tenant-scoped tables.
  - Version or state columns for compare-and-set.
  - `timestamptz` set by the database.
  - CHECK constraints on state columns.
  - Foreign keys only within a domain.
  - Rows ≤ 64 KiB.
  - snake_case names, plural tables, indexes named `<table>_<columns>_idx`.

### 5.2 Outbox (App. E, C2)

Every domain has:

```sql
CREATE TABLE outbox (
  tenant_id     uuid        NOT NULL,
  partition     int         NOT NULL,          -- hash(partition key) mod P, P fixed per domain at creation
  sequence      bigint      NOT NULL,          -- contiguous per (tenant, partition), allocated in-transaction from outbox_counters under row lock
  event_id      uuid        NOT NULL,          -- UUIDv7
  event_type    text        NOT NULL,          -- e.g. resource.created
  event_version int         NOT NULL,
  partition_key uuid        NOT NULL,          -- default: subject resource ID (§11.2)
  payload       bytea       NOT NULL,          -- deterministic CBOR, ≤ 64 KiB
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ((tenant_id, partition) HASH, sequence ASC)
);
CREATE TABLE outbox_counters (tenant_id uuid NOT NULL, partition int NOT NULL, next_sequence bigint NOT NULL,
                              PRIMARY KEY ((tenant_id, partition) HASH));
```

- An outbox row is written only through `Outbox::append(&mut DomainTx, ...)`, inside the same transaction as the state change. There is no other write path.
- Sequences are contiguous per (tenant, partition): the counter is incremented under a row lock in the same transaction, so a gap is detectable (compare §19.1). The source partition in the §18.4 sense is the pair (tenant_id, partition). The consumer dedup key is `(cluster_id, domain_id, tenant_id, partition, sequence)`.
- rev 2: `tenant_id` now leads the primary key, as App. E requires and as its outbox column list shows. Hashing on (tenant_id, partition) avoids a tenant-only key (§18.3). Domain-level (non-tenant) events use the nil UUID as tenant_id.
- Relays to the events domain are M4. In M0, the outbox only needs to be written and read in order with gap detection.

### 5.3 Idempotency records (D.3, C4)

Per domain that accepts client writes:

```sql
CREATE TABLE idempotency_records (
  tenant_id      uuid  NOT NULL,
  principal_id   uuid  NOT NULL,
  key            text  NOT NULL,              -- client Idempotency-Key, 1..255 visible ASCII
  request_digest bytea NOT NULL,              -- BLAKE3 of canonical (method, route template, path params, body)
  state          text  NOT NULL CHECK (state IN ('in_progress','completed')),
  response       bytea,                       -- status + body (CBOR), ≤ 64 KiB; larger results store a reference
  expires_at     timestamptz NOT NULL,        -- now() + 24 h (policy)
  PRIMARY KEY (tenant_id, principal_id, key)
);
```

Semantics:
- Same key and same digest, completed: return the stored response.
- Same key and different digest: `idempotency_mismatch` (422).
- Same key, same digest, still in progress: exactly one of N concurrent identical requests executes. (rev 3) When the record is created in the same transaction as the effect, a concurrent duplicate blocks on the record's row lock and then receives the stored result. `outcome_unknown` (504, retryable) is returned only when an `in_progress` record is visible, meaning it was committed separately, for example by a multi-step or saga flow whose outcome is not yet known. Tests must accept either outcome for concurrent duplicates, but never two executions.
- Request digest (rev 2): BLAKE3 over the deterministic-CBOR array `[method, route_template, sorted path params, body_digest]`, where `body_digest` = BLAKE3 of the RFC 8785 (JCS) canonical JSON of the body. An absent body has the body_digest of the empty string. Non-JSON bodies are hashed raw.
- Expiry (rev 2): a record is honoured until `expires_at`. After that it may be swept, and the same key counts as a new request.
- Size (rev 2): stored responses are ≤ 64 KiB by design; an operation whose response could be larger returns a reference instead. Exceeding the limit is an `internal` error, never truncation.
- The record is created in the same transaction as the operation's effect (single-domain operations) or as the saga's operation record (§18.4).

### 5.4 Saga operation record (§18.4, C3), operations domain

```sql
CREATE TABLE sagas (
  tenant_id       uuid NOT NULL,
  operation_id    uuid NOT NULL,
  saga_type       text NOT NULL,
  protocol_version int NOT NULL,
  actor           uuid NOT NULL,
  idempotency_key text NOT NULL,
  request_digest  bytea NOT NULL,
  state           text NOT NULL CHECK (state IN ('created','running_pre_pivot','pivot_committed','completing','completed',
                                                 'compensating','compensated','blocked_for_operator')),
  pivot           text NOT NULL,                 -- named pivot
  steps           bytea NOT NULL,                -- CBOR: ordered steps, per-step status, source/destination positions, outbox IDs
  deadline        timestamptz NOT NULL,
  result          bytea,
  version         bigint NOT NULL,               -- CAS
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ((tenant_id, operation_id) HASH),
  UNIQUE (tenant_id, saga_type, idempotency_key)
);
```

Saga state transitions (rev 2). Every other transition is rejected:

```text
created            → running_pre_pivot | compensated (nothing executed yet) | blocked_for_operator
running_pre_pivot  → running_pre_pivot (next step) | pivot_committed | compensating | blocked_for_operator
pivot_committed    → completing | completed | blocked_for_operator
completing         → completing (next step) | completed | blocked_for_operator
compensating       → compensating (next step) | compensated | blocked_for_operator
blocked_for_operator → (only via audited operator action) the state it was blocked from
completed, compensated: terminal
```

Step idempotency is the framework's job, not the saga author's (rev 2):
- Every domain that participates in sagas has a `saga_step_receipts (tenant_id, operation_id, step, result bytea, PRIMARY KEY ((tenant_id, operation_id) HASH, step))` table.
- The framework writes the receipt in the same local transaction as the step's effect.
- When a step is delivered again, the framework finds the receipt and returns the stored result without re-running the step.
- The saga author implements only the step body against the transaction handle.

- The state machine is enforced by compare-and-set on `version`.
  - `compensating` is reachable only from pre-pivot states.
  - Once `pivot_committed`, the only transitions are forward ones and `blocked_for_operator`.
- Every saga type implements the `SagaDefinition` trait: steps (each exactly one local transaction plus outbox), named pivot, compensation per pre-pivot step, and a level-triggered `reconcile(authoritative_state)` predicate.
- M0 delivers the framework and a test saga spanning two test domains, with crash injection after every step. Real sagas arrive in M3.

## 6. Configuration (J.4, design)

- One declarative TOML file, validated in full before anything is applied. Unknown keys are an error.
- Sections: `[node]` (id, roles), `[domains.<name>]` (url, pool), `[kms]`, `[api]`, `[telemetry]`, `[policy]` (every policy value carries its default and safe range from the spec; values outside the range are rejected), `[locks]` (settings tenants cannot change).
- Roles: `edge, api, realtime, worker, search, storage, control` (§2.2). The binary refuses roles whose milestone is not implemented, with a clear message. It never starts them silently as no-ops.

## 7. HTTP surface in M0 (design)

- `GET /healthz`: liveness. Process only.
- `GET /readyz`: readiness. Returns 200 only when every configured domain is reachable, migrations are at the expected version, and (from M2) revocation is current. Otherwise 503 with a problem body listing the failing barriers. Process health alone never means ready (§2.6).
- All other routes live under `/api/v2/...` and are frozen per milestone in `docs/contracts/openapi/` (M1 onward).
- rev 2:
  - `instance` is the request path without the query string, so no query data leaks into errors.
  - When 40001/40P01 retries are exhausted, the response is `unavailable` (503, retryable).
  - Migrations are applied only by `cs migrate --config <path>` (the installer step, J.4 step 3). `cs serve --config <path>` never migrates; `/readyz` reports a version mismatch as a failing barrier.
  - There are no JSON-body routes in M0. The malformed-body → 400 test moves to M1, the first milestone with JSON routes.
- Every response carries `X-Request-Id`. Every error is problem+json (§2 above), including 404 or 405 on unknown routes and body-parse failures.
- Server: `axum` on `tokio` (design).

## 8. Telemetry (§25.1)

OpenTelemetry tracing with W3C trace context propagation, structured JSON logs, and Prometheus `/metrics` on a separate admin listener. Secrets, tokens, keys and passwords are never logged (§15.4). Redaction is type-level: `Secret<T>` has no Debug or Display output of its contents.

## 9. KMS (§17.2, J.4, design)

- `trait Kms`: `generate_key`, `wrap(kek_id, plaintext_key)`, `unwrap`, `sign(key_id, bytes)`, `public_key(key_id)`, `rotate`.
- Key IDs carry a version. `LocalSoftwareKms` stores its root key in a file with 0600 permissions, which is acceptable only for single-node deployments (J.4), and logs a warning saying so. Unwrapped keys are held in zeroizing buffers.

## 10. Frontend foundations (§14.3)

- `@cs/sdk`:
  - `ApiClient` (typed fetch wrapper; base URL from config; never hard-codes backend internals).
  - `Problem` type plus the `ErrorCode` union.
  - `RetryPolicy` (§2).
  - `IdempotencyKey` generator (crypto.randomUUID).
  - Design tokens exported as CSS custom properties.
- `@cs/components`: Lit components consume only the SDK's public types. Base set: `cs-button`, `cs-text-field`, `cs-dialog`, `cs-error-banner` (renders a Problem: localized title, request_id for support, never raw internals), `cs-spinner`. They meet WCAG 2.2 AA (§14.6).
- All user-facing strings go through a localization function from day one (§14.6).

## Changelog
- 2026-11-19: initial freeze.
- 2026-11-19 rev 2 (from QA open questions): ChunkId/ExtentId use full 128 random bits; idempotency in-progress, digest, expiry and size rules; outbox and sagas primary keys lead with tenant_id (App. E); explicit saga transition table; the framework guarantees step idempotency through step receipts; envelope encoding, trailing-byte, key_id and size details; vector duplicates merge to the maximum position; problem `instance` excludes the query string; retry exhaustion returns `unavailable`; migrations only via `cs migrate`; malformed-body test moved to M1. Naming: "C1–C10" means spec errata. Appendix C rules are always written "App. C rule Cn".
- 2026-11-20 rev 3: idempotency concurrent-duplicate semantics aligned with the single-transaction design (block, then stored result; `outcome_unknown` only for separately committed in-progress records). Minimum Rust version raised to 1.94 (sqlx 0.9).
