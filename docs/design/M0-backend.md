# M0 Backend Design Notes

Implements `docs/contracts/M0-foundations.md` (revision 2). This note lists each crate's public API and the design choices made where the contract leaves room. Nothing here is `production-ready`.

## Crate dependency order

`cs-crypto` → `cs-common` → `cs-kms`, `cs-db` → `cs-ops` → `cs-api` → `cs` (binary).

`cs-crypto` sits at the bottom because ID generation in `cs-common` must use `cs_crypto::rand`.

## cs-crypto

| Item | Purpose |
|---|---|
| `rand::{fill, bytes::<N>, u64, u64_inclusive}` | The only randomness source: the OS CSPRNG via `getrandom`. Every failure is returned as an error, with no fallback. The `fault-injection` feature adds `rand::inject_failure()` (thread-local) for tests. |
| `cbor::{Value, encode, decode_lenient, decode_canonical, to_canonical, from_canonical, bstr}` | Deterministic CBOR (RFC 8949 §4.2.1). |
| `sig::{Context, KeyId, KeyResolver, RawSigner, StaticKeyResolver, LocalSigner, sign, sign_payload_bytes, verify, verify_bytes, to_text, from_text, signed_bytes}` | The signing envelope. |

### CBOR

- The decoder is our own and treats every input as untrusted:
  - It never allocates from a declared length larger than the remaining input.
  - Nesting depth is capped at 64.
  - Floats, tags, `undefined` and other simple values are rejected.
- Canonical form is checked by decoding, re-encoding and comparing the bytes. This catches non-preferred integers, indefinite lengths, unsorted or duplicate keys and trailing bytes.
- `ciborium::Value` is used only as an in-memory serde bridge. Untrusted bytes never reach ciborium's parser.

### Signing envelope

`verify` runs these checks in order:

1. Size limit (16 KiB; for base64url input, the encoded length is checked first, ≤ ceil(16384·4/3)).
2. Canonical envelope structure.
3. Version must be `1`.
4. Context must be in the closed registry and equal the expected context.
5. `key_id` must have the form `<name>@v<version>` and be at most 128 bytes.
6. The `KeyResolver` resolves the key, with the context passed in so keys can be bound to contexts.
7. `verify_strict` checks the Ed25519 signature, which rejects malleable signatures.
8. The payload is decoded canonically and deserialized.

Test vectors: `crates/cs-crypto/tests/vectors/envelope-{positive,negative}.json`.

- The positive vector uses the RFC 8032 TEST 1 key.
- There are 14 negative vectors.
- They are regenerated with `CS_REGENERATE_VECTORS=1`; otherwise the test checks that the files match the implementation byte for byte.

## cs-common

| Module | API |
|---|---|
| `id` | 15 typed IDs; each has `generate()`, `from_uuid`, `from_bytes`, `FromStr`/`Display` and serde. Serde uses a string in JSON and 16 bytes in CBOR. |
| `urn` | `Urn::{resource, space, parse}` and `ResourceType::parse`. |
| `error` | `ErrorCode` (exactly table D.2), `AppErrorCode`, `Code`, `Error` (caller-safe `detail` plus an internal `cause` that is never serialized), `ProblemDocument`. |
| `vector` | `DomainId`, `VectorComponent`, `ConsistencyVector::{from_components, advance, merge, dominates, position}`. |
| `config` | `Config::{load, from_toml_str}`, `Role`, `POLICY_TABLE`, `PolicyKey`, `Policy::get`. |
| `secret` | `Secret<T>`. |
| `idempotency` | `IdempotencyKey`. |
| `telemetry` | `init` (JSON logs, OpenTelemetry layer with W3C propagator, Prometheus recorder). |

Design choices:

- **IDs.**
  - UUIDv7 IDs are built from a 48-bit millisecond timestamp plus 74 CSPRNG bits.
  - Parsing checks the version and variant.
  - `ChunkId` and `ExtentId` are 16 raw CSPRNG bytes (rev 2), and any 16 bytes parse as one.
- **URNs.** `Urn::resource_id()` returns a value only for non-space types, and `space_id()` only for `core.space`.
- **Application IDs.** Reverse-DNS form: 2 to 16 labels matching `[a-z][a-z0-9]*(-[a-z0-9]+)*`, at most 128 bytes.
  - App error codes have the form `app.<app id>.<code>`, where `<code>` matches `[a-z][a-z0-9_]{0,63}`.
  - Their `retryable` value is derived from the HTTP status. Every D.2 status maps to a single retryability, and a test asserts this.
- **Internal errors.** For an `internal` error, `ProblemDocument.detail` is always a generic text and `errors[]` is dropped.
- **DomainId.** The wire form is the §18.1 name, or `app_<application_id>` for application domains. Vectors sort by (cluster_id bytes, domain wire name bytes, partition).
  - Deserialization is strict: input must already be sorted and deduplicated, with at most 64 components.
  - `from_components` merges duplicate keys to the maximum position before applying the 64 limit (rev 2).
- **Config.**
  - Unknown keys are rejected at every level.
  - All validation errors are collected and reported together.
  - Parse errors report only the message and line number, never the offending line, because URLs may contain passwords.
  - `[domains.<name>]` accepts only the 11 core domains.
  - Policies: `idempotency_retention_hours` (24, 24..=720), `db_retry_max_attempts` (10, 1..=50), `db_retry_max_elapsed_ms` (5000, 100..=60000), `saga_reconcile_interval_ms` (1000, 100..=60000), `revocation_staleness_ms` (2000, 1000..=30000). The spec gives only defaults for most of these, so ranges are design choices (OQ-6).
  - `[locks] policy = [...]` must name known policy keys.
- **Telemetry.** No span exporter is configured in M0. The OTLP exporter is deferred.

## cs-kms

- `trait Kms` (async): `generate_key`, `wrap`, `unwrap`, `sign`, `public_key`, `rotate`, `current`.
- `LocalSoftwareKms` provides `init` (creates the root key file with `O_EXCL` and mode 0600) and `open` (refuses group/other permission bits or a wrong length).
- It also implements `sig::RawSigner` and `sig::KeyResolver`.

Design choices:

- **Key store.** Every key version is encrypted under the root key with XChaCha20-Poly1305. The associated data binds name, version and purpose. The store is written atomically (temp file 0600, fsync, rename, fsync of the directory).
- **Wrapping.** `wrap` uses XChaCha20-Poly1305 with associated data `cs-kms/wrap/v1 ‖ kek_id`, so relabelling a wrapped key under another KEK fails.
- **Key purposes.** `Signing` and `KeyEncryption` keys cannot be used for each other's operations.
- **Warning.** `open` logs the single-node warning.

## cs-db

- `DomainPool::{connect_lazy, transaction, read_snapshot, ping, close, domain}`.
- `DomainTx::{conn, domain}`.
- `RetryPolicy`.
- `migrate::{Migration, MigrationSet, Migrator::{run, status, bootstrap, finalize_release}, common_migrations}`.
- `outbox::{Outbox::{append, read, partition_for}, NewEvent, OutboxPosition, OUTBOX_PARTITIONS}`.
- `idempotency::{IdempotencyRecords::{begin, complete, execute}, request_digest, body_digest, RequestBody, IdempotencyScope, StoredResponse}`.
- `testing::TestDomains` (feature `testing`).

### Transactions and retry

- The closure has type `Fn(&mut DomainTx) -> BoxFuture`: it can be re-run and receives only the transaction handle. Each attempt starts with `BEGIN ISOLATION LEVEL READ COMMITTED`.
- 40001/40P01 errors are retried with full-jitter backoff (10 ms × 2ⁿ, capped at 1 s), bounded by attempts and elapsed time. When the bound is reached the result is `RetryExhausted`, which maps to `unavailable` with `retry_after_ms` 1000.
- Retry budget (contract rev 4): the elapsed bound is charged only with attempt time (BEGIN through COMMIT/ROLLBACK) and backoff. Connection acquisition is excluded; the pool's `acquire_timeout_ms` bounds it instead.
  - To time acquisition separately, `DomainTx` owns the pooled connection and issues BEGIN/COMMIT/ROLLBACK itself. If a transaction is dropped while still open, its connection is closed rather than returned to the pool.
- The migration runner has its own budget: `RetryPolicy::migrations_default()`, 30 attempts or 120 s. It is configured through the policies `db_migration_retry_max_attempts` and `db_migration_retry_max_elapsed_ms`, and set with `DomainPool::with_migration_retry`.
- At COMMIT:
  - A server-reported error means the transaction did not commit, and it is returned as-is.
  - A lost reply becomes `OutcomeUnknown`, which maps to `outcome_unknown` and is never retried. A test drops the reply through a TCP proxy and shows that the row did commit.
- On YugabyteDB 2026.1 the effective isolation is READ COMMITTED; `db::isolation_levels` asserts this. On a cluster without `yb_enable_read_committed_isolation`, YugabyteDB would silently use snapshot isolation.

### Migrations

- Versions `0001`–`0099` are the per-domain tables owned by `cs-db` (common), versions `0100`+ belong to domain crates and versions `1000`+ are used by tests.
- The runner bootstraps `schema_migrations` and `finalized_releases`.
- Each migration runs as one multi-statement simple query. It must be idempotent, so a crash between executing it and recording it simply re-runs it.
- `expand` and `migrate` files may not contain destructive DDL (whole-word match) or a `requires_finalized` header. `contract` files must have the header.
- Applied versions that this binary does not know are tolerated only if they are above its highest version (rolling upgrades).

### Outbox

- P = 16 is a format constant for every domain. Changing it would remap partition keys.
- `partition = BLAKE3(key)[0..8] mod 16`.
- Counter rows are created on first use.
- `read` reads the head counter first and then the rows, so a missing sequence anywhere up to the head is detected (`OutboxGap`).

### Idempotency records

- The record and the effect share one transaction. Exactly one of N concurrent duplicates executes; the others wait on the row lock and then replay the committed result.
- A *visible* `in_progress` record (committed separately, for example by a crashed multi-step flow) yields `outcome_unknown`.
- Expired records are reclaimed by `INSERT … ON CONFLICT DO UPDATE … WHERE expires_at <= now()`.

### Test harness (`testing` feature)

- Every database the harness creates is registered before it is created. `cleanup()` drops each one with:
  - no statement timeout, because a DROP on YugabyteDB can take minutes;
  - up to 8 attempts, each followed by a check against `pg_database`.
- If a database cannot be dropped, cleanup panics and names the database.
- Test pools use a 1 s idle timeout and are closed before the drop.
- If a `TestDomains` is dropped without `cleanup()`, the databases are still dropped and then the test fails.
- The harness drops only databases with its own `cs_test_` prefix that it created itself.

## cs-ops

- `saga::{SagaDefinition, StepDef, StepContext, StepDone, SagaExecutor::{new, register, start, drive, load, verify, try_transition, redeliver_step, step_receipt, with_crash_hook}, Reconciler::{run_once, run}, SagaState}`.
- `migrations()` provides `0100_sagas`.

Design choices:

- **Step receipts.** The framework claims the receipt row before running the step body, fills it in after the body and commits both together. A concurrent claimer blocks on the row and then sees the committed receipt.
- **Fences.** To prove that a step did not commit, the executor writes an "aborted" receipt. This happens to the pivot before any compensation, and to each pre-pivot step inside its compensation transaction. A late execution then sees the fence and cannot commit.
- **Deadlines.** A passed deadline before the pivot triggers only this proof-based abort. It is never treated as a failure by itself.
- **Outbox requirement.** A step or compensation that writes no outbox event is rejected, and its transaction rolls back.
- **Retries after the pivot.** These are bounded (default 10); when exhausted the saga goes to `blocked_for_operator`. A permanent business error after the pivot goes to `blocked_for_operator` immediately.
- **Leaving `blocked_for_operator`.** The audited operator action is M4. The automatic state machine never leaves this state.

## cs-api

- `router`, `public_routes`, `with_middleware`, `admin_router`, `serve`, `ApiState`, `ApiError`, `problem_response`, `IdempotencyKeyHeader`, `JsonBody`, `body_bytes`.
- `ReadinessBarrier` with `DomainReachable` and `MigrationsCurrent`.

Design choices:

- **Finalizing middleware.** One outer middleware does all of the following:
  - generates the `RequestId`;
  - extracts W3C `traceparent` into the span;
  - converts every error response that is not already problem+json (404/405 fallbacks, 413 body limit, extractor rejections, `CatchPanicLayer` 500s) into a problem;
  - sets `X-Request-Id`;
  - records metrics.
- **Request IDs** are always generated by the server; inbound values are ignored.
- **`/readyz` failures** list barrier names in `errors[].pointer` (`/barriers/<name>`). The reasons go only to the log.

## cs (binary)

- `serve`, `migrate`, `init-kms` and `check-config`, each taking `--config <path>`.
- Only the `api` role is implemented. Any other role makes the binary refuse to start, with exit code 2 and an explicit message.
- `serve` never migrates and requires an existing KMS root key (created by `init-kms`).
