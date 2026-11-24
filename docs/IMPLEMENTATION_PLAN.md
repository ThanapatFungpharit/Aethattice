# Implementation Plan — Cloud System Workspace Platform

- Source of truth: `Cloud_System_Workspace_Platform_Specification.md` (v2.4.2 = v2.4 + approved errata C1–C13, see `docs/SPEC_ERRATA.md`).
- Status of this plan: **approved** (2026-11-19). Approved scope: **M0–M3 only**. M4–M9 are planned but not approved for implementation.
- Requirement tracking: `docs/traceability.md`. Every normative requirement (MUST / MUST NOT / mandatory) is either implemented, in progress, or explicitly deferred with a target milestone. Nothing is omitted silently.

## 1. Guiding conditions (from approval)

1. **Architecture fidelity.** The specification is authoritative. Implementation convenience never overrides it. Any needed deviation is escalated to the project owner before merge and recorded in `docs/SPEC_ERRATA.md`.
2. **Contract-first.** API (OpenAPI), database schemas, WIT and error contracts for a milestone are frozen by the Team Leader in `docs/contracts/` before parallel implementation starts. Contract changes during a milestone go through the Team Leader.
3. **Multi-node-ready contracts.** M0–M3 run on a single node, but no contract (tokens, receipts, placement, IDs, vectors, cursors, domain boundaries, saga records) may encode a single-node assumption. Single-node behaviour is a configuration of the distributed design (spec §1.1).
4. **Security-first QA.** Authentication, authorization, tenant isolation, cryptographic correctness and revocation receive independent negative tests written from the specification, not from the implementation.
5. **Failure handling.** Tests cover partial failures, retries, duplicate requests, process crashes and recovery, not only success paths.
6. **Durability honesty.** The development host has one NVMe disk. The system must report this as a single failure domain. It never claims R=3 or independent failure-domain durability on this host (spec §17.3.1, §2.6).
7. **No premature production claims.** Every feature has one of the statuses: `implemented`, `tested`, `production-ready`. Nothing in M0–M3 is `production-ready`. The sealed object format (§17.2) is explicitly **non-production-stable** until independent cryptographic review (R4, C10).
8. **Documentation sync.** Docs and the traceability matrix are updated in the same change as the code.

## 2. Approved spec resolutions (errata)

See `docs/SPEC_ERRATA.md` for exact text changes. Summary:

| # | Resolution |
|---|---|
| C1 | Seal terminal state is `retired` (canonical). `superseded` accepted only as a compatibility synonym for seals. (Version state `superseded`, F.2, is unrelated and unchanged.) |
| C2 | Data-plane tokens follow §6.7 (signed ancestry snapshot handle, max depth 256). H.5 "64 ancestors / 1-minute tokens" note removed. No weaker fallback for protected data. |
| C3 | W ≡ R everywhere. |
| C4 | Exactly four tiers: Hot, Standard, Cold, Archive. Compression: LZ4 Hot; Zstandard Standard and Cold; Zstandard max or LZMA Archive. |
| C5 | F.5 adds `installed → removing`. Install failure, upgrade and rollback are explicit saga states; a plugin is usable only in `enabled` with a completed install/upgrade saga. Partially installed plugins can never become usable. |
| C6 | Upload-session expiry does not apply in `finalizing`; resolution only by pivot proof (§17.5 step 8). |
| C7 | UPSERT = PostgreSQL `INSERT … ON CONFLICT`. |
| C8 | Ed25519 for all signed artifacts (access tokens, data-plane tokens, consistency contexts, decision tickets, receipts, watermark heartbeats, cursors where signed), with explicit domain-separation context strings and canonical serialization. |
| C9 | Document normalized to reference Appendices A–M. |
| C10 | Sealed format implemented with test vectors and fuzzing; classified non-production-stable until independent review. |

## 3. Team and workflow

| Role | Responsibility |
|---|---|
| Team Leader | Spec analysis, contract freezing, task assignment, review, merges, traceability matrix, escalation to owner. |
| Backend Engineer | Rust workspace: core services, storage, metadata domains. |
| Frontend Engineer | `web/`: Lit + Vite + TypeScript UI SDK, shell, platform components, typed API clients. |
| QA Engineer | Independent tests from the spec: correctness, security (negative), failure injection, performance smoke, spec compliance audit of the traceability matrix. |

Git workflow:
- `main` is always buildable and passes CI.
- One branch per milestone (`milestone/m0-foundations`, …). Each agent works in its own git worktree on a sub-branch (`m0/backend`, `m0/frontend`, `m0/qa`) merged into the milestone branch after Team Leader review.
- A milestone branch merges into `main` only after (a) its QA gate passes, (b) Team Leader review, (c) CI is green.
- The next milestone does not start until the previous QA gate has passed.

CI (`scripts/ci.sh`, mirrored in `.github/workflows/ci.yml`): `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test` (unit), DB integration tests against YugabyteDB in Docker, `web/` typecheck + lint + unit tests + build, traceability lint (every requirement ID has a status).

## 4. Repository layout

```text
Cargo.toml                 workspace
crates/
  cs-common                IDs (UUIDv7), Appendix D error model, consistency vectors, config, telemetry
  cs-db                    YSQL access, migration runner (expand–migrate–contract), outbox, idempotency records
  cs-kms                   KMS trait + local software KMS (J.4)
  cs-crypto                sealed object format v1 (§17.2), signing with domain separation (C8)
  cs-identity              identity domain (§5)                                   M1
  cs-authz                 authz domain, projection, ADS, revocation feed (§6)     M2
  cs-resources             resources domain, journal, listings, sharing (§4, §19)  M2
  cs-ops                   operations domain: sagas, leases, epochs (§18.4, §20)   M0 (saga core) / M3
  cs-accounting            quotas, reservations, usage (§8.4, §17.10)              M3
  cs-objects               objects domain: chunks, seals, extents, refs (§17)      M3
  cs-storage-node          volumes, receipts, data-plane transfers (§17.6–17.7)    M3
  cs-api                   public REST API /api/v2 (OpenAPI), edge routing          M0+
  cs                       single binary with roles (J.2)
web/
  packages/sdk             typed API clients, error model, auth, design tokens
  packages/components      shared Lit web components
  apps/shell               web shell, sign-in, account, admin console
dev/                       docker-compose: YugabyteDB, Valkey
docs/                      plan, errata, contracts/, traceability.md, design docs
scripts/                   ci.sh and helpers
```

Crates for later milestones (cs-events, cs-audit, cs-plugins, cs-host, cs-sqlguard, cs-realtime, cs-search, cs-sync, cs-plugin CLI) are created when their milestone is approved.

## 5. Milestones

### M0 — Foundations (approved)
- Backend: Cargo workspace; `cs-common` (UUIDv7 IDs, URNs `cs:{tenant}:{type}:{id}`, Appendix D error codes and RFC 9457 problem details, consistency-vector types per C10 of App. C, config loading/validation, OpenTelemetry + JSON logs); `cs-db` (connection pools per domain, migration runner with expand/contract classes and Appendix E conventions, outbox table per domain, idempotency-key store with request digest → `idempotency_mismatch`, 40001/40P01 retry with backoff+jitter); `cs-ops` saga record skeleton (§18.4 states); `cs-kms` local software KMS; `cs-crypto` Ed25519 signing envelope with domain separation and canonical encoding (C8); `cs` binary with role flags; `cs-api` skeleton with health/readiness (readiness ≠ liveness, §2.6) and problem-details error handling.
- Frontend: Vite/Lit/TS monorepo; design tokens; SDK skeleton with typed fetch client, problem-details error model, retry policy (App. D.3: exponential backoff, full jitter, 200 ms–30 s, honour retry_after_ms); base components; shell skeleton.
- QA: traceability matrix populated for all spec sections; test harness (DB fixtures in Docker, failure-injection helpers); negative tests for error model, idempotency and migration runner.
- **Gate:** CI green; matrix complete (every requirement has a status/milestone); idempotency, retry and migration failure tests pass; frozen M1 contracts reviewed.

### M1 — Identity (approved, starts after M0 gate)
Tenants, users, groups (cycle rejection, versioned membership), OPAQUE (RFC 9807, ristretto255-SHA512) + client Argon2id (64 MiB, t=3, p=1, per-registration params), Ed25519 JWS access tokens (10 min) with sid/sub/tenant/authz version/auth strength/cnf.jkt, DPoP (RFC 9449), refresh tokens (256-bit, SHA-256 stored, single use, reuse revokes session, HttpOnly SameSite=Strict cookie on refresh path), idle/absolute session lifetimes, step-up (5 min) for sensitive operations, WebAuthn passkeys/MFA, account recovery codes and waiting-period flows, indistinguishable unknown-account responses, rate limiting. Frontend: sign-in, registration, account, security, recovery pages; OPAQUE/Argon2id client via WASM.
- **Gate:** auth negative suite, token tampering/replay, refresh reuse detection, enumeration resistance, cross-tenant identity isolation.

### M2 — Resources and authorization (approved, starts after M1 gate)
Spaces, resource registry, hierarchy, lifecycle (App. F.1), journal shards with contiguous sequences (§19.1), relationship tuples + ACL versions, authz projection with source positions, ADS with signed consistency contexts, revocation feed with signed 500 ms heartbeat and S-staleness fail-closed, check/lookup, sharing (roles, link shares with 128-bit tokens), trash/restore, HMAC cursors and live listings (§19.3), resource events through outbox, Appendix D existence hiding. Frontend: shell navigation, share dialog, resource and people pickers, listing views.
- **Gate:** cross-tenant suite (L.5 subset), existence hiding, revocation bound measurement, listing guarantees, stale-projection fail-closed.

### M3 — Object storage on single node (approved, starts after M2 gate)
Snapshots (§19.2: journal-cut snapshots, build, manifests, snapshot listings; the purge executor honours them; owner decision OQ-10, 2026-11-24; snapshot UI later), sealed object format v1 with golden files, test vectors and fuzzing (non-production-stable), chunk/seal/extent model, storage-node volumes (compio/io_uring, group commit fdatasync, fsync-failure seals volume, write-cache check with explicit override), signed receipts, upload saga (reserve → open → plan → transfer → finalize prepare/pivot/complete), quota reservations, data-plane tokens (§6.7) with 1 MiB/1 s revalidation, downloads with read plan, read grace and read leases, reference counting, purge executor, durability reporting by failure domain (honest single-domain report). Frontend: upload component with client-side sealing, download, version history.
- **Gate:** no publication without R durable receipts in R distinct failure domains (and publication unavailable on this host for R>1 unless configured domains truly exist), saga crash/retry injection at every step, revocation mid-transfer, crypto negative vectors, quota races.

### M4–M9 (planned, not approved)
M4 events/ops/audit · M5 plugin platform + minimal Drive plugin (folder/file types, containment, containable-types extension point, built on the real plugin architecture) · M6 realtime/collaboration · M7 search/sync · M8 cluster/recovery · M9 vaults, SSO/SCIM, sandboxed services, full-mode UI, export/import, full Appendix L.

Out of scope until decided: reference applications other than minimal Drive; native desktop/mobile clients (§14.5).

## 6. Durability on the development host

The host has one NVMe. Single-node dev deployments therefore have **one failure domain at every level (disk, host, rack, zone, site)**. Configuration may create multiple volume directories, but they are labelled as the same disk failure domain. With R > 1 configured and one disk domain, publication is refused per §17.3.1 rather than silently lowering R.

**Owner decision (2026-11-24, OQ-11):** J.3 requires at least 2 disks (R = 2) for a single node, so this host cannot run a spec-compliant single-node deployment. Both measures apply:
- A development-only R = 1 profile. `cs serve` refuses it outside `--dev`, and every durability report, API response and admin screen labels it "NON-COMPLIANT: single failure domain, no redundancy".
- Tests that need multiple failure domains use simulated domains (separate volume directories declared `simulated: true`). Their results are reported as simulations and never counted as durability evidence.

M3 gate items 17.3.1-2 and J.3-1 can pass on this host only as "verified by simulation". Real R ≥ 2 evidence requires a second physical disk or host.
