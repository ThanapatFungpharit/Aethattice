# M0 QA Gate — Foundations

Owner: QA Engineer. Decision: Team Leader. Source criteria: docs/IMPLEMENTATION_PLAN.md §5 (M0 gate), docs/contracts/M0-foundations.md, docs/traceability.md.

The gate passes only when **every** item marked **[blocking]** passes on the merged milestone branch `milestone/m0-foundations`. Run the checks in the order given, on a clean checkout, and record each result in §7. If a check is not run or fails, record it as `FAIL` with output. It is never recorded as passed by assumption.

Plan gate criteria and where they are checked:

| Plan criterion | Checked by |
|---|---|
| CI green | §2 |
| Matrix complete (every requirement has a status/milestone) | §5 |
| Idempotency, retry and migration failure tests pass | §3 (`idempotency`, `db_retry`, `migrations`) |
| Frozen M1 contracts reviewed | §6 |

QA adds the rest of §3 (error model, outbox, sagas, signing, vectors, config, readiness), §4 (spec-compliance review) and the frontend items in §2.3. Each one traces to an M0 row of the matrix.

---

## 1. Preconditions

```sh
git fetch --all
git checkout milestone/m0-foundations
git log --oneline -15                      # m0/backend, m0/frontend and m0/qa all merged
git status --short                         # must be empty
docker compose -f dev/docker-compose.yml up -d
# Wait for YugabyteDB (it can take more than a minute on first start):
until docker compose -f dev/docker-compose.yml exec -T yugabyte bin/ysqlsh -h yugabyte -U yugabyte -c 'select 1' >/dev/null 2>&1; do sleep 3; done
export CS_TEST_DATABASE_URL=postgres://yugabyte@localhost:5433/yugabyte
export CS_REQUIRE_DB=1
```

Record: commit SHA, `rustc --version`, `node --version`, the YugabyteDB image tag, and the host (1 NVMe = one failure domain; see plan §6).

## 2. CI [blocking]

### 2.1 Full local CI with database
```sh
scripts/ci.sh --with-db 2>&1 | tee /tmp/m0-ci.log
```
Pass: the script ends with `CI OK`. The steps it runs are fmt, clippy `-D warnings`, unit tests, DB integration tests with `CS_REQUIRE_DB=1`, web typecheck/test/build and trace-lint. A skipped DB test counts as a failure here. Search the log for `SKIP` and require zero hits:
```sh
grep -c 'SKIP' /tmp/m0-ci.log   # must print 0
```

### 2.2 GitHub Actions
The `ci` workflow run for the head commit of `milestone/m0-foundations` must be green (`gh run list --branch milestone/m0-foundations --limit 1`).

### 2.3 Frontend [blocking]
```sh
cd web
npm ci --no-audit --no-fund
npm run typecheck
npm test -- --reporter=verbose 2>&1 | tee /tmp/m0-web.log
npm run build
cd ..
```
Pass: all four commands succeed. The test log must show tests that cover each of the following (the name or a description is enough; record the test names in §7):
- [ ] `RetryPolicy` (D.3, contract §2): retries only when `retryable` is true; exponential backoff with full jitter, starting at 200 ms and capped at 30 s; honours `retry_after_ms` (the next delay is at least that value); default bound of 5 attempts; a write is retried only with the same `Idempotency-Key`; `unauthenticated` triggers exactly one refresh hook and one retry.
- [ ] `Problem` parsing: a non-problem or malformed body is handled without throwing raw internals at the UI.
- [ ] `IdempotencyKey` uses `crypto.randomUUID` and gives the same key across retries of one logical write.
- [ ] `cs-error-banner` renders the localized title and `request_id`, and never renders `detail` fields containing stack traces or internal text.
- [ ] Accessibility checks (WCAG 2.2 AA; for example axe) for `cs-button`, `cs-text-field`, `cs-dialog` (focus trap, Escape, labelled), `cs-error-banner` (role="alert") and `cs-spinner` (accessible name).
- [ ] Every user-facing string goes through the localization function (a test or lint that fails on a raw string literal in a template).

`ErrorCode` union parity with D.2 (contract §2). This must print nothing:
```sh
for c in invalid_request unauthenticated permission_denied not_found method_not_allowed conflict resource_trashed \
         precondition_failed payload_too_large unsupported_media_type idempotency_mismatch locked rate_limited \
         quota_exceeded internal dependency_unavailable unavailable timeout outcome_unknown; do
  grep -rq "'$c'\|\"$c\"" web/packages/sdk/src || echo "missing in @cs/sdk ErrorCode: $c"
done
```
Also check by review that the union contains no codes **beyond** these 19.

## 3. Independent QA suite [blocking]

### 3.1 Bind the adapter (once, at merge)
The suite reaches engineer code only through `crates/cs-qa-tests/tests/support/contract.rs`. Binding it to the real APIs may change **only** that file:
```sh
grep -n 'BIND:' crates/cs-qa-tests/tests/support/contract.rs      # review every site
git diff m0/qa -- crates/cs-qa-tests ':!crates/cs-qa-tests/tests/support/contract.rs' ':!Cargo.lock'
```
Pass: the second command prints nothing. Test expectations are never edited to match an implementation. A disagreement between a test and the implementation is raised with the Team Leader, who decides whether it is a code defect or an erratum. The signatures in `contract.rs` must stay identical to `contract_stub.rs`.

### 3.2 Self-check (QA code compiles and lints on its own)
```sh
cargo clippy -p cs-qa-tests --features qa-selfcheck --tests -- -D warnings
cargo test   -p cs-qa-tests --features qa-selfcheck --test signing vectors_are_self_consistent
```

### 3.3 Run the suite against the implementation
```sh
cargo build -p cs                                   # HTTP tests spawn target/debug/cs (or set CS_QA_BIN)
cargo test -p cs-qa-tests --features m0-contract -- --test-threads=4 2>&1 | tee /tmp/m0-qa.log
grep -E '^test result|FAILED|panicked|SKIP' /tmp/m0-qa.log
```
Pass: every test binary reports `0 failed`, and `SKIP` does not appear. To narrow down a failure, run one area:

| Area | Command (`cargo test -p cs-qa-tests --features m0-contract --test <name>`) | Plan gate item |
|---|---|---|
| QA harness self-test (fixtures create/drop unique DBs) | `harness` | — |
| Appendix D error model | `error_model` | — |
| HTTP surface (404/405/400 problem, X-Request-Id, no leaks, Retry-After) | `http_surface` | — |
| Readiness vs liveness | `readiness` | — |
| Configuration and role refusal | `config` | — |
| Idempotency (replay, mismatch, N-way race, in-progress, scope, expiry, atomicity) | `idempotency` | **idempotency** |
| 40001/40P01 retry | `db_retry` | **retry** |
| Migration runner (tamper, re-run, crash/resume, failure, contract gating, App. E) | `migrations` | **migration failure** |
| Outbox (concurrent contiguity, rollback, gap detection) | `outbox` | — |
| Sagas (crash after every step and pivot, lost ack, compensation order, no post-pivot compensation, CAS, terminal states) | `sagas` | — |
| Signing envelope (independent vectors, 65 negative cases incl. 7 key_id-format cases from contract rev 2) | `signing` | — |
| Consistency vectors (64/65, proptest dominance) | `consistency_vector` | — |
| IDs and URNs | `ids` | — |

`malformed_json_body_returns_400_problem` is `#[ignore]`d with the reason "contract rev 2 (OQ-7): M0 has no JSON-body routes; moved to the M1 gate". The M1 gate must run it with `--ignored` once JSON routes exist. Expect the summary to show exactly 1 ignored test.

### 3.4 Repeatability (flakiness of concurrency and crash tests)
```sh
for i in 1 2 3; do cargo test -p cs-qa-tests --features m0-contract --test idempotency --test outbox --test sagas -- --test-threads=4 || break; done
```
Pass: three consecutive green runs.

### 3.5 No leftover databases
By default every QA test drops its own databases, retries and verifies the drop, and fails the test on a leak (`QA HARNESS LEAK`).

On the dev cluster a single `DROP DATABASE` can take minutes, because it waits on a cluster-wide `ProcSignalBarrier`. When that happens, run the suite with `CS_QA_DEFER_DROP=1`, which records each test database in `target/qa-deferred-drops.txt`, and drop them in one concurrent batch afterwards:
```sh
xargs -P 16 -I{} docker compose -f dev/docker-compose.yml exec -T yugabyte bin/ysqlsh -h yugabyte -U yugabyte \
  -tAc "drop database if exists {} with (force)" < target/qa-deferred-drops.txt
```
In either mode, the harness self-test (`harness::test_db_is_created_isolated_and_dropped`) always drops for real.

Then check:
```sh
docker compose -f dev/docker-compose.yml exec -T yugabyte bin/ysqlsh -h yugabyte -U yugabyte -tAc \
  "select datname from pg_database where datname like 'qa\_%'"
```
Pass: no output. Also record the count of `cs_test_*` databases; that is engineer-harness leakage (finding F-1).

### 3.6 Independent vectors
```sh
python3 -I crates/cs-qa-tests/vectors/gen/gen_sig_vectors.py /tmp/sigvec.json
cmp /tmp/sigvec.json crates/cs-qa-tests/vectors/signing_envelope.json && echo identical
```
Pass: `identical`, and the generator reports that it cross-checked the signatures with OpenSSL. The contract says engineer-owned vectors live in `crates/cs-crypto/tests/vectors/`. Check that they exist and that the `cs-crypto` tests run them. QA's vectors are the independent check; the engineers' vectors do not replace them, and vice versa.

## 4. Specification compliance review [blocking unless marked]

These checks are made by reading the merged code. Each one is a matrix row. Record `PASS` or `FAIL` and the evidence (file:line).

| # | Check | Rows | How |
|---|---|---|---|
| 4.1 | No API can open a transaction spanning two domains; `DomainPool::transaction` borrows exactly one pool | 18.1-2, C.2-1, 8.3.1-3 | Read `cs-db` public API |
| 4.2 | Transaction closures receive only the transaction handle (the engineers' lint test exists and runs) | 18.2-5 | `grep -rn transaction crates/cs-db/tests` |
| 4.3 | No SERIALIZABLE API; REPEATABLE READ helper only for journal reads | 18.2-2, CT.M0-15 | `grep -rni serializable crates/` |
| 4.4 | All randomness via `cs-crypto::rand` (OS CSPRNG); failure propagates; no fallback | 17.2-3, CT.M0-3 | `grep -rn 'rand::\|thread_rng\|SystemTime' crates/*/src` |
| 4.5 | `Secret<T>` has no Debug/Display of contents; tokens, keys and passwords are never logged | 15.4-2, CT.M0-28 | Read `cs-common`; run `cs` with the readiness test config and grep its log for `qa_secret_must_not_leak` (the `http_surface` test does this) |
| 4.6 | No `unsafe`; no `unwrap`/`expect` outside tests | CLAUDE.md | `grep -rn 'unsafe\|\.unwrap()\|\.expect(' crates/*/src` |
| 4.7 | Errors map to Appendix D codes at every public boundary | 3.4-5 | Review `cs-api` error mapping |
| 4.8 | `LocalSoftwareKms`: root key file mode 0600, single-node warning logged, zeroizing buffers | J.4-2, CT.M0-29 | Engineer tests and manual `ls -l` |
| 4.9 | `/metrics` on a separate admin listener; JSON logs; W3C trace context propagated | 25.1-1, 25.1-2, CT.M0-28 | Run `cs`, curl both listeners, inspect one log line |
| 4.10 | No single-node assumptions in contracts (IDs, vectors, outbox dedup key, saga record, config per domain) | 1.1-1 | Contract and code review |
| 4.11 | Bounded pools, queues and timeouts with defined overflow behaviour (M0 components) | 21.3-1 | Review `cs-db` and `cs-api` |
| 4.12 | Durability honesty: nothing in M0 claims more durability than the host has | plan §6 | Review README, UI strings and API |
| 4.13 | No row is marked `production-ready` | CLAUDE.md | `grep -c production-ready docs/traceability.md` gives only the legend lines |

## 5. Traceability matrix completeness [blocking]

```sh
scripts/trace-lint.sh                                                   # passes; prints the row count
grep -cE '^\| *[A-Z0-9.-]+-[0-9]+ *\|' docs/traceability.md             # >= 928 (rows may only be added)
grep -E '^\| *[A-Z0-9.-]+-[0-9]+ *\|' docs/traceability.md | awk -F'|' 'NF!=9' | wc -l   # 0: every row has 7 columns
grep -oE '^\| *[A-Z0-9.-]+-[0-9]+ *\|' docs/traceability.md | sort | uniq -d             # empty: no duplicate IDs
# M0 rows still open at the gate (each needs an explicit Team Leader decision in section 7):
grep -E '^\| *[A-Z0-9.-]+-[0-9]+ *\|[^|]*\|[^|]*\| M0 \| in-progress' docs/traceability.md
# Every qa: test named in the matrix exists:
grep -oE 'qa:[a-z_]+::[a-z0-9_]+' docs/traceability.md | sort -u | while IFS= read -r ref; do f=${ref#qa:}; \
  grep -qE "fn ${f##*::}\b" "crates/cs-qa-tests/tests/${f%%::*}.rs" || echo "MISSING $ref"; done
```
Pass when all of the following hold:
- lint passes;
- column and duplicate checks print nothing;
- no `MISSING` lines;
- every M0 row is `tested` (code path and passing test names filled in) or has a recorded carry-over decision;
- the Coverage notes table lists every spec section;
- every Open question has a recorded Team Leader decision (resolved, erratum raised, or deferred with a milestone).

When this checklist was written (QA commit on `m0/qa`), the matrix had 928 rows:
- by milestone: M0 170 (incl. 32 contract rows `CT.M0-*`), M1 36, M2 101, M3 183, M4 27, M5 154, M6 38, M7 31, M8 149, M9 33, plus 6 `n/a`;
- by status: 170 `in-progress` (all M0), 752 `deferred(Mn)`, 6 `n/a`.

## 6. M1 contracts reviewed [blocking]

- [ ] `docs/contracts/M1-*.md` and `docs/contracts/openapi/` are frozen by the Team Leader.
- [ ] QA has reviewed them against §5, §6.4 (access-token claims), §15.5, App. D and App. L.5. The review covers: OPAQUE parameters, Argon2id defaults, token lifetime and claims, DPoP, refresh rotation and reuse detection, cookie attributes, session lifetimes, step-up, recovery waiting period, indistinguishable unknown-account responses, rate limits and cross-tenant identity isolation.
- [ ] QA has derived the M1 negative-test list (auth, token tampering and replay, refresh reuse, enumeration, cross-tenant) from the frozen M1 contract.
- [ ] Open questions that affect M1 (OQ-1, OQ-3, OQ-4, OQ-5, OQ-7, OQ-13, OQ-18) are resolved.

### 6.1 QA review of `docs/contracts/M1-identity.md` (draft, 2026-11-19)

Reviewed by QA on 2026-11-20 against spec §5, §6.4, §6.8, §15.4, §15.5, §18.5, App. A, D, E, L.5. The draft is not frozen, so this item cannot pass yet. Findings, ordered by severity:

**Blocking (must change or be explicitly accepted by the owner before freeze)**

- **M1-R1 (refresh race revokes legitimate sessions).** §3 says concurrent refreshes with the same token are resolved by CAS, and "reuse of a rotated token revokes the whole session". Two browser tabs share the cookie, so a losing concurrent request presents a token that has just become `rotated` and triggers revocation. Per-tab SDK serialization does not prevent this across tabs. The contract must define how a concurrent loser is told apart from reuse, for example a short grace window keyed by the family generation, or cross-tab serialization with Web Locks. The fix must not weaken §5.5's rule that reuse revokes the session.
- **M1-R2 (`step_up_required` problem extension vs M0 contract).** The M0 contract §2 fixes the problem fields, and the implemented `ProblemDocument` uses `deny_unknown_fields`. An extension member `step_up_required` is therefore a contract change. Also, routing step-up through `unauthenticated` collides with the M0 SDK hook "unauthenticated → refresh once → retry once": the client will refresh (which cannot satisfy step-up) and retry, then surface a generic error. Proposal: a distinct signal via `errors[]` (`code: step_up_required`) that the SDK hook recognizes and does not refresh on, with the M0 contract amended.
- **M1-R3 (unknown-account indistinguishability).** §5.2 states that unknown accounts get indistinguishable responses. The draft accepts accounts with legacy Argon2id parameters as "a known distinguisher". That is a deviation from the spec and needs owner sign-off or a design that closes it, for example unknown logins receiving parameters drawn by a keyed PRF over the login from the real parameter distribution. Unknown *tenant* versus unknown *account* must also be indistinguishable; the draft does not say.
- **M1-R4 (`cs admin` needs the control role, which M0 refuses).** §0 runs the admin CLI "on a control-role node", but the binary refuses every role except `api` until its milestone. Either the CLI must not require the control role, or the plan must say which part of the control role M1 implements.
- **M1-R5 (recovery atomicity).** §4 calls completion "a single identity-domain transaction" but describes two steps: grant, then revoke after the new registration. If the registration never finishes, sessions are never revoked, while an attacker holding the grant can still register. The contract should specify revoking all sessions in the same transaction as `register/finish` under the recovery grant, plus the grant's expiry and idempotency.

**Important**

- **M1-R6 (DPoP `jti` replay cache on Valkey loss).** Falling back to a per-node local cache permits cross-node replay within the ±60 s window. §18.5 says losing Valkey "costs performance only", so this security reduction needs an explicit owner decision, or DPoP-bound requests should fail closed when the shared replay check is unavailable.
- **M1-R7 (dev log sink for recovery email).** A sink that logs recovery links writes bearer secrets to logs (§15.4). It must be refused outside an explicit `--dev` profile, and the log line must be marked as such.
- **M1-R8 (refresh-token lookup and App. E).** `refresh_tokens` is keyed `(tenant_id, token_hash)`, so the refresh endpoint needs the tenant before the lookup. The contract should state where the tenant comes from (cookie format) without trusting a client-chosen tenant. `setup_links` is keyed by `token_hash` alone, with no tenant_id first (App. E); either justify this as a pre-tenant bootstrap table or add tenant_id.
- **M1-R9 (`av` claim semantics).** `av` is defined as the session `generation`, but §5.5 calls it the "authorization version", which M2 will need to compare against authz epochs and membership versions. Rename the claim or define how M2 extends it, so M2 tokens are not a breaking change.
- **M1-R10 (logout and cookie path).** The refresh cookie is scoped to `/api/v2/auth/token`, so `POST /api/v2/auth/logout` never receives it. The contract should state that logout revokes by `sid` from the access token (and the whole refresh family) so a logged-out refresh token cannot be used.
- **M1-R11 (policy ranges).** Step-up 1–60 min and access-token lifetime 60–3600 s are new ranges not in the spec (same class as OQ-6) and need recording.

**Minor**

- **M1-R12.** Rate-limit "IP prefix" length is unspecified (IPv4 /32 or /24? IPv6 /64?). Clock-skew tolerance for `exp`/`iat` is unspecified. The limit/N fallback needs N "from config" to be validated as ≥ 1.
- **M1-R13.** `group_complexity_limit` as an `errors[]` code under `invalid_request` should be listed in a published per-endpoint error catalogue (App. G.5, L.4).
- **M1-R14.** The M1 gate must include `qa:http_surface::malformed_json_body_returns_400_problem` (currently `#[ignore]`d, moved from M0).

**QA negative-test list for M1 (to be finalized at freeze):**
- **Enumeration.** Unknown versus known account, unknown tenant, disabled user: identical bodies, status and timing distribution. Also the Argon2id parameters path.
- **OPAQUE.** Tampered `credential_finalization`, replayed or expired `login_txn` (60 s), and `login_txn` reused from another source or tenant.
- **JWS.** `alg: none`, `HS256` signed with the public key, unknown `kid`, `jku`/`jwk`/`x5u` headers, expired `exp`, a future `iat` beyond tolerance, wrong `aud`, and a token from tenant A presented to tenant B's routes.
- **DPoP.** Missing proof, wrong `htm`/`htu`, stale `iat`, replayed `jti` (including across two API nodes), wrong `ath`, and a mismatching `cnf.jkt`.
- **Refresh.** Reuse after rotation revokes the session and its generation; a concurrent refresh race (M1-R1); cookie attributes (Secure, HttpOnly, SameSite=Strict, Path); refresh after absolute or idle expiry.
- **Step-up.** A sensitive operation at 5 min + 1 s since the last strong auth.
- **Recovery.** The waiting period cannot be shortened; cancellation from another session; MFA users without a second factor; all sessions revoked at completion.
- **Rate limits.** Per account and per source; Valkey down → limit/N, never unlimited.
- **Cross-tenant.** Every M1 endpoint (L.5).

## 7. Results

Recorded by the QA Engineer on branch `m0/qa-gate`, created from `milestone/m0-foundations` at `332457f` (contract rev 3), on 2026-11-20. Raw logs are in `target/qa-gate-logs/` of the QA worktree (not committed).

| Item | Status | Evidence (log path, test names, SHA, notes) | Recorded by | Date |
|---|---|---|---|---|
| 1 Preconditions (SHA, toolchain, DB image) | PASS | Base `332457f`; rustc 1.99.1; node v22.23.1; `yugabytedb/yugabyte:2026.1.2.0-b137`; host = 1 NVMe = one failure domain. Note: during the session the dev stack stopped once (host restart, which also wiped `/tmp`); QA restarted it with `docker compose -f dev/docker-compose.yml up -d`. Later the database became unavailable (F-4). | QA | 2026-11-20 |
| 2.1 `scripts/ci.sh --with-db` | PASS (final re-run blocked) | Run on the merged code before the database incident: `CI OK`; fmt and clippy clean; 240 Rust tests passed, 0 failed, 0 SKIP (with `CS_REQUIRE_DB=1`); web: 8 files, 246 tests, typecheck, lint and build OK; trace-lint. Engineer code is unchanged since. After QA's final harness changes, `scripts/ci.sh` *without* DB passes (`CI OK`, 120 Rust tests, 246 web tests). A final `--with-db` re-run is blocked by F-4. | QA | 2026-11-20 |
| 2.2 GitHub Actions | FAIL (not runnable) | The repository has no git remote, so no workflow run exists. Needs a Team Leader waiver or a push. Not recorded as passed. | QA | 2026-11-20 |
| 2.3 Frontend (typecheck/test/build + listed coverage + ErrorCode parity) | PASS (2 notes) | Typecheck, lint, tests (8 files, 246 tests) and build are green inside 2.1. Coverage present: `RetryPolicy` (5 attempts, 200 ms initial, 30 s cap, full jitter, honours `retry_after_ms`, never retries non-retryable or key-less writes), `ApiClient` "refreshes once and retries once" / "does not refresh twice", `parseProblem`/`synthesizeProblem` (malformed bodies never leak), `idempotencyKey` (`crypto.randomUUID`, fails without a CSPRNG), `cs-error-banner` (localized title, request id, never detail for 5xx), `cs-dialog` focus trap and Escape, `cs-text-field` ARIA, token contrast for both themes, `t()` for every D.2 code. ErrorCode parity loop: no code missing. **Notes (non-blocking):** (a) there is no automated axe/WCAG audit; ARIA and contrast are unit-tested instead; (b) no lint fails on untranslated literals ("shell messages are all registered" only). | QA | 2026-11-20 |
| 3.1 Adapter bound; only contract.rs changed | PASS (with listed corrections) | `support/contract.rs` rebound to the real API (§7.1). Other changes are limited to the explicit corrections in §7.1a (each forced by contract rev 2/3 or a harness defect) and harness infrastructure. No assertion was weakened to make a test pass. | QA | 2026-11-20 |
| 3.2 QA self-check | PASS | `cargo clippy -p cs-qa-tests --features qa-selfcheck --tests -D warnings` and the same with `--features m0-contract` are clean; `vectors_are_self_consistent` passes. | QA | 2026-11-20 |
| 3.3 QA suite `--features m0-contract` | PASS | Two complete runs against the merged implementation: run A 117 passed, 0 failed, 1 ignored, 0 SKIP; run B 117 passed, 0 failed, 1 ignored, 0 SKIP (all 13 test binaries). | QA | 2026-11-20 |
| 3.3a OQ-7 decision for `malformed_json_body_returns_400_problem` | PASS (decided by contract rev 2) | The test is `#[ignore]` with reason "moved to the M1 gate"; it is the 1 ignored test. M1 gate item M1-R14. | QA | 2026-11-20 |
| 3.4 Repeatability ×3 | FAIL (incomplete; environment) | Runs A and B green. Run C: `db_retry::retry_bounded` failed with "40001 was not retried at all (attempts 1, error unavailable)". Diagnosed as a test-design defect: the 5 s budget was consumed by the first connection while parallel tests ran CREATE/DROP DATABASE. Fixed (§7.1a) with assertions unchanged; after the fix all four `db_retry` assertions passed. Later full runs failed only on environmental causes: the deferred-drop stimulus bug in `readyz_200_…` (fixed), a pool acquire timeout while QA cleanup DROPs ran, and the YugabyteDB tablet-replica limit (`total running tablet replica count (1246) to exceed the safe system maximum (1245)`). Then the database became unavailable (F-4). Three consecutive clean runs with the final harness have **not** been achieved. | QA | 2026-11-20 |
| 3.5 No leftover databases | FAIL (blocked) | About 248 `qa_*` databases (QA deferred drops from the runs above) and 159 `cs_test_*` databases (F-1) remain. QA cannot drop its own leftovers while the database is down (F-4). Earlier in the session QA dropped its 318 leaked `qa_*` databases. | QA | 2026-11-20 |
| 3.6 Vectors deterministic; cs-crypto vectors present | PASS | Regenerated `signing_envelope.json` is byte-identical (`cmp`); 16 valid, 65 invalid; 16/16 signatures cross-checked against OpenSSL; RFC 8032 §7.1 self-test passes. `crates/cs-crypto/tests/vectors/envelope-{positive,negative}.json` present and run by `cs-crypto` tests. | QA | 2026-11-20 |
| 4.1 – 4.13 Compliance review | PASS (1 finding) | See §7.2. Finding F-3: W3C trace-context propagation (CT.M0-28, 25.1-1) is claimed but has no test anywhere and is not observable in M0. | QA | 2026-11-20 |
| 5 Matrix completeness | PASS (carry-over list) | trace-lint passes; 0 malformed rows; no duplicate IDs; every `qa:` reference resolves; Coverage notes complete; OQ status table added. M0 rows not `tested` after this gate are listed in §7.3 for a Team Leader carry-over decision. | QA | 2026-11-20 |
| 6 M1 contracts reviewed | FAIL (expected: draft not frozen) | QA review done (§6.1): 5 blocking, 6 important and 3 minor comments, plus the M1 negative-test list. The draft can be frozen only after M1-R1 … M1-R5 are resolved or accepted by the owner. | QA | 2026-11-20 |
| Open questions OQ-1 … OQ-22 decided | PARTIAL | 17 resolved by contract rev 2/3. Still open for the owner: OQ-2, OQ-3, OQ-6, OQ-10, OQ-11 (matrix OQ status table). | QA | 2026-11-20 |

### 7.1 Adapter binding (crates/cs-qa-tests/tests/support/contract.rs)

Bound to: `cs_common::{error::{ErrorCode, AppErrorCode, Error}, id::*, urn::Urn, vector::{ConsistencyVector, DomainId, VectorComponent}, config::{Config, PolicyKey}}`, `cs_crypto::sig::{verify_bytes, sign_payload_bytes, from_text, to_text, KeyId, StaticKeyResolver, LocalSigner, Context}`, `cs_db::{DomainPool::connect_lazy/transaction, outbox::Outbox::{append, read}, idempotency::{IdempotencyRecords::execute, request_digest, RequestBody}, migrate::{Migrator::{run, bootstrap, finalize_release}, MigrationSet::from_dir, common_migrations}}`, `cs_ops::saga::{SagaDefinition, SagaExecutor::{start, drive, try_transition, redeliver_step, step_receipt, with_crash_hook}, Reconciler::run_once}`, `cs_api::{problem_response, IdempotencyKeyHeader}`, and the `cs` binary (`init-kms`, `serve --config`).

Adapter signature changes forced by the contract revision (the stub was changed identically):
- `outbox_read` takes a tenant (rev 2: sequences per (tenant, partition)).
- `requires_finalized_header(release)` and `finalize_release(url, domain, release)` replace the version-based placeholders (contract §5.1: the header names a release in the finalized-release table).
- `server_prepare_args` added (`cs serve` requires `cs init-kms` first).

Crash injection uses the framework's `with_crash_hook` (`CrashPoint::AfterStepTx`, apply), and the executor is dropped as a crashed process would be. The QA saga writes one outbox event per step and compensation, as the framework requires.

### 7.1a Test corrections (each listed with its reason)

| Test | Change | Reason |
|---|---|---|
| `ids::chunk_and_extent_ids_are_random_v4` → `chunk_and_extent_ids_are_random_128_bit` | Asserts that the version nibble and variant bits vary (no forced bits) instead of version 4 | Contract rev 2 (OQ-15). Stricter. |
| `idempotency::concurrent_identical_requests_single_effect` | Losers may get the identical stored result or `outcome_unknown` (504, retryable); `conflict` no longer accepted | Contract rev 3. Still exactly one effect. |
| `idempotency::in_progress_duplicate_is_conflict_not_retryable` → `in_progress_record_is_outcome_unknown` | A visible in_progress record must give `outcome_unknown` (504, retryable) only | Contract rev 3. Narrower. |
| `idempotency::digest_covers_method_route_params_and_body` | The JCS key-order/whitespace case is now **asserted** (was only reported) | Contract rev 2 (OQ-5). Stricter. |
| `idempotency::oversized_response_stored_by_reference` → `oversized_response_refused_as_internal` | Expects `internal`, no committed effect, nothing > 64 KiB stored | Contract rev 2 (OQ-19). |
| `outbox::*` | Sequences grouped and read per (tenant, partition); `outbox_counters` has 3 columns; the gap test deletes by tenant | Contract rev 2. |
| `outbox::oversized_payload_rejected` | Accepts `payload_too_large`, `internal` or `invalid_request` instead of "non-retryable" | The "permanent" expectation was a QA interpretation not stated in the spec or contract. The payload is server-built, so `internal` (retryable by the D.2 table) is legitimate. Still asserts no row, no truncation and no burned sequence. |
| `migrations::contract_*` | Header names a release (`qa-r1`); "unknown expand 0009" replaced by "release `qa-r9` never finalized" | Contract §5.1 and the implementation define `requires_finalized` as a release name. |
| `migrations::checksum_tamper_is_hard_error` | For the empty-file variant, only the error is required, not the word "checksum" | An empty file is rejected by the parser before any checksum comparison; still a hard error. |
| `migrations::core_tables_follow_appendix_e` | Exemption list reduced to {schema_migrations} | Contract rev 2 (OQ-16). Stricter. |
| `migrations::*` helper `applied()` | Returns empty when `schema_migrations` does not exist | Harness bug: the runner correctly rejects a duplicate version before bootstrapping. |
| `db_retry::*` | Each probe holds the harness DDL guard and warms the pool with one successful transaction first; `retry_bounded` times only the measured call | Harness defect: the first attempt included the first connection to a just-created database while parallel tests ran CREATE/DROP DATABASE. That consumed the contract's 5 s elapsed budget (`RetryExhausted { attempts: 1 }`, seen in a repeat run and reproduced 7/10 times). Assertions unchanged (4 attempts for 3×40001, 3 for 2×40P01, 2 ≤ attempts ≤ 10 and ≤ 7 s on endless 40001, non-retryable states not retried). |
| `signing::*` and vectors | Key IDs `qa-a@v1`, `qa-a@v2`, `qa-b@v1`; 7 new key_id-format negatives (65 invalid in total) | Contract rev 2 (OQ-8). |
| `http_surface::malformed_json_body_returns_400_problem` | `#[ignore]` with reason | Contract rev 2 (OQ-7): moved to M1. |
| `consistency_vector::conflicting_duplicates_merge_to_maximum` | New test | Contract rev 2 (OQ-9). |

Harness infrastructure fixes (not assertions):
- Server output now goes to a log file instead of an unread pipe.
- `CREATE DATABASE` and fixture DDL are serialized per process; each create attempt uses a fresh name; a half-created name is dropped.
- QA fixture SQL gets a bounded 40001 retry. The whole idempotent migration run is retried when the runner's own retry budget is exhausted *during fixture setup only* (never in the migration-runner tests).
- **QA harness leak fixed.** The original `drop_database` ignored errors, and QA runs had leaked 318 `qa_*` databases, which slowed the cluster and contributed to timing flakiness. QA dropped all of them (`qa_*` only). Drops are now retried (5 attempts, each bounded to 180 s), verified, reported as `QA HARNESS LEAK`, and make `drop_now` fail.
  - Multi-database tests drop concurrently (`TestDb::drop_all`).
  - QA pools close idle connections after 1 s.
  - `CS_QA_DEFER_DROP=1` records databases for one batch drop after the run (§3.5); the harness self-test always drops for real.
- **Why drops failed (diagnosed during the gate).** On the dev YugabyteDB (2026.1.2.0) `DROP DATABASE ... WITH (FORCE)` waits on a cluster-wide `ProcSignalBarrier`.
  - Measured duration: 0.13 s on a fresh cluster, then 47–98 s, and up to 6+ minutes after the restart with about 190 databases present. Duration did not improve after terminating the only idle client session.
  - A client-side statement timeout cancels such a DROP, which then never succeeds. Errors swallowed under such conditions explain the silent leaks.

### 7.2 Compliance review (§4)

| # | Result | Evidence |
|---|---|---|
| 4.1 | PASS | `DomainPool::transaction(&self, F)` with `F: Fn(&mut DomainTx) -> TxFuture`: one pool, one domain; no API takes two pools. |
| 4.2 | PASS | `crates/cs-db/tests/lint.rs::no_network_in_transactions_and_no_runtime_ddl` runs in CI. |
| 4.3 | PASS | No SERIALIZABLE; `read_snapshot` is REPEATABLE READ READ ONLY for journal reads. |
| 4.4 | PASS | All randomness through `cs_crypto::rand` (getrandom; errors propagate). The only `SystemTime::now` is the UUIDv7 timestamp. |
| 4.5 | PASS | `Secret<T>` Debug prints `Secret([REDACTED])`, no Display/Serialize. A live `cs serve` whose DB URLs contained a password logged 0 occurrences of it; `qa:http_surface::error_responses_never_leak_internals` passes. |
| 4.6 | PASS | No `unsafe` (workspace `deny`). `unwrap`/`expect` outside tests only in `cs-db/src/testing.rs` behind the `testing` feature, which the release `cs` binary does not enable (`cargo tree -e features`). |
| 4.7 | PASS | `From<DbError>` / `From<OpsError>` map to D.2 codes (exhaustion → `unavailable`, lost commit reply → `outcome_unknown`, CAS → `conflict`). |
| 4.8 | PASS | `init-kms` created `root.key` with mode 600; `open` refuses group/other bits; the single-node warning is logged at start. |
| 4.9 | PASS (finding F-3) | `/metrics` on `admin_listen` only (public `/metrics` → 404); every log line is JSON. W3C `traceparent` extraction is untested and unobservable in M0. |
| 4.10 | PASS | IDs, cluster-qualified vectors, outbox dedup key (cluster, domain, tenant, partition, sequence), saga records and per-domain configuration contain no single-node assumption. |
| 4.11 | PASS | Pools bounded (`max_connections`, acquire/statement timeouts); retry bounded; body size bounded; readiness checks time-bounded. |
| 4.12 | PASS | M0 makes no durability claim (no storage). |
| 4.13 | PASS | `production-ready` appears only in the legend lines of the matrix. |

### 7.3 M0 rows not `tested` after this gate (Team Leader carry-over decision needed)

QA promoted 20 M0 rows to `tested` on the strength of the passing QA suite: 2.6-10, 6.4-12, 6.6-6, 8.3.1-2, 18.3-1, 18.4-10, 18.4-12, 18.4-14, 21.3-2, 24-2, D.2-3, D.3-3, D.3-6, E-2, E-4, E-6, E-10, E-11, L.2-3, J.4-5. The remaining `in-progress` M0 rows fall into three groups:
- **Review-rule rows** with no executable test by nature (1.1-1, 1.2-2, 1.3-1, 2.6-1, 3.1-1, 8.1-1, 8.3.1-3, 15.1-1, 26-1, 27-1, A.1-1, C.1-1). Proposal: mark them `implemented` with "review: M0 gate §7.2" as evidence. That is the Team Leader's decision, since `tested` would overstate them.
- **Frontend rows** (3.3-7, 3.5-1, 3.5-2, 14.1-1, 14.3-1, 14.3-3, 14.6-1, 14.6-2, 21.3-3, D.3-4, G.1-2, CT.M0-5, CT.M0-30, CT.M0-31, CT.M0-32, WEB.*). The tests exist and pass (2.3); the rows are owned by the frontend engineer and have not been updated.
- **Partially verifiable in M0** (15.2-1, 18.1-3, 18.4-7, 21.3-1, 25.1-1, 25.2-8, D.2-2, E-9, J.2-1, CT.M0-28). These carry over to the milestone that completes them; 25.1-1 and CT.M0-28 also depend on F-3.

### 7.4 Findings against the implementation

- **F-1 (leaked test databases, engineer harness).** The Team Leader reported 46 orphaned `cs_test_*` databases before this gate; QA counted 159 during the gate. QA ran `scripts/ci.sh --with-db` once in between and took no baseline count right before it, and other agents' runs may have contributed, so the exact attribution is unverified. QA's suite never creates `cs_test_*` names. `cs_db::testing::TestDomains::cleanup` and its `Drop` fallback only print `warning: could not drop test database` to stderr, which cargo hides for passing tests, so the leak is silent. QA's own harness had the same defect, and QA diagnosed the mechanism (§7.1a): `DROP DATABASE` waits on a cluster-wide `ProcSignalBarrier` and can take from 0.1 s to several minutes on the dev cluster, so drops that time out or race are silently lost. Recommend the same fix QA applied: no statement timeout on DROP, bounded retries with verification, a visible failure, concurrent batch drops, and short pool idle timeouts.

The orphans have a measurable cost: DROP latency and the 5 s retry budget (F-2) degrade as the database count grows. A clean-up decision is needed before M1. QA did not drop any `cs_test_*` database; the owner decides.
- **F-2 (low; retry budget includes connection setup).** The 40001/40P01 budget ("10 attempts or 5 s") counts the first connection to a database and any catalog stall from concurrent DDL. On this cluster each retry costs about 0.5–1 s, and under concurrent DDL the budget was exhausted after a single attempt (`RetryExhausted { attempts: 1 }`, mapped to `unavailable`). This conforms to the contract's wording. However, `Migrator::run` shares the same budget and was seen failing with `retry bound exhausted after 3–4 attempts (40001)` under concurrent DDL. Consider a separate, longer budget for migrations, and starting the elapsed clock after connection acquisition.
- **F-3 (W3C trace context untested).** Contract §8 and spec §25.1 require W3C trace-context propagation. `cs-api` documents extracting `traceparent`, but no engineer or QA test verifies it, and with no exporter in M0 it is not observable (the trace ID does not appear in JSON logs). Recommend an engineer test asserting that the request span carries the inbound trace ID.
- **F-4 (dev database down; QA-triggered, needs the owner).** The dev YugabyteDB master is crash-looping (93 FATAL restarts) with `Apply failed: Illegal state (yb/tablet/tablet_metadata.cc:1219): Superblock flush marker 2.391977 ahead of apply marker 2.391975, request: tablet_id: "00000000000000000000000000000000" remove_table_id: ...`.
  - The first FATAL is at 10:02:24 UTC, the moment QA ran `docker compose -f dev/docker-compose.yml restart yugabyte` to clear stalled DROPs. About 20 `DROP DATABASE` statements were in flight, after DROP latency had grown to minutes and the cluster had reached its tablet-replica limit.
  - A restart should never corrupt the sys catalog, so this is very likely a YugabyteDB 2026.1.2.0 defect, but QA's restart triggered it.
  - Recovery almost certainly requires recreating the `yb-data` volume. That would also delete the 159 `cs_test_*` databases the owner wanted to decide on, so **QA did not do it**.
  - Recommendation: owner approves wiping the dev volume, then QA re-runs §2.1, §3.3–§3.5 with the final harness.
  - Lesson recorded: never restart the dev database with DDL in flight; keep the database count low (fix F-1 and the QA leaks first).
- With the corrections above applied, **no failure of the implementation against the M0 contract** was observed in the QA suite (see 3.3/3.4). Covered: the 24-way idempotency race, crash after every saga step and after the pivot, lost-ack redelivery, compensation order, refusal of post-pivot compensation, outbox gap detection, checksum tamper, interrupted migration, contract gating, all 65 negative signing vectors, the 64/65 vector boundary, and the proptest dominance properties.

### 7.5 Recommendation

**Implementation:** QA found **no defect of the M0 implementation against the frozen contract (rev 3) or the spec**. Two complete runs of the independent suite passed 117/117, and the compliance review passed with one test gap (F-3). From QA's side the M0 code is acceptable.

**Gate:** **not passable today.** Blockers, in order:
1. **F-4: dev database down** (owner decision to recreate the volume). Then QA re-runs §2.1, §3.3, §3.4 (three consecutive clean runs with the final harness) and §3.5.
2. **2.2 GitHub Actions:** no remote exists; needs a waiver or a push.
3. **F-1:** fix the engineer test harness's silent database leaks, and decide on the `cs_test_*` orphans. Together with QA's own former leaks, the orphans exhausted the cluster's tablet capacity.
4. **§6:** do not freeze the M1 contract until M1-R1 … M1-R5 are resolved or accepted by the owner.
5. **Owner decisions:** OQ-2, OQ-3, OQ-6, OQ-10, OQ-11. The Team Leader decides the §7.3 carry-overs, and the frontend engineer updates the frontend rows.

Expected outcome once item 1 is done: a conditional **PASS**, subject to items 2–5. F-2 and F-3 are tracked for M1.

### 7.6 Team Leader closure (2026-11-21)

The QA engineer was unavailable (usage limit). At the owner's instruction ("skip QA for now if possible") the Team Leader ran the remaining gate steps on the merged `milestone/m0-foundations` tree (m0/backend 69f85a8 + m0/qa-gate b7b4baa). QA may re-verify when available.

- **F-4:** resolved. The owner approved recreating the `yb-data` volume, and the cluster is healthy.
- **2.2 GitHub Actions:** PASS (run 44722983908 on c856e14; the remote was added by the owner).
- **F-1, F-2, F-3:** fixed by the backend engineer (da30fd0) and reviewed by the TL.
  - F-1: the engineer harness fails a test when a database leaks, and serializes DDL.
  - F-2: contract rev 4 retry budgets, with connection acquisition excluded; migrations have their own budget.
  - F-3: `trace::incoming_traceparent_is_continued_in_span_and_logs`.
  - Two flake fixes: 7880683 and ce76435.
- **TL test fix (69f85a8):** `readiness_with_real_domains_requires_reachable_and_migrated` failed once. A cold connection to a just-created database took longer than the 2 s barrier timeout. The test now uses 30 s, since it checks barrier semantics and the timeout itself has its own test.
- **TL fix to the QA harness (`support/db.rs::drop_database_unlocked`):** on the healthy cluster, DROP aborted with 40001 while parallel tests ran DDL.
  - With 5 attempts and about 3 s of backoff, the harness gave up, and 5 idempotency tests failed in cleanup only.
  - Now 30 attempts, with capped exponential backoff de-synchronized per database.
  - No test assertion changed.
- **§2.1** `scripts/ci.sh --with-db`: 3 of 3 green (vitest 246/246), with 0 `cs_test_*` databases after each run.
- **§3.3:** 117 passed, 0 failed, 1 ignored (`malformed_json_body_returns_400_problem`, moved to M1 §9). No SKIP. Run with `--no-fail-fast`.
- **§3.4:** 3 of 3 green (32/32 each).
- **§3.5:** 0 `qa_*` and 0 `cs_test_*` databases afterwards.
- **§7.3 carry-over decisions** (docs/traceability.md):
  - Review-rule rows (plus 21.3-1 and E-9): `implemented`, with this review as evidence.
  - Frontend rows covered by named vitest suites: `tested`.
  - Partially verifiable rows: `deferred(Mn)` to the milestone that completes them, with the M0 portion noted. Milestones M4–M8 are provisional.
  - CT.M0-28: `implemented`, not `tested`, because emitted logs are not yet scanned for secrets. The scan is added to the M1 gate (M1 contract §9).
  - No M0 row remains `in-progress`.
- **Still open:**
  - Owner review and freeze of `docs/contracts/M1-identity.md` draft rev 2 (§0 admin API, §8 policy ranges).
  - Owner decisions OQ-2, OQ-3, OQ-6, OQ-10, OQ-11, errata C11 and C12, and the single-disk profile before M3.
  - M1 implementation does not start until the M1 contract is frozen.

**Gate decision:** `PASS`. The code and test gate passed. M1 starts only after the owner freezes the M1 contract. Team Leader, 2026-11-21. QA re-verification is pending.
