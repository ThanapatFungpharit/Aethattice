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
| Signing envelope (independent vectors, 58 negative cases) | `signing` | — |
| Consistency vectors (64/65, proptest dominance) | `consistency_vector` | — |
| IDs and URNs | `ids` | — |

`malformed_json_body_returns_400_problem` fails by design until OQ-7 is resolved: no M0 route accepts JSON. The Team Leader either names a route (and sets `JSON_POST_ROUTE` in the adapter) or records a waiver in §7 that moves the test to M1. Silently ignoring this test is not allowed.

### 3.4 Repeatability (flakiness of concurrency and crash tests)
```sh
for i in 1 2 3; do cargo test -p cs-qa-tests --features m0-contract --test idempotency --test outbox --test sagas -- --test-threads=4 || break; done
```
Pass: three consecutive green runs.

### 3.5 No leftover databases
```sh
docker compose -f dev/docker-compose.yml exec -T yugabyte bin/ysqlsh -h yugabyte -U yugabyte -tAc \
  "select datname from pg_database where datname like 'qa\_%'"
```
Pass: no output.

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

## 7. Results

Fill in one row per check. Status: `PASS`, `FAIL`, or `WAIVED` (a waiver needs the Team Leader's name, the reason and the target milestone).

| Item | Status | Evidence (log path, test names, SHA, notes) | Recorded by | Date |
|---|---|---|---|---|
| 1 Preconditions (SHA, toolchain, DB image) | | | | |
| 2.1 `scripts/ci.sh --with-db` | | | | |
| 2.2 GitHub Actions | | | | |
| 2.3 Frontend (typecheck/test/build + listed coverage + ErrorCode parity) | | | | |
| 3.1 Adapter bound; only contract.rs changed | | | | |
| 3.2 QA self-check | | | | |
| 3.3 QA suite `--features m0-contract` | | | | |
| 3.3a OQ-7 decision for `malformed_json_body_returns_400_problem` | | | | |
| 3.4 Repeatability ×3 | | | | |
| 3.5 No leftover databases | | | | |
| 3.6 Vectors deterministic; cs-crypto vectors present | | | | |
| 4.1 – 4.13 Compliance review | | | | |
| 5 Matrix completeness | | | | |
| 6 M1 contracts reviewed | | | | |
| Open questions OQ-1 … OQ-22 decided | | | | |

**Gate decision:** `PASS` / `FAIL` — Team Leader: ______ Date: ______

Failed checks and follow-ups (issue, owner, milestone):

-
