# M1 QA Gate — Identity

Owner: QA Engineer. Decision: Team Leader. Sources: spec §5, §15.4, §18.5, App. A, D, L.5; docs/SPEC_ERRATA.md (C1–C13); docs/contracts/M1-identity.md (FROZEN rev 14, in particular §9 gate additions); docs/qa/M0-gate.md §6.1 (M1 negative-test list).

The gate passes only when every item marked **[blocking]** passes on the merged branch `milestone/m1-identity`. Items are run in order, on a clean checkout, and recorded in §7.

---

## 1. Preconditions

```sh
git checkout milestone/m1-identity && git status --short        # empty
docker compose -f dev/docker-compose.yml up -d                   # YugabyteDB :5433, Valkey :6379
export CS_TEST_DATABASE_URL=postgres://yugabyte@localhost:5433/yugabyte
export CS_TEST_VALKEY_URL=redis://localhost:6379 CS_REQUIRE_DB=1
export CARGO_BUILD_JOBS=2                                         # memory-constrained dev host
cargo build -p cs                                                 # binary tests spawn target/debug/cs
```

The dev host has one NVMe, which is one failure domain. No durability claim is made or tested.

## 2. CI [blocking]

`scripts/ci.sh --with-db` must print `CI OK`. It covers fmt, clippy, the workspace tests (engineer suites included), web, the opaque-wasm freshness check and trace-lint.

## 3. Independent QA suite [blocking]

### 3.1 QA database harness (no CREATE/DROP DATABASE per test)

`crates/cs-qa-tests/tests/support/db.rs` now uses the lease-and-reset design of `cs_db::testing`, with its own pool:

- **Pool.** Up to 24 databases named `qa_pool_<n>`. Each is created once, at the lowest free index, so only peak concurrency is ever created. The harness never drops them.
- **Lease.** Cross-process advisory lock, class "qatp".
- **Reset.** `DROP SCHEMA … CASCADE` of every non-system schema, then the database is verified empty. Connections are re-enabled first.
- **Failure handling.** A failed reset is loud (`QA HARNESS LEAK`, `LEAKED` counter, test failure). A crashed holder's database is reset at the next lease.
- **Readiness.** The readiness "database disappears" stimulus is now `ALTER DATABASE … ALLOW_CONNECTIONS false` plus terminating sessions. It no longer drops the database.
- **Self-test.** `qa:harness::test_db_is_leased_isolated_and_reset` proves isolation, the explicit reset, the panic-path reset (including a disabled database) and that nothing is dropped.
- **Churn log.** `CS_QA_POOL_LOG=<file>` records one line per create, lease, reset and release.

### 3.2 Self-check

```sh
cargo clippy -p cs-qa-tests --features m1-contract --tests -- -D warnings
```

### 3.3 Run

```sh
CS_QA_POOL_LOG=$PWD/target/qa-m1-logs/pool.log \
  cargo test -p cs-qa-tests --features m1-contract --no-fail-fast -- --test-threads=2
```

`m1-contract` implies `m0-contract`. It runs every M0 binary, the M1 suite (`tests/m1/`, one binary) and `http_surface::malformed_json_body_returns_400_problem`. That test is un-ignored under `m1-contract` and runs against `opaque/login/start` (M1-R14).

### 3.4 M1 suite coverage (tests/m1)

The M1 suite drives `cs_identity::http::routes` behind the M0 middleware, in process, on a leased database. A deployment can have several nodes, meaning several `AuthService` instances sharing one DB, one KMS and Valkey. The binary tests use the real `cs serve` and `cs admin`.

| Area (M0-gate §6.1 / brief) | Tests |
|---|---|
| JWS: alg none, HS256 with the public key, unknown/missing kid, jku/jwk/x5u/x5c/crit, typ, tampering, iss/aud/exp (0 s leeway)/iat (+60 s), malformed Authorization | `tokens::access_token_shape_and_jwks`, `tokens::jws_alg_confusion_kid_and_header_injection_rejected`, `tokens::jws_claim_checks_iss_aud_exp_iat`, `tokens::missing_or_malformed_authorization_is_401` |
| Refresh: rotation; reuse revokes the session (generation, family, outbox); [R1] lost-response window and its limits (other key, no key, after 30 s); concurrent race; idle/absolute expiry; cookie attributes; no-store; logout [R10]; rt1 tenant-segment swap and malformed tokens | `refresh::*` (9 tests) |
| Revoked session's access token on every authenticated route (F-3) | `refresh::revoked_session_access_token_refused_on_every_route` |
| DPoP: binding, Bearer with bound token, missing proof, htm/htu (path, host, scheme, slash; query ignored), iat ±60 s, jti, ath missing/wrong, jkt mismatch, typ/alg (none, RS256, ES384), private jwk, foreign jwk, tampered signature, two headers; replay on one node, across two Valkey nodes, across two table nodes, across a Valkey-down node; both stores down → 503; bound refresh without proof or with another key revokes the session; login/finish proof checks and replay | `dpop::*` (5 tests) |
| Enumeration: unknown tenant, unknown account, disabled and invited user vs. wrong password (status, body members, credential_response length, deterministic valid KSF params, identical 401); login/start timing medians; recovery start (code/email/device approval); 429 shape and threshold identical for unknown accounts; source /32 and IPv6 /64; Valkey down → limit/N; register without a valid grant; email 202 independent of delivery time (rev 13) | `enumeration::*` (7 tests) |
| Cross-tenant (L.5): sessions, refresh tokens, login_txn and setup links (segment swaps), txn TTL/source binding/tamper, recovery codes and grants, passkeys (list, delete, passwordless sign-in), recovery requests (list, approve, cancel), groups | `isolation::*` (7 tests) |
| Step-up at 5 min + 1 s on every sensitive route (and its absence at 4 min 59 s); reauth restores step-up without a new session; enrolment-only scope on every route; auth_txn on the wrong endpoint; auth_txn single use | `scopes::*` (3 tests) |
| Recovery: [R5] atomicity with a concurrent snapshot observer; expired grant changes nothing; email waiting period not shortenable, cancellation, MFA factor; device approval with step-up; policy waiting period; grant rotation on polling (rev 12); password change revokes the other sessions | `recovery::*` (5 tests) |
| §9 log scan | Every in-process test ends with `Env::finish`, which scans the captured TRACE log (all crates, JSON) for every secret registered from requests and responses. Patterns are also scanned: rt1, compact JWS, recovery code, private key. `logscan::cs_binary_logs_contain_no_secrets` runs full flows against `cs serve` with `log_level = "trace"` and Valkey, then scans the server log and `cs admin` stderr. `logscan::scanner_detects_each_secret_shape` checks that the scanner cannot pass vacuously. |

## 4. Repeatability [blocking]

The full suite runs three times in a row. Afterwards no `qa_pool_*` database is non-empty or leased, and `pg_database` gains no database apart from the pool.

## 5. Traceability [blocking]

Rows verified by this gate list their `qa:` tests (`docs/traceability.md`). A row whose QA test fails is not `tested`.

---

## 7. Results

Recorded by QA on `m1/qa` (base `milestone/m1-identity` c88e83c, merged with 86e5f60 rev 13) on 2026-11-26. Raw logs are in `target/qa-m1-logs/` (not committed).

| Item | Status | Evidence |
|---|---|---|
| 1 Preconditions | PASS | YugabyteDB and Valkey reachable. Containers were not restarted. |
| 2 CI | NOT RUN | `scripts/ci.sh --with-db` was not run by QA. The host was memory-constrained (load 16–18, OOM reaping of background jobs), and the backend fixes are pending. The TL reruns it on the fixed branch. |
| 3.1 Harness | PASS | See §7.1 for counts. `harness::test_db_is_leased_isolated_and_reset` passes. |
| 3.2 Self-check | PASS | clippy `-D warnings` clean with `m1-contract`. |
| 3.3 QA suite | FAIL (3 product defects) | Full run 2026-11-26 (m1-contract, 2 threads): config 9, consistency_vector 16, db_retry 4, error_model 14, harness 3, http_surface 7, idempotency 11, ids 5: all passed. m1: 38 passed, 4 failed (F-1, F-2, F-3, plus a step-up timing flake that QA fixed afterwards: the inside-window age is now 240 s). migrations, outbox, readiness, sagas and signing did not complete: cargo fail-fast stopped after m1, and the rerun was cut off when the host/cluster became unavailable. The TL reruns them. |
| 3.3a malformed JSON (M1-R14) | PASS | `http_surface` 7 passed, 0 ignored. |
| 3.4 §9 log scan | PASS | No secret found in any in-process test log or in the `cs serve` TRACE log (280 lines) or `cs admin` stderr. |
| 4 Repeatability ×3 | NOT RUN | Blocked until the F-1 … F-3 fixes land. The suite is ready to rerun. |
| 5 Traceability | PASS (rows updated) | See §7.3. |

### 7.1 QA harness catalog churn (one full QA run)

| | CREATE DATABASE | DROP DATABASE |
|---|---|---|
| Before (old harness: one create and one drop per `TestDb`; counted as the leases of the same run) | 57 | 57 |
| After, first run on a fresh cluster (pool created) | 9 (first M1 run; the pool has 12 databases after all runs) | 0 |
| After, steady state (pool exists) | 0 | 0 |

Measured on the binaries that completed in the full run (config through m1): 57 leases, 1 CREATE (a pool database not needed before), 0 DROP. The old harness would have issued 57 CREATE and 57 DROP for the same binaries. The M0 binaries that did not complete (migrations, readiness, sagas, outbox) add about 40 more leases, which means about 40 more CREATE+DROP pairs under the old harness. **Harness defect found and fixed** during the cut-off rerun: a failed `pg_database` inspection on the degraded cluster was read as "database missing". That produced 127 failed CREATE attempts for existing pool databases; none of them succeeded, and nothing was dropped. An inspection error now retries the inspection, never a CREATE. Method: `CS_QA_POOL_LOG` counts `create`, `lease`, `reset` and `release`. Each lease replaces one CREATE and one DROP of the old harness. QA itself created and dropped one probe database (`qa_probe_allowconn`) to confirm that `ALLOW_CONNECTIONS` works on YugabyteDB 2026.1.

### 7.2 Findings against the implementation (reported to the TL; all accepted, fixes in progress)

| ID | Severity | Finding | Test (reproduction) | Ruling |
|---|---|---|---|---|
| F-1 | High | **DPoP replay across the Valkey/table boundary ([R6]).** Node A has Valkey; node E has Valkey configured but unreachable, so it falls back to `dpop_jti`. A proof used on A is accepted again on E, and the reverse also works. The jti is recorded in only one store. | `dpop::proof_replay_rejected_across_nodes` | Rev 14: `dpop_jti` becomes the only authoritative replay record; Valkey leaves the replay path. **Open blocker.** |
| F-2 | High | **Email recovery start waits for delivery (rev 13, §5.2).** With a 3 s notifier, a known account answers in 3023–3081 ms and an unknown one in 44–51 ms. That is a timing oracle for account existence, and the response depends on SMTP. | `enumeration::recovery_email_202_independent_of_delivery_time` | Fixed by the rev 13 bounded queue. **Open blocker.** |
| F-3 | Medium | **Access token of a revoked session still accepted.** After logout (or reuse, or [R5] completion), the unexpired token gets 200 on `GET /me/sessions`, `/me/passkeys`, `/me/recovery-codes` and `/me/recovery-requests`. Only `GET /me` checks the session at `sgen`. | `refresh::revoked_session_access_token_refused_on_every_route` (every authenticated route of `scopes::AUTHED_ROUTES`) | Rev 14: one shared extractor checks session-at-sgen on every authenticated route. **Open blocker.** |
| F-4 | Gate gap | **[R7] / rev 12–13 notifier wiring.** `cs serve` has no `--dev` profile and no `[notifier]` (SMTP relay or `dev_log`); `check-config` does not enforce `dev_log` ⇒ `--dev`. | Not testable black-box until wired | In progress in the same backend slice. **Open blocker.** |

Route coverage for F-3 and the enrolment scope: axum has no public route enumeration, so `scopes::AUTHED_ROUTES` (19 token-authenticated routes) was reconciled by review against `cs_identity::http::routes`. The router has 27 routes. The 8 that take no token are login/start, login/finish, token/refresh, jwks, webauthn/login/start and finish, mfa/recovery-code, and recovery/start and status. Re-check when routes are added.

Observations (no contract violation):

- Starting recovery with a valid code before completion issues a new grant on each call. The code is consumed only at [R5] completion, as the contract says. Each grant still expires after 15 min and is single use.
- login/start medians: known 81.5 ms, unknown account 81.1 ms, unknown tenant 82.6 ms (24 interleaved samples).

### 7.3 Traceability

Updated rows: 5.2-4, 5.2-5, 5.5-5, 5.5-6, 5.5-8, 5.6-4, 15.4-2, 18.5-2, CT.M1-3, CT.M1-10, CT.M1-11, CT.M1-12, CT.M1-13, CT.M1-17, CT.M1-18, CT.M1-21. The rows behind F-1 (CT.M1-18), F-2 (5.2-4) and F-3 (5.5-5, CT.M1-13) are set to `implemented` until their QA tests pass.

### 7.4 Recommendation

**Do not pass the M1 gate yet.** F-1, F-2, F-3 and F-4 are open blockers. All other M1 QA tests pass, including the complete M0-gate §6.1 negative list, [R5] atomicity, cross-tenant isolation, step-up and enrolment scope, and the §9 log scan. Once the backend slice lands, rerun §3.3 three times (§4) and then §2. The suite needs no change for the rev 14 rulings: no test relies on Valkey-first replay semantics.
