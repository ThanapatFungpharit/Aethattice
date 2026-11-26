# Team Leader handoff (state at the end of M1, 2026-11-26)

Read this first in a new session, then `CLAUDE.md`, `docs/IMPLEMENTATION_PLAN.md` §5 and `docs/SPEC_ERRATA.md`.

## Where things stand

| Milestone | State |
|---|---|
| M0 Foundations | Gate passed. Merged to `main`. `docs/qa/M0-gate.md` |
| M1 Identity | Gate passed 2026-11-26. Merged to `main` (5c34fea). `docs/qa/M1-gate.md` §7.5 |
| M2 Resources and authorization | Approved, **not started**. The next step is the M2 contract |
| M3 Object storage (single node) | Approved, not started |
| M4–M9 | Planned, **not approved**. The owner must approve the scope first |

- **Spec:** v2.4.2 (errata C1–C13). C13 is the table of policy safe ranges. Add to it whenever a new policy without a spec range appears, and get owner approval for each addition.
- **Contracts:**
  - `docs/contracts/M0-foundations.md` is at rev 6.
  - `docs/contracts/M1-identity.md` is at rev 16.
  - Every ruling made during the milestone is in the contract's changelog and inline as "(rev N)".
- **Traceability:** `docs/traceability.md`. No M1 row is open. Rows outside the M1 scope were moved to the milestone that delivers them (commit 326e08b).

## How we work (owner's rules and preferences)

- **Roles:** the Team Leader (main session) writes contracts, reviews, merges and makes rulings. Engineers and QA are background agents, each on its own branch in a worktree:
  - backend: `mN/backend-K`;
  - frontend: `mN/frontend-K`;
  - QA: `mN/qa`;
  - milestone branch: `milestone/mN-<name>`.
- **Contract first:**
  1. Write `docs/contracts/MN-<name>.md`.
  2. QA reviews it.
  3. The owner decides the open points.
  4. Freeze it.
  5. Then implement.

  During implementation, agents ask the Team Leader instead of guessing. Each ruling becomes a contract revision with a changelog entry.
- **Gates:**
  - Merge to `main` only after the QA gate passes, the Team Leader has reviewed, and CI is green (local `ci.sh --with-db` and GitHub Actions).
  - Don't start the next milestone until the previous gate has passed and the owner says go.
- **The owner likes forms:** ask decisions with the AskUserQuestion tool, recommended option first.
- **Token economy:**
  - Give agents tight, scoped briefs with a short report limit (12–20 lines).
  - Split a milestone into slices.
  - Resume agents with SendMessage after usage limits.
  - Ask agents to commit work in progress early.
- **Security first:**
  - Use vetted crates only, no home-made crypto or protocol code.
  - Never store bearer secrets in plaintext.
  - Keep enumeration resistance.
  - Fail closed where the contract says so.
- **Durability honesty:** the dev host has one NVMe, so there is one failure domain. Never claim more. Nothing is `production-ready`.
- **Commits:** end with the trailer lines from `CLAUDE.md` / the session.

## Dev environment quirks (important)

- **Dev stack:** `docker compose -f dev/docker-compose.yml up -d --wait` starts YugabyteDB on 5433 and Valkey on 6379. Host reboots stop the containers, so check with `docker ps` first.
- **Never `docker compose restart` YugabyteDB with DDL in flight.** It corrupted the master catalog once (M0).
- **YugabyteDB slows down under CREATE/DROP DATABASE churn** (the sys catalog bloats, and DDL goes from about 2 s to over 300 s).
  - Both test harnesses now lease pooled databases (`cs_test_pool_*`, `qa_pool_*`).
  - `scripts/ci.sh --with-db` compacts the sys catalog afterwards.
  - Manual fix: `docker exec cs-dev-yugabyte-1 bin/yb-admin --master_addresses $(docker exec cs-dev-yugabyte-1 hostname):7100 --timeout_ms 600000 compact_sys_catalog`.
  - Probe: create and drop one database should take a few seconds.
- **Memory-constrained host:** use `CARGO_BUILD_JOBS=2` and `--test-threads=2`.
- **wasm-bindgen-cli 0.2.130** is needed locally for the opaque-wasm freshness check, which is otherwise skipped locally. GitHub Actions always runs it.
- **GitHub Actions** frees runner disk (unused SDKs) and uses line-tables-only debug info. Without that, the runner ran out of disk and YugabyteDB refused writes.

## Open follow-ups carried out of M1 (not blockers)

- **e2e in a fresh worktree:** `scripts/e2e.sh` creates a new KMS root key, then tries to reset the shared `cs_e2e_identity` database. That fails while an idle session is connected. The workaround is to copy `target/e2e/kms/root.key*` from the main checkout. The proper fix is for the reset to use `DROP DATABASE … WITH (FORCE)`, or to reset the schema instead.

- **M4:**
  - Durable recovery-email delivery. The outbox would carry only `request_id`, and the sender would mint the token at send time.
  - Device notifications.
  - Audit.
- **Contract migrations, once a release is finalized:**
  - drop `auth_txns_expiry_idx` (replaced by the bucketed index);
  - drop the unused `recovery_codes` table;
  - widen the `auth_txns` CHECK constraints if the ceremony state should merge back into it.
- **Tests:** add dedicated replay tests for the identity write routes that share the code path but have none (see M1-gate.md §7.5). The QA engineer may also re-review the M1 fixes.
- **M8:** measure the cost of the per-request `dpop_jti` write (rev 14).
- **Browser-level e2e:** real tabs, real Web Locks, BroadcastChannel, IndexedDB and cookies, and a hardware authenticator. M1's e2e runs in Node.

## Next step: M2 contract

1. Read the plan's M2 scope (§5): spaces, resource registry, hierarchy, lifecycle (App. F.1), journal shards (§19.1), relationship tuples and ACL versions, authz projection, ADS with signed consistency contexts, a revocation feed with a signed 500 ms heartbeat and S-staleness fail-closed, check/lookup, sharing (roles, link shares), trash/restore, HMAC cursors and live listings (§19.3), resource events, App. D existence hiding. Frontend: shell navigation, share dialog, pickers, listings.
2. Also pick up the rows moved to M2 by the M1 gate review:
   - guests (5.1-1);
   - directory (5.7-1);
   - OpenAPI (3.4-1);
   - the `av` claim (5.5-2);
   - closure-generation invalidation (6.4-11);
   - the HTTP admin API under the relationship model (M1 §0).
3. Draft `docs/contracts/M2-resources-authz.md` with no single-node assumptions. Have QA review it, take open points to the owner as a form, freeze it, then start the slice agents on `milestone/m2-resources-authz`.
4. The M2 gate (plan §5) covers:
   - a cross-tenant suite (L.5 subset);
   - existence hiding;
   - measurement of the revocation bound;
   - listing guarantees;
   - stale-projection fail-closed.
