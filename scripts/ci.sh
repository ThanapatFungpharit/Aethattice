#!/usr/bin/env bash
# Local CI, mirrored by .github/workflows/ci.yml. Usage: scripts/ci.sh [--with-db]
set -euo pipefail
cd "$(dirname "$0")/.."
echo "== rust: fmt"; cargo fmt --all --check
echo "== rust: clippy"; cargo clippy --workspace --all-targets -- -D warnings
echo "== rust: unit tests"; cargo test --workspace
if [[ "${1:-}" == "--with-db" ]]; then
  echo "== rust: db integration tests (requires dev/docker-compose.yml up)"
  # DB tests read CS_TEST_DATABASE_URL; with CS_REQUIRE_DB=1 a missing/unreachable DB is a failure, not a skip.
  CS_REQUIRE_DB=1 CS_TEST_DATABASE_URL="${CS_TEST_DATABASE_URL:-postgres://yugabyte@localhost:5433/yugabyte}" \
    cargo test --workspace -- --test-threads=4
  # Test databases are created and dropped per test; on YugabyteDB that churn bloats the master's
  # sys catalog and slows every heartbeat and DDL (dev-host finding, 2026-11-25). Compact it after
  # the run. Best effort: skipped when the dev container is not running (e.g. GitHub Actions).
  yb="${CS_DEV_YB_CONTAINER:-cs-dev-yugabyte-1}"
  if docker inspect -f '{{.State.Running}}' "$yb" 2>/dev/null | grep -q true; then
    echo "== db: compact YugabyteDB sys catalog ($yb)"
    docker exec "$yb" bin/yb-admin --master_addresses "$(docker exec "$yb" hostname):7100" \
      --timeout_ms 600000 compact_sys_catalog >/dev/null 2>&1 || echo "warning: sys catalog compaction failed (non-fatal)"
  fi
fi
echo "== opaque-wasm pkg freshness"
# The committed wasm-bindgen output must match the crate (M1 rev 5 §2.1). Needs wasm-bindgen-cli 0.2.130.
if WB="${WASM_BINDGEN:-wasm-bindgen}"; [[ "$("$WB" --version 2>/dev/null)" == "wasm-bindgen 0.2.130" ]]; then
  scripts/build-opaque-wasm.sh --check
else
  echo "SKIPPED: wasm-bindgen 0.2.130 not installed (set WASM_BINDGEN); pkg/ freshness not verified"
fi
echo "== web"; (cd web && npm ci --no-audit --no-fund >/dev/null && npm run typecheck && npm run lint && npm test --if-present -- --passWithNoTests && npm run build)
echo "== traceability lint"; scripts/trace-lint.sh
echo "CI OK"
