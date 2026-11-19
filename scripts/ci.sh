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
fi
echo "== web"; (cd web && npm ci --no-audit --no-fund >/dev/null && npm run typecheck && npm test --if-present -- --passWithNoTests && npm run build)
echo "== traceability lint"; scripts/trace-lint.sh
echo "CI OK"
