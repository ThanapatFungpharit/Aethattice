#!/usr/bin/env bash
# M1 end-to-end suite: the real web SDK (@cs/sdk + opaque-wasm) against a real `cs serve --dev`.
# Usage: scripts/e2e.sh            (called by scripts/ci.sh --with-db)
#
# Needs the dev YugabyteDB (localhost:5433) and Valkey (localhost:6379) of dev/docker-compose.yml; it never
# starts or restarts them. The identity domain is one dedicated database, `cs_e2e_identity`, created once and
# reused: every run migrates it (a no-op when current) and works in a new tenant, so runs are isolated without
# CREATE/DROP DATABASE per run. It is dropped and recreated only when the KMS root key under target/e2e/ is
# new (its signing keys would be unreadable otherwise), or with CS_E2E_RESET=1.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD

YB="${CS_E2E_YB_CONTAINER:-${CS_DEV_YB_CONTAINER:-cs-dev-yugabyte-1}}"
DB_HOST_URL="${CS_E2E_DB_URL:-postgres://yugabyte@localhost:5433}"
VALKEY_URL="${CS_E2E_VALKEY_URL:-redis://localhost:6379}"
DB=cs_e2e_identity
DOMAIN=cs-e2e.test

for hp in localhost:5433 localhost:6379; do
  if ! (exec 3<>"/dev/tcp/${hp%:*}/${hp#*:}") 2>/dev/null; then
    echo "e2e: $hp is not reachable; start dev/docker-compose.yml (this script never starts containers)" >&2
    exit 1
  fi
done
if ! docker inspect -f '{{.State.Running}}' "$YB" 2>/dev/null | grep -q true; then
  echo "e2e: YugabyteDB container '$YB' is not running (set CS_E2E_YB_CONTAINER)" >&2
  exit 1
fi
ysql() { docker exec "$YB" bash -c "bin/ysqlsh -h \$(hostname) -U yugabyte -v ON_ERROR_STOP=1 -qtAc \"$1\""; }

echo "== e2e: build cs"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" cargo build -q -p cs --bin cs
CS="$root/target/debug/cs"

work="$root/target/e2e"
run="$work/run"
rm -rf "$run"
mkdir -p "$work/kms" "$run"
free_port() { node -e 'const s=require("net").createServer();s.listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close()})'; }
PORT=$(free_port)
ADMIN_PORT=$(free_port)
cfg="$run/cs.toml"
cat >"$cfg" <<EOF
[node]
id = "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
roles = ["api"]

[domains.identity]
url = "$DB_HOST_URL/$DB"
pool = { max_connections = 8 }

[kms]
backend = "local_software"
root_key_path = "$work/kms/root.key"

[valkey]
url = "$VALKEY_URL"

[notifier]
kind = "dev_log"

[api]
listen = "127.0.0.1:$PORT"
admin_listen = "127.0.0.1:$ADMIN_PORT"
deployment_domain = "$DOMAIN"

[telemetry]
log_format = "json"

[policy]
# Every request comes from 127.0.0.1 and one account runs every flow within a minute, so the per-source and
# per-account limits are raised (within their C13 ranges). First-party DPoP is required so the suite proves the
# bound path.
rate_limit_source_per_min = 1000
rate_limit_account_per_min = 100
dpop_first_party_required = 1
EOF

reset="${CS_E2E_RESET:-0}"
if [[ ! -f "$work/kms/root.key" ]]; then
  "$CS" init-kms --config "$cfg" >/dev/null
  reset=1
fi
exists=$(ysql "SELECT 1 FROM pg_database WHERE datname = '$DB'")
if [[ "$reset" == "1" && "$exists" == "1" ]]; then
  echo "== e2e: reset database $DB (new KMS root key or CS_E2E_RESET=1)"
  ysql "DROP DATABASE $DB"
  exists=""
fi
[[ "$exists" == "1" ]] || ysql "CREATE DATABASE $DB"

echo "== e2e: migrate, tenant, setup link"
"$CS" check-config --config "$cfg" --dev >/dev/null
"$CS" migrate --config "$cfg" >/dev/null
suffix=$(node -e 'console.log(require("crypto").randomBytes(4).toString("hex"))')
TENANT=$("$CS" admin --config "$cfg" tenant create --name "e2e-$suffix" | sed -n 's/^tenant_id=//p')
LOGIN="e2e-$suffix@example.test"
USER=$("$CS" admin --config "$cfg" user create --tenant "$TENANT" --login "$LOGIN" | sed -n 's/^user_id=//p')
LINK=$("$CS" admin --config "$cfg" setup-link --tenant "$TENANT" --user "$USER" | sed -n 's/^[a-z_]*token=//p')
[[ -n "$TENANT" && -n "$USER" && -n "$LINK" ]] || { echo "e2e: cs admin output not understood" >&2; exit 1; }

echo "== e2e: cs serve --dev on 127.0.0.1:$PORT"
"$CS" serve --config "$cfg" --dev >"$run/serve.log" 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null; wait $pid 2>/dev/null || true' EXIT
for _ in $(seq 1 120); do
  curl -fsS "http://127.0.0.1:$PORT/readyz" >/dev/null 2>&1 && break
  kill -0 $pid 2>/dev/null || { echo "e2e: cs serve exited"; tail -40 "$run/serve.log"; exit 1; }
  sleep 0.5
done
curl -fsS "http://127.0.0.1:$PORT/readyz" >/dev/null || { echo "e2e: cs serve not ready"; tail -40 "$run/serve.log"; exit 1; }

echo "== e2e: vitest (web/e2e)"
status=0
(cd web && CS_E2E_UPSTREAM="http://127.0.0.1:$PORT" CS_E2E_DOMAIN="$DOMAIN" CS_E2E_TENANT="$TENANT" \
  CS_E2E_LOGIN="$LOGIN" CS_E2E_SETUP_LINK="$LINK" npm run --silent test:e2e) || status=$?
if [[ $status -ne 0 ]]; then
  echo "e2e: FAILED; server log tail ($run/serve.log):"
  grep -v "DEV-ONLY SECRET" "$run/serve.log" | tail -40
fi
exit $status
