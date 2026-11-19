#!/usr/bin/env bash
# Fails if any row in docs/traceability.md lacks a valid status. Statuses: implemented | tested | production-ready | in-progress | deferred(Mn) | n/a(<reason>)
set -euo pipefail
f="$(dirname "$0")/../docs/traceability.md"
bad=$(grep -E '^\| *[A-Z0-9.-]+-[0-9]+ *\|' "$f" | grep -vE '\| *(implemented|tested|production-ready|in-progress|deferred\(M[0-9]+\)|n/a\([^)]+\)) *\|' || true)
if [[ -n "$bad" ]]; then echo "traceability rows without valid status:"; echo "$bad"; exit 1; fi
echo "traceability: $(grep -cE '^\| *[A-Z0-9.-]+-[0-9]+ *\|' "$f") requirements tracked"
