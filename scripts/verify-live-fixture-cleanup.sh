#!/bin/bash
set -euo pipefail

# verify-live-fixture-cleanup.sh - Static guard for live verifiers that create
# synthetic hosts. They must register cleanup traps and remove fixture hosts so
# interrupted or failed verifier runs do not pollute agent-fleet health.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

require_host_cleanup() {
    local script="$1"
    local label="${script#$ROOT/}"
    if ! grep -Eq 'trap[[:space:]]+cleanup[[:space:]]+EXIT' "$script"; then
        echo "ERROR: $label creates fixture hosts but does not install 'trap cleanup EXIT'" >&2
        exit 1
    fi
    if ! grep -Eq 'DELETE[^\\n]+/api/hosts/|DELETE[[:space:]]+FROM[[:space:]]+hosts|DELETE[[:space:]]+FROM[[:space:]][a-z_]+[[:space:]][^;]*(host_id|HOST_ID|RUN_ID)' "$script"; then
        echo "ERROR: $label creates fixture hosts but does not visibly remove them in cleanup" >&2
        exit 1
    fi
}

checked=0
while IFS= read -r script; do
    if grep -Eq '(^|[^A-Za-z0-9_])([A-Z_]*HOST_ID|HOST_ID_[A-Z_]+)="host-\$\{' "$script"; then
        require_host_cleanup "$script"
        checked=$((checked + 1))
    fi
done < <(
    find "$ROOT/scripts" -maxdepth 1 -type f \( -name 'verify-live-*.sh' -o -name 'verify-agent-binary-workflow.sh' -o -name 'verify-operator-workflow.sh' \) | sort
)

if [ "$checked" -eq 0 ]; then
    echo "ERROR: no live fixture host verifiers were checked" >&2
    exit 1
fi

echo "Live fixture cleanup verification passed (${checked} scripts checked)"
