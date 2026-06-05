#!/bin/bash
set -euo pipefail

# verify-live-fixture-cleanup.sh - Static guard for live verifiers that create
# synthetic live data. They must register cleanup traps and remove or cancel
# fixture resources so interrupted verifier runs do not pollute operational
# health, authorization, or scan-request queues.

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

require_rbac_cleanup() {
    local script="$1"
    local label="${script#$ROOT/}"
    if ! grep -Eq 'trap[[:space:]]+cleanup[[:space:]]+EXIT' "$script"; then
        echo "ERROR: $label creates RBAC fixtures but does not install 'trap cleanup EXIT'" >&2
        exit 1
    fi
    if ! grep -Eq 'DELETE[^\\n]+/api/admin/rbac/policies/|DELETE[[:space:]]+FROM[[:space:]]+access_policies' "$script"; then
        echo "ERROR: $label creates RBAC policy fixtures but does not visibly remove policies in cleanup" >&2
        exit 1
    fi
    if ! grep -Eq 'DELETE[^\\n]+/api/admin/rbac/subjects/|DELETE[[:space:]]+FROM[[:space:]]+access_subjects' "$script"; then
        echo "ERROR: $label creates RBAC subject fixtures but does not visibly remove subjects in cleanup" >&2
        exit 1
    fi
}

require_scan_request_cleanup() {
    local script="$1"
    local label="${script#$ROOT/}"
    if ! grep -Eq 'trap[[:space:]]+cleanup[[:space:]]+EXIT' "$script"; then
        echo "ERROR: $label creates scan-request fixtures but does not install 'trap cleanup EXIT'" >&2
        exit 1
    fi
    if ! grep -Eq '/api/scan-requests/\$\{?SCAN_REQUEST_ID\}?/cancel|UPDATE[[:space:]]+scan_requests[[:space:]]+SET[[:space:]]+status|DELETE[[:space:]]+FROM[[:space:]]+scan_requests' "$script"; then
        echo "ERROR: $label creates scan-request fixtures but does not visibly cancel or remove them in cleanup" >&2
        exit 1
    fi
}

checked=0
rbac_checked=0
scan_request_checked=0
while IFS= read -r script; do
    if [ "$script" = "$ROOT/scripts/verify-live-fixture-cleanup.sh" ]; then
        continue
    fi
    if grep -Eq '(^|[^A-Za-z0-9_])([A-Z_]*HOST_ID|HOST_ID_[A-Z_]+)="host-\$\{' "$script"; then
        require_host_cleanup "$script"
        checked=$((checked + 1))
    fi
    if grep -Eq '(^|[^A-Za-z0-9_])(SUBJECT_ID|POLICY_ID)="(subject|policy)-\$\{|(POST|api_json[[:space:]]+POST)[^\\n]+/api/admin/rbac/(subjects|policies)' "$script"; then
        require_rbac_cleanup "$script"
        rbac_checked=$((rbac_checked + 1))
    fi
    if grep -Eq '(^|[^A-Za-z0-9_])SCAN_REQUEST_ID=|api_json[[:space:]]+POST[[:space:]]+/api/scan-requests|curl[^\\n]+/api/scan-requests' "$script"; then
        require_scan_request_cleanup "$script"
        scan_request_checked=$((scan_request_checked + 1))
    fi
done < <(
    find "$ROOT/scripts" -maxdepth 1 -type f \( -name 'verify-live-*.sh' -o -name 'verify-agent-binary-workflow.sh' -o -name 'verify-operator-workflow.sh' \) | sort
)

if [ "$checked" -eq 0 ]; then
    echo "ERROR: no live fixture host verifiers were checked" >&2
    exit 1
fi
if [ "$rbac_checked" -eq 0 ]; then
    echo "ERROR: no live RBAC fixture verifiers were checked" >&2
    exit 1
fi
if [ "$scan_request_checked" -eq 0 ]; then
    echo "ERROR: no live scan-request fixture verifiers were checked" >&2
    exit 1
fi

echo "Live fixture cleanup verification passed (${checked} host scripts, ${rbac_checked} RBAC scripts, ${scan_request_checked} scan-request scripts checked)"
