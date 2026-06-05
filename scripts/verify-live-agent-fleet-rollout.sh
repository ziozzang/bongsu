#!/bin/bash
set -euo pipefail

# verify-live-agent-fleet-rollout.sh - Fail-closed verifier for real enrolled
# agent fleet readiness. Fixture workflow verifiers prove code paths; this gate
# proves the deployed fleet is actually current, reporting fresh inventory, and
# scanned against the current security DB revision.

API_BASE="${BONGSU_API_BASE:-http://127.0.0.1:5677}"
API_KEY="${BONGSU_API_KEY:-test-admin-key-0123456789}"
CURL_MAX_TIME="${BONGSU_VERIFY_AGENT_FLEET_CURL_MAX_TIME_SECONDS:-60}"
MIN_HOSTS="${BONGSU_VERIFY_AGENT_FLEET_MIN_HOSTS:-1}"
MIN_ONLINE_HOSTS="${BONGSU_VERIFY_AGENT_FLEET_MIN_ONLINE_HOSTS:-${MIN_HOSTS}}"
MIN_INVENTORY_COVERAGE="${BONGSU_VERIFY_AGENT_FLEET_MIN_INVENTORY_COVERAGE_PERCENT:-100}"
MIN_INVENTORY_FRESH="${BONGSU_VERIFY_AGENT_FLEET_MIN_INVENTORY_FRESH_PERCENT:-100}"
MIN_SECURITY_DB_SCAN_COVERAGE="${BONGSU_VERIFY_AGENT_FLEET_MIN_SECURITY_DB_SCAN_COVERAGE_PERCENT:-100}"
MIN_PACKAGES_PER_HOST="${BONGSU_VERIFY_AGENT_FLEET_MIN_PACKAGES_PER_HOST:-1}"
MAX_OFFLINE_HOSTS="${BONGSU_VERIFY_AGENT_FLEET_MAX_OFFLINE_HOSTS:-0}"
MAX_STALE_HOSTS="${BONGSU_VERIFY_AGENT_FLEET_MAX_STALE_HOSTS:-0}"
MAX_OUTDATED_HOSTS="${BONGSU_VERIFY_AGENT_FLEET_MAX_OUTDATED_HOSTS:-0}"
MAX_UNKNOWN_VERSION_HOSTS="${BONGSU_VERIFY_AGENT_FLEET_MAX_UNKNOWN_VERSION_HOSTS:-0}"
MAX_DEGRADED_INVENTORIES="${BONGSU_VERIFY_AGENT_FLEET_MAX_DEGRADED_INVENTORIES:-0}"
MAX_PENDING_SCAN_REQUESTS="${BONGSU_VERIFY_AGENT_FLEET_MAX_PENDING_SCAN_REQUESTS:-0}"
MAX_STALE_SECURITY_DB_HOSTS="${BONGSU_VERIFY_AGENT_FLEET_MAX_STALE_SECURITY_DB_HOSTS:-0}"
MAX_UNKNOWN_SECURITY_DB_HOSTS="${BONGSU_VERIFY_AGENT_FLEET_MAX_UNKNOWN_SECURITY_DB_HOSTS:-0}"
MAX_NO_SCAN_HOSTS="${BONGSU_VERIFY_AGENT_FLEET_MAX_NO_SCAN_HOSTS:-0}"
MAX_WARNINGS="${BONGSU_VERIFY_AGENT_FLEET_MAX_WARNINGS:-0}"
EXCLUDE_HOST_REGEX="${BONGSU_VERIFY_AGENT_FLEET_EXCLUDE_HOST_REGEX:-^(host-|bongsu-fixture-|fixture-)}"
ALLOWED_SCAN_STATUSES="${BONGSU_VERIFY_AGENT_FLEET_ALLOWED_SCAN_STATUSES:-completed}"
TMP_DIR="$(mktemp -d)"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: missing required tool: $1" >&2
        exit 1
    fi
}

api_get_json() {
    local path="$1"
    local out="$2"
    local status
    if ! status="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$out" -w "%{http_code}" \
        -H "X-API-Key: ${API_KEY}" \
        "${API_BASE}${path}")"; then
        echo "ERROR: GET ${path} did not complete within ${CURL_MAX_TIME}s or failed at the transport layer" >&2
        cat "$out" >&2 || true
        exit 1
    fi
    if [[ "$status" != 2* ]]; then
        echo "ERROR: GET ${path} returned HTTP ${status}" >&2
        cat "$out" >&2 || true
        exit 1
    fi
}

json_number() {
    local file="$1"
    local filter="$2"
    jq -r "${filter} // 0" "$file"
}

assert_at_least() {
    local actual="$1"
    local min="$2"
    local message="$3"
    if ! awk -v a="$actual" -v m="$min" 'BEGIN { exit !(a >= m) }'; then
        echo "ERROR: ${message}; got ${actual}, want >= ${min}" >&2
        exit 1
    fi
}

assert_at_most() {
    local actual="$1"
    local max="$2"
    local message="$3"
    if ! awk -v a="$actual" -v m="$max" 'BEGIN { exit !(a <= m) }'; then
        echo "ERROR: ${message}; got ${actual}, want <= ${max}" >&2
        exit 1
    fi
}

assert_jq() {
    local file="$1"
    local filter="$2"
    local message="$3"
    if ! jq -e "$filter" "$file" >/dev/null; then
        echo "ERROR: ${message}" >&2
        jq . "$file" >&2 || cat "$file" >&2
        exit 1
    fi
}

require_tool curl
require_tool jq
require_tool awk

echo "=== Bongsu Live Agent Fleet Rollout Verification ==="
echo "API: ${API_BASE}"

fleet_json="$TMP_DIR/agent-fleet-status.json"
stats_json="$TMP_DIR/stats.json"
hosts_json="$TMP_DIR/hosts.json"
containers_json="$TMP_DIR/containers.json"
containers_with_labels_json="$TMP_DIR/containers-with-labels.json"
api_get_json "/api/admin/agent-fleet/status" "$fleet_json"
api_get_json "/api/stats" "$stats_json"
api_get_json "/api/hosts?limit=1000" "$hosts_json"
api_get_json "/api/containers?limit=100" "$containers_json"
api_get_json "/api/containers?limit=100&include_labels=true" "$containers_with_labels_json"

echo "[1/5] Checking agent fleet operational status"
fleet_status="$(jq -r '.status // ""' "$fleet_json")"
if [ "$fleet_status" != "ok" ]; then
    warning_count="$(json_number "$fleet_json" '(.warnings // []) | length')"
    if ! awk -v w="$warning_count" -v m="$MAX_WARNINGS" 'BEGIN { exit !(m > 0 && w <= m) }'; then
        echo "ERROR: agent fleet status must be ok unless warnings are explicitly allowed; status=${fleet_status}, warnings=${warning_count}, max_warnings=${MAX_WARNINGS}" >&2
        jq . "$fleet_json" >&2 || cat "$fleet_json" >&2
        exit 1
    fi
fi
assert_jq "$fleet_json" '.installer.ready == true' "one-line installer payloads must be ready"
assert_jq "$fleet_json" '.installer.agent.ready == true' "agent installer binary must be ready"
assert_jq "$fleet_json" '.installer.trivy.ready == true' "installer Trivy payload must be ready"
assert_jq "$fleet_json" '.installer.install_token_configured == true' "install token must be configured"
assert_at_least "$(json_number "$fleet_json" '.total_hosts')" "$MIN_HOSTS" "enrolled host count"
assert_at_least "$(json_number "$fleet_json" '.agent_status_counts.online')" "$MIN_ONLINE_HOSTS" "online host count"
assert_at_most "$(json_number "$fleet_json" '.agent_status_counts.offline')" "$MAX_OFFLINE_HOSTS" "offline host count"
assert_at_most "$(json_number "$fleet_json" '.agent_status_counts.stale')" "$MAX_STALE_HOSTS" "stale host count"
assert_at_most "$(json_number "$fleet_json" '.agent_version_drift_counts.outdated')" "$MAX_OUTDATED_HOSTS" "outdated agent count"
assert_at_most "$(json_number "$fleet_json" '.agent_version_drift_counts.unknown')" "$MAX_UNKNOWN_VERSION_HOSTS" "unknown agent version count"
assert_at_most "$(json_number "$fleet_json" '(.warnings // []) | length')" "$MAX_WARNINGS" "agent fleet warning count"

echo "[2/5] Checking inventory freshness and security DB revision coverage"
assert_at_least "$(json_number "$stats_json" '.inventory_coverage_percent')" "$MIN_INVENTORY_COVERAGE" "inventory coverage percent"
assert_at_least "$(json_number "$stats_json" '.inventory_fresh_percent')" "$MIN_INVENTORY_FRESH" "fresh inventory percent"
assert_at_least "$(json_number "$stats_json" '.security_db_scan_coverage.coverage_percent')" "$MIN_SECURITY_DB_SCAN_COVERAGE" "current security DB scan coverage percent"
assert_at_most "$(json_number "$stats_json" '.security_db_scan_coverage.stale_hosts')" "$MAX_STALE_SECURITY_DB_HOSTS" "security DB stale host count"
assert_at_most "$(json_number "$stats_json" '.security_db_scan_coverage.unknown_hosts')" "$MAX_UNKNOWN_SECURITY_DB_HOSTS" "security DB unknown host count"
assert_at_most "$(json_number "$stats_json" '.security_db_scan_coverage.no_scan_hosts')" "$MAX_NO_SCAN_HOSTS" "security DB no-scan host count"
assert_at_most "$(json_number "$stats_json" '.inventory_status_counts.degraded')" "$MAX_DEGRADED_INVENTORIES" "degraded latest inventory count"
assert_at_most "$(json_number "$stats_json" '.scan_request_counts.pending')" "$MAX_PENDING_SCAN_REQUESTS" "pending scan request count"

echo "[3/5] Checking real enrolled host inventory evidence"
real_host_count="$(jq --arg re "$EXCLUDE_HOST_REGEX" '[.[]? | select((.id // "" | test($re) | not) and (.hostname // "" | test($re) | not))] | length' "$hosts_json")"
assert_at_least "$real_host_count" "$MIN_HOSTS" "real enrolled host count after fixture exclusion"
bad_hosts="$(jq -r --arg re "$EXCLUDE_HOST_REGEX" --arg statuses "$ALLOWED_SCAN_STATUSES" --argjson min_pkg "$MIN_PACKAGES_PER_HOST" '
    def allowed_statuses: ($statuses | split(",") | map(gsub("^\\s+|\\s+$"; "")) | map(select(. != "")));
    [
      .[]?
      | select((.id // "" | test($re) | not) and (.hostname // "" | test($re) | not))
      | select(
          (.agent_status // "") != "online"
          or (.agent_version // "") == ""
          or (.latest_inventory.latest_scan_id // "") == ""
          or (.latest_inventory.latest_scan_at // "") == ""
          or ((.latest_inventory.latest_package_count // 0) < $min_pkg)
          or (((.latest_inventory.latest_scan_status // "") as $status | allowed_statuses | index($status)) | not)
      )
      | "\(.id) status=\(.agent_status // "") scan_status=\(.latest_inventory.latest_scan_status // "") packages=\(.latest_inventory.latest_package_count // 0)"
    ]
    | .[]
' "$hosts_json")"
if [ -n "$bad_hosts" ]; then
    echo "ERROR: real enrolled hosts must be online with completed latest inventory and package evidence" >&2
    printf '%s\n' "$bad_hosts" >&2
    exit 1
fi

echo "[4/5] Checking container metadata exposure defaults"
assert_jq "$containers_json" 'all(.items[]?; (has("labels") | not) and ((.label_count // 0) >= 0))' "container list must redact raw labels by default while exposing label_count"
redacted_label_rows="$(jq '[.items[]? | select((.label_count // 0) > 0 and (.labels_redacted // false) == true)] | length' "$containers_json")"
if [ "$redacted_label_rows" -gt 0 ]; then
    assert_jq "$containers_with_labels_json" 'any(.items[]?; ((.label_count // 0) > 0) and has("labels") and ((.labels | type) == "string") and ((.labels | length) > 2))' "include_labels=true must return raw labels for rows that advertise redacted labels"
fi

echo "[5/5] Checking security DB revision consistency"
fleet_revision="$(jq -r '.security_db_revision // ""' "$fleet_json")"
stats_revision="$(jq -r '.security_db_revision // ""' "$stats_json")"
coverage_revision="$(jq -r '.security_db_scan_coverage.revision // ""' "$stats_json")"
if [ -z "$fleet_revision" ] || [ "$fleet_revision" != "$stats_revision" ] || [ "$fleet_revision" != "$coverage_revision" ]; then
    echo "ERROR: security DB revision must be present and consistent across fleet and stats surfaces" >&2
    echo "fleet=${fleet_revision} stats=${stats_revision} coverage=${coverage_revision}" >&2
    exit 1
fi

echo "Live agent fleet rollout verification passed"
echo "Hosts: $(jq -r '.total_hosts' "$fleet_json"), online: $(jq -r '.agent_status_counts.online // 0' "$fleet_json"), revision: ${fleet_revision}"
