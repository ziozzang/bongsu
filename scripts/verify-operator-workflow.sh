#!/bin/bash
set -euo pipefail

# verify-operator-workflow.sh — Exercise live operator API workflows.
#
# This verifier is intended for a running Bongsu API, not CI-only mocked tests.
# It creates short-lived schedules, asset groups, and notification rules, then
# removes them before exit. Backup/restore checks run in dry-run mode only.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API_BASE="${BONGSU_API_BASE:-http://127.0.0.1:5677}"
API_KEY="${BONGSU_API_KEY:-test-admin}"
AGENT_API_KEY="${BONGSU_AGENT_API_KEY:-test-agent-key}"
ADMIN_USERNAME="${BONGSU_ADMIN_USERNAME:-}"
ADMIN_PASSWORD="${BONGSU_ADMIN_PASSWORD:-}"
CURL_MAX_TIME="${BONGSU_VERIFY_CURL_MAX_TIME_SECONDS:-20}"
RUN_ID="operator-verify-$(date -u +%Y%m%dT%H%M%SZ)-$$"
VERIFY_HOST_ID="host-${RUN_ID}"
VERIFY_AGENT_TOKEN="token-${RUN_ID}"

SCHEDULE_ID=""
ASSET_GROUP_ID=""
NOTIFICATION_RULE_ID=""
SCAN_REQUEST_ID=""
TMP_DIR="$(mktemp -d)"

cleanup() {
    set +e
    if [ -n "$NOTIFICATION_RULE_ID" ]; then
        curl -fsS --max-time "$CURL_MAX_TIME" -X DELETE -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/admin/notification-rules/${NOTIFICATION_RULE_ID}" >/dev/null 2>&1
    fi
    if [ -n "$ASSET_GROUP_ID" ]; then
        curl -fsS --max-time "$CURL_MAX_TIME" -X DELETE -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/asset-groups/${ASSET_GROUP_ID}" >/dev/null 2>&1
    fi
    if [ -n "$SCHEDULE_ID" ]; then
        curl -fsS --max-time "$CURL_MAX_TIME" -X DELETE -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/admin/schedules/${SCHEDULE_ID}" >/dev/null 2>&1
    fi
    if [ -n "$SCAN_REQUEST_ID" ]; then
        curl -fsS --max-time "$CURL_MAX_TIME" -X POST -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/scan-requests/${SCAN_REQUEST_ID}/cancel" >/dev/null 2>&1
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: missing required tool: $1" >&2
        exit 1
    fi
}

api_json() {
    local method="$1"
    local path="$2"
    local body="${3:-}"
    local out="$TMP_DIR/response.json"
    local status
    if [ -n "$body" ]; then
        status="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$out" -w "%{http_code}" -X "$method" \
            -H "X-API-Key: ${API_KEY}" \
            -H "Content-Type: application/json" \
            --data "$body" \
            "${API_BASE}${path}")"
    else
        status="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$out" -w "%{http_code}" -X "$method" \
            -H "X-API-Key: ${API_KEY}" \
            "${API_BASE}${path}")"
    fi
    if [[ "$status" != 2* ]]; then
        echo "ERROR: ${method} ${path} returned HTTP ${status}" >&2
        cat "$out" >&2 || true
        exit 1
    fi
    cat "$out"
}

agent_json() {
    local method="$1"
    local path="$2"
    local body="${3:-}"
    local out="$TMP_DIR/agent-response.json"
    local status
    if [ -n "$body" ]; then
        status="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$out" -w "%{http_code}" -X "$method" \
            -H "X-API-Key: ${AGENT_API_KEY}" \
            -H "X-Bongsu-Agent-Token: ${VERIFY_AGENT_TOKEN}" \
            -H "X-Bongsu-Host-ID: ${VERIFY_HOST_ID}" \
            -H "Content-Type: application/json" \
            --data "$body" \
            "${API_BASE}${path}")"
    else
        status="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$out" -w "%{http_code}" -X "$method" \
            -H "X-API-Key: ${AGENT_API_KEY}" \
            -H "X-Bongsu-Agent-Token: ${VERIFY_AGENT_TOKEN}" \
            -H "X-Bongsu-Host-ID: ${VERIFY_HOST_ID}" \
            "${API_BASE}${path}")"
    fi
    if [[ "$status" != 2* ]]; then
        echo "ERROR: agent ${method} ${path} returned HTTP ${status}" >&2
        cat "$out" >&2 || true
        exit 1
    fi
    cat "$out"
}

assert_json() {
    local json="$1"
    local filter="$2"
    local message="$3"
    if ! jq -e "$filter" >/dev/null <<<"$json"; then
        echo "ERROR: ${message}" >&2
        echo "$json" | jq . >&2 || echo "$json" >&2
        exit 1
    fi
}

assert_json_arg() {
    local json="$1"
    local name="$2"
    local value="$3"
    local filter="$4"
    local message="$5"
    if ! jq -e --arg "$name" "$value" "$filter" >/dev/null <<<"$json"; then
        echo "ERROR: ${message}" >&2
        echo "$json" | jq . >&2 || echo "$json" >&2
        exit 1
    fi
}

new_uuid() {
    if [ -r /proc/sys/kernel/random/uuid ]; then
        cat /proc/sys/kernel/random/uuid
        return
    fi
    local hex
    hex="$(date +%s%N)$$"
    printf '00000000-0000-4000-8000-%012d\n' "$((hex % 1000000000000))"
}

scan_report_json() {
    local scan_id="$1"
    local scan_request_id="${2:-}"
    jq -nc \
        --arg host_id "$VERIFY_HOST_ID" \
        --arg scan_id "$scan_id" \
        --arg scan_request_id "$scan_request_id" \
        --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{
          host: {
            id: $host_id,
            hostname: $host_id,
            ip_address: "127.0.0.1",
            os_name: "Ubuntu",
            os_version: "22.04",
            kernel: "operator-verifier",
            arch: "amd64",
            cpu_model: "verifier",
            cpu_cores: 1,
            memory_mb: 512,
            agent_version: "operator-verifier"
          },
          scan_type: "manual",
          scan_id: $scan_id,
          scan_request_id: $scan_request_id,
          packages: [
            {
              source: "dpkg",
              name: "operator-verifier-package",
              version: "1.0.0",
              arch: "amd64",
              pkg_type: "os",
              ecosystem: "ubuntu",
              asset_type: "host",
              asset_id: $host_id,
              target: "host"
            }
          ],
          containers: [],
          vulnerabilities: [],
          users: [],
          processes: [],
          ports: [],
          timestamp: $ts
        }'
}

require_tool curl
require_tool jq
require_tool tar

echo "=== Bongsu Live Operator Workflow Verification ==="
echo "API: ${API_BASE}"

echo "[1/10] Checking liveness and readiness"
curl -fsS --max-time "$CURL_MAX_TIME" "${API_BASE}/api/live" | jq -e '.status == "alive"' >/dev/null
curl -fsS --max-time "$CURL_MAX_TIME" "${API_BASE}/api/ready" | jq -e '.status == "ready"' >/dev/null

echo "[2/10] Checking OpenAPI documentation endpoint"
curl -fsS --max-time "$CURL_MAX_TIME" "${API_BASE}/api/docs/openapi.yaml" -o "$TMP_DIR/openapi.yaml"
grep -Eq '^openapi: "?3\.' "$TMP_DIR/openapi.yaml"
grep -q '/api/admin/schedules:' "$TMP_DIR/openapi.yaml"
grep -q '/api/asset-groups:' "$TMP_DIR/openapi.yaml"
grep -q '/api/admin/notification-rules:' "$TMP_DIR/openapi.yaml"
grep -q '/api/admin/security-db/status:' "$TMP_DIR/openapi.yaml"
grep -q '/api/admin/agent-fleet/status:' "$TMP_DIR/openapi.yaml"
grep -q '/api/admin/rbac/status:' "$TMP_DIR/openapi.yaml"

echo "[3/10] Checking health and admin metrics observability"
health_json="$(api_json GET /api/health)"
assert_json "$health_json" '.status and .security_db_revision and (.security_recalculation.running | type == "boolean") and (.security_recalculation.pending | type == "boolean")' "health must expose security DB revision and recalculation state"
assert_json "$health_json" '.cve_affected_package_index and ((.cve_affected_package_index.count // 0) > 0) and (.cve_affected_package_index.orphans == 0) and ((.cve_affected_package_index.summary_mode == "indexed-only") or (.cve_affected_package_index.stale == false))' "health must expose usable affected-package index state"
assert_json "$health_json" '.cve_reference_key_index and (.cve_reference_key_index.orphans == 0) and ((.cve_reference_key_index.summary_mode == "indexed-only") or (.cve_reference_key_index.stale == false))' "health must expose usable reference-key index state"
security_db_status_json="$(api_json GET /api/admin/security-db/status)"
assert_json "$security_db_status_json" '.status and .security_db and .security_db.configured == true and .security_db_freshness and .security_recalculation and .security_db_revision' "security DB status must expose sync manager, freshness, recalculation, and revision"
assert_json "$security_db_status_json" '.cve_db_quality and .cve_db_quality.status and .cve_affected_package_index and ((.cve_affected_package_index.count // 0) > 0) and .cve_reference_key_index' "security DB status must expose CVE quality and index health"
agent_fleet_status_json="$(api_json GET /api/admin/agent-fleet/status)"
assert_json "$agent_fleet_status_json" '.status == "ok" and (.total_hosts | type == "number") and (.agent_status_counts | type == "object") and (.agent_version_counts | type == "object") and (.agent_version_drift_counts.current | type == "number") and (.agent_version_drift_counts.outdated | type == "number") and (.agent_version_drift_counts.unknown | type == "number")' "agent fleet status must expose host/version/drift counts"
assert_json "$agent_fleet_status_json" '.installer and (.installer.ready | type == "boolean") and .installer.agent and (.installer.agent.ready | type == "boolean")' "agent fleet status must expose installer readiness"
curl -fsS --max-time "$CURL_MAX_TIME" -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/admin/metrics" -o "$TMP_DIR/admin-metrics.txt"
for metric in \
    '^bongsu_security_db_revision_info[{]revision="' \
    '^bongsu_security_recalculation_running ' \
    '^bongsu_security_recalculation_pending ' \
    '^bongsu_cve_affected_package_index_coverage_percent ' \
    '^bongsu_cve_affected_package_index_stale ' \
    '^bongsu_cve_reference_key_index_coverage_percent ' \
    '^bongsu_cve_reference_key_index_stale ' \
    '^bongsu_cve_epss_enriched_records ' \
    '^bongsu_security_db_rescan_open '; do
    if ! grep -Eq "$metric" "$TMP_DIR/admin-metrics.txt"; then
        echo "ERROR: admin metrics missing ${metric}" >&2
        sed -n '1,160p' "$TMP_DIR/admin-metrics.txt" >&2
        exit 1
    fi
done

if [ -n "$ADMIN_USERNAME" ] && [ -n "$ADMIN_PASSWORD" ]; then
    echo "[4/10] Checking local session login"
    login_json="$(curl -sS --max-time "$CURL_MAX_TIME" -X POST -H "Content-Type: application/json" \
        --data "$(jq -nc --arg u "$ADMIN_USERNAME" --arg p "$ADMIN_PASSWORD" '{username:$u,password:$p}')" \
        "${API_BASE}/api/auth/login")"
    token="$(jq -r '.token // empty' <<<"$login_json")"
    if [ -z "$token" ]; then
        echo "ERROR: login did not return a bearer token" >&2
        echo "$login_json" >&2
        exit 1
    fi
    curl -fsS --max-time "$CURL_MAX_TIME" -H "Authorization: Bearer ${token}" "${API_BASE}/api/auth/me" | jq -e '.user.role == "admin"' >/dev/null
else
    echo "[4/10] Skipping local session login; set BONGSU_ADMIN_USERNAME and BONGSU_ADMIN_PASSWORD to verify it"
fi

echo "[5/10] Checking scheduled scan CRUD contract"
schedules_json="$(api_json GET /api/admin/schedules)"
assert_json "$schedules_json" '.items | type == "array"' "schedule list must return an items array"
schedule_body="$(jq -nc --arg name "$RUN_ID schedule" '{name:$name, cron_expr:"0 */6 * * *", scan_type:"manual", packages_only:true, enabled:false}')"
schedule_json="$(api_json POST /api/admin/schedules "$schedule_body")"
SCHEDULE_ID="$(jq -r '.id' <<<"$schedule_json")"
assert_json "$schedule_json" '.scan_type == "manual" and .packages_only == true and .enabled == false' "created schedule must preserve scan_type/manual and packages_only=true"
schedule_get="$(api_json GET "/api/admin/schedules/${SCHEDULE_ID}")"
assert_json "$schedule_get" '.id and .packages_only == true' "schedule get must return created packages-only schedule"

echo "[6/10] Checking dynamic asset group contract and scan trigger"
groups_json="$(api_json GET /api/asset-groups)"
assert_json "$groups_json" '.items | type == "array"' "asset group list must return an items array"
subjects_json="$(api_json GET /api/admin/rbac/subjects)"
assert_json "$subjects_json" '.items | type == "array"' "RBAC subject list must return a stable items array"
policies_json="$(api_json GET /api/admin/rbac/policies)"
assert_json "$policies_json" '.items | type == "array"' "RBAC policy list must return a stable items array"
rbac_status_json="$(api_json GET /api/admin/rbac/status)"
assert_json "$rbac_status_json" '.status and (.stats.subject_count | type == "number") and (.stats.policy_count | type == "number") and (.stats.orphan_policy_count | type == "number") and (.stats.subject_type_counts | type == "object") and (.stats.resource_type_counts | type == "object") and (.stats.permission_counts | type == "object")' "RBAC status must expose subject, policy, orphan, and distribution counters"
group_body="$(jq -nc --arg name "$RUN_ID asset group" '{name:$name, description:"operator verifier", rule_type:"dynamic", rule_expr:"team=platform"}')"
group_json="$(api_json POST /api/asset-groups "$group_body")"
ASSET_GROUP_ID="$(jq -r '.id' <<<"$group_json")"
assert_json "$group_json" '.rule_type == "dynamic" and .rule_expr == "team=platform"' "asset group must preserve rule_type and rule_expr"
group_scan="$(api_json POST "/api/asset-groups/${ASSET_GROUP_ID}/scan" '{}')"
assert_json "$group_scan" '.status == "ok" and (.queued | type == "number") and (.total | type == "number")' "asset group scan trigger must report queued and total counts"

echo "[7/10] Checking report surfaces"
executive_json="$(api_json GET /api/reports/executive-summary)"
assert_json "$executive_json" '.generated_at and (.total_hosts | type == "number")' "executive summary must expose generated_at and numeric host count"
risk_json="$(api_json GET '/api/reports/risk-breakdown?group_by=owner')"
assert_json "$risk_json" '.group_by == "owner" and (.items | type == "array")' "risk breakdown must preserve group_by and items"
sla_json="$(api_json GET /api/reports/sla-compliance)"
assert_json "$sla_json" '.generated_at and (.overall_compliance_percent | type == "number") and (.overdue_by_owner | type == "array") and (.by_severity | type == "object")' "SLA compliance report must expose generated_at, overall rate, severity buckets, and owner backlog"
for sev in CRITICAL HIGH MEDIUM LOW; do
    assert_json "$sla_json" ".by_severity[\"${sev}\"] and (.by_severity[\"${sev}\"].total | type == \"number\") and (.by_severity[\"${sev}\"].overdue | type == \"number\") and (.by_severity[\"${sev}\"].compliance_percent | type == \"number\")" "SLA compliance report must include numeric bucket for ${sev}"
done
api_json GET '/api/reports/export?format=json&type=executive' | jq -e '.generated_at' >/dev/null
api_json GET '/api/reports/export?format=json&type=sla' | jq -e '.generated_at and .by_severity' >/dev/null
risk_export_json="$(api_json GET '/api/reports/export?format=json&type=risk&group_by=owner')"
assert_json "$risk_export_json" '.group_by == "owner" and (.items | type == "array")' "risk report export must preserve group_by and stable items array"

echo "[8/10] Checking notification rule contract"
rules_json="$(api_json GET /api/admin/notification-rules)"
assert_json "$rules_json" '.items | type == "array"' "notification rules list must return an items array"
rule_body="$(jq -nc --arg name "$RUN_ID notification" '{name:$name, trigger_event:"security_db.updated", min_severity:"HIGH", channel_type:"log", enabled:true}')"
rule_json="$(api_json POST /api/admin/notification-rules "$rule_body")"
NOTIFICATION_RULE_ID="$(jq -r '.id' <<<"$rule_json")"
assert_json "$rule_json" '.trigger_event == "security_db.updated" and .channel_type == "log" and .enabled == true' "notification rule must preserve trigger/channel/enabled"
test_json="$(api_json POST "/api/admin/notification-rules/${NOTIFICATION_RULE_ID}/test" '{}')"
assert_json "$test_json" '.status == "sent"' "log notification test must return sent"
log_json="$(api_json GET '/api/admin/notification-log?limit=20')"
assert_json "$log_json" '.items | type == "array"' "notification log must return an items array"

echo "[9/10] Checking agent claim, report, and scan-request completion"
initial_scan_id="$(new_uuid)"
initial_report="$(agent_json POST /api/report "$(scan_report_json "$initial_scan_id")")"
assert_json "$initial_report" '.status == "ok" and .scan_status == "completed"' "initial agent report must enroll the verifier host"
request_body="$(jq -nc --arg host_id "$VERIFY_HOST_ID" '{host_id:$host_id, scan_type:"manual", packages_only:true, reason:"operator verifier agent e2e"}')"
request_json="$(api_json POST /api/scan-requests "$request_body")"
SCAN_REQUEST_ID="$(jq -r '.id' <<<"$request_json")"
assert_json "$request_json" '.status == "pending" and .packages_only == true' "created agent E2E scan request must be pending packages-only"
claim_json="$(agent_json POST "/api/agent/scan-requests/claim?host_id=${VERIFY_HOST_ID}")"
assert_json_arg "$claim_json" id "$SCAN_REQUEST_ID" '.request.id == $id and .request.status == "claimed" and .request.claimed_by_host_id != ""' "agent must claim the verifier scan request"
claimed_revision="$(jq -r '.request.security_db_revision // ""' <<<"$claim_json")"
claimed_scan_id="$(new_uuid)"
claimed_report="$(scan_report_json "$claimed_scan_id" "$SCAN_REQUEST_ID")"
if [ -n "$claimed_revision" ]; then
    claimed_report="$(jq --arg rev "$claimed_revision" '.security_db_revision = $rev' <<<"$claimed_report")"
fi
report_json="$(agent_json POST /api/report "$claimed_report")"
assert_json "$report_json" '.status == "ok" and .scan_status == "completed" and .inventory_status == "healthy"' "claimed agent report must complete a healthy inventory scan"
complete_json="$(agent_json POST "/api/agent/scan-requests/${SCAN_REQUEST_ID}/complete" "$(jq -nc --arg host_id "$VERIFY_HOST_ID" '{host_id:$host_id, status:"completed", message:"operator verifier complete"}')")"
assert_json "$complete_json" '.status == "completed"' "agent completion endpoint must accept the claimed host"
request_done="$(api_json GET "/api/scan-requests?host_id=${VERIFY_HOST_ID}&limit=5")"
assert_json_arg "$request_done" id "$SCAN_REQUEST_ID" '.items[] | select(.id == $id and .status == "completed" and .claimed_by_host_id != "")' "scan request list must show the verifier request completed by the agent"
scans_done="$(api_json GET "/api/scans?host_id=${VERIFY_HOST_ID}&limit=5")"
assert_json_arg "$scans_done" request_id "$SCAN_REQUEST_ID" '.items[] | select(.scan_request_id == $request_id and .status == "completed" and .package_count >= 1)' "scan list must show a completed inventory scan tied to the request"
SCAN_REQUEST_ID=""

echo "[10/10] Checking backup and restore dry-run surfaces"
BONGSU_DB_PASSWORD="${BONGSU_DB_PASSWORD:-}" "$ROOT/scripts/backup.sh" --dry-run "$TMP_DIR/backup.tar.gz" | grep -q 'Dry-run complete'
mkdir -p "$TMP_DIR/restore-src"
printf 'fixture\n' > "$TMP_DIR/restore-src/database.dump"
printf '{"format_version":1,"database":"bongsu"}\n' > "$TMP_DIR/restore-src/manifest.json"
tar -C "$TMP_DIR/restore-src" -czf "$TMP_DIR/restore-fixture.tar.gz" database.dump manifest.json
BONGSU_DB_PASSWORD="${BONGSU_DB_PASSWORD:-}" "$ROOT/scripts/restore.sh" --dry-run "$TMP_DIR/restore-fixture.tar.gz" | grep -q 'Dry-run complete'

echo "Live operator workflow verification passed"
