#!/bin/bash
set -euo pipefail

# verify-operator-workflow.sh — Exercise live operator API workflows.
#
# This verifier is intended for a running Bongsu API, not CI-only mocked tests.
# It creates short-lived schedules, asset groups, and notification rules, then
# removes them before exit. Backup/restore checks run in dry-run mode only.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API_BASE="${BONGSU_API_BASE:-http://127.0.0.1:5677}"
API_KEY="${BONGSU_API_KEY:-test-admin-key-0123456789}"
AGENT_API_KEY="${BONGSU_AGENT_API_KEY:-test-agent-key-0123456789}"
ADMIN_USERNAME="${BONGSU_ADMIN_USERNAME:-}"
ADMIN_PASSWORD="${BONGSU_ADMIN_PASSWORD:-}"
CURL_MAX_TIME="${BONGSU_VERIFY_CURL_MAX_TIME_SECONDS:-45}"
RUN_ID="operator-verify-$(date -u +%Y%m%dT%H%M%SZ)-$$"
VERIFY_HOST_ID="host-${RUN_ID}"
VERIFY_AGENT_TOKEN="token-${RUN_ID}"

SCHEDULE_ID=""
ASSET_GROUP_ID=""
NOTIFICATION_RULE_ID=""
SCAN_REQUEST_ID=""
WEBHOOK_PID=""
TMP_DIR="$(mktemp -d)"

cleanup() {
    set +e
    if [ -n "$WEBHOOK_PID" ]; then
        kill "$WEBHOOK_PID" >/dev/null 2>&1
        wait "$WEBHOOK_PID" >/dev/null 2>&1
    fi
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
    curl -fsS --max-time "$CURL_MAX_TIME" -X DELETE -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/hosts/${VERIFY_HOST_ID}" >/dev/null 2>&1
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
          users: [
            {username: "bongsu-operator-user", uid: 4242, gid: 4242, home_dir: "/home/bongsu-operator-user", shell: "/bin/bash"}
          ],
          processes: [
            {pid: 4242, name: "bongsu-operator-process", cmdline: "bongsu-operator-process --verify", user: "bongsu-operator-user", cpu_usage: 12.5, mem_usage: 3.5}
          ],
          ports: [
            {name: "bongsu-operator-listener", port: 45678, protocol: "tcp", address: "127.0.0.1", pid: 4242}
          ],
          timestamp: $ts
        }'
}

require_tool curl
require_tool jq
require_tool python3
require_tool tar

echo "=== Bongsu Live Operator Workflow Verification ==="
echo "API: ${API_BASE}"

echo "[1/11] Checking liveness and readiness"
curl -fsS --max-time "$CURL_MAX_TIME" "${API_BASE}/api/live" | jq -e '.status == "alive"' >/dev/null
curl -fsS --max-time "$CURL_MAX_TIME" "${API_BASE}/api/ready" | jq -e '.status == "ready"' >/dev/null

echo "[2/11] Checking OpenAPI documentation endpoint"
curl -fsS --max-time "$CURL_MAX_TIME" "${API_BASE}/api/docs/openapi.yaml" -o "$TMP_DIR/openapi.yaml"
grep -Eq '^openapi: "?3\.' "$TMP_DIR/openapi.yaml"
grep -q '/api/admin/schedules:' "$TMP_DIR/openapi.yaml"
grep -q '/api/asset-groups:' "$TMP_DIR/openapi.yaml"
grep -q '/api/admin/notification-rules:' "$TMP_DIR/openapi.yaml"
grep -q '/api/admin/security-db/status:' "$TMP_DIR/openapi.yaml"
grep -q '/api/admin/agent-fleet/status:' "$TMP_DIR/openapi.yaml"
grep -q '/api/admin/rbac/status:' "$TMP_DIR/openapi.yaml"
grep -q '/api/admin/retention/prune:' "$TMP_DIR/openapi.yaml"
grep -q '/api/hosts/{id}/users:' "$TMP_DIR/openapi.yaml"
grep -q '/api/hosts/{id}/processes:' "$TMP_DIR/openapi.yaml"
grep -q '/api/hosts/{id}/ports:' "$TMP_DIR/openapi.yaml"

echo "[3/11] Checking health and admin metrics observability"
health_json="$(api_json GET /api/health)"
assert_json "$health_json" '.status and ((.security_db_revision // "") != "" or (.security_db_revision_error // "") != "") and (.security_recalculation.running | type == "boolean") and (.security_recalculation.pending | type == "boolean")' "health must expose security DB revision or revision error plus recalculation state"
assert_json "$health_json" '((.security_db_updated_at // "") != "") and (.security_db_updated_at == .security_db_freshness.latest_last_update)' "health must expose top-level security DB update time aligned with persisted source freshness"
assert_json "$health_json" '.cve_affected_package_index and ((.cve_affected_package_index.count // 0) > 0) and (.cve_affected_package_index.orphans == 0) and ((.cve_affected_package_index.summary_mode == "indexed-only") or (.cve_affected_package_index.stale == false))' "health must expose usable affected-package index state"
assert_json "$health_json" '.cve_reference_key_index and (.cve_reference_key_index.orphans == 0) and ((.cve_reference_key_index.summary_mode == "indexed-only") or (.cve_reference_key_index.stale == false))' "health must expose usable reference-key index state"
security_db_status_json="$(api_json GET /api/admin/security-db/status)"
assert_json "$security_db_status_json" '
  .status
  and (.warnings | type == "array")
  and (.recommended_actions | type == "array")
  and .security_db
  and .security_db.configured == true
  and ((.security_db.effective_status // "") != "")
  and ((.security_db.effective_source // "") != "")
  and ((.security_db.effective_last_sync // "") != "")
  and .security_db_freshness
  and .security_db_export
  and (.security_db_export.status | type == "string")
  and (.security_db.effective_status == .security_db_freshness.status)
  and (.security_db.effective_source == .security_db_freshness.latest_source)
  and (.security_db.effective_last_sync == .security_db_freshness.latest_last_update)
  and .security_recalculation
  and ((.security_db_revision // "") != "" or (.security_db_revision_error // "") != "")
' "security DB status must expose sync manager, effective persisted freshness, recalculation, revision or revision error, warnings, and recommended actions"
assert_json "$security_db_status_json" '(.security_db_bundle_import == null) or (.security_db_bundle_import.last_result.status and ((.security_db_bundle_import.last_result.bundle_source_count // 0) >= 0))' "security DB status bundle import summary must expose status and provenance shape when present"
assert_json "$security_db_status_json" '.cve_db_quality and .cve_db_quality.status and .cve_affected_package_index and ((.cve_affected_package_index.count // 0) > 0) and .cve_reference_key_index' "security DB status must expose CVE quality and index health"
agent_fleet_status_json="$(api_json GET /api/admin/agent-fleet/status)"
assert_json "$agent_fleet_status_json" '(.status == "ok" or .status == "degraded") and (.warnings | type == "array") and (.recommended_actions | type == "array") and (.total_hosts | type == "number") and (.outdated_percent | type == "number") and (.agent_status_counts | type == "object") and (.agent_version_counts | type == "object") and (.agent_version_drift_counts.current | type == "number") and (.agent_version_drift_counts.outdated | type == "number") and (.agent_version_drift_counts.unknown | type == "number")' "agent fleet status must expose status, warnings, host/version/drift counts, and outdated percentage"
assert_json "$agent_fleet_status_json" '.installer and (.installer.ready | type == "boolean") and .installer.agent and (.installer.agent.ready | type == "boolean")' "agent fleet status must expose installer readiness"
curl -fsS --max-time "$CURL_MAX_TIME" -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/admin/metrics" -o "$TMP_DIR/admin-metrics.txt"
duplicate_metric_types="$(awk '/^# TYPE / {count[$3]++} END {for (metric in count) if (count[metric] > 1) print metric, count[metric]}' "$TMP_DIR/admin-metrics.txt" | sort)"
if [ -n "$duplicate_metric_types" ]; then
    echo "ERROR: admin metrics must emit one TYPE line per metric family" >&2
    echo "$duplicate_metric_types" >&2
    exit 1
fi
if grep -Eq '^bongsu_.*_metrics_error ' "$TMP_DIR/admin-metrics.txt"; then
    echo "ERROR: admin metrics reported one or more metrics_error gauges" >&2
    grep -E '^bongsu_.*_metrics_error ' "$TMP_DIR/admin-metrics.txt" >&2
    exit 1
fi
for metric in \
    '^bongsu_security_recalculation_running ' \
    '^bongsu_security_recalculation_pending '; do
    if ! grep -Eq "$metric" "$TMP_DIR/admin-metrics.txt"; then
        echo "ERROR: admin metrics missing ${metric}" >&2
        sed -n '1,160p' "$TMP_DIR/admin-metrics.txt" >&2
        exit 1
    fi
done
if ! grep -Eq '^bongsu_security_db_revision_info[{]revision="|^bongsu_security_db_revision_metrics_error ' "$TMP_DIR/admin-metrics.txt"; then
    echo "ERROR: admin metrics must expose security DB revision info or revision metrics error" >&2
    sed -n '1,160p' "$TMP_DIR/admin-metrics.txt" >&2
    exit 1
fi
if ! grep -Eq '^bongsu_security_db_effective_status[{]status="ok"} |^bongsu_security_db_freshness_metrics_error ' "$TMP_DIR/admin-metrics.txt"; then
    echo "ERROR: admin metrics must expose effective security DB status or freshness metrics error" >&2
    sed -n '1,200p' "$TMP_DIR/admin-metrics.txt" >&2
    exit 1
fi
if ! grep -Eq '^bongsu_security_db_effective_source_info[{]source="|^bongsu_security_db_freshness_metrics_error ' "$TMP_DIR/admin-metrics.txt"; then
    echo "ERROR: admin metrics must expose effective security DB source info or freshness metrics error" >&2
    sed -n '1,200p' "$TMP_DIR/admin-metrics.txt" >&2
    exit 1
fi
if ! grep -Eq '^bongsu_security_db_effective_last_sync_timestamp_seconds |^bongsu_security_db_freshness_metrics_error ' "$TMP_DIR/admin-metrics.txt"; then
    echo "ERROR: admin metrics must expose effective security DB last sync timestamp or freshness metrics error" >&2
    sed -n '1,200p' "$TMP_DIR/admin-metrics.txt" >&2
    exit 1
fi
if ! grep -Eq '^bongsu_security_db_effective_age_seconds |^bongsu_security_db_freshness_metrics_error ' "$TMP_DIR/admin-metrics.txt"; then
    echo "ERROR: admin metrics must expose effective security DB age or freshness metrics error" >&2
    sed -n '1,200p' "$TMP_DIR/admin-metrics.txt" >&2
    exit 1
fi
if ! grep -Eq '^bongsu_security_source_registry_ok_sources |^bongsu_security_source_registry_metrics_error ' "$TMP_DIR/admin-metrics.txt"; then
    echo "ERROR: admin metrics must expose security source registry health or registry metrics error" >&2
    sed -n '1,200p' "$TMP_DIR/admin-metrics.txt" >&2
    exit 1
fi
if ! grep -Eq '^bongsu_security_source_registry_records[{]category="[^"]+",source="osv",status="ok"} |^bongsu_security_source_registry_metrics_error ' "$TMP_DIR/admin-metrics.txt"; then
    echo "ERROR: admin metrics must expose OSV source registry record counts or registry metrics error" >&2
    sed -n '1,240p' "$TMP_DIR/admin-metrics.txt" >&2
    exit 1
fi
if ! grep -Eq '^bongsu_security_source_registry_export_stale_sources |^bongsu_security_source_registry_metrics_error ' "$TMP_DIR/admin-metrics.txt"; then
    echo "ERROR: admin metrics must expose stale security DB export source counts or registry metrics error" >&2
    sed -n '1,240p' "$TMP_DIR/admin-metrics.txt" >&2
    exit 1
fi
if ! grep -Eq '^bongsu_cve_affected_package_index_coverage_percent |^bongsu_cve_affected_package_index_metrics_error ' "$TMP_DIR/admin-metrics.txt"; then
    echo "ERROR: admin metrics must expose affected-package index coverage or metrics error" >&2
    sed -n '1,160p' "$TMP_DIR/admin-metrics.txt" >&2
    exit 1
fi
if ! grep -Eq '^bongsu_cve_reference_key_index_coverage_percent |^bongsu_cve_reference_key_index_metrics_error ' "$TMP_DIR/admin-metrics.txt"; then
    echo "ERROR: admin metrics must expose reference-key index coverage or metrics error" >&2
    sed -n '1,160p' "$TMP_DIR/admin-metrics.txt" >&2
    exit 1
fi
if ! grep -Eq '^bongsu_cve_epss_enriched_records |^bongsu_cve_epss_merge_metrics_error ' "$TMP_DIR/admin-metrics.txt"; then
    echo "ERROR: admin metrics must expose EPSS enrichment metrics or metrics error" >&2
    sed -n '1,160p' "$TMP_DIR/admin-metrics.txt" >&2
    exit 1
fi
if ! grep -Eq '^bongsu_cve_osv_ecosystem_indexed_rows[{]ecosystem="|^bongsu_cve_osv_ecosystem_metrics_error ' "$TMP_DIR/admin-metrics.txt"; then
    echo "ERROR: admin metrics must expose OSV ecosystem freshness metrics or metrics error" >&2
    sed -n '1,200p' "$TMP_DIR/admin-metrics.txt" >&2
    exit 1
fi
if ! grep -Eq '^bongsu_agent_fleet_degraded |^bongsu_agent_metrics_error ' "$TMP_DIR/admin-metrics.txt"; then
    echo "ERROR: admin metrics must expose agent fleet operational status or metrics error" >&2
    sed -n '1,200p' "$TMP_DIR/admin-metrics.txt" >&2
    exit 1
fi
if ! grep -Eq '^bongsu_agent_fleet_warnings |^bongsu_agent_metrics_error ' "$TMP_DIR/admin-metrics.txt"; then
    echo "ERROR: admin metrics must expose agent fleet warning count or metrics error" >&2
    sed -n '1,200p' "$TMP_DIR/admin-metrics.txt" >&2
    exit 1
fi
if ! grep -Eq '^bongsu_agent_outdated_percent |^bongsu_agent_metrics_error ' "$TMP_DIR/admin-metrics.txt"; then
    echo "ERROR: admin metrics must expose agent outdated percentage or metrics error" >&2
    sed -n '1,200p' "$TMP_DIR/admin-metrics.txt" >&2
    exit 1
fi
if ! grep -Eq '^bongsu_security_db_rescan_open |^bongsu_security_db_rescan_metrics_error |^bongsu_security_db_revision_metrics_error ' "$TMP_DIR/admin-metrics.txt"; then
    echo "ERROR: admin metrics must expose security DB rescan metrics or metrics error" >&2
    sed -n '1,160p' "$TMP_DIR/admin-metrics.txt" >&2
    exit 1
fi

if [ -n "$ADMIN_USERNAME" ] && [ -n "$ADMIN_PASSWORD" ]; then
    echo "[4/11] Checking local session login"
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
    echo "[4/11] Skipping local session login; set BONGSU_ADMIN_USERNAME and BONGSU_ADMIN_PASSWORD to verify it"
fi

echo "[5/11] Checking scheduled scan CRUD contract"
schedules_json="$(api_json GET /api/admin/schedules)"
assert_json "$schedules_json" '.items | type == "array"' "schedule list must return an items array"
schedule_body="$(jq -nc --arg name "$RUN_ID schedule" '{name:$name, cron_expr:"0 */6 * * *", scan_type:"manual", packages_only:true, enabled:false}')"
schedule_json="$(api_json POST /api/admin/schedules "$schedule_body")"
SCHEDULE_ID="$(jq -r '.id' <<<"$schedule_json")"
assert_json "$schedule_json" '.scan_type == "manual" and .packages_only == true and .enabled == false' "created schedule must preserve scan_type/manual and packages_only=true"
schedule_get="$(api_json GET "/api/admin/schedules/${SCHEDULE_ID}")"
assert_json "$schedule_get" '.id and .packages_only == true' "schedule get must return created packages-only schedule"

echo "[6/11] Checking dynamic asset group contract and scan trigger"
groups_json="$(api_json GET /api/asset-groups)"
assert_json "$groups_json" '.items | type == "array"' "asset group list must return an items array"
subjects_json="$(api_json GET /api/admin/rbac/subjects)"
assert_json "$subjects_json" '.items | type == "array"' "RBAC subject list must return a stable items array"
policies_json="$(api_json GET /api/admin/rbac/policies)"
assert_json "$policies_json" '.items | type == "array"' "RBAC policy list must return a stable items array"
rbac_status_json="$(api_json GET /api/admin/rbac/status)"
assert_json "$rbac_status_json" '.status and (.stats.subject_count | type == "number") and (.stats.policy_count | type == "number") and (.stats.orphan_policy_count | type == "number") and (.stats.subject_type_counts | type == "object") and (.stats.resource_type_counts | type == "object") and (.stats.permission_counts | type == "object") and (.auth.viewer_key_count | type == "number") and (.auth.trusted_identity_configured | type == "boolean") and (.auth.trusted_proxy_cidr_count | type == "number")' "RBAC status must expose subject, policy, orphan, distribution, and auth configuration counters"
group_body="$(jq -nc --arg name "$RUN_ID asset group" '{name:$name, description:"operator verifier", rule_type:"dynamic", rule_expr:"team=platform"}')"
group_json="$(api_json POST /api/asset-groups "$group_body")"
ASSET_GROUP_ID="$(jq -r '.id' <<<"$group_json")"
assert_json "$group_json" '.rule_type == "dynamic" and .rule_expr == "team=platform"' "asset group must preserve rule_type and rule_expr"
group_scan="$(api_json POST "/api/asset-groups/${ASSET_GROUP_ID}/scan" '{}')"
assert_json "$group_scan" '.status == "ok" and (.queued | type == "number") and (.total | type == "number")' "asset group scan trigger must report queued and total counts"

echo "[7/11] Checking report surfaces"
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

echo "[8/11] Checking retention dry-run contract"
retention_body="$(jq -nc '{dry_run:true, scan_days:9999, request_days:9999, audit_days:9999}')"
retention_json="$(api_json POST /api/admin/retention/prune "$retention_body")"
assert_json "$retention_json" '.dry_run == true and .scan_days == 9999 and .request_days == 9999 and .audit_days == 9999' "retention dry-run must preserve requested retention windows"
assert_json "$retention_json" '(.scan_cutoff | type == "string") and (.request_cutoff | type == "string") and (.audit_cutoff | type == "string")' "retention dry-run must expose reproducible cutoff timestamps"
assert_json "$retention_json" '(.scans | type == "number") and (.packages | type == "number") and (.vulnerabilities | type == "number") and (.containers | type == "number") and (.users | type == "number") and (.processes | type == "number") and (.ports | type == "number") and (.scan_requests | type == "number") and (.audit_logs | type == "number")' "retention dry-run must expose numeric blast-radius counters"
retention_audit_json="$(api_json GET '/api/admin/audit-logs?action=retention.prune&status=dry_run&limit=10')"
assert_json "$retention_audit_json" '.items[] | select(.action == "retention.prune" and .status == "dry_run")' "retention dry-run must be audited"

echo "[9/11] Checking notification rule contract"
rules_json="$(api_json GET /api/admin/notification-rules)"
assert_json "$rules_json" '.items | type == "array"' "notification rules list must return an items array"
cat > "$TMP_DIR/webhook_receiver.py" <<'PY'
import hashlib
import hmac
import http.server
import json
import os
import socketserver
import sys

secret, port_file, log_file = sys.argv[1:]
state = {"count": 0}

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        state["count"] += 1
        expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        entry = {
            "attempt": state["count"],
            "path": self.path,
            "event": self.headers.get("X-Bongsu-Event", ""),
            "rule_id": self.headers.get("X-Bongsu-Rule-ID", ""),
            "signature_ok": self.headers.get("X-Bongsu-Signature-256", "") == expected,
            "payload": json.loads(body.decode("utf-8")),
        }
        with open(log_file, "a", encoding="utf-8") as out:
            out.write(json.dumps(entry, separators=(",", ":")) + "\n")
        if state["count"] == 1:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"retry me")
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

with socketserver.TCPServer(("127.0.0.1", 0), Handler) as httpd:
    with open(port_file, "w", encoding="utf-8") as out:
        out.write(str(httpd.server_address[1]))
    httpd.serve_forever()
PY
WEBHOOK_SECRET="secret-${RUN_ID}"
python3 "$TMP_DIR/webhook_receiver.py" "$WEBHOOK_SECRET" "$TMP_DIR/webhook.port" "$TMP_DIR/webhook.log" &
WEBHOOK_PID="$!"
for _ in $(seq 1 50); do
    if [ -s "$TMP_DIR/webhook.port" ]; then
        break
    fi
    sleep 0.1
done
if [ ! -s "$TMP_DIR/webhook.port" ]; then
    echo "ERROR: local webhook receiver did not start" >&2
    exit 1
fi
WEBHOOK_PORT="$(cat "$TMP_DIR/webhook.port")"
rule_body="$(jq -nc --arg name "$RUN_ID notification" --arg url "http://127.0.0.1:${WEBHOOK_PORT}/notify" --arg secret "$WEBHOOK_SECRET" '{name:$name, trigger_event:"security_db.updated", min_severity:"HIGH", channel_type:"webhook", channel_config:{url:$url,secret:$secret}, enabled:true}')"
rule_json="$(api_json POST /api/admin/notification-rules "$rule_body")"
NOTIFICATION_RULE_ID="$(jq -r '.id' <<<"$rule_json")"
assert_json "$rule_json" '.trigger_event == "security_db.updated" and .channel_type == "webhook" and .enabled == true and .channel_config.url' "notification rule must preserve trigger/channel/config/enabled"
test_json="$(api_json POST "/api/admin/notification-rules/${NOTIFICATION_RULE_ID}/test" '{}')"
assert_json "$test_json" '.status == "sent"' "webhook notification test must retry transient failures and return sent"
python3 - "$TMP_DIR/webhook.log" "$NOTIFICATION_RULE_ID" <<'PY'
import json
import sys

path, rule_id = sys.argv[1:]
with open(path, "r", encoding="utf-8") as fh:
    rows = [json.loads(line) for line in fh if line.strip()]
if len(rows) != 2:
    raise SystemExit(f"expected exactly two webhook attempts, got {len(rows)}")
if not all(row.get("signature_ok") for row in rows):
    raise SystemExit("webhook signature verification failed")
if rows[-1].get("event") != "test" or rows[-1].get("rule_id") != rule_id:
    raise SystemExit(f"unexpected final webhook headers: {rows[-1]}")
if rows[-1].get("payload", {}).get("rule_id") != rule_id:
    raise SystemExit(f"unexpected final webhook payload: {rows[-1]}")
PY
log_json="$(api_json GET "/api/admin/notification-log?rule_id=${NOTIFICATION_RULE_ID}&limit=20")"
assert_json "$log_json" '.items | type == "array"' "notification log must return an items array"

echo "[10/11] Checking agent claim, report, and scan-request completion"
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
host_users_json="$(api_json GET "/api/hosts/${VERIFY_HOST_ID}/users?limit=20")"
assert_json "$host_users_json" '.total >= 1 and (.items[] | select(.username == "bongsu-operator-user" and .uid == 4242 and .gid == 4242))' "host user runtime inventory endpoint must expose latest reported user accounts"
host_processes_json="$(api_json GET "/api/hosts/${VERIFY_HOST_ID}/processes?limit=20")"
assert_json "$host_processes_json" '.total >= 1 and (.items[] | select(.name == "bongsu-operator-process" and .pid == 4242 and .user == "bongsu-operator-user"))' "host process runtime inventory endpoint must expose latest reported process snapshot"
host_ports_json="$(api_json GET "/api/hosts/${VERIFY_HOST_ID}/ports?limit=20")"
assert_json "$host_ports_json" '.total >= 1 and (.items[] | select(.name == "bongsu-operator-listener" and .port == 45678 and .address == "127.0.0.1"))' "host port runtime inventory endpoint must expose latest reported listening ports"
complete_json="$(agent_json POST "/api/agent/scan-requests/${SCAN_REQUEST_ID}/complete" "$(jq -nc --arg host_id "$VERIFY_HOST_ID" '{host_id:$host_id, status:"completed", message:"operator verifier complete"}')")"
assert_json "$complete_json" '.status == "completed"' "agent completion endpoint must accept the claimed host"
request_done="$(api_json GET "/api/scan-requests?host_id=${VERIFY_HOST_ID}&limit=5")"
assert_json_arg "$request_done" id "$SCAN_REQUEST_ID" '.items[] | select(.id == $id and .status == "completed" and .claimed_by_host_id != "")' "scan request list must show the verifier request completed by the agent"
scans_done="$(api_json GET "/api/scans?host_id=${VERIFY_HOST_ID}&limit=5")"
assert_json_arg "$scans_done" request_id "$SCAN_REQUEST_ID" '.items[] | select(.scan_request_id == $request_id and .status == "completed" and .package_count >= 1)' "scan list must show a completed inventory scan tied to the request"
SCAN_REQUEST_ID=""

echo "[11/11] Checking backup and restore dry-run surfaces"
BONGSU_DB_PASSWORD="${BONGSU_DB_PASSWORD:-}" "$ROOT/scripts/backup.sh" --dry-run "$TMP_DIR/backup.tar.gz" | grep -q 'Dry-run complete'
mkdir -p "$TMP_DIR/restore-src"
printf 'fixture\n' > "$TMP_DIR/restore-src/database.dump"
printf '{"format_version":1,"database":"bongsu"}\n' > "$TMP_DIR/restore-src/manifest.json"
tar -C "$TMP_DIR/restore-src" -czf "$TMP_DIR/restore-fixture.tar.gz" database.dump manifest.json
BONGSU_DB_PASSWORD="${BONGSU_DB_PASSWORD:-}" "$ROOT/scripts/restore.sh" --dry-run "$TMP_DIR/restore-fixture.tar.gz" | grep -q 'Dry-run complete'

echo "Live operator workflow verification passed"
