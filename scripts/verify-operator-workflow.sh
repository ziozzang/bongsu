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
ADMIN_USERNAME="${BONGSU_ADMIN_USERNAME:-}"
ADMIN_PASSWORD="${BONGSU_ADMIN_PASSWORD:-}"
CURL_MAX_TIME="${BONGSU_VERIFY_CURL_MAX_TIME_SECONDS:-20}"
RUN_ID="operator-verify-$(date -u +%Y%m%dT%H%M%SZ)-$$"

SCHEDULE_ID=""
ASSET_GROUP_ID=""
NOTIFICATION_RULE_ID=""
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

require_tool curl
require_tool jq
require_tool tar

echo "=== Bongsu Live Operator Workflow Verification ==="
echo "API: ${API_BASE}"

echo "[1/8] Checking liveness and readiness"
curl -fsS --max-time "$CURL_MAX_TIME" "${API_BASE}/api/live" | jq -e '.status == "alive"' >/dev/null
curl -fsS --max-time "$CURL_MAX_TIME" "${API_BASE}/api/ready" | jq -e '.status == "ready"' >/dev/null

echo "[2/8] Checking OpenAPI documentation endpoint"
curl -fsS --max-time "$CURL_MAX_TIME" "${API_BASE}/api/docs/openapi.yaml" -o "$TMP_DIR/openapi.yaml"
grep -Eq '^openapi: "?3\.' "$TMP_DIR/openapi.yaml"
grep -q '/api/admin/schedules:' "$TMP_DIR/openapi.yaml"
grep -q '/api/asset-groups:' "$TMP_DIR/openapi.yaml"
grep -q '/api/admin/notification-rules:' "$TMP_DIR/openapi.yaml"

if [ -n "$ADMIN_USERNAME" ] && [ -n "$ADMIN_PASSWORD" ]; then
    echo "[3/8] Checking local session login"
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
    echo "[3/8] Skipping local session login; set BONGSU_ADMIN_USERNAME and BONGSU_ADMIN_PASSWORD to verify it"
fi

echo "[4/8] Checking scheduled scan CRUD contract"
schedules_json="$(api_json GET /api/admin/schedules)"
assert_json "$schedules_json" '.items | type == "array"' "schedule list must return an items array"
schedule_body="$(jq -nc --arg name "$RUN_ID schedule" '{name:$name, cron_expr:"0 */6 * * *", scan_type:"manual", packages_only:true, enabled:false}')"
schedule_json="$(api_json POST /api/admin/schedules "$schedule_body")"
SCHEDULE_ID="$(jq -r '.id' <<<"$schedule_json")"
assert_json "$schedule_json" '.scan_type == "manual" and .packages_only == true and .enabled == false' "created schedule must preserve scan_type/manual and packages_only=true"
schedule_get="$(api_json GET "/api/admin/schedules/${SCHEDULE_ID}")"
assert_json "$schedule_get" '.id and .packages_only == true' "schedule get must return created packages-only schedule"

echo "[5/8] Checking dynamic asset group contract and scan trigger"
groups_json="$(api_json GET /api/asset-groups)"
assert_json "$groups_json" '.items | type == "array"' "asset group list must return an items array"
group_body="$(jq -nc --arg name "$RUN_ID asset group" '{name:$name, description:"operator verifier", rule_type:"dynamic", rule_expr:"team=platform"}')"
group_json="$(api_json POST /api/asset-groups "$group_body")"
ASSET_GROUP_ID="$(jq -r '.id' <<<"$group_json")"
assert_json "$group_json" '.rule_type == "dynamic" and .rule_expr == "team=platform"' "asset group must preserve rule_type and rule_expr"
group_scan="$(api_json POST "/api/asset-groups/${ASSET_GROUP_ID}/scan" '{}')"
assert_json "$group_scan" '.status == "ok" and (.queued | type == "number") and (.total | type == "number")' "asset group scan trigger must report queued and total counts"

echo "[6/8] Checking report surfaces"
executive_json="$(api_json GET /api/reports/executive-summary)"
assert_json "$executive_json" '.generated_at and (.total_hosts | type == "number")' "executive summary must expose generated_at and numeric host count"
risk_json="$(api_json GET '/api/reports/risk-breakdown?group_by=owner')"
assert_json "$risk_json" '.group_by == "owner" and (.items | type == "array")' "risk breakdown must preserve group_by and items"
api_json GET '/api/reports/export?format=json&type=executive' | jq -e '.generated_at' >/dev/null

echo "[7/8] Checking notification rule contract"
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

echo "[8/8] Checking backup and restore dry-run surfaces"
BONGSU_DB_PASSWORD="${BONGSU_DB_PASSWORD:-}" "$ROOT/scripts/backup.sh" --dry-run "$TMP_DIR/backup.tar.gz" | grep -q 'Dry-run complete'
mkdir -p "$TMP_DIR/restore-src"
printf 'fixture\n' > "$TMP_DIR/restore-src/database.dump"
printf '{"format_version":1,"database":"bongsu"}\n' > "$TMP_DIR/restore-src/manifest.json"
tar -C "$TMP_DIR/restore-src" -czf "$TMP_DIR/restore-fixture.tar.gz" database.dump manifest.json
BONGSU_DB_PASSWORD="${BONGSU_DB_PASSWORD:-}" "$ROOT/scripts/restore.sh" --dry-run "$TMP_DIR/restore-fixture.tar.gz" | grep -q 'Dry-run complete'

echo "Live operator workflow verification passed"
