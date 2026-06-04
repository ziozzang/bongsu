#!/bin/bash
set -euo pipefail

# verify-live-scan-request-recovery.sh - Exercise live stale scan-request
# recovery. It creates a host-specific request, claims it as an agent, ages the
# claim in PostgreSQL, requeues stale claims through the admin API, and proves
# the request is pending/claimable again.

API_BASE="${BONGSU_API_BASE:-http://127.0.0.1:5677}"
API_KEY="${BONGSU_API_KEY:-test-admin-key-0123456789}"
AGENT_API_KEY="${BONGSU_AGENT_API_KEY:-test-agent-key-0123456789}"
CURL_MAX_TIME="${BONGSU_VERIFY_CURL_MAX_TIME_SECONDS:-30}"
BONGSU_DB_DSN="${BONGSU_DB_DSN:-}"
BONGSU_DB_PSQL_CONTAINER="${BONGSU_DB_PSQL_CONTAINER:-bongsu-postgres}"
RUN_ID="scan-recovery-$(date -u +%Y%m%dT%H%M%SZ)-$$"
HOST_ID="host-${RUN_ID}"
AGENT_TOKEN="token-${RUN_ID}-0123456789abcdef"
SCAN_REQUEST_ID=""
PSQL_MODE=""
TMP_DIR="$(mktemp -d)"

cleanup() {
    set +e
    if [ -n "$SCAN_REQUEST_ID" ]; then
        curl -fsS --max-time "$CURL_MAX_TIME" -X POST -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/scan-requests/${SCAN_REQUEST_ID}/cancel" >/dev/null 2>&1
    fi
    curl -fsS --max-time "$CURL_MAX_TIME" -X DELETE -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/hosts/${HOST_ID}" >/dev/null 2>&1
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: missing required tool: $1" >&2
        exit 1
    fi
}

prepare_db_checks() {
    if [ -z "$BONGSU_DB_DSN" ]; then
        echo "ERROR: BONGSU_DB_DSN is required for stale scan-request recovery verification" >&2
        exit 1
    fi
    if command -v psql >/dev/null 2>&1; then
        PSQL_MODE="local"
        return
    fi
    if command -v docker >/dev/null 2>&1 && docker inspect "$BONGSU_DB_PSQL_CONTAINER" >/dev/null 2>&1; then
        PSQL_MODE="docker"
        return
    fi
    echo "ERROR: neither local psql nor docker container ${BONGSU_DB_PSQL_CONTAINER} is available" >&2
    exit 1
}

db_exec() {
    local sql="$1"
    if [ "$PSQL_MODE" = "local" ]; then
        psql "$BONGSU_DB_DSN" -X -A -t -v ON_ERROR_STOP=1 -c "$sql" >/dev/null
    else
        docker exec -i "$BONGSU_DB_PSQL_CONTAINER" psql "$BONGSU_DB_DSN" -X -A -t -v ON_ERROR_STOP=1 -c "$sql" >/dev/null
    fi
}

sql_literal() {
    python3 - "$1" <<'PY'
import sys
print("'" + sys.argv[1].replace("'", "''") + "'")
PY
}

api_json() {
    local method="$1"
    local path="$2"
    local body="${3:-}"
    local out="$TMP_DIR/admin-response.json"
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
        echo "ERROR: admin ${method} ${path} returned HTTP ${status}" >&2
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
            -H "X-Bongsu-Agent-Token: ${AGENT_TOKEN}" \
            -H "X-Bongsu-Host-ID: ${HOST_ID}" \
            -H "Content-Type: application/json" \
            --data "$body" \
            "${API_BASE}${path}")"
    else
        status="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$out" -w "%{http_code}" -X "$method" \
            -H "X-API-Key: ${AGENT_API_KEY}" \
            -H "X-Bongsu-Agent-Token: ${AGENT_TOKEN}" \
            -H "X-Bongsu-Host-ID: ${HOST_ID}" \
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
    jq -nc \
        --arg host_id "$HOST_ID" \
        --arg scan_id "$scan_id" \
        --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{
          host: {
            id: $host_id,
            hostname: $host_id,
            ip_address: "127.0.0.1",
            os_name: "Ubuntu",
            os_version: "22.04",
            kernel: "scan-request-recovery-verifier",
            arch: "amd64",
            cpu_model: "verifier",
            cpu_cores: 1,
            memory_mb: 512,
            agent_version: "scan-request-recovery-verifier"
          },
          scan_type: "manual",
          scan_id: $scan_id,
          packages: [
            {
              source: "dpkg",
              name: "bongsu-scan-recovery-fixture",
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
require_tool python3
prepare_db_checks

echo "=== Bongsu Live Scan Request Recovery Verification ==="
echo "API:  ${API_BASE}"
echo "Host: ${HOST_ID}"

echo "[1/5] Enrolling verifier host and creating a scan request"
curl -fsS --max-time "$CURL_MAX_TIME" "${API_BASE}/api/ready" | jq -e '.status == "ready"' >/dev/null
agent_json POST /api/report "$(scan_report_json "$(new_uuid)")" | jq -e '.status == "ok" and .scan_status == "completed"' >/dev/null
request_body="$(jq -nc --arg host_id "$HOST_ID" '{host_id:$host_id, scan_type:"manual", packages_only:true, reason:"scan request recovery verifier"}')"
request_json="$(api_json POST /api/scan-requests "$request_body")"
SCAN_REQUEST_ID="$(jq -r '.id' <<<"$request_json")"
assert_json "$request_json" '.status == "pending" and .packages_only == true' "created scan request must be pending packages-only"

echo "[2/5] Claiming and aging the request"
claim_json="$(agent_json POST "/api/agent/scan-requests/claim?host_id=${HOST_ID}")"
assert_json_arg "$claim_json" id "$SCAN_REQUEST_ID" '.request.id == $id and .request.status == "claimed" and .request.claimed_by_host_id != ""' "agent must claim the verifier request"
request_literal="$(sql_literal "$SCAN_REQUEST_ID")"
db_exec "UPDATE scan_requests SET claimed_at = now() - interval '2 hours' WHERE id = ${request_literal} AND status = 'claimed'"
stale_json="$(api_json GET "/api/scan-requests?host_id=${HOST_ID}&status=claimed&stale=true&limit=10")"
assert_json_arg "$stale_json" id "$SCAN_REQUEST_ID" '.items[] | select(.id == $id and .status == "claimed" and .claim_stale == true and .claim_age_seconds >= 3600)' "aged claimed request must appear in stale claimed list"

echo "[3/5] Requeueing stale claimed requests through the admin API"
requeue_json="$(api_json POST /api/scan-requests/requeue-stale "$(jq -nc '{timeout_minutes:60}')")"
assert_json "$requeue_json" '.status == "ok" and (.requeued // 0) >= 1' "stale requeue API must report at least one requeued request"
pending_json="$(api_json GET "/api/scan-requests?host_id=${HOST_ID}&status=pending&limit=10")"
assert_json_arg "$pending_json" id "$SCAN_REQUEST_ID" '.items[] | select(.id == $id and .status == "pending" and (.claimed_by_host_id // "") == "" and (.error_message // "") == "requeued after claim timeout")' "requeued stale request must return to pending state and clear claim ownership"

echo "[4/5] Verifying the requeued request is claimable again"
claim_again_json="$(agent_json POST "/api/agent/scan-requests/claim?host_id=${HOST_ID}")"
assert_json_arg "$claim_again_json" id "$SCAN_REQUEST_ID" '.request.id == $id and .request.status == "claimed" and .request.claimed_by_host_id != ""' "requeued request must be claimable again"

echo "[5/5] Checking stale requeue audit evidence"
audit_json="$(api_json GET "/api/admin/audit-logs?action=scan_request.requeue_stale&resource_type=scan_request&limit=20")"
assert_json "$audit_json" '.items[] | select(.action == "scan_request.requeue_stale" and .status == "ok" and ((.metadata.requeued // 0) >= 1))' "stale requeue must be audited with requeued count"

echo "Live scan request recovery verification passed"
