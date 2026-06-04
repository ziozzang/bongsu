#!/bin/bash
set -euo pipefail

# verify-live-agent-token-binding.sh - Exercise live agent host-token binding.
#
# The API must run with BONGSU_AGENT_HOST_BINDING=true, which is the production
# default. The verifier binds one host to a primary token, then proves a
# different token cannot report, claim, or complete work for that host.

API_BASE="${BONGSU_API_BASE:-http://127.0.0.1:5677}"
API_KEY="${BONGSU_API_KEY:-test-admin-key}"
AGENT_API_KEY="${BONGSU_AGENT_API_KEY:-test-agent-key}"
CURL_MAX_TIME="${BONGSU_VERIFY_CURL_MAX_TIME_SECONDS:-20}"
RUN_ID="agent-binding-$(date -u +%Y%m%dT%H%M%SZ)-$$"
HOST_ID="host-${RUN_ID}"
PRIMARY_TOKEN="primary-agent-token-${RUN_ID}-0123456789abcdef"
SECONDARY_TOKEN="secondary-agent-token-${RUN_ID}-0123456789abcdef"
SCAN_REQUEST_ID=""
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

agent_status() {
    local token="$1"
    local method="$2"
    local path="$3"
    local body="${4:-}"
    local out="$TMP_DIR/agent-response.json"
    if [ -n "$body" ]; then
        curl -sS --max-time "$CURL_MAX_TIME" -o "$out" -w "%{http_code}" -X "$method" \
            -H "X-API-Key: ${AGENT_API_KEY}" \
            -H "X-Bongsu-Agent-Token: ${token}" \
            -H "X-Bongsu-Host-ID: ${HOST_ID}" \
            -H "Content-Type: application/json" \
            --data "$body" \
            "${API_BASE}${path}"
    else
        curl -sS --max-time "$CURL_MAX_TIME" -o "$out" -w "%{http_code}" -X "$method" \
            -H "X-API-Key: ${AGENT_API_KEY}" \
            -H "X-Bongsu-Agent-Token: ${token}" \
            -H "X-Bongsu-Host-ID: ${HOST_ID}" \
            "${API_BASE}${path}"
    fi
}

agent_json() {
    local token="$1"
    local method="$2"
    local path="$3"
    local body="${4:-}"
    local status
    status="$(agent_status "$token" "$method" "$path" "$body")"
    if [[ "$status" != 2* ]]; then
        echo "ERROR: agent ${method} ${path} returned HTTP ${status}" >&2
        cat "$TMP_DIR/agent-response.json" >&2 || true
        exit 1
    fi
    cat "$TMP_DIR/agent-response.json"
}

assert_status() {
    local status="$1"
    local want="$2"
    local message="$3"
    if [ "$status" != "$want" ]; then
        echo "ERROR: ${message}; got HTTP ${status}, want ${want}" >&2
        cat "$TMP_DIR/agent-response.json" >&2 || true
        exit 1
    fi
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
            kernel: "agent-token-binding-verifier",
            arch: "amd64",
            cpu_model: "verifier",
            cpu_cores: 1,
            memory_mb: 512,
            agent_version: "agent-token-binding-verifier"
          },
          scan_type: "manual",
          scan_id: $scan_id,
          packages: [
            {
              source: "dpkg",
              name: "bongsu-agent-token-binding-fixture",
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

new_uuid() {
    if [ -r /proc/sys/kernel/random/uuid ]; then
        cat /proc/sys/kernel/random/uuid
        return
    fi
    local hex
    hex="$(date +%s%N)$$"
    printf '00000000-0000-4000-8000-%012d\n' "$((hex % 1000000000000))"
}

require_tool curl
require_tool jq

echo "=== Bongsu Live Agent Token Binding Verification ==="
echo "API:  ${API_BASE}"
echo "Host: ${HOST_ID}"

echo "[1/4] Checking API readiness"
curl -fsS --max-time "$CURL_MAX_TIME" "${API_BASE}/api/ready" | jq -e '.status == "ready"' >/dev/null

echo "[2/4] Binding host to the primary agent token"
primary_report="$(scan_report_json "$(new_uuid)")"
agent_json "$PRIMARY_TOKEN" POST /api/report "$primary_report" | jq -e '.status == "ok"' >/dev/null

echo "[3/4] Verifying a different token cannot report or claim for the bound host"
secondary_report="$(scan_report_json "$(new_uuid)")"
status="$(agent_status "$SECONDARY_TOKEN" POST /api/report "$secondary_report")"
assert_status "$status" "403" "secondary token must not report for a host bound to the primary token"
status="$(agent_status "$SECONDARY_TOKEN" POST "/api/agent/scan-requests/claim?host_id=${HOST_ID}")"
assert_status "$status" "403" "secondary token must not claim scan requests for a host bound to the primary token"

echo "[4/4] Verifying completion is also host-token bound"
request_body="$(jq -nc --arg host_id "$HOST_ID" '{host_id:$host_id, scan_type:"manual", packages_only:true, reason:"agent token binding verifier"}')"
request_json="$(api_json POST /api/scan-requests "$request_body")"
SCAN_REQUEST_ID="$(jq -r '.id' <<<"$request_json")"
claim_json="$(agent_json "$PRIMARY_TOKEN" POST "/api/agent/scan-requests/claim?host_id=${HOST_ID}")"
jq -e --arg id "$SCAN_REQUEST_ID" '.request.id == $id' >/dev/null <<<"$claim_json"
complete_body="$(jq -nc --arg host_id "$HOST_ID" '{host_id:$host_id, status:"completed", message:"binding verifier"}')"
status="$(agent_status "$SECONDARY_TOKEN" POST "/api/agent/scan-requests/${SCAN_REQUEST_ID}/complete" "$complete_body")"
assert_status "$status" "403" "secondary token must not complete requests for a host bound to the primary token"
agent_json "$PRIMARY_TOKEN" POST "/api/agent/scan-requests/${SCAN_REQUEST_ID}/complete" "$complete_body" | jq -e '.status == "completed"' >/dev/null
SCAN_REQUEST_ID=""

echo "Live agent token binding verification passed"
