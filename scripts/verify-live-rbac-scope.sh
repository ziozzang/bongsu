#!/bin/bash
set -euo pipefail

# verify-live-rbac-scope.sh - Exercise live viewer RBAC scoping across host,
# package, container, scan, and scan-request endpoints.
#
# The running API must be started with BONGSU_VIEWER_API_KEYS containing the
# supplied BONGSU_VIEWER_API_KEY mapped to BONGSU_VIEWER_SUBJECT.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API_BASE="${BONGSU_API_BASE:-http://127.0.0.1:5677}"
API_KEY="${BONGSU_API_KEY:-test-admin}"
AGENT_API_KEY="${BONGSU_AGENT_API_KEY:-test-agent-key}"
VIEWER_API_KEY="${BONGSU_VIEWER_API_KEY:-}"
VIEWER_SUBJECT="${BONGSU_VIEWER_SUBJECT:-}"
CURL_MAX_TIME="${BONGSU_VERIFY_CURL_MAX_TIME_SECONDS:-20}"
RUN_ID="rbac-live-$(date -u +%Y%m%dT%H%M%SZ)-$$"
ALLOWED_HOST_ID="host-${RUN_ID}-allowed"
DENIED_HOST_ID="host-${RUN_ID}-denied"
ALLOWED_CONTAINER_ID="container-${RUN_ID}-allowed"
DENIED_CONTAINER_ID="container-${RUN_ID}-denied"
SUBJECT_ID="subject-${RUN_ID}"
POLICY_ID="policy-${RUN_ID}"
SCAN_REQUEST_ID=""
SUBJECT_CREATED=0
TMP_DIR="$(mktemp -d)"

cleanup() {
    set +e
    if [ -n "$SCAN_REQUEST_ID" ]; then
        curl -fsS --max-time "$CURL_MAX_TIME" -X POST -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/scan-requests/${SCAN_REQUEST_ID}/cancel" >/dev/null 2>&1
    fi
    curl -fsS --max-time "$CURL_MAX_TIME" -X DELETE -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/admin/rbac/policies/${POLICY_ID}" >/dev/null 2>&1
    if [ "$SUBJECT_CREATED" = "1" ]; then
        curl -fsS --max-time "$CURL_MAX_TIME" -X DELETE -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/admin/rbac/subjects/${SUBJECT_ID}" >/dev/null 2>&1
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

agent_json_for_host() {
    local host_id="$1"
    local method="$2"
    local path="$3"
    local body="${4:-}"
    local out="$TMP_DIR/agent-response.json"
    local status
    status="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$out" -w "%{http_code}" -X "$method" \
        -H "X-API-Key: ${AGENT_API_KEY}" \
        -H "X-Bongsu-Agent-Token: token-${host_id}" \
        -H "X-Bongsu-Host-ID: ${host_id}" \
        -H "Content-Type: application/json" \
        --data "$body" \
        "${API_BASE}${path}")"
    if [[ "$status" != 2* ]]; then
        echo "ERROR: agent ${method} ${path} for ${host_id} returned HTTP ${status}" >&2
        cat "$out" >&2 || true
        exit 1
    fi
    cat "$out"
}

viewer_json() {
    local method="$1"
    local path="$2"
    local out="$TMP_DIR/viewer-response.json"
    local status
    status="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$out" -w "%{http_code}" -X "$method" \
        -H "X-API-Key: ${VIEWER_API_KEY}" \
        "${API_BASE}${path}")"
    if [[ "$status" != 2* ]]; then
        echo "ERROR: viewer ${method} ${path} returned HTTP ${status}" >&2
        cat "$out" >&2 || true
        exit 1
    fi
    cat "$out"
}

viewer_status() {
    local method="$1"
    local path="$2"
    local out="$TMP_DIR/viewer-status-response.json"
    curl -sS --max-time "$CURL_MAX_TIME" -o "$out" -w "%{http_code}" -X "$method" \
        -H "X-API-Key: ${VIEWER_API_KEY}" \
        "${API_BASE}${path}"
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

subject_type() {
    case "$VIEWER_SUBJECT" in
        group:*|group/*) printf 'group\n' ;;
        *) printf 'user\n' ;;
    esac
}

subject_external_id() {
    case "$VIEWER_SUBJECT" in
        user:*|group:*) printf '%s\n' "${VIEWER_SUBJECT#*:}" ;;
        user/*|group/*) printf '%s\n' "${VIEWER_SUBJECT#*/}" ;;
        *) printf '%s\n' "$VIEWER_SUBJECT" ;;
    esac
}

scan_report_json() {
    local host_id="$1"
    local container_id="$2"
    local scan_id="$3"
    local suffix="$4"
    jq -nc \
        --arg host_id "$host_id" \
        --arg container_id "$container_id" \
        --arg scan_id "$scan_id" \
        --arg suffix "$suffix" \
        --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{
          host: {
            id: $host_id,
            hostname: $host_id,
            ip_address: "127.0.0.1",
            os_name: "Ubuntu",
            os_version: "22.04",
            kernel: "live-rbac-verifier",
            arch: "amd64",
            cpu_model: "verifier",
            cpu_cores: 1,
            memory_mb: 512,
            agent_version: "live-rbac-verifier",
            owner: "security",
            team: ("rbac-" + $suffix),
            environment: "test",
            criticality: "medium"
          },
          scan_type: "manual",
          scan_id: $scan_id,
          containers: [
            {
              runtime: "docker",
              container_id: $container_id,
              name: ("bongsu-rbac-" + $suffix),
              image_name: ("registry.example/bongsu-rbac-" + $suffix + ":1.0"),
              image_id: ("sha256:" + $suffix),
              image_digest: ("sha256:" + $suffix + "digest"),
              state: "running"
            }
          ],
          packages: [
            {
              source: "dpkg",
              name: ("bongsu-rbac-host-" + $suffix),
              version: "1.0.0",
              arch: "amd64",
              pkg_type: "os",
              ecosystem: "ubuntu",
              asset_type: "host",
              asset_id: $host_id,
              target: "host"
            },
            {
              source: "trivy",
              name: ("bongsu-rbac-container-" + $suffix),
              version: "2.0.0",
              arch: "amd64",
              pkg_type: "os",
              ecosystem: "alpine",
              asset_type: "container",
              asset_id: $container_id,
              container: ("bongsu-rbac-" + $suffix),
              container_id: $container_id,
              image_name: ("registry.example/bongsu-rbac-" + $suffix + ":1.0"),
              image_id: ("sha256:" + $suffix),
              target: ("container:" + $container_id)
            }
          ],
          vulnerabilities: [],
          users: [],
          processes: [],
          ports: [],
          timestamp: $ts
        }'
}

require_tool curl
require_tool jq

if [ -z "$VIEWER_API_KEY" ] || [ -z "$VIEWER_SUBJECT" ]; then
    echo "ERROR: set BONGSU_VIEWER_API_KEY and BONGSU_VIEWER_SUBJECT for live RBAC verification" >&2
    echo "Example server env: BONGSU_VIEWER_API_KEYS=\"viewer-test-key:${VIEWER_SUBJECT:-rbac-live-viewer}\"" >&2
    exit 1
fi

echo "=== Bongsu Live RBAC Scope Verification ==="
echo "API:     ${API_BASE}"
echo "Subject: ${VIEWER_SUBJECT}"

echo "[1/6] Checking API readiness and viewer key authentication"
curl -fsS --max-time "$CURL_MAX_TIME" "${API_BASE}/api/ready" | jq -e '.status == "ready"' >/dev/null
viewer_status_code="$(viewer_status GET /api/hosts)"
if [ "$viewer_status_code" = "401" ]; then
    echo "ERROR: viewer key was rejected; restart API with BONGSU_VIEWER_API_KEYS mapping this key to ${VIEWER_SUBJECT}" >&2
    exit 1
fi
if [[ "$viewer_status_code" != 2* ]]; then
    echo "ERROR: viewer /api/hosts returned HTTP ${viewer_status_code}" >&2
    cat "$TMP_DIR/viewer-status-response.json" >&2 || true
    exit 1
fi

echo "[2/6] Ingesting allowed and denied host/container inventory fixtures"
allowed_report="$(scan_report_json "$ALLOWED_HOST_ID" "$ALLOWED_CONTAINER_ID" "$(new_uuid)" "allowed")"
denied_report="$(scan_report_json "$DENIED_HOST_ID" "$DENIED_CONTAINER_ID" "$(new_uuid)" "denied")"
agent_json_for_host "$ALLOWED_HOST_ID" POST /api/report "$allowed_report" | jq -e '.status == "ok"' >/dev/null
agent_json_for_host "$DENIED_HOST_ID" POST /api/report "$denied_report" | jq -e '.status == "ok"' >/dev/null

echo "[3/6] Creating viewer subject and host-scoped read policy"
subject_type_value="$(subject_type)"
subject_external_id_value="$(subject_external_id)"
subjects_json="$(api_json GET /api/admin/rbac/subjects)"
if ! jq -e --arg t "$subject_type_value" --arg e "$subject_external_id_value" '.items[] | select(.subject_type == $t and .external_id == $e)' >/dev/null <<<"$subjects_json"; then
    subject_body="$(jq -nc \
        --arg id "$SUBJECT_ID" \
        --arg subject_type "$subject_type_value" \
        --arg external_id "$subject_external_id_value" \
        --arg display_name "$RUN_ID viewer" \
        '{id:$id, subject_type:$subject_type, external_id:$external_id, display_name:$display_name}')"
    api_json POST /api/admin/rbac/subjects "$subject_body" | jq -e '.status == "ok"' >/dev/null
    SUBJECT_CREATED=1
fi
policy_body="$(jq -nc \
    --arg id "$POLICY_ID" \
    --arg subject "$VIEWER_SUBJECT" \
    --arg host_id "$ALLOWED_HOST_ID" \
    '{id:$id, subject_external_id:$subject, resource_type:"host", resource_id:$host_id, permission:"read"}')"
api_json POST /api/admin/rbac/policies "$policy_body" | jq -e '.status == "ok"' >/dev/null

echo "[4/6] Verifying viewer list endpoints are constrained to the allowed host"
hosts_json="$(viewer_json GET /api/hosts)"
assert_json_arg "$hosts_json" host "$ALLOWED_HOST_ID" '.[] | select(.id == $host)' "viewer must see the allowed host"
assert_json_arg "$hosts_json" host "$DENIED_HOST_ID" 'all(.[]; .id != $host)' "viewer must not see the denied host"
packages_json="$(viewer_json GET /api/packages?limit=200)"
assert_json_arg "$packages_json" pkg "bongsu-rbac-host-allowed" '.items[] | select(.name == $pkg and .asset_type == "host")' "viewer must see allowed host package"
assert_json_arg "$packages_json" pkg "bongsu-rbac-container-allowed" '.items[] | select(.name == $pkg and .asset_type == "container")' "viewer must see allowed container package"
assert_json_arg "$packages_json" pkg "bongsu-rbac-host-denied" 'all(.items[]; .name != $pkg)' "viewer must not see denied host package"
assert_json_arg "$packages_json" pkg "bongsu-rbac-container-denied" 'all(.items[]; .name != $pkg)' "viewer must not see denied container package"
containers_json="$(viewer_json GET /api/containers?limit=100)"
assert_json_arg "$containers_json" id "$ALLOWED_CONTAINER_ID" '.items[] | select(.container_id == $id)' "viewer must see allowed container"
assert_json_arg "$containers_json" id "$DENIED_CONTAINER_ID" 'all(.items[]; .container_id != $id)' "viewer must not see denied container"

echo "[5/6] Verifying explicit denied host filters fail closed"
denied_pkg_status="$(viewer_status GET "/api/packages?host_id=${DENIED_HOST_ID}&limit=10")"
if [ "$denied_pkg_status" != "403" ]; then
    echo "ERROR: viewer package query for denied host returned HTTP ${denied_pkg_status}, expected 403" >&2
    cat "$TMP_DIR/viewer-status-response.json" >&2 || true
    exit 1
fi
denied_container_status="$(viewer_status GET "/api/containers?host_id=${DENIED_HOST_ID}&limit=10")"
if [ "$denied_container_status" != "403" ]; then
    echo "ERROR: viewer container query for denied host returned HTTP ${denied_container_status}, expected 403" >&2
    cat "$TMP_DIR/viewer-status-response.json" >&2 || true
    exit 1
fi

echo "[6/6] Verifying scan and scan-request scopes"
request_body="$(jq -nc --arg host_id "$ALLOWED_HOST_ID" '{host_id:$host_id, scan_type:"manual", packages_only:true, reason:"live RBAC scope verifier"}')"
request_json="$(api_json POST /api/scan-requests "$request_body")"
SCAN_REQUEST_ID="$(jq -r '.id' <<<"$request_json")"
viewer_requests="$(viewer_json GET /api/scan-requests?limit=50)"
assert_json_arg "$viewer_requests" id "$SCAN_REQUEST_ID" '.items[] | select(.id == $id and .host_id != "")' "viewer must see allowed host scan request"
denied_request_status="$(viewer_status GET "/api/scan-requests?host_id=${DENIED_HOST_ID}&limit=10")"
if [ "$denied_request_status" != "403" ]; then
    echo "ERROR: viewer scan-request query for denied host returned HTTP ${denied_request_status}, expected 403" >&2
    cat "$TMP_DIR/viewer-status-response.json" >&2 || true
    exit 1
fi
viewer_scans="$(viewer_json GET /api/scans?limit=50)"
assert_json_arg "$viewer_scans" host "$ALLOWED_HOST_ID" '.items[] | select(.host_id == $host)' "viewer must see allowed host scan"
assert_json_arg "$viewer_scans" host "$DENIED_HOST_ID" 'all(.items[]; .host_id != $host)' "viewer must not see denied host scan"

api_json POST "/api/scan-requests/${SCAN_REQUEST_ID}/cancel" >/dev/null
SCAN_REQUEST_ID=""

echo "Live RBAC scope verification passed"
