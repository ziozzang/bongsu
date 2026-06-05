#!/bin/bash
set -euo pipefail

# verify-live-sbom-export-rbac.sh - Exercise live RBAC scoping on the SBOM
# export surface, a high-risk host/package inventory exfiltration path.

API_BASE="${BONGSU_API_BASE:-http://127.0.0.1:5677}"
API_KEY="${BONGSU_API_KEY:-test-admin-key-0123456789}"
AGENT_API_KEY="${BONGSU_AGENT_API_KEY:-test-agent-key-0123456789}"
VIEWER_API_KEY="${BONGSU_VIEWER_API_KEY:-viewer-test-key}"
VIEWER_SUBJECT="${BONGSU_VIEWER_SUBJECT:-rbac-live-viewer}"
CURL_MAX_TIME="${BONGSU_VERIFY_CURL_MAX_TIME_SECONDS:-30}"
RUN_ID="sbom-export-rbac-$(date -u +%Y%m%dT%H%M%SZ)-$$"
ALLOWED_HOST_ID="host-${RUN_ID}-allowed"
DENIED_HOST_ID="host-${RUN_ID}-denied"
SUBJECT_ID="subject-${RUN_ID}"
POLICY_ID="policy-${RUN_ID}"
SUBJECT_CREATED=0
TMP_DIR="$(mktemp -d)"

cleanup() {
    set +e
    curl -fsS --max-time "$CURL_MAX_TIME" -X DELETE -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/admin/rbac/policies/${POLICY_ID}" >/dev/null 2>&1
    if [ "$SUBJECT_CREATED" = "1" ]; then
        curl -fsS --max-time "$CURL_MAX_TIME" -X DELETE -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/admin/rbac/subjects/${SUBJECT_ID}" >/dev/null 2>&1
    fi
    curl -fsS --max-time "$CURL_MAX_TIME" -X DELETE -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/hosts/${ALLOWED_HOST_ID}" >/dev/null 2>&1
    curl -fsS --max-time "$CURL_MAX_TIME" -X DELETE -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/hosts/${DENIED_HOST_ID}" >/dev/null 2>&1
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: missing required tool: $1" >&2
        exit 1
    fi
}

new_uuid() {
    if [ -r /proc/sys/kernel/random/uuid ]; then
        cat /proc/sys/kernel/random/uuid
        return
    fi
    python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
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
    local body="$2"
    local out="$TMP_DIR/agent-response.json"
    local status
    status="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$out" -w "%{http_code}" -X POST \
        -H "X-API-Key: ${AGENT_API_KEY}" \
        -H "X-Bongsu-Agent-Token: token-${host_id}" \
        -H "X-Bongsu-Host-ID: ${host_id}" \
        -H "Content-Type: application/json" \
        --data "$body" \
        "${API_BASE}/api/report")"
    if [[ "$status" != 2* ]]; then
        echo "ERROR: agent report for ${host_id} returned HTTP ${status}" >&2
        cat "$out" >&2 || true
        exit 1
    fi
    cat "$out"
}

viewer_download() {
    local path="$1"
    local out="$2"
    local headers="$3"
    local status
    status="$(curl -sS --max-time "$CURL_MAX_TIME" -D "$headers" -o "$out" -w "%{http_code}" \
        -H "X-API-Key: ${VIEWER_API_KEY}" \
        "${API_BASE}${path}")"
    if [[ "$status" != 2* ]]; then
        echo "ERROR: viewer GET ${path} returned HTTP ${status}" >&2
        cat "$out" >&2 || true
        exit 1
    fi
}

viewer_status() {
    local path="$1"
    local out="$TMP_DIR/viewer-status-response"
    curl -sS --max-time "$CURL_MAX_TIME" -o "$out" -w "%{http_code}" \
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

assert_file_json() {
    local file="$1"
    local filter="$2"
    local message="$3"
    if ! jq -e "$filter" "$file" >/dev/null; then
        echo "ERROR: ${message}" >&2
        jq . "$file" >&2 || cat "$file" >&2
        exit 1
    fi
}

assert_header() {
    local file="$1"
    local pattern="$2"
    local message="$3"
    if ! tr -d '\r' < "$file" | grep -Eiq "$pattern"; then
        echo "ERROR: ${message}" >&2
        tr -d '\r' < "$file" >&2 || true
        exit 1
    fi
}

scan_report_json() {
    local host_id="$1"
    local scan_id="$2"
    local suffix="$3"
    jq -nc \
        --arg host_id "$host_id" \
        --arg scan_id "$scan_id" \
        --arg suffix "$suffix" \
        --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{
          host: {
            id: $host_id,
            hostname: $host_id,
            ip_address: "127.0.0.1",
            os_name: "Ubuntu",
            os_version: "24.04",
            kernel: "sbom-export-rbac-verifier",
            arch: "amd64",
            cpu_model: "verifier",
            cpu_cores: 1,
            memory_mb: 512,
            agent_version: "sbom-export-rbac-verifier"
          },
          scan_type: "manual",
          scan_id: $scan_id,
          containers: [],
          packages: [
            {
              source: "trivy",
              name: ("bongsu-sbom-export-rbac-" + $suffix),
              version: "1.0.0",
              pkg_type: "npm",
              ecosystem: "npm",
              purl: ("pkg:npm/bongsu-sbom-export-rbac-" + $suffix + "@1.0.0"),
              asset_type: "host",
              asset_id: $host_id,
              target: ("package-" + $suffix + ".json")
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

echo "=== Bongsu Live SBOM Export RBAC Verification ==="
echo "API:     ${API_BASE}"
echo "Subject: ${VIEWER_SUBJECT}"

echo "[1/5] Checking viewer key authentication"
viewer_hosts_status="$(viewer_status /api/hosts)"
if [ "$viewer_hosts_status" = "401" ]; then
    echo "ERROR: viewer key was rejected; restart API with BONGSU_VIEWER_API_KEYS mapping this key to ${VIEWER_SUBJECT}" >&2
    exit 1
fi
if [[ "$viewer_hosts_status" != 2* ]]; then
    echo "ERROR: viewer /api/hosts returned HTTP ${viewer_hosts_status}" >&2
    cat "$TMP_DIR/viewer-status-response" >&2 || true
    exit 1
fi

echo "[2/5] Ingesting allowed and denied SBOM fixtures"
agent_json_for_host "$ALLOWED_HOST_ID" "$(scan_report_json "$ALLOWED_HOST_ID" "$(new_uuid)" "allowed")" | jq -e '.status == "ok" and .scan_status == "completed"' >/dev/null
agent_json_for_host "$DENIED_HOST_ID" "$(scan_report_json "$DENIED_HOST_ID" "$(new_uuid)" "denied")" | jq -e '.status == "ok" and .scan_status == "completed"' >/dev/null
api_json POST "/api/hosts/${ALLOWED_HOST_ID}/metadata" "$(jq -nc '{owner:"security", team:"sbom-export-allowed", environment:"test", criticality:"medium", tags:"{}"}')" | jq -e '.team == "sbom-export-allowed"' >/dev/null
api_json POST "/api/hosts/${DENIED_HOST_ID}/metadata" "$(jq -nc '{owner:"security", team:"sbom-export-denied", environment:"test", criticality:"medium", tags:"{}"}')" | jq -e '.team == "sbom-export-denied"' >/dev/null

echo "[3/5] Granting viewer export permission only for the allowed asset group"
subject_type_value="$(subject_type)"
subject_external_id_value="$(subject_external_id)"
subjects_json="$(api_json GET /api/admin/rbac/subjects)"
if ! jq -e --arg t "$subject_type_value" --arg e "$subject_external_id_value" '.items[] | select(.subject_type == $t and .external_id == $e)' >/dev/null <<<"$subjects_json"; then
    subject_body="$(jq -nc \
        --arg id "$SUBJECT_ID" \
        --arg subject_type "$subject_type_value" \
        --arg external_id "$subject_external_id_value" \
        --arg display_name "$RUN_ID SBOM export viewer" \
        '{id:$id, subject_type:$subject_type, external_id:$external_id, display_name:$display_name}')"
    api_json POST /api/admin/rbac/subjects "$subject_body" | jq -e '.status == "ok"' >/dev/null
    SUBJECT_CREATED=1
fi
viewer_subject_query="$(jq -rn --arg v "$VIEWER_SUBJECT" '$v|@uri')"
stale_policy_ids="$(api_json GET "/api/admin/rbac/policies?subject_external_id=${viewer_subject_query}" | jq -r '.items[]? | select((.id // "") | startswith("policy-sbom-export-rbac-")) | .id')"
while IFS= read -r stale_policy_id; do
    if [ -n "$stale_policy_id" ]; then
        api_json DELETE "/api/admin/rbac/policies/${stale_policy_id}" >/dev/null
    fi
done <<<"$stale_policy_ids"
policy_body="$(jq -nc \
    --arg id "$POLICY_ID" \
    --arg subject "$VIEWER_SUBJECT" \
    '{id:$id, subject_external_id:$subject, resource_type:"asset_group", resource_id:"team:sbom-export-allowed", permission:"export"}')"
api_json POST /api/admin/rbac/policies "$policy_body" | jq -e '.status == "ok"' >/dev/null
policies_json="$(api_json GET "/api/admin/rbac/policies?subject_external_id=${viewer_subject_query}")"
assert_json_arg "$policies_json" id "$POLICY_ID" '.items[] | select(.id == $id and .permission == "export" and .resource_type == "asset_group" and .resource_id == "team:sbom-export-allowed")' "admin policy list must include the SBOM export-only asset-group policy"

echo "[4/5] Verifying allowed CycloneDX and SPDX SBOM exports"
CDX_JSON="$TMP_DIR/allowed.cyclonedx.json"
CDX_HEADERS="$TMP_DIR/allowed.cyclonedx.headers"
viewer_download "/api/hosts/${ALLOWED_HOST_ID}/sbom?format=cyclonedx" "$CDX_JSON" "$CDX_HEADERS"
assert_header "$CDX_HEADERS" '^content-type: application/vnd\.cyclonedx\+json' "viewer CycloneDX export must set CycloneDX content type"
assert_file_json "$CDX_JSON" '.bomFormat == "CycloneDX" and (.components[] | select(.name == "bongsu-sbom-export-rbac-allowed" and .purl == "pkg:npm/bongsu-sbom-export-rbac-allowed@1.0.0"))' "viewer CycloneDX export must include allowed host package"

SPDX_JSON="$TMP_DIR/allowed.spdx.json"
SPDX_HEADERS="$TMP_DIR/allowed.spdx.headers"
viewer_download "/api/hosts/${ALLOWED_HOST_ID}/sbom?format=spdx" "$SPDX_JSON" "$SPDX_HEADERS"
assert_header "$SPDX_HEADERS" '^content-type: application/spdx\+json' "viewer SPDX export must set SPDX content type"
assert_file_json "$SPDX_JSON" '.spdxVersion == "SPDX-2.3" and (.packages[] | select(.name == "bongsu-sbom-export-rbac-allowed" and .packageUrl == "pkg:npm/bongsu-sbom-export-rbac-allowed@1.0.0"))' "viewer SPDX export must include allowed host package"

echo "[5/5] Verifying denied host SBOM export fails closed and is audited"
denied_status="$(viewer_status "/api/hosts/${DENIED_HOST_ID}/sbom?format=cyclonedx")"
if [ "$denied_status" != "403" ]; then
    echo "ERROR: viewer SBOM export for denied host returned HTTP ${denied_status}, expected 403" >&2
    cat "$TMP_DIR/viewer-status-response" >&2 || true
    exit 1
fi
audit_json="$(api_json GET '/api/admin/audit-logs?action=sbom.export&limit=20')"
assert_json_arg "$audit_json" host "$ALLOWED_HOST_ID" '.items[] | select(.action == "sbom.export" and .resource_id == $host and .status == "ok" and (.metadata.packages // 0) >= 1)' "allowed SBOM export must be audited as ok"
assert_json_arg "$audit_json" host "$DENIED_HOST_ID" '.items[] | select(.action == "sbom.export" and .resource_id == $host and .status == "forbidden")' "denied SBOM export must be audited as forbidden"

echo "Live SBOM export RBAC verification passed"
