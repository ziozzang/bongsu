#!/bin/bash
set -euo pipefail

# verify-live-security-db-auto-rescan.sh - Verify a finalized CVE DB import
# triggers security recalculation and queues security-db-update scan requests.

API_BASE="${BONGSU_API_BASE:-http://127.0.0.1:5677}"
API_KEY="${BONGSU_API_KEY:-test-admin-key-0123456789}"
AGENT_API_KEY="${BONGSU_AGENT_API_KEY:-test-agent-key-0123456789}"
CURL_MAX_TIME="${BONGSU_VERIFY_CURL_MAX_TIME_SECONDS:-45}"
BONGSU_DB_DSN="${BONGSU_DB_DSN:-}"
BONGSU_DB_PSQL_CONTAINER="${BONGSU_DB_PSQL_CONTAINER:-bongsu-postgres}"
RUN_ID="auto-rescan-$(date -u +%Y%m%dT%H%M%SZ)-$$"
HOST_ID="host-${RUN_ID}"
AGENT_TOKEN="token-${RUN_ID}-0123456789abcdef"
SOURCE="bongsu-autorescan-$(date -u +%H%M%S)-$$"
SCAN_REQUEST_ID=""
PSQL_MODE=""
TMP_DIR="$(mktemp -d)"

cleanup() {
    set +e
    if [ -n "$SCAN_REQUEST_ID" ]; then
        curl -fsS --max-time "$CURL_MAX_TIME" -X POST -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/scan-requests/${SCAN_REQUEST_ID}/cancel" >/dev/null 2>&1
    fi
    curl -fsS --max-time "$CURL_MAX_TIME" -X DELETE -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/hosts/${HOST_ID}" >/dev/null 2>&1
    if [ -n "$BONGSU_DB_DSN" ] && [ -n "$PSQL_MODE" ]; then
        db_exec "DELETE FROM cve_database WHERE source = $(sql_literal "$SOURCE"); DELETE FROM security_sources WHERE id = $(sql_literal "$SOURCE");" >/dev/null 2>&1 || true
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

discover_db_dsn() {
    if [ -n "$BONGSU_DB_DSN" ]; then
        return
    fi
    local pid
    for pid in $(pgrep -f 'bongsu-server|cmd/server' 2>/dev/null || true); do
        if [ -r "/proc/${pid}/environ" ]; then
            BONGSU_DB_DSN="$(tr '\0' '\n' <"/proc/${pid}/environ" | sed -n 's/^BONGSU_DB_DSN=//p' | head -n1)"
            if [ -n "$BONGSU_DB_DSN" ]; then
                return
            fi
        fi
    done
}

prepare_db_checks() {
    discover_db_dsn
    if [ -z "$BONGSU_DB_DSN" ]; then
        echo "ERROR: BONGSU_DB_DSN is required for security DB auto-rescan verification" >&2
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

db_scalar() {
    local sql="$1"
    if [ "$PSQL_MODE" = "local" ]; then
        psql "$BONGSU_DB_DSN" -X -A -t -v ON_ERROR_STOP=1 -c "$sql"
    else
        docker exec -i "$BONGSU_DB_PSQL_CONTAINER" psql "$BONGSU_DB_DSN" -X -A -t -v ON_ERROR_STOP=1 -c "$sql"
    fi
}

db_exec() {
    db_scalar "$1" >/dev/null
}

sql_literal() {
    python3 - "$1" <<'PY'
import sys
print("'" + sys.argv[1].replace("'", "''") + "'")
PY
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
    local body="$3"
    local out="$TMP_DIR/agent-response.json"
    local status
    status="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$out" -w "%{http_code}" -X "$method" \
        -H "X-API-Key: ${AGENT_API_KEY}" \
        -H "X-Bongsu-Agent-Token: ${AGENT_TOKEN}" \
        -H "X-Bongsu-Host-ID: ${HOST_ID}" \
        -H "Content-Type: application/json" \
        --data "$body" \
        "${API_BASE}${path}")"
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
            kernel: "auto-rescan-verifier",
            arch: "amd64",
            cpu_model: "verifier",
            cpu_cores: 1,
            memory_mb: 512,
            agent_version: "auto-rescan-verifier"
          },
          scan_type: "manual",
          scan_id: $scan_id,
          packages: [
            {
              source: "dpkg",
              name: "bongsu-auto-rescan-fixture",
              version: "1.0.0",
              arch: "amd64",
              pkg_type: "deb",
              ecosystem: "Ubuntu",
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

wait_for_auto_rescan() {
    local deadline=$(( $(date +%s) + 180 ))
    local requests_json
    local audit_json
    while true; do
        requests_json="$(api_json GET "/api/scan-requests?host_id=${HOST_ID}&status=pending&limit=20")"
        if jq -e '.items[]? | select(.scan_type == "security-db-update" and .packages_only == true and .requested_by == "system" and .security_db_revision != "")' >/dev/null <<<"$requests_json"; then
            SCAN_REQUEST_ID="$(jq -r '.items[] | select(.scan_type == "security-db-update" and .packages_only == true and .requested_by == "system" and .security_db_revision != "") | .id' <<<"$requests_json" | head -n1)"
            audit_json="$(api_json GET "/api/admin/audit-logs?action=security_db.auto_rescan&resource_type=scan_request&limit=20")"
            assert_json "$audit_json" '.items[] | select(.action == "security_db.auto_rescan" and .status == "ok" and (.metadata.reason == "cve-db import") and ((.metadata.eligible // 0) >= 1) and (((.metadata.queued // 0) >= 1) or ((.metadata.already_pending // 0) >= 1)) and (.metadata.security_db_revision != ""))' "security DB auto-rescan audit must report eligible and queued or already-pending counts"
            return
        fi
        if [ "$(date +%s)" -ge "$deadline" ]; then
            echo "ERROR: timed out waiting for security-db-update scan request for ${HOST_ID}" >&2
            echo "$requests_json" | jq . >&2 || echo "$requests_json" >&2
            exit 1
        fi
        sleep 3
    done
}

require_tool curl
require_tool jq
require_tool python3
prepare_db_checks

echo "=== Bongsu Live Security DB Auto-Rescan Verification ==="
echo "API:    ${API_BASE}"
echo "Host:   ${HOST_ID}"
echo "Source: ${SOURCE}"

echo "[1/4] Enrolling verifier host"
curl -fsS --max-time "$CURL_MAX_TIME" "${API_BASE}/api/ready" | jq -e '.status == "ready"' >/dev/null
agent_json POST /api/report "$(scan_report_json "$(new_uuid)")" | jq -e '.status == "ok" and .scan_status == "completed"' >/dev/null

echo "[2/4] Importing finalized verifier CVE source to trigger security DB update"
python3 - "$TMP_DIR/cve.jsonl" "$SOURCE" <<'PY'
import json
import sys

path, source = sys.argv[1], sys.argv[2]
entry = {
    "id": "CVE-2026-901001",
    "vulnerability_id": "CVE-2026-901001",
    "source": source,
    "category": "code-library",
    "ecosystem": "Packagist",
    "severity": "HIGH",
    "title": "Bongsu auto-rescan verifier fixture",
    "description": "Temporary verifier CVE row for security DB auto-rescan live gate",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "affected_products": json.dumps([{
        "name": "bongsu-auto-rescan-fixture",
        "ecosystem": "Packagist",
        "fixed": ["9.9.9"],
    }], separators=(",", ":")),
    "references": json.dumps(["https://example.invalid/bongsu-auto-rescan-verifier"], separators=(",", ":")),
    "raw_data": json.dumps({"verifier": "security-db-auto-rescan"}, separators=(",", ":")),
}
with open(path, "w", encoding="utf-8") as out:
    out.write(json.dumps(entry, separators=(",", ":")) + "\n")
PY
import_json="$TMP_DIR/import.json"
status="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$import_json" -w "%{http_code}" -X POST \
    -H "X-API-Key: ${API_KEY}" \
    -F "file=@${TMP_DIR}/cve.jsonl" \
    -F "source=${SOURCE}" \
    -F "replace=true" \
    -F "finalize=true" \
    "${API_BASE}/api/admin/cve-db/import")"
if [[ "$status" != 2* ]]; then
    echo "ERROR: verifier CVE import returned HTTP ${status}" >&2
    cat "$import_json" >&2 || true
    exit 1
fi
jq -e '.status == "ok" and .finalized == true and (.imported // 0) == 1 and (.security_db_revision | type == "string" and length > 0)' "$import_json" >/dev/null || {
    echo "ERROR: verifier CVE import did not finalize with a security DB revision" >&2
    cat "$import_json" >&2
    exit 1
}

echo "[3/4] Waiting for post-update recalculation and automatic rescan queueing"
wait_for_auto_rescan

echo "[4/4] Verifying queued request is claimable by the host agent"
claim_json="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$TMP_DIR/claim.json" -w "%{http_code}" -X POST \
    -H "X-API-Key: ${AGENT_API_KEY}" \
    -H "X-Bongsu-Agent-Token: ${AGENT_TOKEN}" \
    -H "X-Bongsu-Host-ID: ${HOST_ID}" \
    "${API_BASE}/api/agent/scan-requests/claim?host_id=${HOST_ID}")"
if [[ "$claim_json" != 2* ]]; then
    echo "ERROR: agent claim returned HTTP ${claim_json}" >&2
    cat "$TMP_DIR/claim.json" >&2 || true
    exit 1
fi
jq -e --arg id "$SCAN_REQUEST_ID" '.request.id == $id and .request.scan_type == "security-db-update" and .request.packages_only == true and .request.security_db_revision != ""' "$TMP_DIR/claim.json" >/dev/null || {
    echo "ERROR: auto-rescan scan request was not claimable with expected metadata" >&2
    cat "$TMP_DIR/claim.json" >&2
    exit 1
}

echo "Live security DB auto-rescan verification passed"
