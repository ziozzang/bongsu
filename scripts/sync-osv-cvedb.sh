#!/bin/bash
# sync-osv-cvedb.sh — Refresh only OSV.dev CVE data in Bongsu.
# Usage: ./sync-osv-cvedb.sh [server_url] [api_key]

set -euo pipefail

SERVER_URL="${1:-http://localhost:5677}"
API_KEY="${2:-${BONGSU_API_KEY:-}}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TMP_PARENT="${BONGSU_TMPDIR:-${TMPDIR:-/tmp}}"
mkdir -p "${TMP_PARENT}"
TMPDIR="$(mktemp -d "${TMP_PARENT%/}/bongsu-osv-sync.XXXXXX")"
trap 'rm -rf "${TMPDIR}"' EXIT

if [ -z "${API_KEY}" ]; then
    echo "ERROR: API key required. Usage: $0 [server_url] [api_key]" >&2
    echo "   or: BONGSU_API_KEY=xxx $0" >&2
    exit 1
fi

IMPORT_URL="${SERVER_URL}/api/admin/cve-db/import"
RECALCULATE_URL="${SERVER_URL}/api/admin/security-db/recalculate"
AFFECTED_INDEX_REBUILD_URL="${SERVER_URL}/api/admin/cve-db/affected-index/rebuild"
REFERENCE_INDEX_REBUILD_URL="${SERVER_URL}/api/admin/cve-db/reference-index/rebuild"
INDEX_REBUILD_WAIT_SECONDS="${BONGSU_CVE_INDEX_REBUILD_WAIT_SECONDS:-900}"
INDEX_REBUILD_POLL_SECONDS="${BONGSU_CVE_INDEX_REBUILD_POLL_SECONDS:-5}"
INDEX_REBUILD_MIN_SERVER_TIMEOUT_SECONDS="${BONGSU_CVE_INDEX_REBUILD_MIN_SERVER_TIMEOUT_SECONDS:-600}"
DEFAULT_OSV_ECOSYSTEMS="PyPI,npm,Go,Maven,crates.io,NuGet,RubyGems,Packagist,Hex,Pub,SwiftURL,Hackage,CRAN,opam,VSCode,GitHub Actions,Alpine,Debian,Ubuntu,SUSE,openSUSE,AlmaLinux,Red Hat,Rocky Linux,Azure Linux,Wolfi,Chainguard,openEuler,Mageia,Android"
OSV_ECOSYSTEMS="${BONGSU_OSV_ECOSYSTEMS:-${DEFAULT_OSV_ECOSYSTEMS}}"
OSV_PRUNE_BEFORE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
OSV_PRUNE_FULL_SOURCE="true"
if [ -n "${BONGSU_OSV_ECOSYSTEMS:-}" ] && [ "$(echo "${BONGSU_OSV_ECOSYSTEMS}" | tr -d '[:space:]')" != "$(echo "${DEFAULT_OSV_ECOSYSTEMS}" | tr -d '[:space:]')" ]; then
    OSV_PRUNE_FULL_SOURCE="false"
fi
OSV_TOTAL=0
OSV_FAILED=0
FAILED_ECOSYSTEMS=()

preflight_index_rebuild_timeouts() {
    local response_file
    local affected_timeout
    local reference_timeout
    response_file="${TMPDIR}/security-db-status-preflight.json"
    if ! curl -fsS -H "X-API-Key: ${API_KEY}" "${SERVER_URL}/api/admin/security-db/status" > "${response_file}"; then
        echo "ERROR: failed to check server CVE index rebuild timeout settings" >&2
        return 1
    fi
    IFS='|' read -r affected_timeout reference_timeout < <(python3 -c '
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as exc:
    print(f"0|0")
    sys.exit(0)
print("|".join([
    str((data.get("cve_affected_index") or {}).get("timeout_seconds") or 0),
    str((data.get("cve_reference_index") or {}).get("timeout_seconds") or 0),
]))
' "${response_file}")
    if [ "${affected_timeout}" -lt "${INDEX_REBUILD_MIN_SERVER_TIMEOUT_SECONDS}" ] || [ "${reference_timeout}" -lt "${INDEX_REBUILD_MIN_SERVER_TIMEOUT_SECONDS}" ]; then
        echo "ERROR: server CVE index rebuild timeout is too low for production-sized OSV sync" >&2
        echo "affected_timeout_seconds=${affected_timeout} reference_timeout_seconds=${reference_timeout} required_min_seconds=${INDEX_REBUILD_MIN_SERVER_TIMEOUT_SECONDS}" >&2
        echo "Increase BONGSU_CVE_AFFECTED_INDEX_REBUILD_TIMEOUT_SECONDS and BONGSU_CVE_REFERENCE_INDEX_REBUILD_TIMEOUT_SECONDS, then restart the API." >&2
        return 1
    fi
}

import_osv_file() {
    local file="$1"
    local result

    if ! result=$(curl -fsS -X POST -H "X-API-Key: ${API_KEY}" \
        -F "file=@${file}" -F "source=osv" -F "replace=false" -F "finalize=false" "${IMPORT_URL}"); then
        echo "ERROR: OSV import request failed" >&2
        return 1
    fi

    echo "${result}" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception as exc:
    print(f"invalid import response: {exc}", file=sys.stderr)
    sys.exit(2)
if data.get("status") != "ok":
    print(f"import response was not ok: {data}", file=sys.stderr)
    sys.exit(3)
print(int(data.get("imported", 0)))
'
}

queue_index_rebuild() {
    local label="$1"
    local url="$2"
    local field="$3"
    local response_file
    local http_code
    local deadline
    local running
    local status
    local duration_ms
    local indexed
    local error_msg

    response_file="${TMPDIR}/rebuild-${field}.json"
    http_code="$(curl -sS -o "${response_file}" -w "%{http_code}" -X POST -H "X-API-Key: ${API_KEY}" "${url}?async=true")"
    if [ "${http_code}" != "202" ] && [ "${http_code}" != "409" ]; then
        echo "ERROR: ${label} rebuild queue request failed with HTTP ${http_code}" >&2
        cat "${response_file}" >&2 || true
        return 1
    fi

    status="$(python3 -c '
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as exc:
    print(f"invalid rebuild response: {exc}", file=sys.stderr)
    sys.exit(2)
print(data.get("status", ""))
' "${response_file}")"
    echo "  ${label} rebuild ${status}."

    deadline=$(( $(date +%s) + INDEX_REBUILD_WAIT_SECONDS ))
    while true; do
        if ! curl -fsS -H "X-API-Key: ${API_KEY}" "${SERVER_URL}/api/health" > "${response_file}"; then
            echo "ERROR: failed to poll ${label} rebuild status" >&2
            return 1
        fi
        IFS='|' read -r running status duration_ms indexed error_msg < <(python3 -c '
import json, sys
field = sys.argv[2]
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as exc:
    print(f"false|error|0|0|invalid health response: {exc}")
    sys.exit(0)
state = data.get(field) or {}
last = state.get("last_result") or {}
print("|".join([
    "true" if state.get("running") else "false",
    str(last.get("status") or ""),
    str(state.get("duration_ms") or last.get("duration_ms") or 0),
    str(last.get("indexed") or 0),
    str(last.get("error") or ""),
]))
' "${response_file}" "${field}")
        if [ "${running}" = "false" ]; then
            if [ "${status}" = "ok" ]; then
                echo "  ${label} rebuild complete: indexed=${indexed}, duration_ms=${duration_ms}"
                return 0
            fi
            echo "ERROR: ${label} rebuild finished with status '${status:-unknown}' ${error_msg}" >&2
            return 1
        fi
        if [ "$(date +%s)" -ge "${deadline}" ]; then
            echo "ERROR: timed out waiting for ${label} rebuild after ${INDEX_REBUILD_WAIT_SECONDS}s" >&2
            return 1
        fi
        echo "  ${label} rebuild running for ${duration_ms}ms..."
        sleep "${INDEX_REBUILD_POLL_SECONDS}"
    done
}

finalize_osv_imports() {
    if [ "${OSV_PRUNE_FULL_SOURCE}" = "true" ]; then
        echo "  Pruning stale OSV rows older than ${OSV_PRUNE_BEFORE}..."
        curl -fsS -X POST -H "X-API-Key: ${API_KEY}" \
            "${SERVER_URL}/api/admin/cve-db/source/osv/prune-stale?before=${OSV_PRUNE_BEFORE}" >/dev/null
    else
        echo "  Skipping stale OSV prune because BONGSU_OSV_ECOSYSTEMS is a partial override."
        echo "  Run a full OSV sync with the default ecosystem list to prune upstream removals safely."
    fi
    echo "  Rebuilding affected package index after OSV imports..."
    queue_index_rebuild "Affected package index" "${AFFECTED_INDEX_REBUILD_URL}" "cve_affected_index_rebuild"
    echo "  Rebuilding reference key index after OSV imports..."
    queue_index_rebuild "Reference key index" "${REFERENCE_INDEX_REBUILD_URL}" "cve_reference_index_rebuild"
    echo "  Queuing security recalculation after OSV imports..."
    curl -fsS -X POST -H "X-API-Key: ${API_KEY}" \
        -H "Content-Type: application/json" \
        -d '{"reason":"osv targeted sync"}' "${RECALCULATE_URL}" >/dev/null
}

echo "=========================================="
echo " Bongsu OSV CVE Database Sync"
echo " Server: ${SERVER_URL}"
echo "=========================================="
echo ""
preflight_index_rebuild_timeouts

IFS=',' read -ra ECO_ARRAY <<< "${OSV_ECOSYSTEMS}"
ECO_COUNT="${#ECO_ARRAY[@]}"
ECO_IDX=0
for eco in "${ECO_ARRAY[@]}"; do
    eco="$(echo "$eco" | xargs)"
    ECO_IDX=$((ECO_IDX + 1))
    OSV_ECO_FILE="${TMPDIR}/osv-${eco}.jsonl"
    echo "  [${ECO_IDX}/${ECO_COUNT}] ${eco}..."
    if ! "${SCRIPT_DIR}/download-osv.sh" "${OSV_ECO_FILE}" "${eco}"; then
        echo "    ERROR: ${eco} download failed" >&2
        FAILED_ECOSYSTEMS+=("${eco}")
        OSV_FAILED=1
        continue
    fi
    if [ ! -s "${OSV_ECO_FILE}" ]; then
        echo "    ERROR: ${eco} produced no OSV data" >&2
        FAILED_ECOSYSTEMS+=("${eco}:no-data")
        OSV_FAILED=1
        continue
    fi
    ECO_LINES="$(wc -l < "${OSV_ECO_FILE}")"
    ECO_SIZE="$(du -h "${OSV_ECO_FILE}" | cut -f1)"
    echo "    Importing ${eco} (${ECO_LINES} entries, ${ECO_SIZE})..."
    if ! IMPORTED="$(import_osv_file "${OSV_ECO_FILE}")"; then
        echo "    ERROR: ${eco} import failed" >&2
        FAILED_ECOSYSTEMS+=("${eco}:import")
        OSV_FAILED=1
        continue
    fi
    echo "    Imported/updated: ${IMPORTED}"
    OSV_TOTAL=$((OSV_TOTAL + IMPORTED))
    rm -f "${OSV_ECO_FILE}"
done

if [ "${OSV_FAILED}" -ne 0 ]; then
    echo "ERROR: incomplete OSV sync: ${FAILED_ECOSYSTEMS[*]}" >&2
    exit 1
fi
if [ "${OSV_TOTAL}" -eq 0 ]; then
    echo "ERROR: OSV sync produced no imported rows" >&2
    exit 1
fi

finalize_osv_imports
echo ""
echo "OSV sync complete. Imported/updated: ${OSV_TOTAL}"
