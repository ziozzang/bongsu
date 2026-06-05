#!/bin/bash
# sync-all-cvedb.sh — Download from all CVE sources and import into Bongsu
# Sources: CISA KEV, FIRST EPSS, OSV.dev (all ecosystems), NVD, Trivy DB
# Usage: ./sync-all-cvedb.sh [server_url] [api_key]
# Environment: NVD_API_KEY for higher NVD rate limits (optional)

set -euo pipefail

SERVER_URL="${1:-http://localhost:5677}"
API_KEY="${2:-${BONGSU_API_KEY:-}}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TMP_PARENT="${BONGSU_TMPDIR:-${TMPDIR:-/tmp}}"
mkdir -p "${TMP_PARENT}"
TMPDIR="$(mktemp -d "${TMP_PARENT%/}/bongsu-cvedb-sync.XXXXXX")"
trap 'rm -rf "${TMPDIR}"' EXIT

if [ -z "${API_KEY}" ]; then
    echo "ERROR: API key required. Usage: $0 [server_url] [api_key]"
    echo "   or: BONGSU_API_KEY=xxx $0"
    exit 1
fi

IMPORT_URL="${SERVER_URL}/api/admin/cve-db/import"
RECALCULATE_URL="${SERVER_URL}/api/admin/security-db/recalculate"
AFFECTED_INDEX_REBUILD_URL="${SERVER_URL}/api/admin/cve-db/affected-index/rebuild"
REFERENCE_INDEX_REBUILD_URL="${SERVER_URL}/api/admin/cve-db/reference-index/rebuild"
REFRESH_SOURCE_STATUS_URL="${SERVER_URL}/api/admin/cve-db/source"
INDEX_REBUILD_WAIT_SECONDS="${BONGSU_CVE_INDEX_REBUILD_WAIT_SECONDS:-900}"
INDEX_REBUILD_POLL_SECONDS="${BONGSU_CVE_INDEX_REBUILD_POLL_SECONDS:-5}"
INDEX_REBUILD_MIN_SERVER_TIMEOUT_SECONDS="${BONGSU_CVE_INDEX_REBUILD_MIN_SERVER_TIMEOUT_SECONDS:-600}"
BONGSU_OSV_POST_SYNC_VERIFY="${BONGSU_OSV_POST_SYNC_VERIFY:-true}"

TOTAL_IMPORTED=0
FAILED_SOURCES=()
REQUIRE_TRIVY_SOURCE="${BONGSU_SYNC_REQUIRE_TRIVY_SOURCE:-true}"
TRIVY_BIN_FOR_SYNC="${TRIVY_BIN:-${BONGSU_TRIVY_PATH:-}}"

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
except Exception:
    print("0|0")
    sys.exit(0)
print("|".join([
    str((data.get("cve_affected_index") or {}).get("timeout_seconds") or 0),
    str((data.get("cve_reference_index") or {}).get("timeout_seconds") or 0),
]))
' "${response_file}")
    if [ "${affected_timeout}" -lt "${INDEX_REBUILD_MIN_SERVER_TIMEOUT_SECONDS}" ] || [ "${reference_timeout}" -lt "${INDEX_REBUILD_MIN_SERVER_TIMEOUT_SECONDS}" ]; then
        echo "ERROR: server CVE index rebuild timeout is too low for production-sized CVE sync" >&2
        echo "affected_timeout_seconds=${affected_timeout} reference_timeout_seconds=${reference_timeout} required_min_seconds=${INDEX_REBUILD_MIN_SERVER_TIMEOUT_SECONDS}" >&2
        echo "Increase BONGSU_CVE_AFFECTED_INDEX_REBUILD_TIMEOUT_SECONDS and BONGSU_CVE_REFERENCE_INDEX_REBUILD_TIMEOUT_SECONDS, then restart the API." >&2
        return 1
    fi
}

find_trivy_binary() {
    if [ -n "${TRIVY_BIN_FOR_SYNC}" ] && [ -x "${TRIVY_BIN_FOR_SYNC}" ]; then
        return 0
    fi
    if command -v trivy &>/dev/null; then
        TRIVY_BIN_FOR_SYNC="$(command -v trivy)"
        return 0
    fi
    for candidate in \
        /opt/bongsu/bin/trivy \
        "${SCRIPT_DIR}/../bin/trivy" \
        "${SCRIPT_DIR}/trivy" \
        "${PWD}/trivy"; do
        if [ -x "${candidate}" ]; then
            TRIVY_BIN_FOR_SYNC="${candidate}"
            return 0
        fi
    done
    return 1
}

import_cve_file() {
    local file="$1"
    local source="$2"
    local replace="${3:-true}"
    local finalize="${4:-true}"
    local result

    if ! result=$(curl -fsS -X POST -H "X-API-Key: ${API_KEY}" \
        -F "file=@${file}" -F "source=${source}" -F "replace=${replace}" -F "finalize=${finalize}" "${IMPORT_URL}"); then
        echo "ERROR: ${source} import request failed" >&2
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

finalize_deferred_cve_imports() {
    local reason="$1"
    local source="${2:-}"
    echo "  Rebuilding affected package index after deferred imports..."
    queue_index_rebuild "Affected package index" "${AFFECTED_INDEX_REBUILD_URL}" "cve_affected_index_rebuild"
    echo "  Rebuilding reference key index after deferred imports..."
    queue_index_rebuild "Reference key index" "${REFERENCE_INDEX_REBUILD_URL}" "cve_reference_index_rebuild"
    if [ -n "${source}" ]; then
        echo "  Refreshing ${source} source registry status after deferred imports..."
        curl -fsS -X POST -H "X-API-Key: ${API_KEY}" \
            "${REFRESH_SOURCE_STATUS_URL}/${source}/refresh-status" >/dev/null
    fi
    echo "  Queuing security recalculation after deferred imports..."
    curl -fsS -X POST -H "X-API-Key: ${API_KEY}" \
        -H "Content-Type: application/json" \
        -d "{\"reason\":\"${reason}\"}" "${RECALCULATE_URL}" >/dev/null
}

verify_osv_post_sync_freshness() {
    if [ "${BONGSU_OSV_POST_SYNC_VERIFY}" != "true" ]; then
        echo "  Skipping post-sync OSV upstream freshness verification because BONGSU_OSV_POST_SYNC_VERIFY=${BONGSU_OSV_POST_SYNC_VERIFY}."
        return 0
    fi
    if [ "${OSV_PRUNE_FULL_SOURCE}" != "true" ] && [ -z "${BONGSU_DB_DSN:-}" ]; then
        echo "  Skipping post-sync OSV upstream freshness verification for partial OSV sync without BONGSU_DB_DSN."
        echo "  Set BONGSU_DB_DSN to verify selected ecosystems without promoting aggregate OSV freshness."
        return 0
    fi
    echo "  Verifying post-sync OSV upstream freshness..."
    BONGSU_API_BASE="${SERVER_URL}" \
        BONGSU_API_KEY="${API_KEY}" \
        BONGSU_VERIFY_CVEDB_REQUIRE_OSV_UPSTREAM_FRESHNESS=true \
        BONGSU_VERIFY_CVEDB_OSV_UPSTREAM_ECOSYSTEMS="${OSV_ECOSYSTEMS}" \
        "${SCRIPT_DIR}/verify-live-cvedb-quality.sh"
}

echo "=========================================="
echo " Bongsu CVE Database Sync"
echo " Server: ${SERVER_URL}"
echo "=========================================="
echo ""
preflight_index_rebuild_timeouts

# --- 1. CISA KEV ---
echo "[1/4] Downloading CISA KEV data..."
CISA_KEV_FILE="${TMPDIR}/cisa-kev.jsonl"
"${SCRIPT_DIR}/download-cisa-kev.sh" "${CISA_KEV_FILE}"

if [ -s "${CISA_KEV_FILE}" ]; then
    echo "  Importing CISA KEV data ($(wc -l < "${CISA_KEV_FILE}") entries, $(du -h "${CISA_KEV_FILE}" | cut -f1))..."
    IMPORTED=$(import_cve_file "${CISA_KEV_FILE}" "cisa-kev")
    echo "  Imported/updated: ${IMPORTED}"
    TOTAL_IMPORTED=$((TOTAL_IMPORTED + IMPORTED))
else
    echo "  ERROR: no CISA KEV data"
    FAILED_SOURCES+=("cisa-kev:no-data")
fi
echo ""

# --- 2. FIRST EPSS ---
echo "[2/5] Downloading FIRST EPSS data..."
EPSS_FILE="${TMPDIR}/epss.jsonl"
"${SCRIPT_DIR}/download-epss.sh" "${EPSS_FILE}"

if [ -s "${EPSS_FILE}" ]; then
    echo "  Importing EPSS data ($(wc -l < "${EPSS_FILE}") entries, $(du -h "${EPSS_FILE}" | cut -f1))..."
    IMPORTED=$(import_cve_file "${EPSS_FILE}" "epss")
    echo "  Imported/updated: ${IMPORTED}"
    TOTAL_IMPORTED=$((TOTAL_IMPORTED + IMPORTED))
else
    echo "  ERROR: no EPSS data"
    FAILED_SOURCES+=("epss:no-data")
fi
echo ""

# --- 3. OSV.dev (per-ecosystem to avoid upload timeouts) ---
DEFAULT_OSV_ECOSYSTEMS="PyPI,npm,Go,Maven,crates.io,NuGet,RubyGems,Packagist,Hex,Pub,SwiftURL,Hackage,CRAN,opam,VSCode,GitHub Actions,Alpine,Debian,Ubuntu,SUSE,openSUSE,AlmaLinux,Red Hat,Rocky Linux,Azure Linux,Wolfi,Chainguard,openEuler,Mageia,Android"
OSV_ECOSYSTEMS="${BONGSU_OSV_ECOSYSTEMS:-${DEFAULT_OSV_ECOSYSTEMS}}"
OSV_TOTAL=0
OSV_FAILED=0
OSV_PRUNE_BEFORE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
OSV_PRUNE_FULL_SOURCE="true"
if [ -n "${BONGSU_OSV_ECOSYSTEMS:-}" ] && [ "$(echo "${BONGSU_OSV_ECOSYSTEMS}" | tr -d '[:space:]')" != "$(echo "${DEFAULT_OSV_ECOSYSTEMS}" | tr -d '[:space:]')" ]; then
    OSV_PRUNE_FULL_SOURCE="false"
fi
ECO_COUNT=$(echo "${OSV_ECOSYSTEMS}" | tr ',' '\n' | wc -l)
ECO_IDX=0
echo "[3/5] Downloading OSV.dev data (${ECO_COUNT} ecosystems)..."

IFS=',' read -ra ECO_ARRAY <<< "${OSV_ECOSYSTEMS}"
for eco in "${ECO_ARRAY[@]}"; do
    ECO_IDX=$((ECO_IDX + 1))
    OSV_ECO_FILE="${TMPDIR}/osv-${eco}.jsonl"
    echo "  [${ECO_IDX}/${ECO_COUNT}] ${eco}..."
    if ! "${SCRIPT_DIR}/download-osv.sh" "${OSV_ECO_FILE}" "${eco}"; then
        echo "    ERROR: ${eco} download failed"
        FAILED_SOURCES+=("osv:${eco}")
        OSV_FAILED=1
        continue
    fi
    if [ -s "${OSV_ECO_FILE}" ]; then
        ECO_LINES=$(wc -l < "${OSV_ECO_FILE}")
        ECO_SIZE=$(du -h "${OSV_ECO_FILE}" | cut -f1)
        echo "    Importing ${eco} (${ECO_LINES} entries, ${ECO_SIZE})..."
        IMPORTED=$(import_cve_file "${OSV_ECO_FILE}" "osv" "false" "false")
        echo "    Imported/updated: ${IMPORTED}"
        OSV_TOTAL=$((OSV_TOTAL + IMPORTED))
        rm -f "${OSV_ECO_FILE}"
    else
        echo "    SKIP: ${eco} produced no data"
    fi
done

TOTAL_IMPORTED=$((TOTAL_IMPORTED + OSV_TOTAL))
if [ "${OSV_TOTAL}" -gt 0 ]; then
    if [ "${OSV_FAILED}" -eq 0 ] && [ "${OSV_PRUNE_FULL_SOURCE}" = "true" ]; then
        echo "  Pruning stale OSV rows older than ${OSV_PRUNE_BEFORE}..."
        curl -fsS -X POST -H "X-API-Key: ${API_KEY}" \
            "${SERVER_URL}/api/admin/cve-db/source/osv/prune-stale?before=${OSV_PRUNE_BEFORE}" >/dev/null
    elif [ "${OSV_FAILED}" -eq 0 ]; then
        echo "  Skipping stale OSV prune because BONGSU_OSV_ECOSYSTEMS is a partial override."
        echo "  Run a full OSV sync with the default ecosystem list to prune upstream removals safely."
        echo "  Keeping aggregate OSV source freshness unchanged after partial sync."
    fi
    OSV_REFRESH_SOURCE=""
    if [ "${OSV_FAILED}" -eq 0 ] && [ "${OSV_PRUNE_FULL_SOURCE}" = "true" ]; then
        OSV_REFRESH_SOURCE="osv"
    fi
    if ! finalize_deferred_cve_imports "osv chunk import" "${OSV_REFRESH_SOURCE}"; then
        echo "  ERROR: OSV deferred import finalization failed"
        FAILED_SOURCES+=("osv:finalize")
    fi
fi
if [ "${OSV_FAILED}" -ne 0 ]; then
    echo "  ERROR: incomplete OSV download"
    FAILED_SOURCES+=("osv:partial")
elif [ "${OSV_TOTAL}" -eq 0 ]; then
    echo "  ERROR: no OSV data"
    FAILED_SOURCES+=("osv:no-data")
fi
echo ""

# --- 4. NVD ---
echo "[4/5] Downloading NVD data..."
CURRENT_YEAR="$(date +%Y)"
NVD_YEAR_WINDOW="${BONGSU_NVD_YEAR_WINDOW:-3}"
NVD_YEARS="${BONGSU_NVD_YEARS:-}"
if [ -z "${NVD_YEARS}" ]; then
    NVD_YEARS="$(seq -s, $((CURRENT_YEAR - NVD_YEAR_WINDOW)) "${CURRENT_YEAR}")"
fi
NVD_FAILED=0
NVD_TOTAL=0
NVD_FILE="${TMPDIR}/nvd.jsonl"
echo "  Years ${NVD_YEARS}..."
if ! "${SCRIPT_DIR}/download-nvd.sh" "${NVD_FILE}" "${NVD_YEARS}"; then
    echo "    ERROR: NVD download failed"
    FAILED_SOURCES+=("nvd:download")
    NVD_FAILED=1
elif [ -s "${NVD_FILE}" ]; then
    NVD_LINES=$(wc -l < "${NVD_FILE}")
    NVD_SIZE=$(du -h "${NVD_FILE}" | cut -f1)
    echo "    Importing NVD (${NVD_LINES} entries, ${NVD_SIZE})..."
    IMPORTED=$(import_cve_file "${NVD_FILE}" "nvd")
    echo "    Imported/updated: ${IMPORTED}"
    NVD_TOTAL=$((NVD_TOTAL + IMPORTED))
    rm -f "${NVD_FILE}"
else
    echo "    ERROR: NVD produced no data"
    FAILED_SOURCES+=("nvd:no-data")
    NVD_FAILED=1
fi

TOTAL_IMPORTED=$((TOTAL_IMPORTED + NVD_TOTAL))
if [ "${NVD_FAILED}" -ne 0 ]; then
    echo "  ERROR: incomplete NVD download; preserving existing nvd source"
elif [ "${NVD_TOTAL}" -eq 0 ]; then
    echo "  ERROR: no NVD data"
    FAILED_SOURCES+=("nvd:no-data")
fi
echo ""

# --- 5. Trivy DB ---
echo "[5/5] Extracting Trivy DB CVE data..."
TRIVY_FILE="${TMPDIR}/trivy-cve.jsonl"
TRIVY_FAILED=0
if find_trivy_binary; then
    if ! TRIVY_BIN="${TRIVY_BIN_FOR_SYNC}" "${SCRIPT_DIR}/extract-trivy-cvedb.sh" "${TRIVY_FILE}"; then
        echo "  ERROR: trivy extraction failed"
        FAILED_SOURCES+=("trivy:extract")
        TRIVY_FAILED=1
    fi

    if [ -s "${TRIVY_FILE}" ]; then
        echo "  Importing Trivy CVEs ($(wc -l < "${TRIVY_FILE}") entries)..."
        IMPORTED=$(import_cve_file "${TRIVY_FILE}" "trivy")
        echo "  Imported/updated: ${IMPORTED}"
        TOTAL_IMPORTED=$((TOTAL_IMPORTED + IMPORTED))
    elif [ "${TRIVY_FAILED}" -eq 0 ]; then
        echo "  ERROR: no Trivy CVE data"
        FAILED_SOURCES+=("trivy:no-data")
    fi
else
    if [ "${REQUIRE_TRIVY_SOURCE}" = "true" ]; then
        echo "  ERROR: trivy not installed"
        FAILED_SOURCES+=("trivy:not-installed")
    else
        echo "  SKIP: trivy not installed"
    fi
fi
echo ""

# --- Summary ---
echo "=========================================="
echo " Sync Complete"
echo " Total imported/updated: ${TOTAL_IMPORTED}"
echo ""

if [ "${#FAILED_SOURCES[@]}" -gt 0 ]; then
    echo "ERROR: source sync incomplete: ${FAILED_SOURCES[*]}" >&2
    exit 1
fi

if [ "${OSV_TOTAL}" -gt 0 ]; then
    verify_osv_post_sync_freshness
fi

# Show DB stats
STATS=$(curl -fsS -H "X-API-Key: ${API_KEY}" "${SERVER_URL}/api/cve-db/stats")
echo " Current DB stats:"
echo "${STATS}" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for s in data.get('sources', []):
        print(f'  {s[\"source\"].upper():12s} {s[\"count\"]:>8,} records  (last: {s[\"last_update\"][:19] if s.get(\"last_update\") else \"N/A\"})')
except:
    print('  (unable to parse stats)')
"
echo "=========================================="
