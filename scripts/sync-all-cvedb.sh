#!/bin/bash
# sync-all-cvedb.sh — Download from all CVE sources and import into Bongsu
# Sources: CISA KEV, FIRST EPSS, OSV.dev (all ecosystems), NVD, Trivy DB
# Usage: ./sync-all-cvedb.sh [server_url] [api_key]
# Environment: NVD_API_KEY for higher NVD rate limits (optional)

set -euo pipefail

SERVER_URL="${1:-http://localhost:5677}"
API_KEY="${2:-${BONGSU_API_KEY:-}}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" EXIT

if [ -z "${API_KEY}" ]; then
    echo "ERROR: API key required. Usage: $0 [server_url] [api_key]"
    echo "   or: BONGSU_API_KEY=xxx $0"
    exit 1
fi

IMPORT_URL="${SERVER_URL}/api/admin/cve-db/import"
RECALCULATE_URL="${SERVER_URL}/api/admin/security-db/recalculate"
AFFECTED_INDEX_REBUILD_URL="${SERVER_URL}/api/admin/cve-db/affected-index/rebuild"
REFERENCE_INDEX_REBUILD_URL="${SERVER_URL}/api/admin/cve-db/reference-index/rebuild"

TOTAL_IMPORTED=0
FAILED_SOURCES=()
REQUIRE_TRIVY_SOURCE="${BONGSU_SYNC_REQUIRE_TRIVY_SOURCE:-true}"
TRIVY_BIN_FOR_SYNC="${TRIVY_BIN:-${BONGSU_TRIVY_PATH:-}}"

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

finalize_deferred_cve_imports() {
    local reason="$1"
    echo "  Rebuilding affected package index after deferred imports..."
    curl -fsS -X POST -H "X-API-Key: ${API_KEY}" "${AFFECTED_INDEX_REBUILD_URL}" >/dev/null
    echo "  Rebuilding reference key index after deferred imports..."
    curl -fsS -X POST -H "X-API-Key: ${API_KEY}" "${REFERENCE_INDEX_REBUILD_URL}" >/dev/null
    echo "  Queuing security recalculation after deferred imports..."
    curl -fsS -X POST -H "X-API-Key: ${API_KEY}" \
        -H "Content-Type: application/json" \
        -d "{\"reason\":\"${reason}\"}" "${RECALCULATE_URL}" >/dev/null
}

echo "=========================================="
echo " Bongsu CVE Database Sync"
echo " Server: ${SERVER_URL}"
echo "=========================================="
echo ""

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
OSV_ECOSYSTEMS="${BONGSU_OSV_ECOSYSTEMS:-PyPI,npm,Go,Maven,crates.io,NuGet,RubyGems,Packagist,Hex,Pub,SwiftURL,Hackage,CRAN,opam,VSCode,GitHub Actions,Alpine,Debian,Ubuntu,SUSE,openSUSE,AlmaLinux,Red Hat,Rocky Linux,Azure Linux,Wolfi,Chainguard,openEuler,Mageia,Android}"
OSV_TOTAL=0
OSV_FAILED=0
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
    if ! finalize_deferred_cve_imports "osv chunk import"; then
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

# --- 4. NVD (per-year to avoid upload timeouts) ---
echo "[4/5] Downloading NVD data..."
CURRENT_YEAR=$(date +%Y)
NVD_FAILED=0
NVD_TOTAL=0
for YEAR in $(seq $((CURRENT_YEAR - 3)) ${CURRENT_YEAR}); do
    NVD_FILE="${TMPDIR}/nvd-${YEAR}.jsonl"
    echo "  Year ${YEAR}..."
    if ! "${SCRIPT_DIR}/download-nvd.sh" "${NVD_FILE}" "${YEAR}"; then
        echo "    ERROR: ${YEAR} download failed"
        FAILED_SOURCES+=("nvd:${YEAR}")
        NVD_FAILED=1
        continue
    fi

    if [ -s "${NVD_FILE}" ]; then
        NVD_LINES=$(wc -l < "${NVD_FILE}")
        NVD_SIZE=$(du -h "${NVD_FILE}" | cut -f1)
        echo "    Importing ${YEAR} (${NVD_LINES} entries, ${NVD_SIZE})..."
        IMPORTED=$(import_cve_file "${NVD_FILE}" "nvd")
        echo "    Imported/updated: ${IMPORTED}"
        NVD_TOTAL=$((NVD_TOTAL + IMPORTED))
        rm -f "${NVD_FILE}"
    else
        echo "    ERROR: ${YEAR} produced no NVD data"
        FAILED_SOURCES+=("nvd:${YEAR}:no-data")
        NVD_FAILED=1
    fi
done

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
