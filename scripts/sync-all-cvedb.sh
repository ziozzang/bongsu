#!/bin/bash
# sync-all-cvedb.sh — Download from all CVE sources and import into Bongsu
# Sources: OSV.dev (all ecosystems), NVD, Trivy DB
# Usage: ./sync-all-cvedb.sh [server_url] [api_key]
# Environment: NVD_API_KEY for higher NVD rate limits (optional)

set -euo pipefail

SERVER_URL="${1:-http://localhost:5678}"
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

TOTAL_IMPORTED=0

import_cve_file() {
    local file="$1"
    local source="$2"
    local result

    if ! result=$(curl -fsS -X POST -H "X-API-Key: ${API_KEY}" \
        -F "file=@${file}" -F "source=${source}" "${IMPORT_URL}"); then
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

echo "=========================================="
echo " Bongsu CVE Database Sync"
echo " Server: ${SERVER_URL}"
echo "=========================================="
echo ""

# --- 1. OSV.dev ---
echo "[1/3] Downloading OSV.dev data..."
OSV_FILE="${TMPDIR}/osv-all.jsonl"
"${SCRIPT_DIR}/download-osv.sh" "${OSV_FILE}" \
    "PyPI,npm,Go,Maven,crates.io,NuGet,RubyGems,Packagist,Hex,Pub,Alpine,Debian,SUSE,AlmaLinux,Chainguard"

if [ -s "${OSV_FILE}" ]; then
    echo "  Importing OSV data ($(wc -l < "${OSV_FILE}") entries, $(du -h "${OSV_FILE}" | cut -f1))..."
    IMPORTED=$(import_cve_file "${OSV_FILE}" "osv")
    echo "  Imported/updated: ${IMPORTED}"
    TOTAL_IMPORTED=$((TOTAL_IMPORTED + IMPORTED))
else
    echo "  SKIP: no OSV data"
fi
echo ""

# --- 2. NVD ---
echo "[2/3] Downloading NVD data..."
CURRENT_YEAR=$(date +%Y)
NVD_ALL_FILE="${TMPDIR}/nvd-all.jsonl"
for YEAR in $(seq $((CURRENT_YEAR - 3)) ${CURRENT_YEAR}); do
    NVD_FILE="${TMPDIR}/nvd-${YEAR}.jsonl"
    echo "  Year ${YEAR}..."
    "${SCRIPT_DIR}/download-nvd.sh" "${NVD_FILE}" "${YEAR}" || echo "  SKIP: ${YEAR} failed"

    if [ -s "${NVD_FILE}" ]; then
        echo "    Collected $(wc -l < "${NVD_FILE}") entries"
        cat "${NVD_FILE}" >> "${NVD_ALL_FILE}"
    fi
done
if [ -s "${NVD_ALL_FILE}" ]; then
    echo "  Importing combined NVD data ($(wc -l < "${NVD_ALL_FILE}") entries, $(du -h "${NVD_ALL_FILE}" | cut -f1))..."
    IMPORTED=$(import_cve_file "${NVD_ALL_FILE}" "nvd")
    echo "  Imported/updated: ${IMPORTED}"
    TOTAL_IMPORTED=$((TOTAL_IMPORTED + IMPORTED))
else
    echo "  SKIP: no NVD data"
fi
echo ""

# --- 3. Trivy DB ---
echo "[3/3] Extracting Trivy DB CVE data..."
TRIVY_FILE="${TMPDIR}/trivy-cve.jsonl"
if command -v trivy &>/dev/null || [ -x /opt/bongsu/bin/trivy ]; then
    "${SCRIPT_DIR}/extract-trivy-cvedb.sh" "${TRIVY_FILE}" || echo "  SKIP: trivy extraction failed"

    if [ -s "${TRIVY_FILE}" ]; then
        echo "  Importing Trivy CVEs ($(wc -l < "${TRIVY_FILE}") entries)..."
        IMPORTED=$(import_cve_file "${TRIVY_FILE}" "trivy")
        echo "  Imported/updated: ${IMPORTED}"
        TOTAL_IMPORTED=$((TOTAL_IMPORTED + IMPORTED))
    fi
else
    echo "  SKIP: trivy not installed"
fi
echo ""

# --- Summary ---
echo "=========================================="
echo " Sync Complete"
echo " Total imported/updated: ${TOTAL_IMPORTED}"
echo ""

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
