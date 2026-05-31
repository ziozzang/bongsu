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
IMPORT_CMD="curl -s -X POST -H 'X-API-Key: ${API_KEY}'"

TOTAL_IMPORTED=0

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
    RESULT=$(curl -s -X POST -H "X-API-Key: ${API_KEY}" \
        -F "file=@${OSV_FILE}" -F "source=osv" "${IMPORT_URL}")
    echo "  Result: ${RESULT}"
    IMPORTED=$(echo "${RESULT}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('imported',0))" 2>/dev/null || echo "0")
    TOTAL_IMPORTED=$((TOTAL_IMPORTED + IMPORTED))
else
    echo "  SKIP: no OSV data"
fi
echo ""

# --- 2. NVD ---
echo "[2/3] Downloading NVD data..."
CURRENT_YEAR=$(date +%Y)
for YEAR in $(seq $((CURRENT_YEAR - 3)) ${CURRENT_YEAR}); do
    NVD_FILE="${TMPDIR}/nvd-${YEAR}.jsonl"
    echo "  Year ${YEAR}..."
    "${SCRIPT_DIR}/download-nvd.sh" "${NVD_FILE}" "${YEAR}" || echo "  SKIP: ${YEAR} failed"

    if [ -s "${NVD_FILE}" ]; then
        echo "    Importing ($(wc -l < "${NVD_FILE}") entries)..."
        RESULT=$(curl -s -X POST -H "X-API-Key: ${API_KEY}" \
            -F "file=@${NVD_FILE}" -F "source=nvd" "${IMPORT_URL}")
        echo "    Result: ${RESULT}"
        IMPORTED=$(echo "${RESULT}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('imported',0))" 2>/dev/null || echo "0")
        TOTAL_IMPORTED=$((TOTAL_IMPORTED + IMPORTED))
    fi
done
echo ""

# --- 3. Trivy DB ---
echo "[3/3] Extracting Trivy DB CVE data..."
TRIVY_FILE="${TMPDIR}/trivy-cve.jsonl"
if command -v trivy &>/dev/null || [ -x /opt/bongsu/bin/trivy ]; then
    "${SCRIPT_DIR}/extract-trivy-cvedb.sh" "${TRIVY_FILE}" || echo "  SKIP: trivy extraction failed"

    if [ -s "${TRIVY_FILE}" ]; then
        echo "  Importing Trivy CVEs ($(wc -l < "${TRIVY_FILE}") entries)..."
        RESULT=$(curl -s -X POST -H "X-API-Key: ${API_KEY}" \
            -F "file=@${TRIVY_FILE}" -F "source=trivy" "${IMPORT_URL}")
        echo "  Result: ${RESULT}"
        IMPORTED=$(echo "${RESULT}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('imported',0))" 2>/dev/null || echo "0")
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
STATS=$(curl -s -H "X-API-Key: ${API_KEY}" "${SERVER_URL}/api/cve-db/stats")
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
