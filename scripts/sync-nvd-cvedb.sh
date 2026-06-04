#!/bin/bash
# sync-nvd-cvedb.sh - Refresh only the NVD CVE source.
# Usage: ./sync-nvd-cvedb.sh [server_url] [api_key]

set -euo pipefail

SERVER_URL="${1:-${BONGSU_SERVER_URL:-http://localhost:5677}}"
API_KEY="${2:-${BONGSU_API_KEY:-}}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TMP_PARENT="${BONGSU_TMPDIR:-${TMPDIR:-/tmp}}"
mkdir -p "${TMP_PARENT}"
TMPDIR="$(mktemp -d "${TMP_PARENT%/}/bongsu-nvd-sync.XXXXXX")"
trap 'rm -rf "${TMPDIR}"' EXIT

if [ -z "${API_KEY}" ]; then
    echo "ERROR: API key required. Usage: $0 [server_url] [api_key]" >&2
    echo "   or: BONGSU_API_KEY=xxx $0" >&2
    exit 1
fi

CURRENT_YEAR="$(date +%Y)"
NVD_YEAR_WINDOW="${BONGSU_NVD_YEAR_WINDOW:-3}"
NVD_YEARS="${BONGSU_NVD_YEARS:-}"
if [ -z "${NVD_YEARS}" ]; then
    NVD_YEARS="$(seq -s, $((CURRENT_YEAR - NVD_YEAR_WINDOW)) "${CURRENT_YEAR}")"
fi

NVD_FILE="${TMPDIR}/nvd.jsonl"

echo "=== Bongsu NVD CVE Source Sync ==="
echo "Server: ${SERVER_URL}"
echo "Years: ${NVD_YEARS}"

if ! "${SCRIPT_DIR}/download-nvd.sh" "${NVD_FILE}" "${NVD_YEARS}"; then
    echo "ERROR: NVD download failed; preserving existing nvd source" >&2
    exit 1
fi
if [ ! -s "${NVD_FILE}" ]; then
    echo "ERROR: NVD download produced no data; preserving existing nvd source" >&2
    exit 1
fi

NVD_LINES="$(wc -l < "${NVD_FILE}")"
NVD_SIZE="$(du -h "${NVD_FILE}" | cut -f1)"
echo "Importing NVD CVEs (${NVD_LINES} entries, ${NVD_SIZE})..."
result="$(curl -fsS -X POST -H "X-API-Key: ${API_KEY}" \
    -F "file=@${NVD_FILE}" \
    -F "source=nvd" \
    -F "replace=true" \
    -F "finalize=true" \
    "${SERVER_URL}/api/admin/cve-db/import")"
IMPORTED="$(echo "${result}" | python3 -c '
import json, sys
data = json.load(sys.stdin)
if data.get("status") != "ok":
    print(f"import response was not ok: {data}", file=sys.stderr)
    sys.exit(1)
print(int(data.get("imported", 0)))
')"
if [ "${IMPORTED}" -le 0 ]; then
    echo "ERROR: NVD import returned zero imported rows" >&2
    exit 1
fi

echo "Imported/updated: ${IMPORTED}"
echo "Current NVD source status:"
curl -fsS -H "X-API-Key: ${API_KEY}" "${SERVER_URL}/api/cve-db/stats" | \
    python3 -c '
import json, sys
data = json.load(sys.stdin)
for source in data.get("sources", []):
    if source.get("source") == "nvd":
        print(json.dumps(source, indent=2))
        break
else:
    print("ERROR: nvd source missing after import", file=sys.stderr)
    sys.exit(1)
'

echo "NVD CVE source sync passed"
