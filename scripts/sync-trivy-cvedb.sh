#!/bin/bash
# sync-trivy-cvedb.sh - Refresh only the Trivy-derived CVE source.
# Usage: ./sync-trivy-cvedb.sh [server_url] [api_key]

set -euo pipefail

SERVER_URL="${1:-${BONGSU_SERVER_URL:-http://localhost:5677}}"
API_KEY="${2:-${BONGSU_API_KEY:-}}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

if [ -z "${API_KEY}" ]; then
    echo "ERROR: API key required. Usage: $0 [server_url] [api_key]" >&2
    echo "   or: BONGSU_API_KEY=xxx $0" >&2
    exit 1
fi

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

import_trivy_file() {
    local file="$1"
    local result
    result=$(curl -fsS -X POST -H "X-API-Key: ${API_KEY}" \
        -F "file=@${file}" \
        -F "source=trivy" \
        -F "replace=true" \
        -F "finalize=true" \
        "${SERVER_URL}/api/admin/cve-db/import")
    echo "${result}" | python3 -c '
import json, sys
data = json.load(sys.stdin)
if data.get("status") != "ok":
    print(f"import response was not ok: {data}", file=sys.stderr)
    sys.exit(1)
print(int(data.get("imported", 0)))
'
}

echo "=== Bongsu Trivy CVE Source Sync ==="
echo "Server: ${SERVER_URL}"

if ! find_trivy_binary; then
    echo "ERROR: trivy not installed. Set TRIVY_BIN or BONGSU_TRIVY_PATH." >&2
    exit 1
fi

TRIVY_FILE="${TMPDIR}/trivy-cve.jsonl"
echo "Extracting Trivy CVE source with ${TRIVY_BIN_FOR_SYNC}..."
TRIVY_BIN="${TRIVY_BIN_FOR_SYNC}" "${SCRIPT_DIR}/extract-trivy-cvedb.sh" "${TRIVY_FILE}"

if [ ! -s "${TRIVY_FILE}" ]; then
    echo "ERROR: Trivy extraction produced no CVE data" >&2
    exit 1
fi

echo "Importing Trivy CVEs ($(wc -l < "${TRIVY_FILE}") entries, $(du -h "${TRIVY_FILE}" | cut -f1))..."
IMPORTED="$(import_trivy_file "${TRIVY_FILE}")"
if [ "${IMPORTED}" -le 0 ]; then
    echo "ERROR: Trivy import returned zero imported rows" >&2
    exit 1
fi

echo "Imported/updated: ${IMPORTED}"
echo "Current Trivy source status:"
curl -fsS -H "X-API-Key: ${API_KEY}" "${SERVER_URL}/api/cve-db/stats" | \
    python3 -c '
import json, sys
data = json.load(sys.stdin)
for source in data.get("sources", []):
    if source.get("source") == "trivy":
        print(json.dumps(source, indent=2))
        break
else:
    print("ERROR: trivy source missing after import", file=sys.stderr)
    sys.exit(1)
'

echo "Trivy CVE source sync passed"
