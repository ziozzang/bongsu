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
OSV_ECOSYSTEMS="${BONGSU_OSV_ECOSYSTEMS:-PyPI,npm,Go,Maven,crates.io,NuGet,RubyGems,Packagist,Hex,Pub,SwiftURL,Hackage,CRAN,opam,VSCode,GitHub Actions,Alpine,Debian,Ubuntu,SUSE,openSUSE,AlmaLinux,Red Hat,Rocky Linux,Azure Linux,Wolfi,Chainguard,openEuler,Mageia,Android}"
OSV_PRUNE_BEFORE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
OSV_TOTAL=0
OSV_FAILED=0
FAILED_ECOSYSTEMS=()

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

finalize_osv_imports() {
    echo "  Pruning stale OSV rows older than ${OSV_PRUNE_BEFORE}..."
    curl -fsS -X POST -H "X-API-Key: ${API_KEY}" \
        "${SERVER_URL}/api/admin/cve-db/source/osv/prune-stale?before=${OSV_PRUNE_BEFORE}" >/dev/null
    echo "  Rebuilding affected package index after OSV imports..."
    curl -fsS -X POST -H "X-API-Key: ${API_KEY}" "${AFFECTED_INDEX_REBUILD_URL}" >/dev/null
    echo "  Rebuilding reference key index after OSV imports..."
    curl -fsS -X POST -H "X-API-Key: ${API_KEY}" "${REFERENCE_INDEX_REBUILD_URL}" >/dev/null
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
