#!/bin/bash
set -euo pipefail

# export-security-db-bundle.sh — Export CVE DB + optional Trivy DB as one airgap bundle
# Usage: ./export-security-db-bundle.sh <server-url> <api-key> [output-file]

SERVER_URL="${1:-${BONGSU_SERVER_URL:-}}"
API_KEY="${2:-${BONGSU_API_KEY:-}}"
OUTPUT="${3:-bongsu-security-db-bundle.tar.gz}"
INCLUDE_TRIVY="${BONGSU_BUNDLE_INCLUDE_TRIVY:-true}"
VERIFY_FRESHNESS="${BONGSU_BUNDLE_VERIFY_FRESHNESS:-true}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -z "$SERVER_URL" ] || [ -z "$API_KEY" ]; then
    echo "Usage: $0 <server-url> <api-key> [output-file]"
    echo "  or set BONGSU_SERVER_URL and BONGSU_API_KEY"
    exit 1
fi

echo "=== Exporting Bongsu Security DB Bundle ==="
echo "Server:  $SERVER_URL"
echo "Output:  $OUTPUT"

curl -fSL \
    -H "X-API-Key: ${API_KEY}" \
    "${SERVER_URL}/api/admin/security-db/export?include_trivy=${INCLUDE_TRIVY}" \
    -o "${OUTPUT}"

sha256sum "${OUTPUT}" > "${OUTPUT}.sha256"
echo "Done: $(du -h "${OUTPUT}" | cut -f1)"
echo "SHA256: $(cut -d' ' -f1 "${OUTPUT}.sha256")"

if [ "$VERIFY_FRESHNESS" != "false" ]; then
    echo "Verifying exported bundle freshness..."
    BONGSU_API_BASE="$SERVER_URL" \
    BONGSU_API_KEY="$API_KEY" \
        "${SCRIPT_DIR}/verify-live-security-db-export-freshness.sh"
fi
