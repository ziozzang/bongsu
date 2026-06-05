#!/bin/bash
set -euo pipefail

# import-security-db-bundle.sh — Import airgap security DB bundle
# Usage: ./import-security-db-bundle.sh <server-url> <api-key> [bundle-file]

SERVER_URL="${1:-${BONGSU_SERVER_URL:-}}"
API_KEY="${2:-${BONGSU_API_KEY:-}}"
BUNDLE="${3:-bongsu-security-db-bundle.tar.gz}"
VERIFY_BEFORE_IMPORT="${BONGSU_BUNDLE_VERIFY_BEFORE_IMPORT:-true}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -z "$SERVER_URL" ] || [ -z "$API_KEY" ]; then
    echo "Usage: $0 <server-url> <api-key> [bundle-file]"
    echo "  or set BONGSU_SERVER_URL and BONGSU_API_KEY"
    exit 1
fi

if [ ! -f "$BUNDLE" ]; then
    echo "ERROR: bundle not found: $BUNDLE"
    exit 1
fi

echo "=== Importing Bongsu Security DB Bundle ==="
echo "Server: $SERVER_URL"
echo "Bundle: $BUNDLE ($(du -h "$BUNDLE" | cut -f1))"

if [ "$VERIFY_BEFORE_IMPORT" != "false" ]; then
    echo "Verifying bundle before upload..."
    "${SCRIPT_DIR}/verify-security-db-bundle-file.sh" "$BUNDLE"
fi

curl -fSL \
    -X POST \
    -H "X-API-Key: ${API_KEY}" \
    -F "bundle=@${BUNDLE}" \
    "${SERVER_URL}/api/admin/security-db/import"

echo ""
echo "Import submitted. Server will recalculate CVSS/enrichment/rematch in the background."
