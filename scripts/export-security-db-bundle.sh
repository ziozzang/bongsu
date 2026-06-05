#!/bin/bash
set -euo pipefail

# export-security-db-bundle.sh — Export CVE DB + optional Trivy DB as one airgap bundle
# Usage: ./export-security-db-bundle.sh <server-url> <api-key> [output-file]

SERVER_URL="${1:-${BONGSU_SERVER_URL:-}}"
API_KEY="${2:-${BONGSU_API_KEY:-}}"
OUTPUT="${3:-bongsu-security-db-bundle.tar.gz}"
INCLUDE_TRIVY="${BONGSU_BUNDLE_INCLUDE_TRIVY:-true}"
VERIFY_FRESHNESS="${BONGSU_BUNDLE_VERIFY_FRESHNESS:-true}"
VERIFY_FRESHNESS_ATTEMPTS="${BONGSU_BUNDLE_VERIFY_FRESHNESS_ATTEMPTS:-5}"
VERIFY_FRESHNESS_RETRY_SECONDS="${BONGSU_BUNDLE_VERIFY_FRESHNESS_RETRY_SECONDS:-2}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="$(dirname "$OUTPUT")"
OUTPUT_BASE="$(basename "$OUTPUT")"
TMP_OUTPUT=""

cleanup() {
    if [ -n "$TMP_OUTPUT" ] && [ -f "$TMP_OUTPUT" ]; then
        rm -f "$TMP_OUTPUT"
    fi
}
trap cleanup EXIT

if [ -z "$SERVER_URL" ] || [ -z "$API_KEY" ]; then
    echo "Usage: $0 <server-url> <api-key> [output-file]"
    echo "  or set BONGSU_SERVER_URL and BONGSU_API_KEY"
    exit 1
fi

echo "=== Exporting Bongsu Security DB Bundle ==="
echo "Server:  $SERVER_URL"
echo "Output:  $OUTPUT"

TMP_OUTPUT="$(mktemp "${OUTPUT_DIR%/}/.${OUTPUT_BASE}.tmp.XXXXXX")"
curl -fSL \
    -H "X-API-Key: ${API_KEY}" \
    "${SERVER_URL}/api/admin/security-db/export?include_trivy=${INCLUDE_TRIVY}" \
    -o "${TMP_OUTPUT}"

if [ "$VERIFY_FRESHNESS" != "false" ]; then
    echo "Verifying exported bundle freshness..."
    attempt=1
    while true; do
        if BONGSU_API_BASE="$SERVER_URL" \
            BONGSU_API_KEY="$API_KEY" \
                "${SCRIPT_DIR}/verify-live-security-db-export-freshness.sh"; then
            break
        fi
        if [ "$attempt" -ge "$VERIFY_FRESHNESS_ATTEMPTS" ]; then
            echo "ERROR: exported bundle freshness verification failed after ${attempt} attempts" >&2
            exit 1
        fi
        echo "Export freshness not visible yet; retrying in ${VERIFY_FRESHNESS_RETRY_SECONDS}s (${attempt}/${VERIFY_FRESHNESS_ATTEMPTS})..." >&2
        sleep "$VERIFY_FRESHNESS_RETRY_SECONDS"
        attempt=$((attempt + 1))
    done
fi

mv "$TMP_OUTPUT" "$OUTPUT"
TMP_OUTPUT=""
sha256sum "${OUTPUT}" > "${OUTPUT}.sha256"
echo "Done: $(du -h "${OUTPUT}" | cut -f1)"
echo "SHA256: $(cut -d' ' -f1 "${OUTPUT}.sha256")"
