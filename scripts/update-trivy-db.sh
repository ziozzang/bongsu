#!/bin/bash
set -euo pipefail

# update-trivy-db.sh — Upload trivy-db to air-gapped Bongsu server
# Usage: ./update-trivy-db.sh <server-url> <api-key> [db-file]

SERVER_URL="${1:-${BONGSU_SERVER_URL:-}}"
API_KEY="${2:-${BONGSU_API_KEY:-}}"
DB_FILE="${3:-trivy-db.tar.gz}"

if [ -z "$SERVER_URL" ] || [ -z "$API_KEY" ]; then
    echo "Usage: $0 <server-url> <api-key> [db-file]"
    echo "  or set BONGSU_SERVER_URL and BONGSU_API_KEY environment variables"
    exit 1
fi

if [ ! -f "$DB_FILE" ]; then
    echo "ERROR: $DB_FILE not found"
    exit 1
fi

SIZE=$(du -h "$DB_FILE" | cut -f1)
echo "=== Uploading trivy-db ==="
echo "Server:  $SERVER_URL"
echo "DB file: $DB_FILE ($SIZE)"

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST \
    "${SERVER_URL}/api/admin/trivy-db" \
    -H "X-API-Key: ${API_KEY}" \
    -F "db=@${DB_FILE}" \
    --max-time 600)

if [ "$HTTP_CODE" = "200" ]; then
    echo "Upload successful."
    echo ""
    echo "Verifying health..."
    HEALTH=$(curl -sf "${SERVER_URL}/api/health" -H "X-API-Key: ${API_KEY}" 2>/dev/null || echo '{}')
    echo "$HEALTH" | python3 -m json.tool 2>/dev/null || echo "$HEALTH"
elif [ "$HTTP_CODE" = "401" ]; then
    echo "ERROR: Unauthorized — check API key"
    exit 1
elif [ "$HTTP_CODE" = "503" ]; then
    echo "ERROR: Server trivy manager not available (trivy binary may be missing)"
    exit 1
else
    echo "ERROR: Upload failed (HTTP $HTTP_CODE)"
    exit 1
fi
