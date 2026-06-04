#!/bin/bash
set -euo pipefail

# verify-live-security-db-export-freshness.sh - Gate airgap promotion on a
# current security DB bundle export. Connected environments can have fresh CVE
# sources while the last airgap bundle export is still stale; this verifier
# fails that state explicitly before release or offline transfer.

API_BASE="${BONGSU_API_BASE:-http://127.0.0.1:5677}"
API_KEY="${BONGSU_API_KEY:-test-admin-key-0123456789}"
CURL_MAX_TIME="${BONGSU_VERIFY_CURL_MAX_TIME_SECONDS:-60}"
REQUIRE_FRESHNESS_OK="${BONGSU_VERIFY_SECURITY_DB_EXPORT_REQUIRE_FRESHNESS_OK:-true}"
STATUS_FILE="${BONGSU_VERIFY_SECURITY_DB_EXPORT_STATUS_FILE:-}"
TMP_DIR="$(mktemp -d)"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: missing required tool: $1" >&2
        exit 1
    fi
}

require_tool jq

STATUS_JSON="$TMP_DIR/security-db-status.json"
if [ -n "$STATUS_FILE" ]; then
    if [ ! -f "$STATUS_FILE" ]; then
        echo "ERROR: BONGSU_VERIFY_SECURITY_DB_EXPORT_STATUS_FILE does not exist: ${STATUS_FILE}" >&2
        exit 1
    fi
    cp "$STATUS_FILE" "$STATUS_JSON"
else
    require_tool curl
    HTTP_STATUS="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$STATUS_JSON" -w "%{http_code}" \
        -H "X-API-Key: ${API_KEY}" \
        "${API_BASE}/api/admin/security-db/status")"
    if [[ "$HTTP_STATUS" != 2* ]]; then
        echo "ERROR: /api/admin/security-db/status returned HTTP ${HTTP_STATUS}" >&2
        cat "$STATUS_JSON" >&2 || true
        exit 1
    fi
fi

if [ "$REQUIRE_FRESHNESS_OK" = "true" ]; then
    if ! jq -e '.security_db_freshness.status == "ok"' "$STATUS_JSON" >/dev/null; then
        echo "ERROR: security DB source freshness is not ok; export freshness is not meaningful" >&2
        jq '{status,warnings,recommended_actions,security_db_freshness}' "$STATUS_JSON" >&2
        exit 1
    fi
fi

if ! jq -e '.security_db_export and (.security_db_export.status | type == "string")' "$STATUS_JSON" >/dev/null; then
    echo "ERROR: security_db_export status is missing from /api/admin/security-db/status" >&2
    jq '{status,warnings,recommended_actions,security_db_export}' "$STATUS_JSON" >&2
    exit 1
fi

EXPORT_STATUS="$(jq -r '.security_db_export.status' "$STATUS_JSON")"
case "$EXPORT_STATUS" in
    ok)
        ;;
    stale)
        echo "ERROR: security DB export is stale; export a new bundle before airgap promotion" >&2
        jq '{security_db_export:{status:.security_db_export.status,latest_exported_at:.security_db_export.latest_exported_at,latest_source_update_at:.security_db_export.latest_source_update_at,outdated_source_count:.security_db_export.outdated_source_count,outdated_sources:.security_db_export.outdated_sources},warnings,recommended_actions}' "$STATUS_JSON" >&2
        exit 1
        ;;
    never)
        echo "ERROR: security DB has never been exported; export a bundle before airgap promotion" >&2
        jq '{security_db_export,warnings,recommended_actions}' "$STATUS_JSON" >&2
        exit 1
        ;;
    *)
        echo "ERROR: unsupported security DB export status: ${EXPORT_STATUS}" >&2
        jq '{security_db_export,warnings,recommended_actions}' "$STATUS_JSON" >&2
        exit 1
        ;;
esac

if ! jq -e '((.security_db_export.outdated_sources // []) | length) == 0 and ((.security_db_export.outdated_source_count // 0) == 0)' "$STATUS_JSON" >/dev/null; then
    echo "ERROR: security DB export reports outdated sources despite ok status" >&2
    jq '{security_db_export}' "$STATUS_JSON" >&2
    exit 1
fi

if ! jq -e '(.security_db_export.latest_exported_at // "") != "" and (.security_db_export.latest_source_update_at // "") != ""' "$STATUS_JSON" >/dev/null; then
    echo "ERROR: security DB export freshness timestamps are incomplete" >&2
    jq '{security_db_export}' "$STATUS_JSON" >&2
    exit 1
fi

echo "Security DB export freshness verification passed"
jq -r '"Latest export: " + .security_db_export.latest_exported_at + "\nLatest source update: " + .security_db_export.latest_source_update_at' "$STATUS_JSON"
