#!/bin/bash
set -euo pipefail

# verify-live-trusted-identity-rbac.sh - Verify trusted reverse-proxy identity
# headers can authorize RBAC/admin access, while unauthenticated direct access
# remains rejected.

API_BASE="${BONGSU_API_BASE:-http://127.0.0.1:5677}"
CURL_MAX_TIME="${BONGSU_VERIFY_TRUSTED_IDENTITY_CURL_MAX_TIME_SECONDS:-20}"
TRUSTED_USER_HEADER="${BONGSU_VERIFY_TRUSTED_IDENTITY_HEADER:-X-Forwarded-User}"
TRUSTED_GROUPS_HEADER="${BONGSU_VERIFY_TRUSTED_GROUPS_HEADER:-X-Forwarded-Groups}"
TRUSTED_USER="${BONGSU_VERIFY_TRUSTED_IDENTITY_USER:-trusted-rbac@example.test}"
TRUSTED_ADMIN_GROUP="${BONGSU_VERIFY_TRUSTED_IDENTITY_ADMIN_GROUP:-security-admins}"
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

require_tool curl
require_tool jq

echo "=== Bongsu Live Trusted Identity RBAC Verification ==="
echo "API: ${API_BASE}"
echo "User header: ${TRUSTED_USER_HEADER}"
echo "Groups header: ${TRUSTED_GROUPS_HEADER}"
echo "Admin group: ${TRUSTED_ADMIN_GROUP}"

unauth_json="$TMP_DIR/unauth-rbac-status.json"
trusted_json="$TMP_DIR/trusted-rbac-status.json"
mixed_json="$TMP_DIR/trusted-rbac-status-mixed.json"

echo "  checking direct unauthenticated admin access is rejected"
status="$(curl -sS --max-time "$CURL_MAX_TIME" \
    -o "$unauth_json" \
    -w "%{http_code}" \
    "${API_BASE}/api/admin/rbac/status")"
if [ "$status" != "401" ]; then
    echo "ERROR: direct /api/admin/rbac/status returned HTTP ${status}, want 401" >&2
    cat "$unauth_json" >&2 || true
    exit 1
fi

echo "  checking trusted identity admin group authorizes admin RBAC status"
status="$(curl -sS --max-time "$CURL_MAX_TIME" \
    -o "$trusted_json" \
    -w "%{http_code}" \
    -H "${TRUSTED_USER_HEADER}: ${TRUSTED_USER}" \
    -H "${TRUSTED_GROUPS_HEADER}: ${TRUSTED_ADMIN_GROUP}" \
    "${API_BASE}/api/admin/rbac/status")"
if [ "$status" != "200" ]; then
    echo "ERROR: trusted identity admin group returned HTTP ${status}, want 200" >&2
    cat "$trusted_json" >&2 || true
    echo "Hint: start the API with BONGSU_TRUSTED_IDENTITY_HEADER=${TRUSTED_USER_HEADER}, BONGSU_TRUSTED_GROUPS_HEADER=${TRUSTED_GROUPS_HEADER}, BONGSU_TRUSTED_IDENTITY_PROXY_CIDRS including this caller, and BONGSU_TRUSTED_ADMIN_GROUPS including ${TRUSTED_ADMIN_GROUP}." >&2
    exit 1
fi
jq -e '.status == "ok" and .stats and (.stats.subject_count | type == "number")' "$trusted_json" >/dev/null || {
    echo "ERROR: trusted identity RBAC status response is not the expected admin status shape" >&2
    cat "$trusted_json" >&2
    exit 1
}

echo "  checking comma/semicolon-separated trusted groups are parsed"
status="$(curl -sS --max-time "$CURL_MAX_TIME" \
    -o "$mixed_json" \
    -w "%{http_code}" \
    -H "${TRUSTED_USER_HEADER}: ${TRUSTED_USER}" \
    -H "${TRUSTED_GROUPS_HEADER}: platform, ${TRUSTED_ADMIN_GROUP};ops" \
    "${API_BASE}/api/admin/rbac/status")"
if [ "$status" != "200" ]; then
    echo "ERROR: trusted identity mixed group header returned HTTP ${status}, want 200" >&2
    cat "$mixed_json" >&2 || true
    exit 1
fi

echo "Live trusted identity RBAC verification passed"
