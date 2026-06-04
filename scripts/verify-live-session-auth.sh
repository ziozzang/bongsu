#!/bin/bash
set -euo pipefail

# verify-live-session-auth.sh - Verify local username/password session auth
# through the API and, when available, the deployed web proxy.

API_BASE="${BONGSU_API_BASE:-http://127.0.0.1:5677}"
WEB_BASE="${BONGSU_WEB_BASE:-http://127.0.0.1:5678}"
ADMIN_USERNAME="${BONGSU_ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${BONGSU_ADMIN_PASSWORD:-password}"
CURL_MAX_TIME="${BONGSU_VERIFY_SESSION_AUTH_CURL_MAX_TIME_SECONDS:-20}"
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

login_and_verify_base() {
    local base="$1"
    local label="$2"
    local login_json="$TMP_DIR/${label}-login.json"
    local me_json="$TMP_DIR/${label}-me.json"
    local admin_json="$TMP_DIR/${label}-admin.json"
    local logout_json="$TMP_DIR/${label}-logout.json"
    local after_logout_json="$TMP_DIR/${label}-after-logout.json"
    local status
    local token

    echo "  ${label}: POST /api/auth/login"
    status="$(curl -sS --max-time "$CURL_MAX_TIME" \
        -o "$login_json" \
        -w "%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        --data "$(jq -nc --arg u "$ADMIN_USERNAME" --arg p "$ADMIN_PASSWORD" '{username:$u,password:$p}')" \
        "${base}/api/auth/login")"
    if [ "$status" != "200" ]; then
        echo "ERROR: ${label} login returned HTTP ${status}, want 200" >&2
        cat "$login_json" >&2 || true
        exit 1
    fi
    token="$(jq -r '.token // empty' "$login_json")"
    if [ -z "$token" ] || [ "${#token}" -lt 32 ]; then
        echo "ERROR: ${label} login did not return a plausible bearer token" >&2
        jq 'del(.token)' "$login_json" >&2 || cat "$login_json" >&2
        exit 1
    fi
    jq -e --arg u "$ADMIN_USERNAME" '.user.username == $u and .user.role == "admin" and (.expires | type == "string")' "$login_json" >/dev/null || {
        echo "ERROR: ${label} login response must include the admin user and expiration" >&2
        jq 'del(.token)' "$login_json" >&2 || cat "$login_json" >&2
        exit 1
    }

    echo "  ${label}: GET /api/auth/me with bearer token"
    curl -fsS --max-time "$CURL_MAX_TIME" \
        -H "Authorization: Bearer ${token}" \
        "${base}/api/auth/me" >"$me_json"
    jq -e --arg u "$ADMIN_USERNAME" '.user.username == $u and .user.role == "admin"' "$me_json" >/dev/null || {
        echo "ERROR: ${label} auth/me did not return the logged-in admin user" >&2
        cat "$me_json" >&2
        exit 1
    }

    echo "  ${label}: GET /api/admin/rbac/status with bearer token"
    curl -fsS --max-time "$CURL_MAX_TIME" \
        -H "Authorization: Bearer ${token}" \
        "${base}/api/admin/rbac/status" >"$admin_json"
    jq -e '.status and .stats and (.stats.subject_count | type == "number")' "$admin_json" >/dev/null || {
        echo "ERROR: ${label} bearer token must authorize admin RBAC status" >&2
        cat "$admin_json" >&2
        exit 1
    }

    echo "  ${label}: POST /api/auth/logout and reject reused token"
    curl -fsS --max-time "$CURL_MAX_TIME" \
        -X POST \
        -H "Authorization: Bearer ${token}" \
        "${base}/api/auth/logout" >"$logout_json"
    jq -e '.status == "logged_out"' "$logout_json" >/dev/null || {
        echo "ERROR: ${label} logout response was not logged_out" >&2
        cat "$logout_json" >&2
        exit 1
    }
    status="$(curl -sS --max-time "$CURL_MAX_TIME" \
        -o "$after_logout_json" \
        -w "%{http_code}" \
        -H "Authorization: Bearer ${token}" \
        "${base}/api/auth/me")"
    if [ "$status" != "401" ]; then
        echo "ERROR: ${label} reused token after logout returned HTTP ${status}, want 401" >&2
        cat "$after_logout_json" >&2 || true
        exit 1
    fi
}

require_tool curl
require_tool jq

if [ -z "$ADMIN_USERNAME" ] || [ -z "$ADMIN_PASSWORD" ]; then
    echo "ERROR: BONGSU_ADMIN_USERNAME and BONGSU_ADMIN_PASSWORD are required" >&2
    exit 1
fi

echo "=== Bongsu Live Session Auth Verification ==="
echo "API: ${API_BASE}"
echo "Web: ${WEB_BASE}"
echo "User: ${ADMIN_USERNAME}"

login_and_verify_base "$API_BASE" api

if curl -fsS --max-time "$CURL_MAX_TIME" "${WEB_BASE}/" >/dev/null 2>&1; then
    login_and_verify_base "$WEB_BASE" web
else
    echo "  web: skipped because ${WEB_BASE}/ is not reachable"
fi

echo "Live session auth verification passed"
