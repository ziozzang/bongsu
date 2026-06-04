#!/bin/bash
set -euo pipefail

# verify-live-server-build.sh - Verify the live API server build metadata.
#
# Defaults target the local live deployment. The expected commit is the latest
# commit touching server/runtime source paths, so docs-only or deploy-only
# commits do not force a server rebuild. If the live binary reports a newer
# commit, the verifier accepts it only when the server build input files are
# identical between the expected commit and the reported commit. Set
# BONGSU_VERIFY_SERVER_ALLOW_DEV_VERSION=true for local development builds that
# intentionally use version=dev.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API_BASE="${BONGSU_API_BASE:-http://127.0.0.1:5677}"
API_KEY="${BONGSU_API_KEY:-test-admin-key-0123456789}"
CURL_MAX_TIME="${BONGSU_VERIFY_SERVER_CURL_MAX_TIME_SECONDS:-15}"
EXPECTED_SERVER_COMMIT="${BONGSU_VERIFY_SERVER_COMMIT:-}"
ALLOW_DEV_VERSION="${BONGSU_VERIFY_SERVER_ALLOW_DEV_VERSION:-false}"

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: missing required tool: $1" >&2
        exit 1
    fi
}

require_tool curl
require_tool jq

if [ -z "$EXPECTED_SERVER_COMMIT" ]; then
    require_tool git
    mapfile -t SERVER_BUILD_FILES < <(
        cd "$ROOT"
        git ls-files \
            cmd/server \
            internal/server \
            internal/shared \
            migrations \
            deploy/Dockerfile.server \
            Makefile |
            grep -Ev '(^|/)(testdata|fixtures)(/|$)|_test\.go$'
    )
    if [ "${#SERVER_BUILD_FILES[@]}" -eq 0 ]; then
        echo "ERROR: could not find server build input files" >&2
        exit 1
    fi
    EXPECTED_SERVER_COMMIT="$(
        cd "$ROOT"
        git log -1 --format=%H -- "${SERVER_BUILD_FILES[@]}" |
            cut -c1-12
    )"
fi

if [ -z "$EXPECTED_SERVER_COMMIT" ]; then
    echo "ERROR: could not determine expected server commit" >&2
    exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bongsu-server-build.XXXXXX")"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

health_json="$TMP_DIR/health.json"

echo "=== Bongsu Live Server Build Verification ==="
echo "API:             $API_BASE"
echo "Expected commit: $EXPECTED_SERVER_COMMIT"

curl -fsS --max-time "$CURL_MAX_TIME" \
    -H "X-API-Key: $API_KEY" \
    "$API_BASE/api/health" >"$health_json"

jq -e '.status == "ok" or .status == "degraded"' "$health_json" >/dev/null || {
    echo "ERROR: live API health status is not usable" >&2
    jq . "$health_json" >&2
    exit 1
}

server_commit="$(jq -r '.commit // ""' "$health_json")"
server_version="$(jq -r '.version // ""' "$health_json")"
build_date="$(jq -r '.build_date // ""' "$health_json")"

if [ -z "$server_commit" ] || [ "$server_commit" = "unknown" ]; then
    echo "ERROR: live API server commit is not release-identifying: $server_commit" >&2
    exit 1
fi
if [ "$EXPECTED_SERVER_COMMIT" != "skip" ] && [ "$server_commit" != "$EXPECTED_SERVER_COMMIT" ]; then
    if ! git -C "$ROOT" cat-file -e "${server_commit}^{commit}" 2>/dev/null ||
        ! git -C "$ROOT" merge-base --is-ancestor "$EXPECTED_SERVER_COMMIT" "$server_commit" ||
        ! git -C "$ROOT" diff --quiet "$EXPECTED_SERVER_COMMIT" "$server_commit" -- "${SERVER_BUILD_FILES[@]}"; then
        echo "ERROR: live API server commit does not match expected source commit" >&2
        echo "Expected: $EXPECTED_SERVER_COMMIT" >&2
        echo "Actual:   $server_commit" >&2
        exit 1
    fi
    echo "Server commit ${server_commit} is newer than expected ${EXPECTED_SERVER_COMMIT}; server build inputs are unchanged"
fi

if [ -z "$server_version" ] || [ "$server_version" = "unknown" ]; then
    echo "ERROR: live API server version is not set" >&2
    exit 1
fi
if [ "$server_version" = "dev" ] && [ "$ALLOW_DEV_VERSION" != "true" ]; then
    echo "ERROR: live API server version is dev; set BONGSU_VERIFY_SERVER_ALLOW_DEV_VERSION=true only for local development gates" >&2
    exit 1
fi
if [ -z "$build_date" ] || [ "$build_date" = "unknown" ]; then
    echo "ERROR: live API server build date is not set" >&2
    exit 1
fi

echo "Server: version=${server_version}, commit=${server_commit}, build_date=${build_date}"
echo "Live server build verification passed"
