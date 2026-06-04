#!/bin/bash
set -euo pipefail

# verify-live-installer-payload.sh - Verify the live one-line installer payload.
#
# Defaults target the local development deployment. Override BONGSU_API_BASE and
# BONGSU_API_KEY for staging/production. By default the expected agent commit is
# the latest commit that touched agent or installer source paths, so docs-only
# commits do not force an unnecessary agent rebuild.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API_BASE="${BONGSU_API_BASE:-http://127.0.0.1:5677}"
API_KEY="${BONGSU_API_KEY:-test-admin-key-0123456789}"
CURL_MAX_TIME="${BONGSU_VERIFY_INSTALLER_CURL_MAX_TIME_SECONDS:-15}"
EXPECTED_AGENT_COMMIT="${BONGSU_VERIFY_INSTALLER_AGENT_COMMIT:-}"

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: missing required tool: $1" >&2
        exit 1
    fi
}

require_tool curl
require_tool jq

if [ -z "$EXPECTED_AGENT_COMMIT" ]; then
    require_tool git
    EXPECTED_AGENT_COMMIT="$(
        cd "$ROOT"
        git log -1 --format=%H -- \
            cmd/agent \
            internal/agent \
            internal/shared \
            scripts/install-agent.sh \
            internal/server/api/installer.go \
            deploy/Dockerfile.agent \
            Makefile |
            cut -c1-12
    )"
fi

if [ -z "$EXPECTED_AGENT_COMMIT" ]; then
    echo "ERROR: could not determine expected agent commit" >&2
    exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bongsu-installer-payload.XXXXXX")"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

status_json="$TMP_DIR/installer-status.json"

echo "=== Bongsu Live Installer Payload Verification ==="
echo "API:             $API_BASE"
echo "Expected commit: $EXPECTED_AGENT_COMMIT"

curl -fsS --max-time "$CURL_MAX_TIME" \
    -H "X-API-Key: $API_KEY" \
    "$API_BASE/api/admin/installer/status" >"$status_json"

jq -e '.ready == true' "$status_json" >/dev/null || {
    echo "ERROR: installer status is not ready" >&2
    jq . "$status_json" >&2
    exit 1
}
jq -e '.install_token_configured == true' "$status_json" >/dev/null || {
    echo "ERROR: installer install token is not configured" >&2
    exit 1
}
jq -e '.agent.ready == true' "$status_json" >/dev/null || {
    echo "ERROR: bongsu-agent installer payload is not ready" >&2
    jq '.agent' "$status_json" >&2
    exit 1
}
jq -e '.trivy.ready == true' "$status_json" >/dev/null || {
    echo "ERROR: trivy installer payload is not ready" >&2
    jq '.trivy' "$status_json" >&2
    exit 1
}
jq -e '(.agent.bytes // 0) > 0 and (.trivy.bytes // 0) > 0' "$status_json" >/dev/null || {
    echo "ERROR: installer payload byte counts are invalid" >&2
    exit 1
}
jq -e '(.agent.sha256 // "") | test("^[0-9a-f]{64}$")' "$status_json" >/dev/null || {
    echo "ERROR: bongsu-agent installer payload SHA256 is invalid" >&2
    jq '.agent' "$status_json" >&2
    exit 1
}
jq -e '(.trivy.sha256 // "") | test("^[0-9a-f]{64}$")' "$status_json" >/dev/null || {
    echo "ERROR: trivy installer payload SHA256 is invalid" >&2
    jq '.trivy' "$status_json" >&2
    exit 1
}

agent_version="$(jq -r '.agent.version // ""' "$status_json")"
if [ -z "$agent_version" ] || [ "$agent_version" = "dev" ] || [ "$agent_version" = "unknown" ]; then
    echo "ERROR: bongsu-agent installer payload version is not release-identifying: $agent_version" >&2
    exit 1
fi

if [ "$EXPECTED_AGENT_COMMIT" != "skip" ] && [[ "$agent_version" != *"+${EXPECTED_AGENT_COMMIT}+"* ]]; then
    echo "ERROR: bongsu-agent installer payload version does not include expected commit" >&2
    echo "Expected: +${EXPECTED_AGENT_COMMIT}+" >&2
    echo "Actual:   $agent_version" >&2
    exit 1
fi

agent_sha="$(jq -r '.agent.sha256' "$status_json")"
agent_bytes="$(jq -r '.agent.bytes' "$status_json")"
trivy_sha="$(jq -r '.trivy.sha256' "$status_json")"
trivy_bytes="$(jq -r '.trivy.bytes' "$status_json")"

echo "Agent: $agent_version, ${agent_bytes} bytes, sha256=${agent_sha}"
echo "Trivy: ${trivy_bytes} bytes, sha256=${trivy_sha}"
echo "Live installer payload verification passed"
