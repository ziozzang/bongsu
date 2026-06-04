#!/bin/bash
set -euo pipefail

# verify-live-install-script.sh - Verify the live one-line installer endpoint
# and authenticated binary download path. This complements installer payload
# readiness by exercising the actual URLs operators use.

API_BASE="${BONGSU_API_BASE:-http://127.0.0.1:5677}"
API_KEY="${BONGSU_API_KEY:-test-admin-key-0123456789}"
INSTALL_TOKEN="${BONGSU_INSTALL_TOKEN:-test-install-token-0123456789}"
CURL_MAX_TIME="${BONGSU_VERIFY_INSTALL_SCRIPT_CURL_MAX_TIME_SECONDS:-30}"
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

file_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "ERROR: sha256sum or shasum is required" >&2
        exit 1
    fi
}

http_status() {
    local path="$1"
    local out="$TMP_DIR/status-body"
    shift
    curl -sS --max-time "$CURL_MAX_TIME" -o "$out" -w "%{http_code}" "$@" "${API_BASE}${path}"
}

assert_status() {
    local got="$1"
    local want="$2"
    local message="$3"
    if [ "$got" != "$want" ]; then
        echo "ERROR: ${message}; got HTTP ${got}, want ${want}" >&2
        cat "$TMP_DIR/status-body" >&2 || true
        exit 1
    fi
}

assert_contains() {
    local file="$1"
    local pattern="$2"
    local message="$3"
    if ! grep -Fq "$pattern" "$file"; then
        echo "ERROR: ${message}; missing ${pattern}" >&2
        sed -n '1,220p' "$file" >&2 || true
        exit 1
    fi
}

assert_not_contains() {
    local file="$1"
    local pattern="$2"
    local message="$3"
    if grep -Fq "$pattern" "$file"; then
        echo "ERROR: ${message}; found ${pattern}" >&2
        sed -n '1,220p' "$file" >&2 || true
        exit 1
    fi
}

download_with_sha() {
    local name="$1"
    local path="$2"
    local out="$TMP_DIR/${name}"
    local headers="$TMP_DIR/${name}.headers"
    local status
    local expected
    local actual

    status="$(curl -sS --max-time "$CURL_MAX_TIME" \
        -D "$headers" \
        -o "$out" \
        -w "%{http_code}" \
        -H "X-Install-Token: ${INSTALL_TOKEN}" \
        "${API_BASE}${path}")"
    if [[ "$status" != 2* ]]; then
        echo "ERROR: download ${path} returned HTTP ${status}" >&2
        cat "$out" >&2 || true
        exit 1
    fi
    expected="$(awk 'tolower($1)=="x-bongsu-sha256:" {print $2}' "$headers" | tail -1 | tr -d '\r')"
    if ! printf '%s' "$expected" | grep -Eq '^[0-9a-f]{64}$'; then
        echo "ERROR: ${name} download is missing a valid X-Bongsu-SHA256 header" >&2
        cat "$headers" >&2
        exit 1
    fi
    actual="$(file_sha256 "$out")"
    if [ "$actual" != "$expected" ]; then
        echo "ERROR: ${name} checksum mismatch; header=${expected} actual=${actual}" >&2
        exit 1
    fi
    if [ ! -s "$out" ]; then
        echo "ERROR: ${name} download is empty" >&2
        exit 1
    fi
    echo "${name}: $(wc -c < "$out" | tr -d ' ') bytes sha256=${actual}"
}

require_tool curl
require_tool grep
require_tool awk

echo "=== Bongsu Live Install Script Verification ==="
echo "API: $API_BASE"

echo "[1/4] Verifying installer and download endpoints require header authentication"
status="$(http_status /api/install.sh)"
assert_status "$status" "401" "installer script must reject unauthenticated requests"
status="$(http_status "/api/install.sh?token=${INSTALL_TOKEN}")"
assert_status "$status" "401" "installer script must reject token query parameters"
status="$(http_status /api/downloads/bongsu-agent)"
assert_status "$status" "401" "agent binary download must reject unauthenticated requests"
status="$(http_status /api/downloads/trivy)"
assert_status "$status" "401" "trivy binary download must reject unauthenticated requests"

echo "[2/4] Downloading generated one-line installer script"
installer="$TMP_DIR/install.sh"
curl -fsS --max-time "$CURL_MAX_TIME" \
    -H "X-Install-Token: ${INSTALL_TOKEN}" \
    "${API_BASE}/api/install.sh" >"$installer"
head -1 "$installer" | grep -q '^#!/bin/bash$' || {
    echo "ERROR: installer script must start with #!/bin/bash" >&2
    exit 1
}
assert_contains "$installer" 'curl -fsSL -H "X-Install-Token: $BONGSU_INSTALL_TOKEN"' "installer usage must show header-authenticated one-line command"
assert_contains "$installer" 'BONGSU_AGENT_API_KEY' "installer must allow env-provided agent API key"
assert_contains "$installer" 'INSTALL_TOKEN=' "installer must carry an install token for binary downloads"
assert_contains "$installer" 'header = "X-Install-Token:' "installer must use curl config header for binary downloads"
assert_contains "$installer" 'verify_download_sha256' "installer must verify binary checksums"
assert_contains "$installer" 'X-Bongsu-SHA256' "installer must require server-provided binary checksum headers"
assert_contains "$installer" 'chmod 600 "$WORK_DIR/config.yaml"' "installer must protect config permissions"
assert_contains "$installer" 'chmod 600 "$WORK_DIR/agent.token"' "installer must protect agent token permissions"
assert_contains "$installer" 'bongsu-agent-daemon.service' "installer must support force-scan daemon service"
assert_contains "$installer" 'crontab -l' "installer must support cron mode"
assert_not_contains "$installer" '?token=' "installer must not use token-bearing URLs"
assert_not_contains "$installer" 'api_key=' "installer must not use API-key query parameters"

echo "[3/4] Verifying authenticated binary downloads and checksums"
download_with_sha bongsu-agent /api/downloads/bongsu-agent
download_with_sha trivy /api/downloads/trivy

echo "[4/4] Verifying admin API key can also download binaries for manual operations"
status="$(http_status /api/downloads/bongsu-agent -H "X-API-Key: ${API_KEY}")"
if [[ "$status" != 2* ]]; then
    echo "ERROR: admin API key should allow manual agent binary download; got HTTP ${status}" >&2
    cat "$TMP_DIR/status-body" >&2 || true
    exit 1
fi

echo "Live install script verification passed"
