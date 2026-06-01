#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

INSTALLER_DIR="$TMP_DIR/installer"
WORK_DIR="$TMP_DIR/work"
STUB_DIR="$TMP_DIR/stubs"
TOKEN="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
SERVER_URL="http://bongsu.example:5677"
API_KEY="agent-api-key-for-installer-smoke"

mkdir -p "$INSTALLER_DIR/bin" "$STUB_DIR"
cp "$ROOT_DIR/scripts/install-agent.sh" "$INSTALLER_DIR/install-agent.sh"

cat > "$INSTALLER_DIR/bin/bongsu-agent" <<'AGENT'
#!/bin/sh
echo "bongsu-agent smoke run: $*"
exit 0
AGENT
chmod +x "$INSTALLER_DIR/bin/bongsu-agent"

cat > "$INSTALLER_DIR/bin/trivy" <<'TRIVY'
#!/bin/sh
echo "trivy smoke"
exit 0
TRIVY
chmod +x "$INSTALLER_DIR/bin/trivy"

cat > "$STUB_DIR/openssl" <<'OPENSSL'
#!/bin/sh
if [ "$1" = "rand" ] && [ "$2" = "-hex" ] && [ "$3" = "32" ]; then
    printf '%s\n' "$BONGSU_TEST_AGENT_TOKEN"
    exit 0
fi
exit 1
OPENSSL
chmod +x "$STUB_DIR/openssl"

cat > "$STUB_DIR/crontab" <<'CRONTAB'
#!/bin/sh
if [ "${1:-}" = "-l" ]; then
    if [ -f "$BONGSU_TEST_CRONTAB" ]; then
        cat "$BONGSU_TEST_CRONTAB"
        exit 0
    fi
    exit 1
fi
cat > "$BONGSU_TEST_CRONTAB"
CRONTAB
chmod +x "$STUB_DIR/crontab"

assert_file() {
    if [ ! -f "$1" ]; then
        echo "ERROR: expected file missing: $1" >&2
        exit 1
    fi
}

assert_executable() {
    assert_file "$1"
    if [ ! -x "$1" ]; then
        echo "ERROR: expected executable file: $1" >&2
        exit 1
    fi
}

assert_contains() {
    local file="$1"
    local expected="$2"
    if ! grep -Fq "$expected" "$file"; then
        echo "ERROR: expected '$expected' in $file" >&2
        echo "---- $file ----" >&2
        sed -n '1,160p' "$file" >&2
        exit 1
    fi
}

assert_mode() {
    local file="$1"
    local expected="$2"
    local actual
    actual="$(stat -c '%a' "$file")"
    if [ "$actual" != "$expected" ]; then
        echo "ERROR: expected mode $expected for $file, got $actual" >&2
        exit 1
    fi
}

PATH="$STUB_DIR:/usr/bin:/bin" \
BONGSU_WORK_DIR="$WORK_DIR" \
BONGSU_PACKAGES_ONLY=true \
BONGSU_CRON="17 4 * * *" \
BONGSU_INSTALL_MODE=cron \
BONGSU_FORCE_SCAN_DAEMON=false \
BONGSU_TEST_AGENT_TOKEN="$TOKEN" \
BONGSU_TEST_CRONTAB="$TMP_DIR/crontab.installed" \
bash "$INSTALLER_DIR/install-agent.sh" "$SERVER_URL" "$API_KEY" > "$TMP_DIR/install.out"

assert_executable "$WORK_DIR/bin/bongsu-agent"
assert_executable "$WORK_DIR/bin/trivy"
assert_file "$WORK_DIR/config.yaml"
assert_file "$WORK_DIR/agent.token"
assert_file "$TMP_DIR/crontab.installed"

assert_mode "$WORK_DIR/config.yaml" "600"
assert_mode "$WORK_DIR/agent.token" "600"
assert_contains "$WORK_DIR/config.yaml" "server_url: $SERVER_URL"
assert_contains "$WORK_DIR/config.yaml" "api_key: $API_KEY"
assert_contains "$WORK_DIR/config.yaml" "agent_token: $TOKEN"
assert_contains "$WORK_DIR/config.yaml" "work_dir: $WORK_DIR"
assert_contains "$WORK_DIR/agent.token" "$TOKEN"
assert_contains "$TMP_DIR/crontab.installed" "17 4 * * * $WORK_DIR/bin/bongsu-agent --config $WORK_DIR/config.yaml --type daily --packages-only >> $WORK_DIR/agent.log 2>&1"
assert_contains "$TMP_DIR/install.out" "Running first scan"
assert_contains "$TMP_DIR/install.out" "bongsu-agent smoke run:"

PATH="$STUB_DIR:/usr/bin:/bin" \
BONGSU_WORK_DIR="$WORK_DIR" \
BONGSU_PACKAGES_ONLY=true \
BONGSU_CRON="23 5 * * *" \
BONGSU_INSTALL_MODE=cron \
BONGSU_FORCE_SCAN_DAEMON=false \
BONGSU_TEST_AGENT_TOKEN="should-not-be-used" \
BONGSU_TEST_CRONTAB="$TMP_DIR/crontab.installed" \
bash "$INSTALLER_DIR/install-agent.sh" "$SERVER_URL" "$API_KEY" > "$TMP_DIR/reinstall.out"

assert_contains "$WORK_DIR/agent.token" "$TOKEN"
assert_contains "$WORK_DIR/config.yaml" "agent_token: $TOKEN"
assert_contains "$TMP_DIR/crontab.installed" "23 5 * * * $WORK_DIR/bin/bongsu-agent --config $WORK_DIR/config.yaml --type daily --packages-only >> $WORK_DIR/agent.log 2>&1"
if grep -Fq "17 4 * * *" "$TMP_DIR/crontab.installed"; then
    echo "ERROR: reinstall did not replace the previous bongsu cron entry" >&2
    exit 1
fi

echo "Installer smoke verification passed"

DOWNLOAD_INSTALLER_DIR="$TMP_DIR/download-installer"
DOWNLOAD_WORK_DIR="$TMP_DIR/download-work"
DOWNLOAD_STUB_DIR="$TMP_DIR/download-stubs"
DOWNLOAD_LOG="$TMP_DIR/curl-download.log"
INSTALL_TOKEN="installer-token-for-header-only-download"

mkdir -p "$DOWNLOAD_INSTALLER_DIR" "$DOWNLOAD_STUB_DIR"
cp "$ROOT_DIR/scripts/install-agent.sh" "$DOWNLOAD_INSTALLER_DIR/install-agent.sh"
cp "$STUB_DIR/openssl" "$DOWNLOAD_STUB_DIR/openssl"
cp "$STUB_DIR/crontab" "$DOWNLOAD_STUB_DIR/crontab"

cat > "$DOWNLOAD_STUB_DIR/curl" <<'CURL'
#!/bin/sh
set -eu

header_file=""
output_file=""
config_file=""
url=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --config)
            config_file="$2"
            shift 2
            ;;
        -D)
            header_file="$2"
            shift 2
            ;;
        -o)
            output_file="$2"
            shift 2
            ;;
        http://*|https://*)
            url="$1"
            shift
            ;;
        *)
            shift
            ;;
    esac
done

{
    printf 'url=%s\n' "$url"
    if [ -n "$config_file" ]; then
        printf 'config=%s\n' "$(cat "$config_file")"
    else
        printf 'config=\n'
    fi
} >> "$BONGSU_TEST_CURL_LOG"

if [ -z "$header_file" ] || [ -z "$output_file" ] || [ -z "$url" ]; then
    exit 22
fi
if printf '%s' "$url" | grep -Fq "$BONGSU_TEST_INSTALL_TOKEN"; then
    echo "install token leaked into URL" >&2
    exit 23
fi

case "$url" in
    */api/downloads/bongsu-agent)
        cat > "$output_file" <<'AGENT'
#!/bin/sh
echo "downloaded bongsu-agent smoke run: $*"
exit 0
AGENT
        ;;
    */api/downloads/trivy)
        cat > "$output_file" <<'TRIVY'
#!/bin/sh
echo "downloaded trivy smoke"
exit 0
TRIVY
        ;;
    *)
        exit 24
        ;;
esac

sha="$(sha256sum "$output_file" | awk '{print $1}')"
if [ "${BONGSU_TEST_BAD_SHA:-false}" = "true" ]; then
    sha="0000000000000000000000000000000000000000000000000000000000000000"
fi
{
    printf 'HTTP/1.1 200 OK\r\n'
    printf 'X-Bongsu-SHA256: %s\r\n' "$sha"
    printf '\r\n'
} > "$header_file"
CURL
chmod +x "$DOWNLOAD_STUB_DIR/curl"

PATH="$DOWNLOAD_STUB_DIR:/usr/bin:/bin" \
BONGSU_WORK_DIR="$DOWNLOAD_WORK_DIR" \
BONGSU_PACKAGES_ONLY=true \
BONGSU_CRON="31 6 * * *" \
BONGSU_INSTALL_MODE=cron \
BONGSU_FORCE_SCAN_DAEMON=false \
BONGSU_INSTALL_TOKEN="$INSTALL_TOKEN" \
BONGSU_TEST_INSTALL_TOKEN="$INSTALL_TOKEN" \
BONGSU_TEST_AGENT_TOKEN="$TOKEN" \
BONGSU_TEST_CRONTAB="$TMP_DIR/download-crontab.installed" \
BONGSU_TEST_CURL_LOG="$DOWNLOAD_LOG" \
bash "$DOWNLOAD_INSTALLER_DIR/install-agent.sh" "$SERVER_URL" "$API_KEY" > "$TMP_DIR/download-install.out"

assert_executable "$DOWNLOAD_WORK_DIR/bin/bongsu-agent"
assert_executable "$DOWNLOAD_WORK_DIR/bin/trivy"
assert_contains "$TMP_DIR/download-install.out" "Downloading bongsu-agent from server"
assert_contains "$TMP_DIR/download-install.out" "Trivy binary downloaded"
assert_contains "$TMP_DIR/download-install.out" "downloaded bongsu-agent smoke run:"
assert_contains "$DOWNLOAD_LOG" "url=$SERVER_URL/api/downloads/bongsu-agent"
assert_contains "$DOWNLOAD_LOG" "url=$SERVER_URL/api/downloads/trivy"
assert_contains "$DOWNLOAD_LOG" "config=header = \"X-Install-Token: $INSTALL_TOKEN\""
if grep -Fq "$INSTALL_TOKEN" "$DOWNLOAD_LOG" && grep -F "$INSTALL_TOKEN" "$DOWNLOAD_LOG" | grep -Fq "url="; then
    echo "ERROR: install token appeared in a download URL" >&2
    exit 1
fi

BAD_SHA_WORK_DIR="$TMP_DIR/bad-sha-work"
if PATH="$DOWNLOAD_STUB_DIR:/usr/bin:/bin" \
    BONGSU_WORK_DIR="$BAD_SHA_WORK_DIR" \
    BONGSU_PACKAGES_ONLY=true \
    BONGSU_CRON="37 7 * * *" \
    BONGSU_INSTALL_MODE=cron \
    BONGSU_FORCE_SCAN_DAEMON=false \
    BONGSU_INSTALL_TOKEN="$INSTALL_TOKEN" \
    BONGSU_TEST_INSTALL_TOKEN="$INSTALL_TOKEN" \
    BONGSU_TEST_AGENT_TOKEN="$TOKEN" \
    BONGSU_TEST_CRONTAB="$TMP_DIR/bad-sha-crontab.installed" \
    BONGSU_TEST_CURL_LOG="$TMP_DIR/bad-sha-curl.log" \
    BONGSU_TEST_BAD_SHA=true \
    bash "$DOWNLOAD_INSTALLER_DIR/install-agent.sh" "$SERVER_URL" "$API_KEY" > "$TMP_DIR/bad-sha.out" 2>&1; then
    echo "ERROR: installer accepted a checksum-mismatched agent download" >&2
    exit 1
fi
assert_contains "$TMP_DIR/bad-sha.out" "checksum mismatch"
if [ -e "$BAD_SHA_WORK_DIR/bin/bongsu-agent" ]; then
    echo "ERROR: checksum-mismatched agent binary was left on disk" >&2
    exit 1
fi

echo "Installer download verification passed"
