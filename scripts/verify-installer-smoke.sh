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
