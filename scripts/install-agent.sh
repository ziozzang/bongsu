#!/bin/bash
set -euo pipefail

# install-agent.sh — Install Bongsu agent on a target host
# Usage: ./install-agent.sh <server-url> [agent-api-key]
#        BONGSU_AGENT_API_KEY=... ./install-agent.sh <server-url>

SERVER_URL="${1:-}"
API_KEY="${2:-${BONGSU_AGENT_API_KEY:-}}"
WORK_DIR="${BONGSU_WORK_DIR:-/opt/bongsu}"
PACKAGES_ONLY="${BONGSU_PACKAGES_ONLY:-true}"
CRON_SCHEDULE="${BONGSU_CRON:-0 3 * * *}"
INSTALL_MODE="${BONGSU_INSTALL_MODE:-cron}"
FORCE_SCAN_DAEMON="${BONGSU_FORCE_SCAN_DAEMON:-true}"
INSTALL_TOKEN="${BONGSU_INSTALL_TOKEN:-}"
AGENT_TOKEN="${BONGSU_AGENT_TOKEN:-}"
HOST_ID="${BONGSU_HOST_ID:-${BONGSU_AGENT_HOST_ID:-}}"
SYSTEMD_DIR="${BONGSU_SYSTEMD_DIR:-/etc/systemd/system}"
SYSTEMCTL_BIN="${BONGSU_SYSTEMCTL_BIN:-systemctl}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

curl_download() {
    local url="$1"
    local output="$2"
    local headers
    headers="$(mktemp)"
    trap 'rm -f "$headers"' RETURN
    if [ -n "$INSTALL_TOKEN" ]; then
        local curl_config
        curl_config="$(mktemp)"
        chmod 600 "$curl_config"
        printf 'header = "X-Install-Token: %s"\n' "$INSTALL_TOKEN" > "$curl_config"
        if curl -fsSL --config "$curl_config" -D "$headers" "$url" -o "$output"; then
            rm -f "$curl_config"
            if ! verify_download_sha256 "$headers" "$output"; then
                rm -f "$headers"
                trap - RETURN
                return 1
            fi
            rm -f "$headers"
            trap - RETURN
            return 0
        fi
        rm -f "$curl_config"
        rm -f "$headers"
        trap - RETURN
        return 1
    fi
    if curl -fsSL -D "$headers" "$url" -o "$output"; then
        if ! verify_download_sha256 "$headers" "$output"; then
            rm -f "$headers"
            trap - RETURN
            return 1
        fi
        rm -f "$headers"
        trap - RETURN
        return 0
    fi
    rm -f "$headers"
    trap - RETURN
    return 1
}

file_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "ERROR: sha256sum or shasum is required to verify downloaded binaries" >&2
        return 1
    fi
}

verify_download_sha256() {
    local headers="$1"
    local output="$2"
    local expected
    expected="$(awk 'tolower($1)=="x-bongsu-sha256:" {print $2}' "$headers" | tail -1 | tr -d '\r')"
    if [ -z "$expected" ]; then
        echo "ERROR: missing X-Bongsu-SHA256 header for $output" >&2
        rm -f "$output"
        return 1
    fi
    local actual
    actual="$(file_sha256 "$output")"
    if [ "$actual" != "$expected" ]; then
        echo "ERROR: checksum mismatch for $output" >&2
        rm -f "$output"
        return 1
    fi
}

generate_agent_token() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    elif command -v uuidgen >/dev/null 2>&1; then
        printf '%s%s\n' "$(uuidgen)" "$(uuidgen)" | tr -d '-'
    else
        date +%s%N | sha256sum | awk '{print $1}'
    fi
}

if [ -z "$SERVER_URL" ] || [ -z "$API_KEY" ]; then
    echo "Usage: $0 <server-url> [agent-api-key]"
    echo "   or: BONGSU_AGENT_API_KEY=... $0 <server-url>"
    echo ""
    echo "Environment variables:"
    echo "  BONGSU_WORK_DIR       Installation directory (default: /opt/bongsu)"
    echo "  BONGSU_PACKAGES_ONLY  Server-side CVE matching (default: true)"
    echo "  BONGSU_CRON           Cron schedule (default: '0 3 * * *')"
    echo "  BONGSU_INSTALL_MODE   cron or systemd (default: cron)"
    echo "  BONGSU_FORCE_SCAN_DAEMON  Install force scan daemon in systemd mode (default: true)"
    echo "  BONGSU_INSTALL_TOKEN  Optional server install/download token"
    echo "  BONGSU_AGENT_API_KEY  Agent API key when not passed as an argument"
    echo "  BONGSU_AGENT_TOKEN    Optional persistent per-host token"
    echo "  BONGSU_HOST_ID        Optional stable host id override for cloned/containerized hosts"
    echo "  BONGSU_SYSTEMD_DIR    Systemd unit directory (default: /etc/systemd/system)"
    echo "  BONGSU_SYSTEMCTL_BIN  systemctl command path/name (default: systemctl)"
    exit 1
fi

echo "=== Bongsu Agent Installer ==="
echo "Server:  $SERVER_URL"
echo "WorkDir: $WORK_DIR"
echo "Mode:    $INSTALL_MODE"

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) BIN_ARCH="amd64" ;;
    aarch64) BIN_ARCH="arm64" ;;
    *) echo "ERROR: Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Create directories
mkdir -p "$WORK_DIR/bin"

if [ -z "$AGENT_TOKEN" ]; then
    if [ -s "$WORK_DIR/agent.token" ]; then
        AGENT_TOKEN="$(tr -d '\r\n' < "$WORK_DIR/agent.token")"
    else
        AGENT_TOKEN="$(generate_agent_token)"
        umask 077
        printf '%s\n' "$AGENT_TOKEN" > "$WORK_DIR/agent.token"
    fi
fi

# Locate agent binary
AGENT_BIN=""
if [ -f "$SCRIPT_DIR/bin/bongsu-agent" ]; then
    AGENT_BIN="$SCRIPT_DIR/bin/bongsu-agent"
elif [ -f "$SCRIPT_DIR/bongsu-agent" ]; then
    AGENT_BIN="$SCRIPT_DIR/bongsu-agent"
elif [ -f "$SCRIPT_DIR/bongsu-agent-linux-${BIN_ARCH}" ]; then
    AGENT_BIN="$SCRIPT_DIR/bongsu-agent-linux-${BIN_ARCH}"
elif command -v bongsu-agent &>/dev/null; then
    AGENT_BIN="$(command -v bongsu-agent)"
fi

if [ -z "$AGENT_BIN" ]; then
    echo "Downloading bongsu-agent from server..."
    curl_download "${SERVER_URL}/api/downloads/bongsu-agent" "$WORK_DIR/bin/bongsu-agent"
    chmod +x "$WORK_DIR/bin/bongsu-agent"
    AGENT_BIN="$WORK_DIR/bin/bongsu-agent"
fi

# Install agent binary (skip if identical)
if [ "$AGENT_BIN" != "$WORK_DIR/bin/bongsu-agent" ] && [ -f "$WORK_DIR/bin/bongsu-agent" ] && cmp -s "$AGENT_BIN" "$WORK_DIR/bin/bongsu-agent"; then
    echo "Agent binary unchanged, skipping copy."
elif [ "$AGENT_BIN" != "$WORK_DIR/bin/bongsu-agent" ]; then
    cp "$AGENT_BIN" "$WORK_DIR/bin/bongsu-agent"
    chmod +x "$WORK_DIR/bin/bongsu-agent"
    echo "Agent binary installed: $WORK_DIR/bin/bongsu-agent"
fi

TRIVY_BIN=""
if [ -f "$SCRIPT_DIR/bin/trivy" ]; then
    TRIVY_BIN="$SCRIPT_DIR/bin/trivy"
elif [ -f "$SCRIPT_DIR/trivy" ]; then
    TRIVY_BIN="$SCRIPT_DIR/trivy"
elif command -v trivy &>/dev/null; then
    TRIVY_BIN="$(command -v trivy)"
fi

if [ -n "$TRIVY_BIN" ]; then
    cp "$TRIVY_BIN" "$WORK_DIR/bin/trivy"
    chmod +x "$WORK_DIR/bin/trivy"
    echo "Trivy binary installed: $WORK_DIR/bin/trivy"
elif curl_download "${SERVER_URL}/api/downloads/trivy" "$WORK_DIR/bin/trivy"; then
    chmod +x "$WORK_DIR/bin/trivy"
    echo "Trivy binary downloaded: $WORK_DIR/bin/trivy"
else
    rm -f "$WORK_DIR/bin/trivy"
    echo "WARNING: trivy not found. Package scanning requires trivy at $WORK_DIR/bin/trivy or in PATH."
fi

# Write config file. It contains the agent API key, so keep it owner-readable only.
umask 077
cat > "$WORK_DIR/config.yaml" << EOF
server_url: ${SERVER_URL}
api_key: ${API_KEY}
agent_token: ${AGENT_TOKEN}
work_dir: ${WORK_DIR}
EOF
if [ -n "$HOST_ID" ]; then
    printf 'host_id: %s\n' "$HOST_ID" >> "$WORK_DIR/config.yaml"
fi
chmod 600 "$WORK_DIR/config.yaml"
chmod 600 "$WORK_DIR/agent.token" 2>/dev/null || true
echo "Config written: $WORK_DIR/config.yaml"

# Build agent command
AGENT_CMD="$WORK_DIR/bin/bongsu-agent --config $WORK_DIR/config.yaml --type daily"
if [ "$PACKAGES_ONLY" = "true" ]; then
    AGENT_CMD="$AGENT_CMD --packages-only"
fi

if [ "$INSTALL_MODE" = "systemd" ] && command -v "$SYSTEMCTL_BIN" >/dev/null 2>&1 && [ "$(id -u)" = "0" ]; then
    mkdir -p "$SYSTEMD_DIR"
    cat > "$SYSTEMD_DIR/bongsu-agent.service" << SERVICE
[Unit]
Description=Bongsu package inventory agent
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$AGENT_CMD
Nice=10
IOSchedulingClass=best-effort
UMask=0077
ProtectSystem=strict
ReadWritePaths=$WORK_DIR
PrivateTmp=true
SERVICE
    cat > "$SYSTEMD_DIR/bongsu-agent.timer" << TIMER
[Unit]
Description=Run Bongsu package inventory agent

[Timer]
OnCalendar=*-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
TIMER
    "$SYSTEMCTL_BIN" daemon-reload
    "$SYSTEMCTL_BIN" enable --now bongsu-agent.timer
    echo "Systemd timer installed: bongsu-agent.timer"
    if [ "$FORCE_SCAN_DAEMON" = "true" ]; then
        cat > "$SYSTEMD_DIR/bongsu-agent-daemon.service" << SERVICE
[Unit]
Description=Bongsu force scan polling agent
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=$WORK_DIR/bin/bongsu-agent --config $WORK_DIR/config.yaml --daemon --poll-interval 60s
Restart=always
RestartSec=10
Nice=10
IOSchedulingClass=best-effort
UMask=0077
ProtectSystem=strict
ReadWritePaths=$WORK_DIR
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SERVICE
        "$SYSTEMCTL_BIN" daemon-reload
        "$SYSTEMCTL_BIN" enable --now bongsu-agent-daemon.service
        echo "Systemd daemon installed: bongsu-agent-daemon.service"
    fi
else
    CRON_ENTRY="$CRON_SCHEDULE $AGENT_CMD >> $WORK_DIR/agent.log 2>&1"
    EXISTING_CRON=$(crontab -l 2>/dev/null | grep -v "bongsu-agent" || true)
    if [ -z "$EXISTING_CRON" ]; then
        echo "$CRON_ENTRY" | crontab -
    else
        printf "%s\n%s\n" "$EXISTING_CRON" "$CRON_ENTRY" | crontab -
    fi
    echo "Cron job installed: $CRON_SCHEDULE"
fi

# Run first scan
echo ""
echo "Running first scan..."
$AGENT_CMD 2>&1 | tail -5 || true

echo ""
echo "=== Installation Complete ==="
echo "  Binary:    $WORK_DIR/bin/bongsu-agent"
echo "  Config:    $WORK_DIR/config.yaml"
echo "  Schedule:  $CRON_SCHEDULE"
echo "  Log:       $WORK_DIR/agent.log"
echo ""
echo "To uninstall:"
echo "  crontab -l | grep -v bongsu-agent | crontab -"
echo "  rm -rf $WORK_DIR"
