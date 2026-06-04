package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateInstall(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if s.installToken == "" {
		s.audit(r, "installer.generate", "installer", "install.sh", "error", map[string]any{
			"reason": "install token is not configured",
		})
		writeError(w, http.StatusServiceUnavailable, "install token is not configured")
		return
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Host
	apiKey := s.agentKey
	serverURL := fmt.Sprintf("%s://%s", scheme, host)

	script := fmt.Sprintf(`#!/bin/bash
set -euo pipefail

# Bongsu Agent Installer
# Usage: curl -fsSL -H "X-Install-Token: $BONGSU_INSTALL_TOKEN" %s://%s/api/install.sh | bash

SERVER=%s
API_KEY=%s
INSTALL_TOKEN=%s
WORK_DIR="${BONGSU_WORK_DIR:-/opt/bongsu}"
INSTALL_MODE="${BONGSU_INSTALL_MODE:-cron}"
CRON_SCHEDULE="${BONGSU_CRON:-0 3 * * *}"
FORCE_SCAN_DAEMON="${BONGSU_FORCE_SCAN_DAEMON:-true}"
SYSTEMD_DIR="${BONGSU_SYSTEMD_DIR:-/etc/systemd/system}"
SYSTEMCTL_BIN="${BONGSU_SYSTEMCTL_BIN:-systemctl}"
AGENT_TOKEN="${BONGSU_AGENT_TOKEN:-}"
HOST_ID="${BONGSU_HOST_ID:-${BONGSU_AGENT_HOST_ID:-}}"

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
        printf 'header = "X-Install-Token: %%s"\n' "$INSTALL_TOKEN" > "$curl_config"
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
        printf '%%s%%s\n' "$(uuidgen)" "$(uuidgen)" | tr -d '-'
    else
        date +%%s%%N | sha256sum | awk '{print $1}'
    fi
}

echo "=== Bongsu Agent Installer ==="
echo "Server:  $SERVER"
echo "WorkDir: $WORK_DIR"
echo "Mode:    $INSTALL_MODE"

mkdir -p "$WORK_DIR/bin"
if [ -z "$AGENT_TOKEN" ]; then
    if [ -s "$WORK_DIR/agent.token" ]; then
        AGENT_TOKEN="$(tr -d '\r\n' < "$WORK_DIR/agent.token")"
    else
        AGENT_TOKEN="$(generate_agent_token)"
        umask 077
        printf '%%s\n' "$AGENT_TOKEN" > "$WORK_DIR/agent.token"
    fi
fi

# Download agent binary from server
echo "Downloading bongsu-agent..."
if ! curl_download "$SERVER/api/downloads/bongsu-agent" "$WORK_DIR/bin/bongsu-agent"; then
    rm -f "$WORK_DIR/bin/bongsu-agent"
    echo "ERROR: Failed to download bongsu-agent"
    exit 1
fi
chmod +x "$WORK_DIR/bin/bongsu-agent"

if [ ! -x "$WORK_DIR/bin/bongsu-agent" ]; then
    echo "ERROR: Failed to download bongsu-agent"
    exit 1
fi

echo "Downloading trivy..."
if curl_download "$SERVER/api/downloads/trivy" "$WORK_DIR/bin/trivy"; then
    chmod +x "$WORK_DIR/bin/trivy"
else
    rm -f "$WORK_DIR/bin/trivy"
    echo "WARNING: trivy download failed; install trivy manually or provide it at $WORK_DIR/bin/trivy"
fi

# Write config. It contains the agent API key, so keep it owner-readable only.
umask 077
cat > "$WORK_DIR/config.yaml" <<EOF
server_url: ${SERVER}
api_key: ${API_KEY}
agent_token: ${AGENT_TOKEN}
work_dir: ${WORK_DIR}
EOF
if [ -n "$HOST_ID" ]; then
    printf 'host_id: %%s\n' "$HOST_ID" >> "$WORK_DIR/config.yaml"
fi
chmod 600 "$WORK_DIR/config.yaml"
chmod 600 "$WORK_DIR/agent.token" 2>/dev/null || true

AGENT_CMD="$WORK_DIR/bin/bongsu-agent --config $WORK_DIR/config.yaml --type daily --packages-only"

if [ "$INSTALL_MODE" = "systemd" ] && command -v "$SYSTEMCTL_BIN" >/dev/null 2>&1 && [ "$(id -u)" = "0" ]; then
    mkdir -p "$SYSTEMD_DIR"
    cat > "$SYSTEMD_DIR/bongsu-agent.service" <<SERVICE
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
    cat > "$SYSTEMD_DIR/bongsu-agent.timer" <<TIMER
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
        cat > "$SYSTEMD_DIR/bongsu-agent-daemon.service" <<SERVICE
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
    CRON_CMD="$AGENT_CMD >> $WORK_DIR/agent.log 2>&1"
    (crontab -l 2>/dev/null | grep -v bongsu-agent; echo "$CRON_SCHEDULE $CRON_CMD") | crontab -
    echo "Cron installed: $CRON_SCHEDULE"
fi

# Run first scan
echo "Running first scan..."
$AGENT_CMD 2>&1 | tail -5 || true

echo ""
echo "=== Done ==="
echo "  Config:  $WORK_DIR/config.yaml"
echo "  Manual:  $WORK_DIR/bin/bongsu-agent --config $WORK_DIR/config.yaml --type daily --packages-only"
echo "  Log:     $WORK_DIR/agent.log"
`, scheme, host, shellQuote(serverURL), shellQuote(apiKey), shellQuote(s.installToken))

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/x-shellscript")
	s.audit(r, "installer.generate", "installer", "install.sh", "ok", map[string]any{
		"server":            serverURL,
		"install_token_set": s.installToken != "",
	})
	w.Write([]byte(script))
}

func (s *Server) handleAgentDownload(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateInstall(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	agentPath := agentBinaryPath()

	f, err := os.Open(agentPath)
	if err != nil {
		s.audit(r, "installer.download", "binary", "bongsu-agent", "error", map[string]any{
			"reason": "agent binary not found",
			"path":   agentPath,
		})
		writeError(w, http.StatusNotFound, "agent binary not found")
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		s.audit(r, "installer.download", "binary", "bongsu-agent", "error", map[string]any{
			"reason": "agent binary is not readable",
			"path":   agentPath,
		})
		writeError(w, http.StatusInternalServerError, "agent binary not readable")
		return
	}
	digest, err := fileSHA256Hex(f)
	if err != nil {
		s.audit(r, "installer.download", "binary", "bongsu-agent", "error", map[string]any{
			"reason": "agent binary checksum failed",
			"path":   agentPath,
			"error":  err.Error(),
		})
		writeError(w, http.StatusInternalServerError, "agent binary checksum failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	w.Header().Set("Content-Disposition", "attachment; filename=bongsu-agent")
	w.Header().Set("X-Bongsu-SHA256", digest)
	if _, err := io.Copy(w, f); err != nil {
		log.Printf("agent binary download failed: %v", err)
		s.audit(r, "installer.download", "binary", "bongsu-agent", "error", map[string]any{
			"reason": "copy failed",
			"path":   agentPath,
			"error":  err.Error(),
		})
		return
	}
	s.audit(r, "installer.download", "binary", "bongsu-agent", "ok", map[string]any{
		"bytes":  info.Size(),
		"sha256": digest,
	})
}

func (s *Server) handleTrivyDownload(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateInstall(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	trivyPath := trivyBinaryPath()
	f, err := os.Open(trivyPath)
	if err != nil {
		s.audit(r, "installer.download", "binary", "trivy", "error", map[string]any{
			"reason": "trivy binary not found",
			"path":   trivyPath,
		})
		writeError(w, http.StatusNotFound, "trivy binary not found")
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		s.audit(r, "installer.download", "binary", "trivy", "error", map[string]any{
			"reason": "trivy binary is not readable",
			"path":   trivyPath,
		})
		writeError(w, http.StatusInternalServerError, "trivy binary not readable")
		return
	}
	digest, err := fileSHA256Hex(f)
	if err != nil {
		s.audit(r, "installer.download", "binary", "trivy", "error", map[string]any{
			"reason": "trivy binary checksum failed",
			"path":   trivyPath,
			"error":  err.Error(),
		})
		writeError(w, http.StatusInternalServerError, "trivy binary checksum failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	w.Header().Set("Content-Disposition", "attachment; filename=trivy")
	w.Header().Set("X-Bongsu-SHA256", digest)
	if _, err := io.Copy(w, f); err != nil {
		log.Printf("trivy binary download failed: %v", err)
		s.audit(r, "installer.download", "binary", "trivy", "error", map[string]any{
			"reason": "copy failed",
			"path":   trivyPath,
			"error":  err.Error(),
		})
		return
	}
	s.audit(r, "installer.download", "binary", "trivy", "ok", map[string]any{
		"bytes":  info.Size(),
		"sha256": digest,
	})
}

type installerBinaryStatus struct {
	Name    string `json:"name"`
	Ready   bool   `json:"ready"`
	Path    string `json:"path,omitempty"`
	Version string `json:"version,omitempty"`
	Bytes   int64  `json:"bytes,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Error   string `json:"error,omitempty"`
}

func (s *Server) handleInstallerStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	agent := installerBinaryReadiness("bongsu-agent", agentBinaryPath())
	trivy := installerBinaryReadiness("trivy", trivyBinaryPath())
	writeJSON(w, http.StatusOK, map[string]any{
		"install_token_configured": s.installToken != "",
		"agent":                    agent,
		"trivy":                    trivy,
		"ready":                    s.installToken != "" && agent.Ready,
	})
}

func (s *Server) handleAgentFleetStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	agent := installerBinaryReadiness("bongsu-agent", agentBinaryPath())
	trivy := installerBinaryReadiness("trivy", trivyBinaryPath())
	latestVersion := agent.Version
	if latestVersion == "" {
		latestVersion = binaryVersion(agentBinaryPath())
	}
	agentStatusCounts := map[string]int{"online": 0, "stale": 0, "offline": 0, "unknown": 0}
	agentVersionCounts := map[string]int{}
	hosts, err := s.db.ListHosts(r.Context())
	if err != nil {
		log.Printf("agent fleet status hosts: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	now := time.Now()
	for _, host := range hosts {
		applyAgentStatus(&host, now)
		status := host.AgentStatus
		if status == "" {
			status = "unknown"
		}
		agentStatusCounts[status]++
		version := strings.TrimSpace(host.AgentVersion)
		if version == "" {
			version = "unknown"
		}
		agentVersionCounts[version]++
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":                     "ok",
		"total_hosts":                len(hosts),
		"latest_agent_version":       latestVersion,
		"agent_status_counts":        agentStatusCounts,
		"agent_version_counts":       agentVersionCounts,
		"agent_version_drift_counts": agentVersionDriftCounts(agentVersionCounts, latestVersion),
		"installer": map[string]any{
			"install_token_configured": s.installToken != "",
			"ready":                    s.installToken != "" && agent.Ready,
			"agent":                    agent,
			"trivy":                    trivy,
		},
	})
}

func agentBinaryPath() string {
	agentPath := os.Getenv("BONGSU_AGENT_BIN")
	if agentPath != "" {
		return agentPath
	}
	exe, _ := os.Executable()
	agentPath = filepath.Join(filepath.Dir(exe), "bongsu-agent")
	if _, err := os.Stat(agentPath); err != nil {
		return "/app/bin/bongsu-agent"
	}
	return agentPath
}

func trivyBinaryPath() string {
	trivyPath := os.Getenv("BONGSU_TRIVY_PATH")
	if trivyPath == "" {
		trivyPath = "/usr/local/bin/trivy"
	}
	return trivyPath
}

func installerBinaryReadiness(name, path string) installerBinaryStatus {
	status := installerBinaryStatus{Name: name, Path: path}
	f, err := os.Open(path)
	if err != nil {
		status.Error = "not found"
		return status
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		status.Error = "not readable"
		return status
	}
	digest, err := fileSHA256Hex(f)
	if err != nil {
		status.Error = "checksum failed"
		return status
	}
	status.Ready = true
	status.Bytes = info.Size()
	status.SHA256 = digest
	status.Version = binaryVersion(path)
	return status
}

func binaryVersion(path string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func agentVersionDriftCounts(versionCounts map[string]int, latestVersion string) map[string]int {
	out := map[string]int{"current": 0, "outdated": 0, "unknown": 0}
	latestVersion = strings.TrimSpace(latestVersion)
	for version, count := range versionCounts {
		out[agentVersionState(version, latestVersion)] += count
	}
	return out
}

func agentVersionState(version, latestVersion string) string {
	version = strings.TrimSpace(version)
	latestVersion = strings.TrimSpace(latestVersion)
	if version == "" || version == "unknown" {
		return "unknown"
	}
	if latestVersion != "" && version == latestVersion {
		return "current"
	}
	return "outdated"
}

func fileSHA256Hex(f *os.File) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
