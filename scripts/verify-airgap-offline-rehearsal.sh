#!/bin/bash
set -euo pipefail

# verify-airgap-offline-rehearsal.sh - Rehearse the extracted airgap package
# operator flow without loading images into a real Docker daemon.
# Usage: ./scripts/verify-airgap-offline-rehearsal.sh bongsu-<version>.tar.gz

ARCHIVE="${1:-}"
if [ -z "$ARCHIVE" ]; then
    echo "Usage: $0 <bongsu-release.tar.gz>" >&2
    exit 1
fi
if [ ! -f "$ARCHIVE" ]; then
    echo "ERROR: archive not found: $ARCHIVE" >&2
    exit 1
fi

TMP_DIR="$(mktemp -d)"
STUB_DIR="$TMP_DIR/bin"
LOAD_LOG="$TMP_DIR/docker-load.log"
COMPOSE_CONFIG="$TMP_DIR/airgap-compose-rendered.yml"

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

require_text() {
    local file="$1"
    local pattern="$2"
    local message="$3"
    if ! grep -Eq "$pattern" "$file"; then
        echo "ERROR: $message" >&2
        echo "Missing pattern: $pattern in $file" >&2
        exit 1
    fi
}

reject_text() {
    local file="$1"
    local pattern="$2"
    local message="$3"
    if grep -Eq "$pattern" "$file"; then
        echo "ERROR: $message" >&2
        echo "Forbidden pattern: $pattern in $file" >&2
        exit 1
    fi
}

require_tool tar
require_tool gzip
require_tool sha256sum

echo "=== Bongsu Airgap Offline Rehearsal ==="
echo "Archive: $ARCHIVE"

if [ -f "${ARCHIVE}.sha256" ]; then
    echo "[1/6] Checking outer archive checksum"
    (cd "$(dirname "$ARCHIVE")" && sha256sum -c "$(basename "${ARCHIVE}.sha256")")
else
    echo "[1/6] No outer .sha256 file found, skipping outer checksum"
fi

echo "[2/6] Extracting archive and checking inner manifest"
tar -xzf "$ARCHIVE" -C "$TMP_DIR"
ROOT_COUNT="$(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
if [ "$ROOT_COUNT" != "1" ]; then
    echo "ERROR: archive must contain exactly one top-level directory, found $ROOT_COUNT" >&2
    find "$TMP_DIR" -mindepth 1 -maxdepth 1 >&2
    exit 1
fi
ROOT_DIR="$(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d | head -1)"
(cd "$ROOT_DIR" && sha256sum -c SHA256SUMS >/dev/null)

echo "[3/6] Rehearsing image loader with a Docker-load stub"
mkdir -p "$STUB_DIR"
cat > "$STUB_DIR/docker" << 'EOF'
#!/bin/bash
set -euo pipefail
if [ "${1:-}" != "load" ]; then
    echo "stub docker only supports: docker load" >&2
    exit 1
fi
tmp="$(mktemp)"
cat > "$tmp"
gzip -t "$tmp"
tar -tzf "$tmp" >/dev/null
printf 'loaded %s bytes\n' "$(wc -c < "$tmp")" >> "$BONGSU_AIRGAP_REHEARSAL_LOAD_LOG"
rm -f "$tmp"
EOF
chmod +x "$STUB_DIR/docker"
(
    export PATH="$STUB_DIR:$PATH"
    export BONGSU_AIRGAP_REHEARSAL_LOAD_LOG="$LOAD_LOG"
    cd "$ROOT_DIR"
    ./load-images.sh
)
if [ "$(wc -l < "$LOAD_LOG" | tr -d ' ')" != "4" ]; then
    echo "ERROR: loader must load exactly four image archives" >&2
    cat "$LOAD_LOG" >&2 || true
    exit 1
fi

echo "[4/6] Rendering packaged airgap compose config"
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
    echo "ERROR: docker compose is required to rehearse packaged airgap compose config" >&2
    exit 1
fi
cat > "$TMP_DIR/airgap.env" << 'EOF'
BONGSU_VERSION=0.1.0
BONGSU_DB_PASSWORD=rehearsal-db-password-0123456789
BONGSU_API_KEY=rehearsal-admin-key-0123456789
BONGSU_AGENT_API_KEY=rehearsal-agent-key-0123456789
BONGSU_INSTALL_TOKEN=rehearsal-install-token-0123456789
BONGSU_ADMIN_USERNAME=admin
BONGSU_ADMIN_PASSWORD=rehearsal-admin-password-0123456789
BONGSU_API_PORT=5677
BONGSU_WEB_PORT=5678
BONGSU_WEB_AUTH=true
BONGSU_ALLOW_WEAK_SECRETS=false
BONGSU_AGENT_HOST_BINDING=true
EOF
docker compose --env-file "$TMP_DIR/airgap.env" -f "$ROOT_DIR/deploy/docker-compose.airgap.yml" config > "$COMPOSE_CONFIG"

echo "[5/6] Checking airgap compose invariants from packaged files"
require_text "$COMPOSE_CONFIG" 'BONGSU_PORT: "5677"' "packaged API service must listen on 5677"
require_text "$COMPOSE_CONFIG" 'published: "5677"' "packaged API compose must publish 5677"
require_text "$COMPOSE_CONFIG" 'published: "5678"' "packaged web compose must publish 5678"
require_text "$COMPOSE_CONFIG" 'BONGSU_TRIVY_DB_INTERVAL_HOURS: "0"' "packaged airgap compose must disable Trivy DB refresh"
require_text "$COMPOSE_CONFIG" 'BONGSU_SECURITY_DB_SYNC_ON_START: "false"' "packaged airgap compose must not sync on start"
require_text "$COMPOSE_CONFIG" 'BONGSU_SECURITY_DB_SYNC_CMD: ""' "packaged airgap compose must not run connected sync"
require_text "$COMPOSE_CONFIG" 'BONGSU_SYNC_REQUIRE_TRIVY_SOURCE: "false"' "packaged airgap compose must not require online Trivy source"
require_text "$COMPOSE_CONFIG" 'BONGSU_WEB_AUTH: "true"' "packaged web auth must default to enabled"
require_text "$COMPOSE_CONFIG" 'BONGSU_ALLOW_WEAK_SECRETS: "false"' "packaged weak-secret override must default to false"
reject_text "$COMPOSE_CONFIG" 'change-me|your-server|example-token|test-admin-key|test-agent-key' "packaged compose rendered weak or placeholder secrets"

echo "[6/6] Checking packaged operator scripts and docs"
require_text "$ROOT_DIR/scripts/import-security-db-bundle.sh" '/api/admin/security-db/import' "packaged import script must target security DB bundle import"
require_text "$ROOT_DIR/scripts/export-security-db-bundle.sh" '/api/admin/security-db/export' "packaged export script must target security DB bundle export"
require_text "$ROOT_DIR/docs/operations-runbook.md" 'verify-airgap-offline-rehearsal\.sh' "runbook must document offline rehearsal"
require_text "$ROOT_DIR/docs/requirements-audit.md" 'verify-airgap-offline-rehearsal\.sh' "requirements audit must include offline rehearsal"

echo "Airgap offline rehearsal passed"
