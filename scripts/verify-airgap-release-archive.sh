#!/bin/bash
set -euo pipefail

# verify-airgap-release-archive.sh — Validate a generated Bongsu airgap archive.
# Usage: ./scripts/verify-airgap-release-archive.sh bongsu-<version>.tar.gz

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
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require_file() {
    local path="$1"
    if [ ! -e "$path" ]; then
        echo "ERROR: missing required package entry: ${path#$ROOT_DIR/}" >&2
        exit 1
    fi
}

require_executable() {
    local path="$1"
    require_file "$path"
    if [ ! -x "$path" ]; then
        echo "ERROR: package entry is not executable: ${path#$ROOT_DIR/}" >&2
        exit 1
    fi
}

require_text() {
    local file="$1"
    local pattern="$2"
    local message="$3"
    if ! grep -Eq "$pattern" "$file"; then
        echo "ERROR: $message" >&2
        echo "Missing pattern: $pattern in ${file#$ROOT_DIR/}" >&2
        exit 1
    fi
}

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: missing required tool: $1" >&2
        exit 1
    fi
}

require_tool tar
require_tool gzip
require_tool sha256sum
require_tool file

echo "=== Bongsu Airgap Release Archive Verification ==="
echo "Archive: $ARCHIVE"

if [ -f "${ARCHIVE}.sha256" ]; then
    echo "[1/7] Checking outer archive checksum"
    (cd "$(dirname "$ARCHIVE")" && sha256sum -c "$(basename "${ARCHIVE}.sha256")")
else
    echo "[1/7] No outer .sha256 file found, skipping outer checksum"
fi

echo "[2/7] Extracting archive"
tar -xzf "$ARCHIVE" -C "$TMP_DIR"
ROOT_COUNT="$(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
if [ "$ROOT_COUNT" != "1" ]; then
    echo "ERROR: archive must contain exactly one top-level directory, found $ROOT_COUNT" >&2
    find "$TMP_DIR" -mindepth 1 -maxdepth 1 >&2
    exit 1
fi
ROOT_DIR="$(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d | head -1)"
echo "Root:    $(basename "$ROOT_DIR")"

echo "[3/7] Checking required package entries"
for path in \
    "$ROOT_DIR/images/bongsu-server.tar.gz" \
    "$ROOT_DIR/images/bongsu-agent.tar.gz" \
    "$ROOT_DIR/images/bongsu-web.tar.gz" \
    "$ROOT_DIR/images/postgres-16-alpine.tar.gz" \
    "$ROOT_DIR/bin/bongsu-server" \
    "$ROOT_DIR/bin/bongsu-agent" \
    "$ROOT_DIR/scripts/backup.sh" \
    "$ROOT_DIR/scripts/restore.sh" \
    "$ROOT_DIR/scripts/install-agent.sh" \
    "$ROOT_DIR/scripts/update-trivy-db.sh" \
    "$ROOT_DIR/scripts/import-security-db-bundle.sh" \
    "$ROOT_DIR/scripts/export-security-db-bundle.sh" \
    "$ROOT_DIR/scripts/verify-release-readiness.sh" \
    "$ROOT_DIR/scripts/verify-backup-restore-archive.sh" \
    "$ROOT_DIR/scripts/verify-operator-workflow.sh" \
    "$ROOT_DIR/scripts/verify-agent-binary-workflow.sh" \
    "$ROOT_DIR/scripts/verify-airgap-release-archive.sh" \
    "$ROOT_DIR/scripts/verify-airgap-offline-rehearsal.sh" \
    "$ROOT_DIR/scripts/verify-airgap-package-smoke.sh" \
    "$ROOT_DIR/scripts/verify-live-agent-token-binding.sh" \
    "$ROOT_DIR/scripts/verify-live-cvedb-quality.sh" \
    "$ROOT_DIR/scripts/verify-live-rbac-scope.sh" \
    "$ROOT_DIR/scripts/verify-live-web-smoke.sh" \
    "$ROOT_DIR/deploy/docker-compose.yml" \
    "$ROOT_DIR/deploy/docker-compose.airgap.yml" \
    "$ROOT_DIR/deploy/.env.example" \
    "$ROOT_DIR/migrations" \
    "$ROOT_DIR/docs" \
    "$ROOT_DIR/web/dist" \
    "$ROOT_DIR/README.md" \
    "$ROOT_DIR/SHA256SUMS"
do
    require_file "$path"
done
require_executable "$ROOT_DIR/bin/bongsu-server"
require_executable "$ROOT_DIR/bin/bongsu-agent"
require_executable "$ROOT_DIR/load-images.sh"
for script in "$ROOT_DIR"/scripts/*.sh; do
    require_executable "$script"
done

echo "[4/7] Checking inner SHA256SUMS manifest"
(cd "$ROOT_DIR" && sha256sum -c SHA256SUMS)

echo "[5/7] Checking binaries"
file "$ROOT_DIR/bin/bongsu-server" | grep -Eq 'ELF .* executable|Mach-O|PE32' || {
    echo "ERROR: bongsu-server is not a recognized executable" >&2
    exit 1
}
file "$ROOT_DIR/bin/bongsu-agent" | grep -Eq 'ELF .* executable|Mach-O|PE32' || {
    echo "ERROR: bongsu-agent is not a recognized executable" >&2
    exit 1
}
if file "$ROOT_DIR/bin/bongsu-server" | grep -q 'ELF'; then
    if file "$ROOT_DIR/bin/bongsu-server" | grep -q 'dynamically linked'; then
        echo "ERROR: bongsu-server is dynamically linked; airgap package expects static binary" >&2
        exit 1
    fi
fi
if file "$ROOT_DIR/bin/bongsu-agent" | grep -q 'ELF'; then
    if file "$ROOT_DIR/bin/bongsu-agent" | grep -q 'dynamically linked'; then
        echo "ERROR: bongsu-agent is dynamically linked; airgap package expects static binary" >&2
        exit 1
    fi
fi

echo "[6/7] Checking Docker image archives and loader"
gzip -t "$ROOT_DIR/images/bongsu-server.tar.gz"
gzip -t "$ROOT_DIR/images/bongsu-agent.tar.gz"
gzip -t "$ROOT_DIR/images/bongsu-web.tar.gz"
gzip -t "$ROOT_DIR/images/postgres-16-alpine.tar.gz"
tar -tzf "$ROOT_DIR/images/bongsu-server.tar.gz" >/dev/null
tar -tzf "$ROOT_DIR/images/bongsu-agent.tar.gz" >/dev/null
tar -tzf "$ROOT_DIR/images/bongsu-web.tar.gz" >/dev/null
tar -tzf "$ROOT_DIR/images/postgres-16-alpine.tar.gz" >/dev/null
require_text "$ROOT_DIR/load-images.sh" 'docker load < images/bongsu-server\.tar\.gz' "loader must load server image"
require_text "$ROOT_DIR/load-images.sh" 'docker load < images/bongsu-agent\.tar\.gz' "loader must load agent image"
require_text "$ROOT_DIR/load-images.sh" 'docker load < images/bongsu-web\.tar\.gz' "loader must load web image"
require_text "$ROOT_DIR/load-images.sh" 'docker load < images/postgres-16-alpine\.tar\.gz' "loader must load postgres image"

echo "[7/7] Checking airgap deployment invariants"
require_text "$ROOT_DIR/deploy/docker-compose.airgap.yml" 'BONGSU_TRIVY_DB_INTERVAL_HOURS: "(0|\$\{BONGSU_TRIVY_DB_INTERVAL_HOURS:-0\})"' "airgap compose must disable Trivy DB auto refresh by default"
require_text "$ROOT_DIR/deploy/docker-compose.airgap.yml" 'BONGSU_SECURITY_DB_SYNC_ON_START: "(false|\$\{BONGSU_SECURITY_DB_SYNC_ON_START:-false\})"' "airgap compose must disable source sync on start by default"
require_text "$ROOT_DIR/deploy/docker-compose.airgap.yml" 'BONGSU_SECURITY_DB_SYNC_CMD: "(\$\{BONGSU_SECURITY_DB_SYNC_CMD:-\})?"' "airgap compose must default to empty security DB sync command"
require_text "$ROOT_DIR/docs/operations-runbook.md" 'verify-airgap-release-archive\.sh' "runbook must document archive verification"
require_text "$ROOT_DIR/docs/requirements-audit.md" 'verify-airgap-release-archive\.sh' "requirements audit must include archive verification"

echo "Airgap release archive verification passed"
