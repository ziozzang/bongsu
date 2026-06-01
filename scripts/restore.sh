#!/bin/bash
set -euo pipefail

# restore.sh — Restore from backup
# Usage: ./scripts/restore.sh [--dry-run] <backup-file>

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

DRY_RUN=false
BACKUP_FILE=""

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        *) BACKUP_FILE="$arg" ;;
    esac
done

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 [--dry-run] <backup-file>"
    exit 1
fi

if [ ! -f "$BACKUP_FILE" ]; then
    echo "ERROR: backup file not found: $BACKUP_FILE" >&2
    exit 1
fi

DB_HOST="${BONGSU_DB_HOST:-localhost}"
DB_PORT="${BONGSU_DB_PORT:-5432}"
DB_NAME="${BONGSU_DB_NAME:-bongsu}"
DB_USER="${BONGSU_DB_USER:-bongsu}"
DB_PASSWORD="${BONGSU_DB_PASSWORD:-}"
TRIVY_CACHE_DIR="${BONGSU_TRIVY_CACHE_DIR:-/app/trivy-cache}"
SERVER_CONTAINER="${BONGSU_SERVER_CONTAINER:-bongsu-server-1}"

TMP_DIR="$(mktemp -d)"
cleanup() {
    if [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

echo "=== Bongsu Restore ==="
echo "Backup:     ${BACKUP_FILE}"
echo "Database:   ${DB_NAME}@${DB_HOST}:${DB_PORT}"
echo "Container:  ${SERVER_CONTAINER}"
if [ "$DRY_RUN" = true ]; then
    echo "Mode:       dry-run"
fi

# Step 1: Extract backup
echo ""
echo "[1/5] Extracting backup..."
tar -xzf "$BACKUP_FILE" -C "$TMP_DIR"

if [ ! -f "${TMP_DIR}/database.dump" ]; then
    echo "ERROR: database.dump not found in backup archive" >&2
    exit 1
fi
echo "  database.dump found ($(du -h "${TMP_DIR}/database.dump" | cut -f1))"

if [ -f "${TMP_DIR}/manifest.json" ]; then
    echo "  manifest.json found"
fi

if [ "$DRY_RUN" = true ]; then
    echo ""
    echo "[dry-run] Would stop container: docker stop ${SERVER_CONTAINER}"
    echo "[dry-run] Would run pg_restore:"
    echo "  pg_restore -h ${DB_HOST} -p ${DB_PORT} -U ${DB_USER} --clean --if-exists -d ${DB_NAME}"
    if [ -f "${TMP_DIR}/trivy-cache.tar" ]; then
        echo "[dry-run] Would restore trivy cache to: ${TRIVY_CACHE_DIR}"
    fi
    echo "[dry-run] Would restart container: docker start ${SERVER_CONTAINER}"
    echo "Dry-run complete."
    exit 0
fi

# Step 2: Stop server container
echo ""
echo "[2/5] Stopping server container..."
docker stop "$SERVER_CONTAINER"
echo "  ${SERVER_CONTAINER} stopped"

# Step 3: Restore database
echo ""
echo "[3/5] Restoring database..."
PGPASSWORD="${DB_PASSWORD}" pg_restore \
    -h "${DB_HOST}" \
    -p "${DB_PORT}" \
    -U "${DB_USER}" \
    --clean \
    --if-exists \
    -d "${DB_NAME}" \
    "${TMP_DIR}/database.dump" || true
echo "  Database restored"

# Step 4: Restore trivy cache if present
if [ -f "${TMP_DIR}/trivy-cache.tar" ]; then
    echo ""
    echo "[4/5] Restoring trivy cache..."
    mkdir -p "$(dirname "$TRIVY_CACHE_DIR")"
    tar -xf "${TMP_DIR}/trivy-cache.tar" -C "$(dirname "$TRIVY_CACHE_DIR")"
    echo "  Trivy cache restored"
else
    echo ""
    echo "[4/5] No trivy cache in backup, skipping."
fi

# Step 5: Restart server container
echo ""
echo "[5/5] Restarting server container..."
docker start "$SERVER_CONTAINER"
echo "  ${SERVER_CONTAINER} started"

echo ""
echo "=== Restore Complete ==="
