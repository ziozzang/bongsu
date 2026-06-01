#!/bin/bash
set -euo pipefail

# backup.sh — Backup PostgreSQL + Trivy cache
# Usage: ./scripts/backup.sh [--dry-run] [output-file]

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

DRY_RUN=false
OUTPUT_ARG=""

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        *) OUTPUT_ARG="$arg" ;;
    esac
done

DB_HOST="${BONGSU_DB_HOST:-localhost}"
DB_PORT="${BONGSU_DB_PORT:-5432}"
DB_NAME="${BONGSU_DB_NAME:-bongsu}"
DB_USER="${BONGSU_DB_USER:-bongsu}"
DB_PASSWORD="${BONGSU_DB_PASSWORD:-}"
TRIVY_CACHE_DIR="${BONGSU_TRIVY_CACHE_DIR:-/app/trivy-cache}"

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTPUT="${OUTPUT_ARG:-bongsu-backup-${TIMESTAMP}.tar.gz}"

TMP_DIR="$(mktemp -d)"
cleanup() {
    if [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

echo "=== Bongsu Backup ==="
echo "Database: ${DB_NAME}@${DB_HOST}:${DB_PORT}"
echo "Output:   ${OUTPUT}"
if [ "$DRY_RUN" = true ]; then
    echo "Mode:     dry-run"
fi

if [ "$DRY_RUN" = true ]; then
    echo ""
    echo "[dry-run] Would run pg_dump:"
    echo "  pg_dump -h ${DB_HOST} -p ${DB_PORT} -U ${DB_USER} --format=custom --no-owner --no-acl ${DB_NAME}"
    if [ -d "$TRIVY_CACHE_DIR" ]; then
        echo "[dry-run] Would archive trivy cache from: ${TRIVY_CACHE_DIR}"
    fi
    echo "[dry-run] Would create manifest.json"
    echo "[dry-run] Would create archive: ${OUTPUT}"
    echo "[dry-run] Would generate ${OUTPUT}.sha256"
    echo "Dry-run complete."
    exit 0
fi

# Step 1: Dump database
echo ""
echo "[1/4] Dumping database..."
PGPASSWORD="${DB_PASSWORD}" pg_dump \
    -h "${DB_HOST}" \
    -p "${DB_PORT}" \
    -U "${DB_USER}" \
    --format=custom \
    --no-owner \
    --no-acl \
    "${DB_NAME}" \
    > "${TMP_DIR}/database.dump"
echo "  database.dump ($(du -h "${TMP_DIR}/database.dump" | cut -f1))"

# Step 2: Copy trivy cache if present
if [ -d "$TRIVY_CACHE_DIR" ]; then
    echo ""
    echo "[2/4] Archiving trivy cache..."
    tar -cf "${TMP_DIR}/trivy-cache.tar" -C "$(dirname "$TRIVY_CACHE_DIR")" "$(basename "$TRIVY_CACHE_DIR")"
    echo "  trivy-cache.tar ($(du -h "${TMP_DIR}/trivy-cache.tar" | cut -f1))"
else
    echo ""
    echo "[2/4] Trivy cache directory not found, skipping."
fi

# Step 3: Create manifest
echo ""
echo "[3/4] Creating manifest..."
cat > "${TMP_DIR}/manifest.json" <<EOF
{
  "format_version": 1,
  "timestamp": "${TIMESTAMP}",
  "database": "${DB_NAME}"
}
EOF

# Step 4: Create archive and checksum
echo ""
echo "[4/4] Creating archive..."
tar -C "$TMP_DIR" -czf "${OUTPUT}" database.dump manifest.json
if [ -f "${TMP_DIR}/trivy-cache.tar" ]; then
    # Re-create with trivy cache included
    tar -C "$TMP_DIR" -czf "${OUTPUT}" database.dump trivy-cache.tar manifest.json
fi

SHA=$(sha256sum "${OUTPUT}" | cut -d" " -f1)
echo "${SHA}  $(basename "${OUTPUT}")" > "${OUTPUT}.sha256"

echo ""
echo "=== Backup Complete ==="
echo "Archive: ${OUTPUT} ($(du -h "${OUTPUT}" | cut -f1))"
echo "SHA256:  ${SHA}"
