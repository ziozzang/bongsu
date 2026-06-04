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

json_string_value() {
    local file="$1"
    local key="$2"
    sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$file" | sed -n '1p'
}

json_bool_value() {
    local file="$1"
    local key="$2"
    sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\\(true\\|false\\).*/\\1/p" "$file" | sed -n '1p'
}

verify_sidecar_checksum() {
    local archive="$1"
    local sidecar="${archive}.sha256"
    if [ ! -f "$sidecar" ]; then
        return 0
    fi

    local expected actual
    expected="$(awk '{print $1}' "$sidecar" | sed -n '1p')"
    if ! printf '%s' "$expected" | grep -Eq '^[0-9a-fA-F]{64}$'; then
        echo "ERROR: invalid backup sidecar checksum: $sidecar" >&2
        exit 1
    fi

    actual="$(sha256sum "$archive" | cut -d" " -f1)"
    expected="$(printf '%s' "$expected" | tr 'A-F' 'a-f')"
    actual="$(printf '%s' "$actual" | tr 'A-F' 'a-f')"
    if [ "$actual" != "$expected" ]; then
        echo "ERROR: backup archive checksum mismatch" >&2
        exit 1
    fi
    echo "  sidecar checksum verified"
}

validate_backup_archive() {
    local archive="$1"
    local listing="$TMP_DIR/archive-list.txt"
    tar -tzf "$archive" > "$listing"

    local database_count manifest_count trivy_count
    database_count="$(grep -xc 'database.dump' "$listing" || true)"
    manifest_count="$(grep -xc 'manifest.json' "$listing" || true)"
    trivy_count="$(grep -xc 'trivy-cache.tar' "$listing" || true)"

    if [ "$database_count" != "1" ]; then
        echo "ERROR: backup archive must contain exactly one database.dump" >&2
        exit 1
    fi
    if [ "$manifest_count" != "1" ]; then
        echo "ERROR: backup archive must contain exactly one manifest.json" >&2
        exit 1
    fi
    if [ "$trivy_count" -gt 1 ]; then
        echo "ERROR: backup archive contains duplicate trivy-cache.tar" >&2
        exit 1
    fi

    while IFS= read -r entry; do
        case "$entry" in
            database.dump|manifest.json|trivy-cache.tar)
                if tar -tvzf "$archive" "$entry" | grep -qv '^-'; then
                    echo "ERROR: backup archive entry must be a regular file: $entry" >&2
                    exit 1
                fi
                ;;
            /*|*../*|../*|*/..|.)
                echo "ERROR: unsafe backup archive entry: $entry" >&2
                exit 1
                ;;
            *)
                echo "ERROR: unexpected backup archive entry: $entry" >&2
                exit 1
                ;;
        esac
    done < "$listing"
}

validate_manifest_checksums() {
    local manifest="${TMP_DIR}/manifest.json"
    if [ ! -f "$manifest" ]; then
        echo "ERROR: manifest.json not found in backup archive" >&2
        exit 1
    fi

    local db_sha trivy_included trivy_sha actual
    db_sha="$(json_string_value "$manifest" "database_dump_sha256")"
    if [ -n "$db_sha" ]; then
        actual="$(sha256sum "${TMP_DIR}/database.dump" | cut -d" " -f1)"
        if [ "$actual" != "$db_sha" ]; then
            echo "ERROR: database.dump checksum mismatch" >&2
            exit 1
        fi
    fi

    trivy_included="$(json_bool_value "$manifest" "trivy_cache_included")"
    trivy_sha="$(json_string_value "$manifest" "trivy_cache_sha256")"
    if [ "$trivy_included" = "true" ] && [ ! -f "${TMP_DIR}/trivy-cache.tar" ]; then
        echo "ERROR: manifest requires trivy-cache.tar but archive is missing" >&2
        exit 1
    fi
    if [ -n "$trivy_sha" ] && [ -f "${TMP_DIR}/trivy-cache.tar" ]; then
        actual="$(sha256sum "${TMP_DIR}/trivy-cache.tar" | cut -d" " -f1)"
        if [ "$actual" != "$trivy_sha" ]; then
            echo "ERROR: trivy-cache.tar checksum mismatch" >&2
            exit 1
        fi
    fi
}

echo "=== Bongsu Restore ==="
echo "Backup:     ${BACKUP_FILE}"
echo "Database:   ${DB_NAME}@${DB_HOST}:${DB_PORT}"
echo "Container:  ${SERVER_CONTAINER}"
if [ "$DRY_RUN" = true ]; then
    echo "Mode:       dry-run"
fi

# Step 1: Extract backup
echo ""
echo "[1/5] Validating and extracting backup..."
verify_sidecar_checksum "$BACKUP_FILE"
validate_backup_archive "$BACKUP_FILE"
tar -xzf "$BACKUP_FILE" -C "$TMP_DIR" database.dump manifest.json
if tar -tzf "$BACKUP_FILE" | grep -qx 'trivy-cache.tar'; then
    tar -xzf "$BACKUP_FILE" -C "$TMP_DIR" trivy-cache.tar
fi

if [ ! -f "${TMP_DIR}/database.dump" ]; then
    echo "ERROR: database.dump not found in backup archive" >&2
    exit 1
fi
echo "  database.dump found ($(du -h "${TMP_DIR}/database.dump" | cut -f1))"

if [ -f "${TMP_DIR}/manifest.json" ]; then
    echo "  manifest.json found"
fi
validate_manifest_checksums

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
