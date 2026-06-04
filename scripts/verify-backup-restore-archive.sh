#!/bin/bash
set -euo pipefail

# verify-backup-restore-archive.sh - Validate backup archive safety and restore
# dry-run checksum handling without requiring a live database.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
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

make_valid_backup() {
    local dir="$1"
    local archive="$2"
    mkdir -p "$dir"
    printf 'fixture database dump\n' > "$dir/database.dump"
    printf 'fixture trivy cache\n' > "$dir/trivy-cache.tar"
    local db_sha trivy_sha
    db_sha="$(sha256sum "$dir/database.dump" | cut -d" " -f1)"
    trivy_sha="$(sha256sum "$dir/trivy-cache.tar" | cut -d" " -f1)"
    cat > "$dir/manifest.json" <<EOF
{
  "format_version": 1,
  "timestamp": "2026-01-01T00:00:00Z",
  "database": "bongsu",
  "database_dump_sha256": "${db_sha}",
  "trivy_cache_included": true,
  "trivy_cache_sha256": "${trivy_sha}"
}
EOF
    tar -C "$dir" -czf "$archive" database.dump trivy-cache.tar manifest.json
}

expect_restore_ok() {
    local archive="$1"
    local out="$TMP_DIR/restore-ok.out"
    if ! "$ROOT/scripts/restore.sh" --dry-run "$archive" > "$out" 2>&1; then
        cat "$out" >&2
        echo "ERROR: restore dry-run rejected a valid backup archive" >&2
        exit 1
    fi
    grep -q 'Dry-run complete' "$out"
}

expect_restore_fail() {
    local archive="$1"
    local want="$2"
    local out="$TMP_DIR/restore-fail.out"
    if "$ROOT/scripts/restore.sh" --dry-run "$archive" > "$out" 2>&1; then
        cat "$out" >&2
        echo "ERROR: restore dry-run accepted invalid backup archive: $want" >&2
        exit 1
    fi
    if ! grep -qi "$want" "$out"; then
        cat "$out" >&2
        echo "ERROR: restore failure did not mention: $want" >&2
        exit 1
    fi
}

require_tool tar
require_tool sha256sum

echo "=== Bongsu Backup/Restore Archive Verification ==="

echo "[1/8] backup.sh produces a restorable archive and sidecar checksum"
backup_case_dir="$TMP_DIR/backup-script"
backup_bin_dir="$backup_case_dir/bin"
backup_trivy_dir="$backup_case_dir/trivy-cache"
backup_archive="$backup_case_dir/generated-backup.tar.gz"
mkdir -p "$backup_bin_dir" "$backup_trivy_dir"
cat > "$backup_bin_dir/pg_dump" <<'EOF'
#!/bin/sh
set -eu
printf 'fixture pg_dump for %s\n' "$*"
EOF
chmod +x "$backup_bin_dir/pg_dump"
printf 'trivy db fixture\n' > "$backup_trivy_dir/db.metadata.json"
PATH="$backup_bin_dir:$PATH" \
    BONGSU_TRIVY_CACHE_DIR="$backup_trivy_dir" \
    BONGSU_DB_HOST="backup-fixture-db" \
    BONGSU_DB_PORT="15432" \
    BONGSU_DB_NAME="bongsu_fixture" \
    BONGSU_DB_USER="bongsu_fixture" \
    "$ROOT/scripts/backup.sh" "$backup_archive" > "$backup_case_dir/backup.out"
test -f "$backup_archive"
test -f "${backup_archive}.sha256"
grep -q 'Backup Complete' "$backup_case_dir/backup.out"
tar -tzf "$backup_archive" | grep -qx 'database.dump'
tar -tzf "$backup_archive" | grep -qx 'manifest.json'
tar -tzf "$backup_archive" | grep -qx 'trivy-cache.tar'
tar -xzf "$backup_archive" -C "$backup_case_dir" manifest.json
grep -q '"database": "bongsu_fixture"' "$backup_case_dir/manifest.json"
grep -q '"trivy_cache_included": true' "$backup_case_dir/manifest.json"
expect_restore_ok "$backup_archive"

echo "[2/8] Valid backup archive is accepted"
valid_dir="$TMP_DIR/valid"
valid_archive="$TMP_DIR/valid-backup.tar.gz"
make_valid_backup "$valid_dir" "$valid_archive"
sha256sum "$valid_archive" > "${valid_archive}.sha256"
expect_restore_ok "$valid_archive"

echo "[3/8] Missing database dump is rejected"
missing_dir="$TMP_DIR/missing-db"
mkdir -p "$missing_dir"
printf '{"format_version":1,"database":"bongsu"}\n' > "$missing_dir/manifest.json"
tar -C "$missing_dir" -czf "$TMP_DIR/missing-db.tar.gz" manifest.json
expect_restore_fail "$TMP_DIR/missing-db.tar.gz" "database.dump"

echo "[4/8] Unexpected archive path is rejected"
unexpected_dir="$TMP_DIR/unexpected"
make_valid_backup "$unexpected_dir/root" "$TMP_DIR/unexpected-base.tar.gz"
printf 'unexpected\n' > "$unexpected_dir/root/extra.txt"
tar -C "$unexpected_dir/root" -czf "$TMP_DIR/unexpected.tar.gz" database.dump manifest.json extra.txt
expect_restore_fail "$TMP_DIR/unexpected.tar.gz" "unexpected"

echo "[5/8] Duplicate manifest is rejected"
dup_dir="$TMP_DIR/duplicate"
make_valid_backup "$dup_dir/root" "$TMP_DIR/duplicate-base.tar.gz"
mkdir -p "$dup_dir/one" "$dup_dir/two"
cp "$dup_dir/root/database.dump" "$dup_dir/one/database.dump"
cp "$dup_dir/root/manifest.json" "$dup_dir/one/manifest.json"
cp "$dup_dir/root/manifest.json" "$dup_dir/two/manifest.json"
tar -C "$dup_dir/one" -cf "$TMP_DIR/duplicate.tar" database.dump manifest.json
tar -C "$dup_dir/two" -rf "$TMP_DIR/duplicate.tar" manifest.json
gzip -c "$TMP_DIR/duplicate.tar" > "$TMP_DIR/duplicate.tar.gz"
expect_restore_fail "$TMP_DIR/duplicate.tar.gz" "manifest"

echo "[6/8] Manifest checksum mismatch is rejected"
bad_dir="$TMP_DIR/bad-checksum"
bad_archive="$TMP_DIR/bad-checksum.tar.gz"
make_valid_backup "$bad_dir" "$bad_archive"
printf 'tampered\n' > "$bad_dir/database.dump"
tar -C "$bad_dir" -czf "$bad_archive" database.dump trivy-cache.tar manifest.json
expect_restore_fail "$bad_archive" "checksum"

echo "[7/8] Archive sidecar checksum mismatch is rejected"
sidecar_dir="$TMP_DIR/bad-sidecar"
sidecar_archive="$TMP_DIR/bad-sidecar.tar.gz"
make_valid_backup "$sidecar_dir" "$sidecar_archive"
printf '0000000000000000000000000000000000000000000000000000000000000000  %s\n' "$(basename "$sidecar_archive")" > "${sidecar_archive}.sha256"
expect_restore_fail "$sidecar_archive" "archive checksum"

echo "[8/8] Symlink archive members are rejected"
symlink_dir="$TMP_DIR/symlink-member"
mkdir -p "$symlink_dir"
ln -s /etc/passwd "$symlink_dir/database.dump"
printf '{"format_version":1,"database":"bongsu"}\n' > "$symlink_dir/manifest.json"
tar -C "$symlink_dir" -czf "$TMP_DIR/symlink-member.tar.gz" database.dump manifest.json
expect_restore_fail "$TMP_DIR/symlink-member.tar.gz" "regular file"

echo "Backup/restore archive verification passed"
