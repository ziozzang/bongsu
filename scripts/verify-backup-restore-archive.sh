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

echo "[1/5] Valid backup archive is accepted"
valid_dir="$TMP_DIR/valid"
valid_archive="$TMP_DIR/valid-backup.tar.gz"
make_valid_backup "$valid_dir" "$valid_archive"
expect_restore_ok "$valid_archive"

echo "[2/5] Missing database dump is rejected"
missing_dir="$TMP_DIR/missing-db"
mkdir -p "$missing_dir"
printf '{"format_version":1,"database":"bongsu"}\n' > "$missing_dir/manifest.json"
tar -C "$missing_dir" -czf "$TMP_DIR/missing-db.tar.gz" manifest.json
expect_restore_fail "$TMP_DIR/missing-db.tar.gz" "database.dump"

echo "[3/5] Unexpected archive path is rejected"
unexpected_dir="$TMP_DIR/unexpected"
make_valid_backup "$unexpected_dir/root" "$TMP_DIR/unexpected-base.tar.gz"
printf 'unexpected\n' > "$unexpected_dir/root/extra.txt"
tar -C "$unexpected_dir/root" -czf "$TMP_DIR/unexpected.tar.gz" database.dump manifest.json extra.txt
expect_restore_fail "$TMP_DIR/unexpected.tar.gz" "unexpected"

echo "[4/5] Duplicate manifest is rejected"
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

echo "[5/5] Manifest checksum mismatch is rejected"
bad_dir="$TMP_DIR/bad-checksum"
bad_archive="$TMP_DIR/bad-checksum.tar.gz"
make_valid_backup "$bad_dir" "$bad_archive"
printf 'tampered\n' > "$bad_dir/database.dump"
tar -C "$bad_dir" -czf "$bad_archive" database.dump trivy-cache.tar manifest.json
expect_restore_fail "$bad_archive" "checksum"

echo "Backup/restore archive verification passed"
