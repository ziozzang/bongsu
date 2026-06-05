#!/bin/bash
set -euo pipefail

# verify-security-db-bundle-file-fixtures.sh - Fixture tests for the local
# security DB bundle file verifier.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-security-db-bundle-file.sh"
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

require_tool jq
require_tool tar
require_tool sha256sum

write_bundle() {
    local dir="$1"
    local bundle="$2"
    local cve_records="$3"
    local trivy_sha_override="${4:-}"

    mkdir -p "$dir"
    printf '{"id":"CVE-2099-0001","source":"osv"}\n' > "$dir/cve-database.jsonl"
    printf 'fixture trivy db\n' > "$dir/trivy-db.tar.gz"
    local cve_sha
    cve_sha="$(sha256sum "$dir/cve-database.jsonl" | awk '{print $1}')"
    local trivy_sha
    trivy_sha="$(sha256sum "$dir/trivy-db.tar.gz" | awk '{print $1}')"
    if [ -n "$trivy_sha_override" ]; then
        trivy_sha="$trivy_sha_override"
    fi
    jq -nc \
        --arg cve_sha "$cve_sha" \
        --arg trivy_sha "$trivy_sha" \
        --argjson cve_records "$cve_records" \
        '{
          format:"bongsu-security-db-bundle",
          version:1,
          created_at:"2026-06-05T00:00:00Z",
          security_db_revision:"fixture-revision",
          cve_records:$cve_records,
          cve_database_sha256:$cve_sha,
          trivy_db_included:true,
          trivy_db_sha256:$trivy_sha,
          sources:[
            {source:"cisa-kev", count:1, last_update:"2026-06-05T00:00:00Z"},
            {source:"epss", count:1, last_update:"2026-06-05T00:00:00Z"},
            {source:"osv", count:1, last_update:"2026-06-05T00:00:00Z"},
            {source:"nvd", count:1, last_update:"2026-06-05T00:00:00Z"},
            {source:"trivy", count:1, last_update:"2026-06-05T00:00:00Z"}
          ]
        }' > "$dir/manifest.json"
    tar -C "$dir" -czf "$bundle" manifest.json cve-database.jsonl trivy-db.tar.gz
    sha256sum "$bundle" > "${bundle}.sha256"
}

expect_fail() {
    local name="$1"
    local bundle="$2"
    local pattern="$3"
    if "$VERIFY" "$bundle" >"$TMP_DIR/${name}.out" 2>"$TMP_DIR/${name}.err"; then
        echo "ERROR: fixture $name should fail" >&2
        exit 1
    fi
    if ! grep -q "$pattern" "$TMP_DIR/${name}.err"; then
        echo "ERROR: fixture $name failed with unexpected message" >&2
        cat "$TMP_DIR/${name}.err" >&2
        exit 1
    fi
}

valid_dir="$TMP_DIR/valid"
valid_bundle="$TMP_DIR/valid.tar.gz"
write_bundle "$valid_dir" "$valid_bundle" 1
"$VERIFY" "$valid_bundle" >/dev/null

path_sidecar_dir="$TMP_DIR/path-sidecar"
path_sidecar_bundle="$TMP_DIR/path-sidecar.tar.gz"
write_bundle "$path_sidecar_dir" "$path_sidecar_bundle" 1
sha256sum "$path_sidecar_bundle" > "${path_sidecar_bundle}.sha256"
"$VERIFY" "$path_sidecar_bundle" >/dev/null

missing_sidecar_dir="$TMP_DIR/missing-sidecar"
missing_sidecar_bundle="$TMP_DIR/missing-sidecar.tar.gz"
write_bundle "$missing_sidecar_dir" "$missing_sidecar_bundle" 1
rm -f "${missing_sidecar_bundle}.sha256"
expect_fail missing_sidecar "$missing_sidecar_bundle" 'missing security DB bundle checksum sidecar'

bad_count_dir="$TMP_DIR/bad-count"
bad_count_bundle="$TMP_DIR/bad-count.tar.gz"
write_bundle "$bad_count_dir" "$bad_count_bundle" 2
expect_fail bad_count "$bad_count_bundle" 'record count mismatch'

bad_trivy_dir="$TMP_DIR/bad-trivy"
bad_trivy_bundle="$TMP_DIR/bad-trivy.tar.gz"
write_bundle "$bad_trivy_dir" "$bad_trivy_bundle" 1 "0000000000000000000000000000000000000000000000000000000000000000"
expect_fail bad_trivy "$bad_trivy_bundle" 'trivy-db.tar.gz checksum mismatch'

echo "Security DB bundle file fixture verification passed"
