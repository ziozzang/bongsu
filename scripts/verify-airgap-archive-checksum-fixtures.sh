#!/bin/bash
set -euo pipefail

# verify-airgap-archive-checksum-fixtures.sh - Exercise fail-closed handling for
# airgap archive promotion when the outer .sha256 sidecar is missing.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d)"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

ARCHIVE="$TMP_DIR/bongsu-missing-sidecar.tar.gz"
printf 'not a real archive\n' >"$ARCHIVE"

expect_missing_sidecar_failure() {
    local name="$1"
    local script="$2"
    local out="$TMP_DIR/${name}.out"
    local err="$TMP_DIR/${name}.err"
    if "$script" "$ARCHIVE" >"$out" 2>"$err"; then
        echo "ERROR: $name should fail when the outer checksum sidecar is missing" >&2
        cat "$out" "$err" >&2
        exit 1
    fi
    if ! grep -q 'missing required outer checksum sidecar' "$err"; then
        echo "ERROR: $name did not fail with the expected missing-sidecar message" >&2
        cat "$out" "$err" >&2
        exit 1
    fi
}

expect_missing_sidecar_failure verify-airgap-release-archive "$ROOT/scripts/verify-airgap-release-archive.sh"
expect_missing_sidecar_failure verify-airgap-offline-rehearsal "$ROOT/scripts/verify-airgap-offline-rehearsal.sh"

echo "Airgap archive checksum fixture verification passed"
