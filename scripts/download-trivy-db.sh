#!/bin/bash
set -euo pipefail

# download-trivy-db.sh — Download trivy vulnerability database (run on internet-connected machine)
# Usage: ./download-trivy-db.sh [output-file]

TRIVY_VERSION="${TRIVY_VERSION:-0.70.0}"
CACHE_DIR=""
TRIVY_DOWNLOAD_DIR=""
OUTPUT="${1:-trivy-db.tar.gz}"
DB_REPO="${TRIVY_DB_REPO:-ghcr.io/aquasecurity/trivy-db}"
TMP_PARENT="${BONGSU_TMPDIR:-${TMPDIR:-/tmp}}"
mkdir -p "${TMP_PARENT}"

cleanup() {
    if [ -n "$CACHE_DIR" ] && [ -d "$CACHE_DIR" ]; then
        rm -rf "$CACHE_DIR"
    fi
    if [ -n "$TRIVY_DOWNLOAD_DIR" ] && [ -d "$TRIVY_DOWNLOAD_DIR" ]; then
        rm -rf "$TRIVY_DOWNLOAD_DIR"
    fi
}
trap cleanup EXIT

echo "=== Bongsu trivy-db Downloader ==="

# Check for trivy binary
TRIVY_BIN=""
if command -v trivy &>/dev/null; then
    TRIVY_BIN="trivy"
elif [ -x ./trivy ]; then
    TRIVY_BIN="./trivy"
else
    echo "Downloading trivy v${TRIVY_VERSION}..."
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) TRIVY_ARCH="64bit" ;;
        aarch64) TRIVY_ARCH="ARM64" ;;
        *) echo "ERROR: Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    TRIVY_DOWNLOAD_DIR="$(mktemp -d "${TMP_PARENT%/}/bongsu-trivy-bin.XXXXXX")"
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" | \
        tar -xzf - -C "${TRIVY_DOWNLOAD_DIR}" trivy
    TRIVY_BIN="${TRIVY_DOWNLOAD_DIR}/trivy"
fi

CACHE_DIR="$(mktemp -d "${TMP_PARENT%/}/bongsu-trivy-db.XXXXXX")"
echo "Downloading trivy-db from ${DB_REPO}..."
"$TRIVY_BIN" image --download-db-only --cache-dir "$CACHE_DIR" 2>&1

if [ ! -f "$CACHE_DIR/db/trivy.db" ]; then
    echo "ERROR: trivy.db not found after download"
    exit 1
fi

echo "Creating archive..."
tar -C "$CACHE_DIR" -czf "$OUTPUT" db/

SIZE=$(du -h "$OUTPUT" | cut -f1)
SHA=$(sha256sum "$OUTPUT" | cut -d' ' -f1)

echo ""
echo "=== Done ==="
echo "File:     $OUTPUT"
echo "Size:     $SIZE"
echo "SHA256:   $SHA"
echo ""
echo "Verify on target: sha256sum $OUTPUT"
echo ""
echo "Transfer to air-gapped server and run:"
echo "  ./scripts/update-trivy-db.sh <server-url> <api-key> $OUTPUT"
