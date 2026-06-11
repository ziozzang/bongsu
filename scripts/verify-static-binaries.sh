#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${BONGSU_STATIC_VERIFY_DIR:-$(mktemp -d)}"
KEEP_OUT="${BONGSU_STATIC_VERIFY_KEEP:-false}"

cleanup() {
    if [ "$KEEP_OUT" != "true" ] && [ -d "$OUT_DIR" ]; then
        rm -rf "$OUT_DIR"
    fi
}
trap cleanup EXIT

mkdir -p "$OUT_DIR"
cd "$ROOT"

VERSION="${BONGSU_VERSION:-0.2.0-static-verify}"
COMMIT="${BONGSU_COMMIT:-$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)}"
BUILD_DATE="${BONGSU_BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}"

echo "Building static linux/amd64 binaries in $OUT_DIR"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$LDFLAGS" -o "$OUT_DIR/bongsu-agent" ./cmd/agent
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$LDFLAGS" -o "$OUT_DIR/bongsu-server" ./cmd/server

verify_static() {
    local bin="$1"
    local meta
    meta="$(file "$bin")"
    echo "$meta"
    if ! grep -qi "statically linked" <<<"$meta"; then
        echo "ERROR: $bin is not reported as statically linked" >&2
        return 1
    fi
    if ldd "$bin" 2>&1 | grep -Eiq "=>|ld-linux|libc"; then
        echo "ERROR: $bin has dynamic runtime dependencies" >&2
        ldd "$bin" >&2 || true
        return 1
    fi
}

verify_static "$OUT_DIR/bongsu-agent"
verify_static "$OUT_DIR/bongsu-server"

agent_version="$("$OUT_DIR/bongsu-agent" --version)"
server_version="$("$OUT_DIR/bongsu-server" --version)"
echo "agent version:  $agent_version"
echo "server version: $server_version"
for got in "$agent_version" "$server_version"; do
    if [[ "$got" != "${VERSION}+${COMMIT}+${BUILD_DATE}" ]]; then
        echo "ERROR: static binary build metadata mismatch: got $got, want ${VERSION}+${COMMIT}+${BUILD_DATE}" >&2
        exit 1
    fi
done

echo "Static binary verification passed"
