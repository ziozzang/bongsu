#!/bin/bash
set -euo pipefail

# verify-airgap-package-smoke.sh - Exercise scripts/package.sh end-to-end with
# lightweight build tool stubs, then validate the generated archive.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${BONGSU_PACKAGE_SMOKE_VERSION:-smoke-$(date -u +%Y%m%d%H%M%S)-$$}"
PACKAGE="$ROOT/bongsu-${VERSION}.tar.gz"
TMP_DIR="$(mktemp -d)"
STUB_DIR="$TMP_DIR/bin"
STATIC_BINARY="$ROOT/bin/bongsu-agent"
BUILT_STATIC="$TMP_DIR/static-bongsu-agent"

AGENT_OUT="$ROOT/bin/bongsu-agent-linux-amd64"
SERVER_OUT="$ROOT/bin/bongsu-server-linux-amd64"
AGENT_BACKUP="$TMP_DIR/bongsu-agent-linux-amd64.backup"
SERVER_BACKUP="$TMP_DIR/bongsu-server-linux-amd64.backup"
HAD_AGENT_OUT=0
HAD_SERVER_OUT=0
HAD_WEB_DIST=0

cleanup() {
    rm -f "$PACKAGE" "$PACKAGE.sha256"
    if [ "$HAD_AGENT_OUT" = "1" ]; then
        cp "$AGENT_BACKUP" "$AGENT_OUT"
    else
        rm -f "$AGENT_OUT"
    fi
    if [ "$HAD_SERVER_OUT" = "1" ]; then
        cp "$SERVER_BACKUP" "$SERVER_OUT"
    else
        rm -f "$SERVER_OUT"
    fi
    if [ "$HAD_WEB_DIST" = "0" ]; then
        rm -rf "$ROOT/web/dist"
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: missing required tool: $1" >&2
        exit 1
    fi
}

require_tool file
require_tool tar
require_tool gzip
require_tool sha256sum
require_tool go

if [ -e "$AGENT_OUT" ]; then
    HAD_AGENT_OUT=1
    cp "$AGENT_OUT" "$AGENT_BACKUP"
fi
if [ -e "$SERVER_OUT" ]; then
    HAD_SERVER_OUT=1
    cp "$SERVER_OUT" "$SERVER_BACKUP"
fi
if [ -d "$ROOT/web/dist" ]; then
    HAD_WEB_DIST=1
fi

if [ -x "$STATIC_BINARY" ] && file "$STATIC_BINARY" | grep -q 'statically linked'; then
    SMOKE_STATIC_BINARY="$STATIC_BINARY"
else
    echo "Building a static fixture binary for package smoke verification"
    (cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o "$BUILT_STATIC" ./cmd/agent)
    SMOKE_STATIC_BINARY="$BUILT_STATIC"
fi

mkdir -p "$STUB_DIR"

cat > "$STUB_DIR/go" << 'EOF'
#!/bin/bash
set -euo pipefail
out=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o)
            shift
            out="${1:-}"
            ;;
        -o*)
            out="${1#-o}"
            ;;
    esac
    shift || true
done
if [ -z "$out" ]; then
    echo "stub go: missing -o output" >&2
    exit 1
fi
cp "$BONGSU_PACKAGE_SMOKE_STATIC_BINARY" "$out"
chmod +x "$out"
EOF

cat > "$STUB_DIR/npm" << 'EOF'
#!/bin/bash
set -euo pipefail
case "${1:-}" in
    ci)
        exit 0
        ;;
    run)
        if [ "${2:-}" != "build" ]; then
            echo "stub npm: unsupported npm run target: ${2:-}" >&2
            exit 1
        fi
        if [ ! -d dist ]; then
            mkdir -p dist/assets
            printf '<!doctype html><html><head><title>bongsu</title></head><body><div id="root"></div></body></html>\n' > dist/index.html
        fi
        exit 0
        ;;
esac
echo "stub npm: unsupported command: $*" >&2
exit 1
EOF

cat > "$STUB_DIR/docker" << 'EOF'
#!/bin/bash
set -euo pipefail
case "${1:-}" in
    build)
        echo "stub docker build $*" >&2
        exit 0
        ;;
    save)
        tmp="$(mktemp -d)"
        cleanup_stub() {
            rm -rf "$tmp"
        }
        trap cleanup_stub EXIT
        printf '[{"Config":"config.json","RepoTags":["%s"],"Layers":[]}]\n' "${2:-bongsu:smoke}" > "$tmp/manifest.json"
        printf '{}\n' > "$tmp/config.json"
        tar -C "$tmp" -cf - manifest.json config.json
        exit 0
        ;;
esac
echo "stub docker: unsupported command: $*" >&2
exit 1
EOF

chmod +x "$STUB_DIR/go" "$STUB_DIR/npm" "$STUB_DIR/docker"

echo "=== Bongsu Airgap Package Smoke Verification ==="
echo "Version: $VERSION"

(
    cd "$ROOT"
    PATH="$STUB_DIR:$PATH" \
        BONGSU_PACKAGE_SMOKE_STATIC_BINARY="$SMOKE_STATIC_BINARY" \
        BONGSU_BUILD_DATE="2026-01-01T00:00:00Z" \
        ./scripts/package.sh "$VERSION"
)

"$ROOT/scripts/verify-airgap-release-archive.sh" "$PACKAGE"

echo "Airgap package smoke verification passed"
