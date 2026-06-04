#!/bin/bash
set -euo pipefail

# verify-agent-binary-workflow.sh — Run the real agent binary with fixture
# collection tools, then verify host/container inventory reaches the API.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API_BASE="${BONGSU_API_BASE:-http://127.0.0.1:5677}"
API_KEY="${BONGSU_API_KEY:-test-admin}"
AGENT_API_KEY="${BONGSU_AGENT_API_KEY:-test-agent-key}"
CURL_MAX_TIME="${BONGSU_VERIFY_CURL_MAX_TIME_SECONDS:-20}"
WORK_DIR="${BONGSU_VERIFY_AGENT_WORK_DIR:-/tmp/bongsu-agent-binary-verifier}"
TMP_DIR="$(mktemp -d)"
AGENT_BIN="$TMP_DIR/bongsu-agent"
STUB_DIR="$TMP_DIR/stubs"
SCAN_REQUEST_ID=""

cleanup() {
    set +e
    if [ -n "$SCAN_REQUEST_ID" ]; then
        curl -fsS --max-time "$CURL_MAX_TIME" -X POST -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/scan-requests/${SCAN_REQUEST_ID}/cancel" >/dev/null 2>&1
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

api_json() {
    local method="$1"
    local path="$2"
    local body="${3:-}"
    local out="$TMP_DIR/response.json"
    local status
    if [ -n "$body" ]; then
        status="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$out" -w "%{http_code}" -X "$method" \
            -H "X-API-Key: ${API_KEY}" \
            -H "Content-Type: application/json" \
            --data "$body" \
            "${API_BASE}${path}")"
    else
        status="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$out" -w "%{http_code}" -X "$method" \
            -H "X-API-Key: ${API_KEY}" \
            "${API_BASE}${path}")"
    fi
    if [[ "$status" != 2* ]]; then
        echo "ERROR: ${method} ${path} returned HTTP ${status}" >&2
        cat "$out" >&2 || true
        exit 1
    fi
    cat "$out"
}

assert_json() {
    local json="$1"
    local filter="$2"
    local message="$3"
    if ! jq -e "$filter" >/dev/null <<<"$json"; then
        echo "ERROR: ${message}" >&2
        echo "$json" | jq . >&2 || echo "$json" >&2
        exit 1
    fi
}

assert_json_arg() {
    local json="$1"
    local name="$2"
    local value="$3"
    local filter="$4"
    local message="$5"
    if ! jq -e --arg "$name" "$value" "$filter" >/dev/null <<<"$json"; then
        echo "ERROR: ${message}" >&2
        echo "$json" | jq . >&2 || echo "$json" >&2
        exit 1
    fi
}

assert_json_arg2() {
    local json="$1"
    local name1="$2"
    local value1="$3"
    local name2="$4"
    local value2="$5"
    local filter="$6"
    local message="$7"
    if ! jq -e --arg "$name1" "$value1" --arg "$name2" "$value2" "$filter" >/dev/null <<<"$json"; then
        echo "ERROR: ${message}" >&2
        echo "$json" | jq . >&2 || echo "$json" >&2
        exit 1
    fi
}

derive_host_id() {
    if [ -r /etc/machine-id ] && [ -s /etc/machine-id ]; then
        tr -d '[:space:]' </etc/machine-id
        return
    fi
    if [ -r /var/lib/dbus/machine-id ] && [ -s /var/lib/dbus/machine-id ]; then
        tr -d '[:space:]' </var/lib/dbus/machine-id
        return
    fi
    hostname
}

write_fixture_tools() {
    mkdir -p "$WORK_DIR/bin" "$STUB_DIR"

    cat > "$WORK_DIR/bin/trivy" <<'TRIVY'
#!/bin/bash
set -euo pipefail
mode=""
for arg in "$@"; do
    case "$arg" in
        fs|image) mode="$arg" ;;
    esac
done
if [ "$mode" = "image" ]; then
    cat <<'JSON'
{"Results":[{"Target":"fixture.registry/bongsu-agent-fixture:1.0","Type":"alpine","Packages":[{"Name":"bongsu-container-fixture-package","Version":"2.0.0-r0","Arch":"x86_64","SrcName":"bongsu-container-fixture-package","FilePath":"/lib/apk/db/installed","Layer":{"DiffID":"sha256:fixture-container-layer"}}]}]}
JSON
else
    cat <<'JSON'
{"Results":[{"Target":"/","Type":"ubuntu","Packages":[{"Name":"bongsu-host-fixture-package","Version":"1.0.0","Arch":"amd64","SrcName":"bongsu-host-fixture-package","FilePath":"/var/lib/dpkg/status","Layer":{"DiffID":"sha256:fixture-host-layer"}}]}]}
JSON
fi
TRIVY

    cat > "$WORK_DIR/bin/osqueryi" <<'OSQUERY'
#!/bin/bash
set -euo pipefail
query="$*"
if printf '%s' "$query" | grep -q 'listening_ports'; then
    printf '[{"name":"bongsu-fixture-listener","port":"5677","protocol":"6","address":"127.0.0.1","pid":"1"}]\n'
elif printf '%s' "$query" | grep -q 'deb_packages'; then
    printf '[{"name":"bongsu-osquery-fixture-package","version":"3.0.0","arch":"amd64","source_name":"bongsu-osquery-fixture-package"}]\n'
else
    printf '[]\n'
fi
OSQUERY

    cat > "$STUB_DIR/docker" <<'DOCKER'
#!/bin/bash
set -euo pipefail
if [ "${1:-}" = "ps" ]; then
    printf 'fixture-container-id\n'
    exit 0
fi
if [ "${1:-}" = "inspect" ] && [ "${2:-}" = "--format" ]; then
    printf 'fixture.registry/bongsu-agent-fixture:1.0\n'
    exit 0
fi
if [ "${1:-}" = "inspect" ]; then
    cat <<'JSON'
[{"Id":"fixture-container-id","Name":"/bongsu-fixture-container","Image":"sha256:fixture-image-id","Config":{"Image":"fixture.registry/bongsu-agent-fixture:1.0","Labels":{"com.example.service":"bongsu-fixture"}},"State":{"Status":"running","StartedAt":"2026-06-01T00:00:00Z"}}]
JSON
    exit 0
fi
echo "unsupported docker fixture command: $*" >&2
exit 1
DOCKER

    chmod +x "$WORK_DIR/bin/trivy" "$WORK_DIR/bin/osqueryi" "$STUB_DIR/docker"
}

run_agent_once() {
    local extra_args=("$@")
    PATH="$STUB_DIR:$PATH" \
    BONGSU_AGENT_RETRY_ATTEMPTS=1 \
    BONGSU_AGENT_RETRY_MAX_BACKOFF_SECONDS=1 \
    BONGSU_SERVER_URL="$API_BASE" \
    BONGSU_AGENT_API_KEY="$AGENT_API_KEY" \
    BONGSU_AGENT_TOKEN="$AGENT_TOKEN" \
    "$AGENT_BIN" --work-dir "$WORK_DIR" "${extra_args[@]}"
}

require_tool curl
require_tool jq
require_tool go
require_tool timeout

echo "=== Bongsu Agent Binary Workflow Verification ==="
echo "API:      ${API_BASE}"
echo "Work dir: ${WORK_DIR}"

mkdir -p "$WORK_DIR"
if [ ! -s "$WORK_DIR/agent.token" ]; then
    printf 'verify-agent-token-%s-%s\n' "$(date -u +%Y%m%dT%H%M%SZ)" "$$" > "$WORK_DIR/agent.token"
    chmod 0600 "$WORK_DIR/agent.token"
fi
AGENT_TOKEN="$(tr -d '[:space:]' < "$WORK_DIR/agent.token")"
if [ "${#AGENT_TOKEN}" -lt 32 ]; then
    echo "ERROR: verifier agent token is too short" >&2
    exit 1
fi

write_fixture_tools

echo "[1/6] Building agent binary"
go build -o "$AGENT_BIN" ./cmd/agent

HOST_ID="$(derive_host_id)"
if [ -z "$HOST_ID" ]; then
    echo "ERROR: could not derive host id" >&2
    exit 1
fi

echo "[2/6] Running one-shot package/container inventory scan"
run_agent_once --type manual --packages-only

echo "[3/6] Verifying host, container, package, and port inventory"
hosts_json="$(api_json GET /api/hosts)"
assert_json_arg "$hosts_json" id "$HOST_ID" '.[] | select(.id == $id and .latest_inventory.latest_package_count >= 3 and .latest_inventory.latest_container_count >= 1)' "agent host must have latest package and container inventory"
packages_json="$(api_json GET "/api/packages?host_id=${HOST_ID}&limit=200")"
assert_json "$packages_json" '.items[] | select(.name == "bongsu-host-fixture-package" and .asset_type == "host" and .ecosystem == "Ubuntu" and .target == "/")' "host Trivy package must preserve host target context"
assert_json "$packages_json" '.items[] | select(.name == "bongsu-container-fixture-package" and .asset_type == "container" and .container == "bongsu-fixture-container" and .container_id == "fixture-container-id" and .image_name == "fixture.registry/bongsu-agent-fixture:1.0")' "container Trivy package must preserve container/image context"
assert_json "$packages_json" '.items[] | select(.name == "bongsu-osquery-fixture-package" and .source == "osquery" and .asset_type == "host")' "osquery package must be ingested as host package"
containers_json="$(api_json GET "/api/containers?host_id=${HOST_ID}&limit=20")"
assert_json "$containers_json" '.items[] | select(.name == "bongsu-fixture-container" and .container_id == "fixture-container-id" and .image_name == "fixture.registry/bongsu-agent-fixture:1.0" and .state == "running")' "container asset must be persisted"

echo "[4/6] Creating host-specific scan request"
request_body="$(jq -nc --arg host_id "$HOST_ID" '{host_id:$host_id, scan_type:"manual", packages_only:true, reason:"agent binary verifier"}')"
request_json="$(api_json POST /api/scan-requests "$request_body")"
SCAN_REQUEST_ID="$(jq -r '.id' <<<"$request_json")"
assert_json "$request_json" '.status == "pending" and .packages_only == true' "scan request must be pending packages-only"

echo "[5/6] Running agent daemon long enough to claim and complete the request"
PATH="$STUB_DIR:$PATH" \
BONGSU_AGENT_RETRY_ATTEMPTS=1 \
BONGSU_AGENT_RETRY_MAX_BACKOFF_SECONDS=1 \
BONGSU_SERVER_URL="$API_BASE" \
BONGSU_AGENT_API_KEY="$AGENT_API_KEY" \
BONGSU_AGENT_TOKEN="$AGENT_TOKEN" \
timeout 25 "$AGENT_BIN" --work-dir "$WORK_DIR" --daemon --poll-interval 1s >/tmp/bongsu-agent-binary-verifier-daemon.log 2>&1 || true

request_done="$(api_json GET "/api/scan-requests?host_id=${HOST_ID}&limit=20")"
assert_json_arg2 "$request_done" id "$SCAN_REQUEST_ID" host_id "$HOST_ID" '.items[] | select(.id == $id and (.status == "completed" or .status == "degraded") and .claimed_by_host_id == $host_id)' "daemon must claim and complete the host-specific scan request"
SCAN_REQUEST_ID=""

echo "[6/6] Verifying scan request is tied to a completed inventory scan"
scans_json="$(api_json GET "/api/scans?host_id=${HOST_ID}&limit=20")"
assert_json "$scans_json" '.items[] | select((.status == "completed" or .status == "degraded") and .package_count >= 3 and .container_count >= 1)' "agent binary scan must persist package and container counts"

echo "Agent binary workflow verification passed"
