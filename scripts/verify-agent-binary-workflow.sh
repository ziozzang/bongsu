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
RUN_ID="agent-binary-$(date -u +%Y%m%dT%H%M%SZ)-$$"
HOST_ID_PRIMARY="host-${RUN_ID}-primary"
HOST_ID_SECONDARY="host-${RUN_ID}-secondary"
PRIMARY_CONTAINER_ID="fixture-container-${HOST_ID_PRIMARY}"
SECONDARY_CONTAINER_ID="fixture-container-${HOST_ID_SECONDARY}"

cleanup() {
    set +e
    if [ -n "$SCAN_REQUEST_ID" ]; then
        curl -fsS --max-time "$CURL_MAX_TIME" -X POST -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/scan-requests/${SCAN_REQUEST_ID}/cancel" >/dev/null 2>&1
    fi
    curl -fsS --max-time "$CURL_MAX_TIME" -X DELETE -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/hosts/${HOST_ID_PRIMARY}" >/dev/null 2>&1
    curl -fsS --max-time "$CURL_MAX_TIME" -X DELETE -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/hosts/${HOST_ID_SECONDARY}" >/dev/null 2>&1
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
{"Results":[{"Target":"fixture.registry/bongsu-agent-fixture:1.0","Type":"alpine","Packages":[{"Name":"bongsu-container-fixture-package","Version":"2.0.0-r0","Arch":"x86_64","SrcName":"bongsu-container-fixture-package","FilePath":"/lib/apk/db/installed","Layer":{"DiffID":"sha256:fixture-container-layer"}}]},{"Target":"app/requirements.txt","Type":"python-pkg","Packages":[{"Name":"bongsu-container-python-library","Version":"1.2.3","FilePath":"/app/requirements.txt","Layer":{"DiffID":"sha256:fixture-container-python-layer"}}]}]}
JSON
else
    cat <<'JSON'
{"Results":[{"Target":"/","Type":"ubuntu","Packages":[{"Name":"bongsu-host-fixture-package","Version":"1.0.0","Arch":"amd64","SrcName":"bongsu-host-fixture-package","FilePath":"/var/lib/dpkg/status","Layer":{"DiffID":"sha256:fixture-host-layer"}}]},{"Target":"package-lock.json","Type":"npm","Packages":[{"Name":"bongsu-host-npm-library","Version":"4.5.6","FilePath":"/srv/app/package-lock.json","Layer":{"DiffID":"sha256:fixture-host-npm-layer"}}]}]}
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
    printf '%s\n' "fixture-container-${BONGSU_VERIFY_AGENT_HOST_ID:-default}"
    exit 0
fi
if [ "${1:-}" = "inspect" ] && [ "${2:-}" = "--format" ]; then
    printf 'fixture.registry/bongsu-agent-fixture:%s\n' "${BONGSU_VERIFY_AGENT_HOST_ID:-default}"
    exit 0
fi
if [ "${1:-}" = "inspect" ]; then
    host_id="${BONGSU_VERIFY_AGENT_HOST_ID:-default}"
    jq -nc --arg host_id "$host_id" '[{
      Id: ("fixture-container-" + $host_id),
      Name: ("/bongsu-fixture-container-" + $host_id),
      Image: ("sha256:fixture-image-" + $host_id),
      Config: {
        Image: ("fixture.registry/bongsu-agent-fixture:" + $host_id),
        Labels: {"com.example.service":"bongsu-fixture"}
      },
      State: {Status:"running", StartedAt:"2026-06-01T00:00:00Z"}
    }]'
    exit 0
fi
echo "unsupported docker fixture command: $*" >&2
exit 1
DOCKER

    chmod +x "$WORK_DIR/bin/trivy" "$WORK_DIR/bin/osqueryi" "$STUB_DIR/docker"
}

run_agent_once() {
    local host_id="$1"
    local work_dir="$2"
    local token="$3"
    shift 3
    local extra_args=("$@")
    prepare_agent_work_dir "$work_dir"
    PATH="$STUB_DIR:$PATH" \
    BONGSU_AGENT_RETRY_ATTEMPTS=1 \
    BONGSU_AGENT_RETRY_MAX_BACKOFF_SECONDS=1 \
    BONGSU_SERVER_URL="$API_BASE" \
    BONGSU_AGENT_API_KEY="$AGENT_API_KEY" \
    BONGSU_AGENT_TOKEN="$token" \
    BONGSU_VERIFY_AGENT_HOST_ID="$host_id" \
    "$AGENT_BIN" --work-dir "$work_dir" --host-id "$host_id" "${extra_args[@]}"
}

prepare_agent_work_dir() {
    local work_dir="$1"
    mkdir -p "$work_dir/bin"
    cp "$WORK_DIR/bin/trivy" "$work_dir/bin/trivy"
    cp "$WORK_DIR/bin/osqueryi" "$work_dir/bin/osqueryi"
    chmod +x "$work_dir/bin/trivy" "$work_dir/bin/osqueryi"
}

ensure_token() {
    local work_dir="$1"
    local token_file="$work_dir/agent.token"
    mkdir -p "$work_dir"
    if [ ! -s "$token_file" ]; then
        printf 'verify-agent-token-%s-%s\n' "$(date -u +%Y%m%dT%H%M%SZ)" "$$" > "$token_file"
        chmod 0600 "$token_file"
    fi
    tr -d '[:space:]' < "$token_file"
}

require_tool curl
require_tool jq
require_tool go
require_tool timeout

echo "=== Bongsu Agent Binary Workflow Verification ==="
echo "API:       ${API_BASE}"
echo "Work dir:  ${WORK_DIR}"
echo "Primary:   ${HOST_ID_PRIMARY}"
echo "Secondary: ${HOST_ID_SECONDARY}"

PRIMARY_WORK_DIR="$WORK_DIR/primary"
SECONDARY_WORK_DIR="$WORK_DIR/secondary"
PRIMARY_AGENT_TOKEN="$(ensure_token "$PRIMARY_WORK_DIR")"
SECONDARY_AGENT_TOKEN="$(ensure_token "$SECONDARY_WORK_DIR")"
if [ "${#PRIMARY_AGENT_TOKEN}" -lt 32 ] || [ "${#SECONDARY_AGENT_TOKEN}" -lt 32 ]; then
    echo "ERROR: verifier agent token is too short" >&2
    exit 1
fi

write_fixture_tools

echo "[1/7] Building agent binary"
go build -o "$AGENT_BIN" ./cmd/agent

echo "[2/7] Running one-shot package/container inventory scans for two logical hosts"
run_agent_once "$HOST_ID_PRIMARY" "$PRIMARY_WORK_DIR" "$PRIMARY_AGENT_TOKEN" --type manual --packages-only
run_agent_once "$HOST_ID_SECONDARY" "$SECONDARY_WORK_DIR" "$SECONDARY_AGENT_TOKEN" --type manual --packages-only

echo "[3/7] Verifying primary host, container, package, and port inventory"
hosts_json="$(api_json GET /api/hosts)"
assert_json_arg "$hosts_json" id "$HOST_ID_PRIMARY" '.[] | select(.id == $id and .latest_inventory.latest_package_count >= 5 and .latest_inventory.latest_container_count >= 1)' "primary agent host must have latest package, code-library, and container inventory"
assert_json_arg "$hosts_json" id "$HOST_ID_SECONDARY" '.[] | select(.id == $id and .latest_inventory.latest_package_count >= 5 and .latest_inventory.latest_container_count >= 1)' "secondary agent host must have latest package, code-library, and container inventory"
packages_json="$(api_json GET "/api/packages?host_id=${HOST_ID_PRIMARY}&limit=200")"
assert_json "$packages_json" '.items[] | select(.name == "bongsu-host-fixture-package" and .asset_type == "host" and .ecosystem == "Ubuntu" and .target == "/")' "host Trivy package must preserve host target context"
assert_json "$packages_json" '.items[] | select(.name == "bongsu-host-npm-library" and .asset_type == "host" and .pkg_type == "npm" and .ecosystem == "npm" and .purl == "pkg:npm/bongsu-host-npm-library@4.5.6" and .target == "package-lock.json")' "host Trivy code library must preserve npm ecosystem and purl"
assert_json_arg2 "$packages_json" container_id "$PRIMARY_CONTAINER_ID" image_name "fixture.registry/bongsu-agent-fixture:${HOST_ID_PRIMARY}" '.items[] | select(.name == "bongsu-container-fixture-package" and .asset_type == "container" and .container_id == $container_id and .image_name == $image_name)' "container Trivy package must preserve container/image context"
assert_json_arg2 "$packages_json" container_id "$PRIMARY_CONTAINER_ID" image_name "fixture.registry/bongsu-agent-fixture:${HOST_ID_PRIMARY}" '.items[] | select(.name == "bongsu-container-python-library" and .asset_type == "container" and .container_id == $container_id and .image_name == $image_name and .pkg_type == "python-pkg" and .ecosystem == "PyPI" and .purl == "pkg:pypi/bongsu-container-python-library@1.2.3" and .target == "app/requirements.txt")' "container Trivy code library must preserve PyPI ecosystem, purl, and container/image context"
assert_json "$packages_json" '.items[] | select(.name == "bongsu-osquery-fixture-package" and .source == "osquery" and .asset_type == "host")' "osquery package must be ingested as host package"
containers_json="$(api_json GET "/api/containers?host_id=${HOST_ID_PRIMARY}&limit=20")"
assert_json_arg2 "$containers_json" container_id "$PRIMARY_CONTAINER_ID" image_name "fixture.registry/bongsu-agent-fixture:${HOST_ID_PRIMARY}" '.items[] | select(.container_id == $container_id and .image_name == $image_name and .state == "running")' "container asset must be persisted"

echo "[4/7] Verifying secondary host inventory is separately queryable"
secondary_packages_json="$(api_json GET "/api/packages?host_id=${HOST_ID_SECONDARY}&limit=200")"
assert_json "$secondary_packages_json" '.items[] | select(.name == "bongsu-host-fixture-package" and .asset_type == "host")' "secondary host package must be queryable by secondary host id"
assert_json "$secondary_packages_json" '.items[] | select(.name == "bongsu-host-npm-library" and .asset_type == "host" and .ecosystem == "npm")' "secondary host code-library package must be queryable by secondary host id"
assert_json_arg2 "$secondary_packages_json" container_id "$SECONDARY_CONTAINER_ID" image_name "fixture.registry/bongsu-agent-fixture:${HOST_ID_SECONDARY}" '.items[] | select(.name == "bongsu-container-fixture-package" and .asset_type == "container" and .container_id == $container_id and .image_name == $image_name)' "secondary container package must preserve secondary container/image context"
assert_json_arg2 "$secondary_packages_json" container_id "$SECONDARY_CONTAINER_ID" image_name "fixture.registry/bongsu-agent-fixture:${HOST_ID_SECONDARY}" '.items[] | select(.name == "bongsu-container-python-library" and .asset_type == "container" and .container_id == $container_id and .image_name == $image_name and .ecosystem == "PyPI")' "secondary container code-library package must preserve secondary container/image context"
assert_json_arg "$secondary_packages_json" host "$HOST_ID_PRIMARY" 'all(.items[]; .host_id != $host)' "secondary host package query must not leak primary host packages"

echo "[5/7] Creating host-specific scan request"
request_body="$(jq -nc --arg host_id "$HOST_ID_PRIMARY" '{host_id:$host_id, scan_type:"manual", packages_only:true, reason:"agent binary verifier"}')"
request_json="$(api_json POST /api/scan-requests "$request_body")"
SCAN_REQUEST_ID="$(jq -r '.id' <<<"$request_json")"
assert_json "$request_json" '.status == "pending" and .packages_only == true' "scan request must be pending packages-only"

echo "[6/7] Running primary agent daemon long enough to claim and complete the request"
PATH="$STUB_DIR:$PATH" \
BONGSU_AGENT_RETRY_ATTEMPTS=1 \
BONGSU_AGENT_RETRY_MAX_BACKOFF_SECONDS=1 \
BONGSU_SERVER_URL="$API_BASE" \
BONGSU_AGENT_API_KEY="$AGENT_API_KEY" \
BONGSU_AGENT_TOKEN="$PRIMARY_AGENT_TOKEN" \
BONGSU_VERIFY_AGENT_HOST_ID="$HOST_ID_PRIMARY" \
timeout 25 "$AGENT_BIN" --work-dir "$PRIMARY_WORK_DIR" --host-id "$HOST_ID_PRIMARY" --daemon --poll-interval 1s >/tmp/bongsu-agent-binary-verifier-daemon.log 2>&1 || true

request_done="$(api_json GET "/api/scan-requests?host_id=${HOST_ID_PRIMARY}&limit=20")"
assert_json_arg2 "$request_done" id "$SCAN_REQUEST_ID" host_id "$HOST_ID_PRIMARY" '.items[] | select(.id == $id and (.status == "completed" or .status == "degraded") and .claimed_by_host_id == $host_id)' "daemon must claim and complete the host-specific scan request"
SCAN_REQUEST_ID=""

echo "[7/7] Verifying scans are tied to the correct host identities"
scans_json="$(api_json GET "/api/scans?host_id=${HOST_ID_PRIMARY}&limit=20")"
assert_json "$scans_json" '.items[] | select((.status == "completed" or .status == "degraded") and .package_count >= 5 and .container_count >= 1)' "agent binary scan must persist OS package, code-library, and container counts"
assert_json_arg "$scans_json" host "$HOST_ID_SECONDARY" 'all(.items[]; .host_id != $host)' "primary scan query must not include secondary host scans"
secondary_scans_json="$(api_json GET "/api/scans?host_id=${HOST_ID_SECONDARY}&limit=20")"
assert_json "$secondary_scans_json" '.items[] | select((.status == "completed" or .status == "degraded") and .package_count >= 5 and .container_count >= 1)' "secondary agent scan must persist OS package, code-library, and container counts"

echo "Agent binary workflow verification passed"
