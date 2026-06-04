#!/bin/bash
set -euo pipefail

# verify-live-sbom-export-workflow.sh - Verify live SBOM export preserves
# host/container package ontology in CycloneDX and SPDX.

API_BASE="${BONGSU_API_BASE:-http://127.0.0.1:5677}"
API_KEY="${BONGSU_API_KEY:-test-admin-key-0123456789}"
AGENT_API_KEY="${BONGSU_AGENT_API_KEY:-test-agent-key-0123456789}"
AGENT_TOKEN="${BONGSU_VERIFY_SBOM_AGENT_TOKEN:-verify-sbom-export-agent-token-0123456789}"
CURL_MAX_TIME="${BONGSU_VERIFY_CURL_MAX_TIME_SECONDS:-30}"
RUN_ID="sbom-export-$(date -u +%Y%m%dT%H%M%SZ)-$$"
HOST_ID="host-${RUN_ID}"
HOSTNAME="bongsu-sbom-${RUN_ID}"
SCAN_ID=""
CONTAINER_ID="container-${RUN_ID}"
CONTAINER_NAME="bongsu-sbom-container-${RUN_ID}"
IMAGE_NAME="fixture.registry/bongsu-sbom:${RUN_ID}"
IMAGE_ID="sha256:sbom-image-${RUN_ID}"
TMP_DIR="$(mktemp -d)"

cleanup() {
    set +e
    curl -fsS --max-time "$CURL_MAX_TIME" -X DELETE -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/hosts/${HOST_ID}" >/dev/null 2>&1
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: missing required tool: $1" >&2
        exit 1
    fi
}

new_uuid() {
    if [ -r /proc/sys/kernel/random/uuid ]; then
        cat /proc/sys/kernel/random/uuid
        return
    fi
    python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
}

api_json() {
    local method="$1"
    local path="$2"
    local body="${3:-}"
    local out="$TMP_DIR/api-response.json"
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

agent_json() {
    local method="$1"
    local path="$2"
    local body="$3"
    local out="$TMP_DIR/agent-response.json"
    local status
    status="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$out" -w "%{http_code}" -X "$method" \
        -H "X-API-Key: ${AGENT_API_KEY}" \
        -H "X-Bongsu-Agent-Token: ${AGENT_TOKEN}" \
        -H "X-Bongsu-Host-ID: ${HOST_ID}" \
        -H "Content-Type: application/json" \
        --data "$body" \
        "${API_BASE}${path}")"
    if [[ "$status" != 2* ]]; then
        echo "ERROR: agent ${method} ${path} returned HTTP ${status}" >&2
        cat "$out" >&2 || true
        exit 1
    fi
    cat "$out"
}

api_download() {
    local path="$1"
    local out="$2"
    local headers="$3"
    local status
    status="$(curl -sS --max-time "$CURL_MAX_TIME" -D "$headers" -o "$out" -w "%{http_code}" \
        -H "X-API-Key: ${API_KEY}" \
        "${API_BASE}${path}")"
    if [[ "$status" != 2* ]]; then
        echo "ERROR: GET ${path} returned HTTP ${status}" >&2
        cat "$out" >&2 || true
        exit 1
    fi
}

assert_json() {
    local file="$1"
    local filter="$2"
    local message="$3"
    if ! jq -e "$filter" "$file" >/dev/null; then
        echo "ERROR: ${message}" >&2
        jq . "$file" >&2 || cat "$file" >&2
        exit 1
    fi
}

assert_header() {
    local file="$1"
    local pattern="$2"
    local message="$3"
    if ! tr -d '\r' < "$file" | grep -Eiq "$pattern"; then
        echo "ERROR: ${message}" >&2
        tr -d '\r' < "$file" >&2 || true
        exit 1
    fi
}

require_tool curl
require_tool jq

echo "=== Bongsu Live SBOM Export Workflow Verification ==="
echo "API:  ${API_BASE}"
echo "Host: ${HOST_ID}"

echo "[1/4] Uploading fixture SBOM inventory with host and container packages"
SCAN_ID="$(new_uuid)"
report_body="$(jq -nc \
    --arg host_id "$HOST_ID" \
    --arg hostname "$HOSTNAME" \
    --arg scan_id "$SCAN_ID" \
    --arg container_id "$CONTAINER_ID" \
    --arg container_name "$CONTAINER_NAME" \
    --arg image_name "$IMAGE_NAME" \
    --arg image_id "$IMAGE_ID" \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
      host: {
        id: $host_id,
        hostname: $hostname,
        ip_address: "127.0.0.1",
        os_name: "Ubuntu",
        os_version: "24.04",
        kernel: "sbom-export-verifier",
        arch: "amd64",
        cpu_model: "verifier",
        cpu_cores: 1,
        memory_mb: 512,
        agent_version: "sbom-export-verifier",
        owner: "platform",
        team: "security",
        environment: "verification",
        criticality: "medium",
        tags: "sbom,export,verification"
      },
      scan_type: "manual",
      scan_id: $scan_id,
      containers: [
        {
          runtime: "docker",
          container_id: $container_id,
          name: $container_name,
          image_name: $image_name,
          image_id: $image_id,
          state: "running",
          labels: "{\"app\":\"bongsu-sbom-export\"}",
          package_count: 2
        }
      ],
      packages: [
        {
          source: "trivy",
          name: "bongsu-sbom-host-os",
          version: "1.0.0",
          arch: "amd64",
          pkg_type: "deb",
          ecosystem: "Ubuntu",
          purl: "pkg:deb/ubuntu/bongsu-sbom-host-os@1.0.0?arch=amd64",
          asset_type: "host",
          asset_id: $host_id,
          target: "/",
          file_path: "/var/lib/dpkg/status"
        },
        {
          source: "trivy",
          name: "bongsu-sbom-host-npm",
          version: "4.5.6",
          pkg_type: "npm",
          ecosystem: "npm",
          purl: "pkg:npm/bongsu-sbom-host-npm@4.5.6",
          asset_type: "host",
          asset_id: $host_id,
          target: "package-lock.json",
          file_path: "/srv/app/package-lock.json"
        },
        {
          source: "trivy",
          name: "bongsu-sbom-container-os",
          version: "2.0.0-r0",
          arch: "x86_64",
          pkg_type: "apk",
          ecosystem: "Alpine",
          purl: "pkg:apk/alpine/bongsu-sbom-container-os@2.0.0-r0?arch=x86_64",
          asset_type: "container",
          asset_id: $container_id,
          container: $container_name,
          container_id: $container_id,
          image_name: $image_name,
          image_id: $image_id,
          target: "alpine:3.19",
          file_path: "/lib/apk/db/installed",
          layer_id: "sha256:sbom-container-layer"
        },
        {
          source: "trivy",
          name: "bongsu-sbom-container-pypi",
          version: "1.2.3",
          pkg_type: "python-pkg",
          ecosystem: "PyPI",
          purl: "pkg:pypi/bongsu-sbom-container-pypi@1.2.3",
          asset_type: "container",
          asset_id: $container_id,
          container: $container_name,
          container_id: $container_id,
          image_name: $image_name,
          image_id: $image_id,
          target: "app/requirements.txt",
          file_path: "/app/requirements.txt",
          layer_id: "sha256:sbom-python-layer"
        }
      ],
      vulnerabilities: [],
      timestamp: $ts
    }')"
report_json="$(agent_json POST /api/report "$report_body")"
if ! jq -e '
  .status == "ok"
  and (.scan_status == "completed" or .scan_status == "degraded")
  and ((.ingest_errors // []) | map(select(test("server_match|multiple types of OS packages"; "i"))) | length == 0)
' >/dev/null <<<"$report_json"; then
    echo "ERROR: fixture report did not complete" >&2
    echo "$report_json" | jq . >&2 || echo "$report_json" >&2
    exit 1
fi

echo "[2/4] Verifying stored package and container ontology before export"
packages_json="$(api_json GET "/api/packages?host_id=${HOST_ID}&limit=20")"
if ! jq -e --arg container_id "$CONTAINER_ID" --arg image_name "$IMAGE_NAME" --arg image_id "$IMAGE_ID" '
  (.items | length) >= 4 and
  (.items[] | select(.name == "bongsu-sbom-host-os" and .asset_type == "host" and .ecosystem == "Ubuntu" and .purl == "pkg:deb/ubuntu/bongsu-sbom-host-os@1.0.0?arch=amd64")) and
  (.items[] | select(.name == "bongsu-sbom-host-npm" and .asset_type == "host" and .ecosystem == "npm" and .target == "package-lock.json")) and
  (.items[] | select(.name == "bongsu-sbom-container-os" and .asset_type == "container" and .asset_id == $container_id and .container_id == $container_id and .image_name == $image_name and .image_id == $image_id and .target == "alpine:3.19")) and
  (.items[] | select(.name == "bongsu-sbom-container-pypi" and .asset_type == "container" and .asset_id == $container_id and .container_id == $container_id and .image_name == $image_name and .image_id == $image_id and .ecosystem == "PyPI" and .target == "app/requirements.txt"))
' >/dev/null <<<"$packages_json"; then
    echo "ERROR: stored packages did not preserve expected ontology" >&2
    echo "$packages_json" | jq . >&2 || echo "$packages_json" >&2
    exit 1
fi
containers_json="$(api_json GET "/api/containers?host_id=${HOST_ID}&limit=20")"
if ! jq -e --arg container_id "$CONTAINER_ID" --arg container_name "$CONTAINER_NAME" --arg image_name "$IMAGE_NAME" --arg image_id "$IMAGE_ID" \
    '.items[] | select(.container_id == $container_id and .name == $container_name and .image_name == $image_name and .image_id == $image_id and .runtime == "docker")' >/dev/null <<<"$containers_json"; then
    echo "ERROR: stored container asset did not preserve runtime/image context" >&2
    echo "$containers_json" | jq . >&2 || echo "$containers_json" >&2
    exit 1
fi

echo "[3/4] Exporting and validating CycloneDX SBOM"
CDX_JSON="$TMP_DIR/sbom.cyclonedx.json"
CDX_HEADERS="$TMP_DIR/sbom.cyclonedx.headers"
api_download "/api/hosts/${HOST_ID}/sbom?format=cyclonedx" "$CDX_JSON" "$CDX_HEADERS"
assert_header "$CDX_HEADERS" '^content-type: application/vnd\.cyclonedx\+json' "CycloneDX export must set CycloneDX content type"
assert_header "$CDX_HEADERS" "content-disposition: attachment; filename=\"${HOSTNAME}-cyclonedx\\.json\"" "CycloneDX export must set a host-based attachment filename"
assert_json "$CDX_JSON" '.bomFormat == "CycloneDX" and .specVersion == "1.5"' "CycloneDX export must identify CycloneDX 1.5"
assert_json "$CDX_JSON" '.serialNumber | startswith("urn:uuid:")' "CycloneDX export must include a stable UUID serial"
jq -e --arg host_id "$HOST_ID" --arg scan_id "$SCAN_ID" '
  .metadata.component.properties as $props |
  ($props[] | select(.name == "bongsu:host_id" and .value == $host_id)) and
  ($props[] | select(.name == "bongsu:scan_id" and .value == $scan_id)) and
  ($props[] | select(.name == "bongsu:os_name" and .value == "Ubuntu")) and
  ($props[] | select(.name == "bongsu:os_version" and .value == "24.04")) and
  ($props[] | select(.name == "bongsu:kernel" and .value == "sbom-export-verifier")) and
  ($props[] | select(.name == "bongsu:arch" and .value == "amd64"))
' "$CDX_JSON" >/dev/null || {
    echo "ERROR: CycloneDX root component did not preserve host metadata" >&2
    jq . "$CDX_JSON" >&2
    exit 1
}
jq -e --arg container_id "$CONTAINER_ID" --arg image_name "$IMAGE_NAME" --arg image_id "$IMAGE_ID" --arg scan_id "$SCAN_ID" '
  (.components | length) >= 4 and
  (.components[] | select(.name == "bongsu-sbom-host-npm" and .purl == "pkg:npm/bongsu-sbom-host-npm@4.5.6" and (.properties[] | select(.name == "bongsu:asset_type" and .value == "host")) and (.properties[] | select(.name == "bongsu:scan_id" and .value == $scan_id)))) and
  (.components[] | select(.name == "bongsu-sbom-container-pypi" and .purl == "pkg:pypi/bongsu-sbom-container-pypi@1.2.3" and (.properties[] | select(.name == "bongsu:asset_type" and .value == "container")) and (.properties[] | select(.name == "bongsu:asset_id" and .value == $container_id)) and (.properties[] | select(.name == "bongsu:container_id" and .value == $container_id)) and (.properties[] | select(.name == "bongsu:image_name" and .value == $image_name)) and (.properties[] | select(.name == "bongsu:image_id" and .value == $image_id)) and (.properties[] | select(.name == "bongsu:target" and .value == "app/requirements.txt"))))
' "$CDX_JSON" >/dev/null || {
    echo "ERROR: CycloneDX export did not preserve package/container ontology" >&2
    jq . "$CDX_JSON" >&2
    exit 1
}

echo "[4/4] Exporting and validating SPDX SBOM"
SPDX_JSON="$TMP_DIR/sbom.spdx.json"
SPDX_HEADERS="$TMP_DIR/sbom.spdx.headers"
api_download "/api/hosts/${HOST_ID}/sbom?format=spdx" "$SPDX_JSON" "$SPDX_HEADERS"
assert_header "$SPDX_HEADERS" '^content-type: application/spdx\+json' "SPDX export must set SPDX content type"
assert_header "$SPDX_HEADERS" "content-disposition: attachment; filename=\"${HOSTNAME}-spdx\\.json\"" "SPDX export must set a host-based attachment filename"
assert_json "$SPDX_JSON" '.spdxVersion == "SPDX-2.3" and .dataLicense == "CC0-1.0"' "SPDX export must identify SPDX 2.3"
jq -e --arg scan_id "$SCAN_ID" --arg container_id "$CONTAINER_ID" --arg image_name "$IMAGE_NAME" --arg image_id "$IMAGE_ID" '
  (.documentNamespace | contains($scan_id)) and
  (.packages | length) >= 5 and
  (.packages[] | select(.name == "bongsu-sbom-host-npm" and .packageUrl == "pkg:npm/bongsu-sbom-host-npm@4.5.6" and (.comment | contains("scan_id=" + $scan_id)) and (.comment | contains("asset_type=host")) and (.comment | contains("target=package-lock.json")))) and
  (.packages[] | select(.name == "bongsu-sbom-container-pypi" and .packageUrl == "pkg:pypi/bongsu-sbom-container-pypi@1.2.3" and (.comment | contains("asset_type=container")) and (.comment | contains("asset_id=" + $container_id)) and (.comment | contains("container_id=" + $container_id)) and (.comment | contains("image_name=" + $image_name)) and (.comment | contains("image_id=" + $image_id)) and (.comment | contains("target=app/requirements.txt")))) and
  (.relationships[] | select(.relationshipType == "CONTAINS"))
' "$SPDX_JSON" >/dev/null || {
    echo "ERROR: SPDX export did not preserve package/container ontology" >&2
    jq . "$SPDX_JSON" >&2
    exit 1
}

echo "Live SBOM export workflow verification passed"
