#!/bin/bash
set -euo pipefail

# verify-live-package-performance.sh - Fail-closed live gate for package list
# latency. The package view is the operator's SBOM drilldown and remediation
# entry point; vulnerability-count and max-CVSS sorts must use the materialized
# package_vulnerability_summaries path instead of re-aggregating findings live.

API_BASE="${BONGSU_API_BASE:-http://127.0.0.1:5677}"
API_KEY="${BONGSU_API_KEY:-test-admin-key-0123456789}"
CURL_MAX_TIME="${BONGSU_VERIFY_PACKAGE_PERF_CURL_MAX_TIME_SECONDS:-30}"
MAX_DEFAULT_SECONDS="${BONGSU_VERIFY_PACKAGE_PERF_MAX_DEFAULT_SECONDS:-1.0}"
MAX_VULN_SORT_SECONDS="${BONGSU_VERIFY_PACKAGE_PERF_MAX_VULN_SORT_SECONDS:-1.0}"
MAX_CVSS_SORT_SECONDS="${BONGSU_VERIFY_PACKAGE_PERF_MAX_CVSS_SORT_SECONDS:-1.0}"
MIN_RESPONSE_BYTES="${BONGSU_VERIFY_PACKAGE_PERF_MIN_RESPONSE_BYTES:-1000}"
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

assert_at_most() {
    local actual="$1"
    local max="$2"
    local message="$3"
    if ! awk -v a="$actual" -v m="$max" 'BEGIN { exit !(a <= m) }'; then
        echo "ERROR: ${message}; got ${actual}s, want <= ${max}s" >&2
        exit 1
    fi
}

assert_at_least() {
    local actual="$1"
    local min="$2"
    local message="$3"
    if ! awk -v a="$actual" -v m="$min" 'BEGIN { exit !(a >= m) }'; then
        echo "ERROR: ${message}; got ${actual}, want >= ${min}" >&2
        exit 1
    fi
}

measure_endpoint() {
    local label="$1"
    local path="$2"
    local max_seconds="$3"
    local out="$TMP_DIR/${label}.json"
    local metrics="$TMP_DIR/${label}.metrics"
    local http_code time_total size_download

    if ! curl -sS --max-time "$CURL_MAX_TIME" -o "$out" -w "%{http_code} %{time_total} %{size_download}\n" \
        -H "X-API-Key: ${API_KEY}" \
        "${API_BASE}${path}" >"$metrics"; then
        echo "ERROR: ${path} did not complete within ${CURL_MAX_TIME}s or failed at the transport layer" >&2
        cat "$out" >&2 || true
        exit 1
    fi
    read -r http_code time_total size_download <"$metrics"
    if [[ "$http_code" != 2* ]]; then
        echo "ERROR: ${path} returned HTTP ${http_code}" >&2
        cat "$out" >&2 || true
        exit 1
    fi
    assert_at_most "$time_total" "$max_seconds" "${label} latency"
    assert_at_least "$size_download" "$MIN_RESPONSE_BYTES" "${label} response size"
    if ! jq -e '(.items | type == "array") and (.total | type == "number")' "$out" >/dev/null; then
        echo "ERROR: ${path} did not return a package list contract" >&2
        jq . "$out" >&2 || cat "$out" >&2
        exit 1
    fi
    printf '%s %ss bytes=%s\n' "$label" "$time_total" "$size_download"
}

require_tool curl
require_tool jq
require_tool awk

echo "=== Bongsu Live Package Performance Verification ==="
echo "API: ${API_BASE}"

measure_endpoint "packages_default" "/api/packages?limit=100" "$MAX_DEFAULT_SECONDS"
measure_endpoint "packages_vuln_count_sort" "/api/packages?limit=100&sort_by=vuln_count&sort_order=desc" "$MAX_VULN_SORT_SECONDS"
measure_endpoint "packages_max_cvss_sort" "/api/packages?limit=100&sort_by=max_cvss&sort_order=desc" "$MAX_CVSS_SORT_SECONDS"

echo "Live package performance verification passed"
