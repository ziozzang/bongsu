#!/bin/bash
set -euo pipefail

# verify-live-cvedb-concurrency.sh - Exercise concurrent CVE DB observability
# endpoints against a live API. This catches regressions where large CVE DB
# stats/status/metrics requests exhaust PostgreSQL shared memory or return 5xx.

API_BASE="${BONGSU_API_BASE:-http://127.0.0.1:5677}"
API_KEY="${BONGSU_API_KEY:-test-admin-key-0123456789}"
CURL_MAX_TIME="${BONGSU_VERIFY_CVEDB_CONCURRENCY_CURL_MAX_TIME_SECONDS:-90}"
STATS_REQUESTS="${BONGSU_VERIFY_CVEDB_CONCURRENCY_STATS_REQUESTS:-3}"
TMP_DIR="$(mktemp -d)"
LOG_FILE="${BONGSU_API_LOG_FILE:-/tmp/bongsu-api-5677.log}"

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

bounded_stats_requests() {
    if ! [[ "$STATS_REQUESTS" =~ ^[0-9]+$ ]]; then
        echo "ERROR: BONGSU_VERIFY_CVEDB_CONCURRENCY_STATS_REQUESTS must be numeric" >&2
        exit 1
    fi
    if [ "$STATS_REQUESTS" -lt 2 ]; then
        STATS_REQUESTS=2
    fi
    if [ "$STATS_REQUESTS" -gt 8 ]; then
        STATS_REQUESTS=8
    fi
}

run_request() {
    local name="$1"
    local url="$2"
    local out="$TMP_DIR/${name}.body"
    local headers="$TMP_DIR/${name}.headers"
    local time_file="$TMP_DIR/${name}.time"
    local status

    status="$(curl -sS --max-time "$CURL_MAX_TIME" \
        -D "$headers" \
        -o "$out" \
        -w "%{http_code} %{time_total}" \
        -H "X-API-Key: ${API_KEY}" \
        "$url")"
    printf '%s %s\n' "$name" "$status" >"$time_file"
}

assert_request_ok() {
    local name="$1"
    local body="$TMP_DIR/${name}.body"
    local time_file="$TMP_DIR/${name}.time"
    local code

    if [ ! -s "$time_file" ]; then
        echo "ERROR: request ${name} did not complete" >&2
        exit 1
    fi
    code="$(awk '{print $2}' "$time_file")"
    if [[ "$code" != 2* ]]; then
        echo "ERROR: request ${name} returned HTTP ${code}" >&2
        cat "$body" >&2 || true
        exit 1
    fi
}

assert_json_ok() {
    local name="$1"
    local body="$TMP_DIR/${name}.body"
    if ! jq -e 'type == "object"' "$body" >/dev/null; then
        echo "ERROR: request ${name} did not return a JSON object" >&2
        cat "$body" >&2 || true
        exit 1
    fi
    if jq -e '(.status? // "ok") == "error"' "$body" >/dev/null; then
        echo "ERROR: request ${name} returned error status" >&2
        jq . "$body" >&2 || cat "$body" >&2
        exit 1
    fi
}

assert_metrics_ok() {
    local body="$TMP_DIR/metrics.body"
    if ! grep -Eq '^bongsu_' "$body"; then
        echo "ERROR: admin metrics response did not contain bongsu_* metrics" >&2
        head -50 "$body" >&2 || true
        exit 1
    fi
}

assert_no_new_shared_memory_errors() {
    local start_line="$1"
    if [ ! -f "$LOG_FILE" ]; then
        echo "Skipping log scan; API log file not found: $LOG_FILE"
        return
    fi
    if tail -n +"$((start_line + 1))" "$LOG_FILE" | grep -Eiq 'shared memory|could not resize|No space left on device|pq: .*53100'; then
        echo "ERROR: API log contains new PostgreSQL shared-memory/storage error during concurrency verifier" >&2
        tail -n +"$((start_line + 1))" "$LOG_FILE" >&2
        exit 1
    fi
}

require_tool curl
require_tool jq
require_tool awk
bounded_stats_requests

echo "=== Bongsu Live CVE DB Concurrency Verification ==="
echo "API:            $API_BASE"
echo "Stats requests: $STATS_REQUESTS"

log_start_line=0
if [ -f "$LOG_FILE" ]; then
    log_start_line="$(wc -l <"$LOG_FILE" | tr -d ' ')"
fi

for i in $(seq 1 "$STATS_REQUESTS"); do
    run_request "stats${i}" "${API_BASE}/api/cve-db/stats?refresh=true" &
done
run_request "status" "${API_BASE}/api/admin/security-db/status" &
run_request "metrics" "${API_BASE}/api/admin/metrics" &
wait

for i in $(seq 1 "$STATS_REQUESTS"); do
    assert_request_ok "stats${i}"
    assert_json_ok "stats${i}"
done
assert_request_ok "status"
assert_json_ok "status"
if ! jq -e '
  (.status // "") == "ok"
  and ((.cve_db_quality.status // "") == "ok" or (.cve_db_quality.status // "") == "warning")
  and (
    (.cve_db_quality.status // "") == "ok"
    or (
      ((.cve_db_quality.warnings // []) | length) > 0
      and (
        (.cve_db_quality.affected_index_summary_mode // "") == "indexed-only"
        or (.cve_db_quality.reference_index_summary_mode // "") == "indexed-only"
      )
    )
  )
' "$TMP_DIR/status.body" >/dev/null; then
    echo "ERROR: security DB status is not usable after concurrent CVE DB observability requests" >&2
    jq . "$TMP_DIR/status.body" >&2 || cat "$TMP_DIR/status.body" >&2
    exit 1
fi
assert_request_ok "metrics"
assert_metrics_ok
assert_no_new_shared_memory_errors "$log_start_line"

echo "Concurrent request timings:"
cat "$TMP_DIR"/*.time | sort
echo "Live CVE DB concurrency verification passed"
