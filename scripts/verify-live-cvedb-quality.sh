#!/bin/bash
set -euo pipefail

# verify-live-cvedb-quality.sh - Gate a live CVE DB snapshot for quality,
# matchability, EPSS enrichment, index health, direct DB invariants, and API
# responsiveness.

API_BASE="${BONGSU_API_BASE:-http://127.0.0.1:5677}"
API_KEY="${BONGSU_API_KEY:-test-admin-key-0123456789}"
CURL_MAX_TIME="${BONGSU_VERIFY_CURL_MAX_TIME_SECONDS:-60}"
MIN_TOTAL_RECORDS="${BONGSU_VERIFY_CVEDB_MIN_TOTAL_RECORDS:-1000}"
MIN_SOURCE_COUNT="${BONGSU_VERIFY_CVEDB_MIN_SOURCE_COUNT:-3}"
MIN_MATCHABLE_RECORDS="${BONGSU_VERIFY_CVEDB_MIN_MATCHABLE_RECORDS:-1}"
MIN_AFFECTED_INDEX_COVERAGE="${BONGSU_VERIFY_CVEDB_MIN_AFFECTED_INDEX_COVERAGE:-99}"
MIN_REFERENCE_INDEX_COVERAGE="${BONGSU_VERIFY_CVEDB_MIN_REFERENCE_INDEX_COVERAGE:-99}"
MIN_EPSS_NON_EPSS_COVERAGE="${BONGSU_VERIFY_CVEDB_MIN_EPSS_NON_EPSS_COVERAGE:-50}"
MIN_REFERENCE_MULTI_SOURCE_GROUPS="${BONGSU_VERIFY_CVEDB_MIN_REFERENCE_MULTI_SOURCE_GROUPS:-1}"
MIN_REFERENCE_VENDOR_GROUPS="${BONGSU_VERIFY_CVEDB_MIN_REFERENCE_VENDOR_GROUPS:-1}"
MIN_OSV_PACKAGIST_SENTINEL_ROWS="${BONGSU_VERIFY_CVEDB_MIN_OSV_PACKAGIST_SENTINEL_ROWS:-1000}"
MIN_OSV_PACKAGIST_SENTINEL_MATCHES="${BONGSU_VERIFY_CVEDB_MIN_OSV_PACKAGIST_SENTINEL_MATCHES:-3}"
MIN_OSV_CHAINGUARD_WOLFI_SENTINEL_MATCHES="${BONGSU_VERIFY_CVEDB_MIN_OSV_CHAINGUARD_WOLFI_SENTINEL_MATCHES:-10}"
MAX_STATS_WALL_SECONDS="${BONGSU_VERIFY_CVEDB_MAX_STATS_WALL_SECONDS:-30}"
MAX_STATS_INTERNAL_MS="${BONGSU_VERIFY_CVEDB_MAX_STATS_INTERNAL_MS:-20000}"
MAX_SEARCH_WALL_SECONDS="${BONGSU_VERIFY_CVEDB_MAX_SEARCH_WALL_SECONDS:-10}"
BONGSU_DB_DSN="${BONGSU_DB_DSN:-}"
BONGSU_DB_PSQL_CONTAINER="${BONGSU_DB_PSQL_CONTAINER:-bongsu-postgres}"
BONGSU_VERIFY_CVEDB_REQUIRE_DB="${BONGSU_VERIFY_CVEDB_REQUIRE_DB:-false}"
BONGSU_VERIFY_CVEDB_REQUIRE_FRESH_SOURCES="${BONGSU_VERIFY_CVEDB_REQUIRE_FRESH_SOURCES:-false}"
BONGSU_VERIFY_CVEDB_REQUIRE_OSV_UPSTREAM_FRESHNESS="${BONGSU_VERIFY_CVEDB_REQUIRE_OSV_UPSTREAM_FRESHNESS:-false}"
BONGSU_VERIFY_CVEDB_OSV_UPSTREAM_ECOSYSTEMS="${BONGSU_VERIFY_CVEDB_OSV_UPSTREAM_ECOSYSTEMS:-Packagist,Debian,Ubuntu,npm,PyPI,Wolfi}"
BONGSU_VERIFY_CVEDB_OSV_UPSTREAM_GRACE_SECONDS="${BONGSU_VERIFY_CVEDB_OSV_UPSTREAM_GRACE_SECONDS:-3600}"
PSQL_MODE=""
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

api_get_json() {
    local path="$1"
    local out="$2"
    local time_file="$3"
    local status
    status="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$out" -w "%{http_code} %{time_total}" \
        -H "X-API-Key: ${API_KEY}" \
        "${API_BASE}${path}")"
    printf '%s\n' "$status" > "$time_file"
    local code
    code="$(awk '{print $1}' "$time_file")"
    if [[ "$code" != 2* ]]; then
        echo "ERROR: GET ${path} returned HTTP ${code}" >&2
        cat "$out" >&2 || true
        exit 1
    fi
}

elapsed_seconds() {
    awk '{print $2}' "$1"
}

assert_jq() {
    local file="$1"
    local filter="$2"
    local message="$3"
    if ! jq -e "$filter" "$file" >/dev/null; then
        echo "ERROR: ${message}" >&2
        jq . "$file" >&2 || cat "$file" >&2
        exit 1
    fi
}

assert_jq_arg() {
    local file="$1"
    local name="$2"
    local value="$3"
    local filter="$4"
    local message="$5"
    if ! jq -e --arg "$name" "$value" "$filter" "$file" >/dev/null; then
        echo "ERROR: ${message}" >&2
        jq . "$file" >&2 || cat "$file" >&2
        exit 1
    fi
}

assert_jq_numarg() {
    local file="$1"
    local name="$2"
    local value="$3"
    local filter="$4"
    local message="$5"
    if ! jq -e --argjson "$name" "$value" "$filter" "$file" >/dev/null; then
        echo "ERROR: ${message}" >&2
        jq . "$file" >&2 || cat "$file" >&2
        exit 1
    fi
}

assert_elapsed_at_most() {
    local time_file="$1"
    local max="$2"
    local label="$3"
    local elapsed
    elapsed="$(elapsed_seconds "$time_file")"
    if ! awk -v e="$elapsed" -v m="$max" 'BEGIN { exit !(e <= m) }'; then
        echo "ERROR: ${label} took ${elapsed}s, max ${max}s" >&2
        exit 1
    fi
}

db_scalar() {
    local sql="$1"
    local out
    if [ "$PSQL_MODE" = "local" ]; then
        out="$(psql "$BONGSU_DB_DSN" -X -A -t -v ON_ERROR_STOP=1 -c "$sql")"
    else
        out="$(docker exec -i "$BONGSU_DB_PSQL_CONTAINER" psql "$BONGSU_DB_DSN" -X -A -t -v ON_ERROR_STOP=1 -c "$sql")"
    fi
    printf '%s\n' "$out" | sed -n '1p'
}

discover_live_db_dsn() {
    if [ -n "$BONGSU_DB_DSN" ]; then
        return 0
    fi
    if ! command -v ss >/dev/null 2>&1; then
        return 1
    fi
    local port
    local pid
    port="$(python3 - "$API_BASE" <<'PY'
import sys
from urllib.parse import urlparse

parsed = urlparse(sys.argv[1])
if parsed.port:
    print(parsed.port)
PY
)"
    if [ -z "$port" ]; then
        return 1
    fi
    pid="$(ss -ltnp 2>/dev/null | sed -n "s/.*:${port} .*pid=\([0-9][0-9]*\).*/\1/p" | head -n1)"
    if [ -z "$pid" ] || [ ! -r "/proc/${pid}/environ" ]; then
        return 1
    fi
    BONGSU_DB_DSN="$(tr '\0' '\n' < "/proc/${pid}/environ" | sed -n 's/^BONGSU_DB_DSN=//p' | head -n1)"
    [ -n "$BONGSU_DB_DSN" ]
}

prepare_db_checks() {
    discover_live_db_dsn || true
    if [ -z "$BONGSU_DB_DSN" ]; then
        return 1
    fi
    if command -v psql >/dev/null 2>&1; then
        PSQL_MODE="local"
        return 0
    fi
    if command -v docker >/dev/null 2>&1 && docker inspect "$BONGSU_DB_PSQL_CONTAINER" >/dev/null 2>&1; then
        PSQL_MODE="docker"
        return 0
    fi
    return 1
}

assert_db_zero() {
    local sql="$1"
    local message="$2"
    local value
    value="$(db_scalar "$sql")"
    if [ "$value" != "0" ]; then
        echo "ERROR: ${message}; got ${value}, want 0" >&2
        exit 1
    fi
}

assert_db_positive() {
    local sql="$1"
    local message="$2"
    local value
    value="$(db_scalar "$sql")"
    if ! awk -v v="$value" 'BEGIN { exit !(v > 0) }'; then
        echo "ERROR: ${message}; got ${value}, want > 0" >&2
        exit 1
    fi
}

assert_db_at_least() {
    local sql="$1"
    local min="$2"
    local message="$3"
    local value
    value="$(db_scalar "$sql")"
    if ! awk -v v="$value" -v m="$min" 'BEGIN { exit !(v >= m) }'; then
        echo "ERROR: ${message}; got ${value}, want >= ${min}" >&2
        exit 1
    fi
}

assert_db_equals() {
    local sql="$1"
    local want="$2"
    local message="$3"
    local value
    value="$(db_scalar "$sql")"
    if [ "$value" != "$want" ]; then
        echo "ERROR: ${message}; got ${value}, want ${want}" >&2
        exit 1
    fi
}

http_last_modified_epoch() {
    local url="$1"
    local header_file="$2"
    curl -fsSI --max-time "$CURL_MAX_TIME" "$url" -o "$header_file"
    python3 - "$header_file" <<'PY'
import email.utils
import sys

header_file = sys.argv[1]
last_modified = ""
with open(header_file, "r", encoding="utf-8", errors="replace") as fh:
    for line in fh:
        if line.lower().startswith("last-modified:"):
            last_modified = line.split(":", 1)[1].strip()
            break
if not last_modified:
    raise SystemExit("missing Last-Modified header")
dt = email.utils.parsedate_to_datetime(last_modified)
print(int(dt.timestamp()))
PY
}

iso_to_epoch() {
    python3 - "$1" <<'PY'
from datetime import datetime, timezone
import sys

raw = (sys.argv[1] or "").strip()
if not raw or raw == "null":
    raise SystemExit("missing timestamp")
if raw.endswith("Z"):
    raw = raw[:-1] + "+00:00"
print(int(datetime.fromisoformat(raw).timestamp()))
PY
}

urlencode() {
    python3 - "$1" <<'PY'
import sys
import urllib.parse

print(urllib.parse.quote(sys.argv[1]))
PY
}

sql_literal() {
    python3 - "$1" <<'PY'
import sys

print("'" + sys.argv[1].replace("'", "''") + "'")
PY
}

assert_osv_upstream_freshness() {
    local stats_json="$1"
    local local_last_update
    local local_epoch
    local max_upstream_epoch=0
    local max_upstream_ecosystem=""
    local db_ready=false

    require_tool python3
    local_last_update="$(jq -r '.sources[]? | select(.source == "osv") | .last_update // empty' "$stats_json")"
    if [ -z "$local_last_update" ]; then
        echo "ERROR: OSV source is missing from CVE DB stats" >&2
        jq . "$stats_json" >&2
        exit 1
    fi
    local_epoch="$(iso_to_epoch "$local_last_update")"
    if prepare_db_checks; then
        db_ready=true
    fi

    IFS=',' read -ra OSV_UPSTREAM_ECOSYSTEM_ARRAY <<< "$BONGSU_VERIFY_CVEDB_OSV_UPSTREAM_ECOSYSTEMS"
    for eco in "${OSV_UPSTREAM_ECOSYSTEM_ARRAY[@]}"; do
        eco="$(echo "$eco" | xargs)"
        [ -n "$eco" ] || continue
        encoded_eco="$(urlencode "$eco")"
        header_file="$TMP_DIR/osv-upstream-${encoded_eco}.headers"
        upstream_epoch="$(http_last_modified_epoch "https://osv-vulnerabilities.storage.googleapis.com/${encoded_eco}/all.zip" "$header_file")"
        if awk -v u="$upstream_epoch" -v m="$max_upstream_epoch" 'BEGIN { exit !(u > m) }'; then
            max_upstream_epoch="$upstream_epoch"
            max_upstream_ecosystem="$eco"
        fi
        if [ "$db_ready" = "true" ]; then
            eco_literal="$(sql_literal "$eco")"
            raw_ecosystem_condition="lower(split_part(c.ecosystem, ':', 1)) = lower(${eco_literal})"
            if [ "$(printf '%s' "$eco" | tr '[:upper:]' '[:lower:]')" = "wolfi" ]; then
                raw_ecosystem_condition="(${raw_ecosystem_condition} OR lower(split_part(c.ecosystem, ':', 1)) = 'chainguard')"
            fi
            local_raw_ecosystem_count="$(db_scalar "
SELECT count(*)
FROM cve_database c
WHERE c.source = 'osv'
  AND ${raw_ecosystem_condition}")"
            if ! awk -v v="$local_raw_ecosystem_count" 'BEGIN { exit !(v > 0) }'; then
                echo "ERROR: local OSV raw source has no rows for upstream sentinel ecosystem ${eco}" >&2
                exit 1
            fi
            local_matchable_ecosystem_count="$(db_scalar "
SELECT count(*)
FROM cve_affected_packages
WHERE source = 'osv'
  AND lower(split_part(ecosystem, ':', 1)) = lower(${eco_literal})")"
            if ! awk -v v="$local_matchable_ecosystem_count" 'BEGIN { exit !(v > 0) }'; then
                echo "ERROR: local OSV affected-package index has no matchable rows for upstream sentinel ecosystem ${eco}" >&2
                exit 1
            fi
            local_ecosystem_epoch="$(db_scalar "
SELECT COALESCE(EXTRACT(EPOCH FROM max(updated_at))::bigint, 0)
FROM cve_database c
WHERE c.source = 'osv'
  AND ${raw_ecosystem_condition}")"
            if ! awk -v local="$local_ecosystem_epoch" -v upstream="$upstream_epoch" -v grace="$BONGSU_VERIFY_CVEDB_OSV_UPSTREAM_GRACE_SECONDS" 'BEGIN { exit !((local + grace) >= upstream) }'; then
                echo "ERROR: local OSV ecosystem ${eco} is older than upstream beyond grace" >&2
                echo "local_raw_ecosystem_epoch=${local_ecosystem_epoch} upstream_epoch=${upstream_epoch} grace_seconds=${BONGSU_VERIFY_CVEDB_OSV_UPSTREAM_GRACE_SECONDS}" >&2
                exit 1
            fi
        fi
    done

    if [ "$db_ready" != "true" ]; then
        if ! awk -v local="$local_epoch" -v upstream="$max_upstream_epoch" -v grace="$BONGSU_VERIFY_CVEDB_OSV_UPSTREAM_GRACE_SECONDS" 'BEGIN { exit !((local + grace) >= upstream) }'; then
            echo "ERROR: local OSV source is older than upstream sentinel ${max_upstream_ecosystem} beyond grace" >&2
            echo "local_osv_last_update=${local_last_update} local_epoch=${local_epoch}" >&2
            echo "upstream_ecosystem=${max_upstream_ecosystem} upstream_epoch=${max_upstream_epoch} grace_seconds=${BONGSU_VERIFY_CVEDB_OSV_UPSTREAM_GRACE_SECONDS}" >&2
            exit 1
        fi
    fi

    if [ "$db_ready" = "true" ]; then
        echo "OSV upstream freshness ok: newest_upstream_ecosystem=${max_upstream_ecosystem}"
        echo "OSV ecosystem-scoped freshness ok for: ${BONGSU_VERIFY_CVEDB_OSV_UPSTREAM_ECOSYSTEMS}"
    else
        echo "OSV upstream freshness ok: local=${local_last_update}, newest_upstream_ecosystem=${max_upstream_ecosystem}"
        echo "Skipping ecosystem-scoped OSV freshness; set BONGSU_DB_DSN for direct DB checks"
    fi
}

require_tool curl
require_tool jq
require_tool awk

echo "=== Bongsu Live CVE DB Quality Verification ==="
echo "API: ${API_BASE}"

echo "[1/7] Checking live CVE DB stats and quality gates"
stats_json="$TMP_DIR/stats.json"
stats_time="$TMP_DIR/stats.time"
api_get_json "/api/cve-db/stats?refresh=true" "$stats_json" "$stats_time"
assert_elapsed_at_most "$stats_time" "$MAX_STATS_WALL_SECONDS" "fresh CVE DB stats"
assert_jq_numarg "$stats_json" min "$MIN_TOTAL_RECORDS" '(.total_records // .total // 0) >= $min' "CVE DB must contain enough records for a meaningful live quality gate"
assert_jq_numarg "$stats_json" min "$MIN_SOURCE_COUNT" '(.source_count // 0) >= $min' "CVE DB must contain enough distinct sources"
assert_jq_numarg "$stats_json" min "$MIN_MATCHABLE_RECORDS" '(.total_matchable // .cve_db_quality.total_matchable // 0) >= $min' "CVE DB must contain matchable affected-package records"
assert_jq_numarg "$stats_json" max "$MAX_STATS_INTERNAL_MS" '(.durations_ms.total // 0) <= $max' "CVE DB stats internal duration is too slow"
assert_jq "$stats_json" '.cve_db_quality.status == "ok"' "CVE DB quality status must be ok"
assert_jq "$stats_json" '(.cve_db_quality.warning_count // 0) == 0' "CVE DB quality warnings must be zero"
assert_jq "$stats_json" '(.cve_db_quality.temporary_placeholders // 0) == 0' "TEMP/CVD placeholder rows must be absent"
assert_jq "$stats_json" '(.cve_db_quality.empty_vulnerability_ids // 0) == 0' "empty vulnerability IDs must be absent"

if [ "$BONGSU_VERIFY_CVEDB_REQUIRE_FRESH_SOURCES" = "true" ]; then
    freshness_json="$TMP_DIR/security-db-status.json"
    freshness_time="$TMP_DIR/security-db-status.time"
    api_get_json "/api/admin/security-db/status" "$freshness_json" "$freshness_time"
    assert_elapsed_at_most "$freshness_time" "$MAX_STATS_WALL_SECONDS" "security DB freshness status"
    assert_jq "$freshness_json" '.security_db_freshness.status == "ok"' "security DB required sources must be fresh"
    assert_jq "$freshness_json" '((.security_db_freshness.missing_sources // []) | length) == 0' "security DB required sources must not be missing"
    assert_jq "$freshness_json" '((.security_db_freshness.stale_sources // []) | length) == 0' "security DB required sources must not be stale"
fi
if [ "$BONGSU_VERIFY_CVEDB_REQUIRE_OSV_UPSTREAM_FRESHNESS" = "true" ]; then
    echo "Checking OSV upstream freshness sentinels"
    assert_osv_upstream_freshness "$stats_json"
fi

echo "[2/7] Checking affected-package and reference-key indexes"
assert_jq_numarg "$stats_json" min "$MIN_AFFECTED_INDEX_COVERAGE" '(.affected_package_index.coverage_percent // 0) >= $min' "affected-package index coverage is below threshold"
assert_jq "$stats_json" '(.affected_package_index.stale // false) == false' "affected-package index must not be stale"
assert_jq "$stats_json" '(.affected_package_index.orphans // 0) == 0' "affected-package index must not contain orphans"
assert_jq "$stats_json" '((.affected_package_index.missing_matchable_sources // []) | length) == 0' "affected-package index must cover every matchable source"
assert_jq_numarg "$stats_json" min "$MIN_REFERENCE_INDEX_COVERAGE" '(.reference_key_index.coverage_percent // 0) >= $min' "reference-key index coverage is below threshold"
assert_jq "$stats_json" '(.reference_key_index.stale // false) == false' "reference-key index must not be stale"
assert_jq "$stats_json" '(.reference_key_index.orphans // 0) == 0' "reference-key index must not contain orphans"

echo "[3/7] Checking EPSS merge coverage"
assert_jq "$stats_json" '(.epss_merge.epss_records // 0) > 0' "EPSS records must be loaded"
assert_jq "$stats_json" '(.epss_merge.enriched_records // 0) > 0' "EPSS must enrich non-EPSS advisory rows"
assert_jq_numarg "$stats_json" min "$MIN_EPSS_NON_EPSS_COVERAGE" '(.epss_merge.non_epss_coverage_percent // 0) >= $min' "EPSS non-EPSS advisory coverage is below threshold"

echo "[4/7] Checking matchable search and affected package evidence"
matchable_json="$TMP_DIR/matchable.json"
matchable_time="$TMP_DIR/matchable.time"
api_get_json "/api/cve-db/search?limit=1&matchable=true" "$matchable_json" "$matchable_time"
assert_elapsed_at_most "$matchable_time" "$MAX_SEARCH_WALL_SECONDS" "matchable CVE DB search"
assert_jq "$matchable_json" '(.total // 0) > 0 and (.items | length) > 0 and .items[0].matchable == true and (.items[0].matchable_affected_count // 0) > 0' "matchable search must return a matchable row with affected package evidence"
matchable_id="$(jq -r '.items[0].id' "$matchable_json")"
matchable_vuln="$(jq -r '.items[0].vulnerability_id' "$matchable_json")"
reference_key="$(jq -r '.items[0].reference_group_key // empty' "$matchable_json")"
affected_json="$TMP_DIR/affected.json"
affected_time="$TMP_DIR/affected.time"
api_get_json "/api/cve-db/${matchable_id}/affected-packages" "$affected_json" "$affected_time"
assert_elapsed_at_most "$affected_time" "$MAX_SEARCH_WALL_SECONDS" "affected package lookup"
assert_jq "$affected_json" '(.total // 0) > 0 and (.items[] | select((.package_name // "") != "" and (.ecosystem // "") != "" and (.fixed_version // "") != ""))' "affected package lookup must expose package/ecosystem/fixed evidence"
empty_search_json="$TMP_DIR/empty-search.json"
empty_search_time="$TMP_DIR/empty-search.time"
api_get_json "/api/cve-db/search?q=BONGSU-NO-SUCH-CVE-SEARCH-SENTINEL-000000&limit=5" "$empty_search_json" "$empty_search_time"
assert_elapsed_at_most "$empty_search_time" "$MAX_SEARCH_WALL_SECONDS" "empty CVE DB search"
assert_jq "$empty_search_json" '(.items | type) == "array" and (.total // 0) == 0' "empty CVE DB search must return an array items field"
empty_affected_json="$TMP_DIR/empty-affected.json"
empty_affected_time="$TMP_DIR/empty-affected.time"
api_get_json "/api/cve-db/BONGSU-NO-SUCH-CVE-ID-000000/affected-packages?limit=5" "$empty_affected_json" "$empty_affected_time"
assert_elapsed_at_most "$empty_affected_time" "$MAX_SEARCH_WALL_SECONDS" "empty affected package lookup"
assert_jq "$empty_affected_json" '(.items | type) == "array" and (.total // 0) == 0 and (.limit // 0) == 5 and (.offset // -1) == 0' "empty affected package lookup must return stable array and pagination fields"

echo "[5/7] Checking reference grouping and EPSS-enriched search"
if [ -n "$reference_key" ] && [ "$reference_key" != "null" ]; then
    ref_json="$TMP_DIR/reference-group.json"
    ref_time="$TMP_DIR/reference-group.time"
    api_get_json "/api/cve-db/reference-group?key=${reference_key}" "$ref_json" "$ref_time"
    assert_elapsed_at_most "$ref_time" "$MAX_SEARCH_WALL_SECONDS" "reference group lookup"
    assert_jq_arg "$ref_json" vuln "$matchable_vuln" '(.total // 0) > 0 and (.items[] | select(.vulnerability_id == $vuln))' "reference group must include the sampled matchable CVE"
    assert_jq_arg "$ref_json" key "$reference_key" '.key == $key and ((.reference_keys // []) | index($key)) and ((.sources // []) | length) > 0 and ((.source_groups // []) | length) > 0' "reference group must expose key, source buckets, and source/category/ecosystem buckets"
    assert_jq "$ref_json" '(.affected_package_total // 0) >= 0 and all(.affected_packages[]?; (.package_name // "") != "" and (.ecosystem // "") != "" and (.fixed_version // "") != "")' "reference group affected-package evidence must preserve package/ecosystem/fixed fields"
fi
epss_json="$TMP_DIR/epss-search.json"
epss_time="$TMP_DIR/epss-search.time"
api_get_json "/api/cve-db/search?limit=1&min_epss=0.000001" "$epss_json" "$epss_time"
assert_elapsed_at_most "$epss_time" "$MAX_SEARCH_WALL_SECONDS" "EPSS CVE DB search"
assert_jq "$epss_json" '(.total // 0) > 0 and (.items[] | select((.epss_score // 0) > 0 and (.source // "") != "epss"))' "EPSS search must return non-EPSS advisory rows enriched with EPSS columns"

echo "[6/7] Checking placeholder exact searches"
placeholder_json="$TMP_DIR/placeholder.json"
placeholder_time="$TMP_DIR/placeholder.time"
api_get_json "/api/cve-db/search?q=TEMP-0000000-F7A20F&limit=10" "$placeholder_json" "$placeholder_time"
assert_jq "$placeholder_json" 'all(.items[]?; ((.vulnerability_id // "") | startswith("TEMP-") or startswith("CVD-")) | not)' "TEMP/CVD placeholders must not be returned as CVE rows"

echo "[7/7] Checking direct CVE DB invariants"
if prepare_db_checks; then
    echo "Using ${PSQL_MODE} psql for direct DB checks"
    health_json="$TMP_DIR/health.json"
    health_time="$TMP_DIR/health.time"
    api_get_json "/api/health" "$health_json" "$health_time"
    health_latest_source="$(jq -r '.security_db_freshness.latest_source // ""' "$health_json")"
    health_latest_epoch="$(jq -r '(.security_db_freshness.latest_last_update // empty) | if . == "" then "" else fromdateiso8601 | tostring end' "$health_json")"
    db_latest_source="$(db_scalar "
SELECT id
FROM security_sources
WHERE id IN (SELECT DISTINCT source FROM cve_database WHERE source != '')
  AND last_sync_finished_at IS NOT NULL
ORDER BY last_sync_finished_at DESC, id
LIMIT 1")"
    db_latest_epoch="$(db_scalar "
SELECT floor(extract(epoch FROM last_sync_finished_at))::bigint
FROM security_sources
WHERE id IN (SELECT DISTINCT source FROM cve_database WHERE source != '')
  AND last_sync_finished_at IS NOT NULL
ORDER BY last_sync_finished_at DESC, id
LIMIT 1")"
    if [ "$health_latest_source" != "$db_latest_source" ] || [ "$health_latest_epoch" != "$db_latest_epoch" ]; then
        echo "ERROR: health security DB freshness must be backed by security_sources registry" >&2
        echo "health_latest_source=${health_latest_source} health_latest_epoch=${health_latest_epoch}" >&2
        echo "db_latest_source=${db_latest_source} db_latest_epoch=${db_latest_epoch}" >&2
        exit 1
    fi
    assert_db_equals "
WITH latest_deferred_osv AS (
    SELECT max(created_at) AS at
    FROM audit_logs
    WHERE action='cve_db.import'
      AND status='ok'
      AND resource_id='osv'
      AND metadata->>'finalize' = 'false'
),
latest_final_osv AS (
    SELECT max(created_at) AS at
    FROM audit_logs
    WHERE resource_id='osv'
      AND status='ok'
      AND (
        action='cve_db.prune_stale_source'
        OR (action='cve_db.import' AND COALESCE(metadata->>'finalize', 'true') != 'false')
      )
)
SELECT count(*)
FROM security_sources s, latest_deferred_osv d, latest_final_osv f
WHERE s.id='osv'
  AND d.at IS NOT NULL
  AND s.last_sync_finished_at >= date_trunc('second', d.at)
  AND (f.at IS NULL OR d.at > f.at)" "0" "OSV source registry freshness must not be promoted by deferred chunk imports"
    assert_db_zero "
WITH bad AS (
    SELECT vulnerability_id AS value FROM cve_database
    WHERE upper(trim(vulnerability_id)) LIKE 'TEMP-%'
       OR upper(trim(id)) LIKE 'TEMP-%'
       OR upper(trim(vulnerability_id)) LIKE 'CVD-%'
       OR upper(trim(id)) LIKE 'CVD-%'
    UNION ALL
    SELECT vulnerability_id AS value FROM cve_affected_packages
    WHERE upper(trim(vulnerability_id)) LIKE 'TEMP-%'
       OR upper(trim(cve_id)) LIKE 'TEMP-%'
       OR upper(trim(vulnerability_id)) LIKE 'CVD-%'
       OR upper(trim(cve_id)) LIKE 'CVD-%'
    UNION ALL
    SELECT reference_key AS value FROM cve_reference_keys
    WHERE upper(trim(reference_key)) LIKE '%TEMP-%'
       OR upper(trim(reference_key)) LIKE '%CVD-%'
)
SELECT count(*) FROM bad" "direct DB tables must not contain TEMP/CVD placeholder identifiers"
    assert_db_zero "
SELECT count(*)
FROM cve_affected_packages
WHERE trim(package_name) = ''
   OR trim(ecosystem) = ''
   OR trim(fixed_version) = ''" "affected package index rows must all have package/ecosystem/fixed evidence"
    assert_db_zero "
SELECT count(*)
FROM cve_affected_packages
WHERE trim(fixed_version) = '0'
   OR fixed_version !~ '[0-9]'
   OR fixed_version ~* '^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$'
   OR fixed_version ~* '^(?:https?|git|ssh)://'
   OR fixed_version ~* '^git\+'
   OR fixed_version ~* '^pkg:'
   OR fixed_version ~ '/'
   OR fixed_version ~* '^(?:main|master|trunk|head|latest|stable|unstable|develop|development)$'" "affected package index rows must keep version-like fixed versions only"
    assert_db_zero "
SELECT count(*)
FROM cve_affected_packages cap
WHERE NOT EXISTS (SELECT 1 FROM cve_database c WHERE c.id = cap.cve_id)" "affected package index must not contain orphan rows"
    assert_db_zero "
SELECT count(*)
FROM cve_reference_keys crk
WHERE NOT EXISTS (SELECT 1 FROM cve_database c WHERE c.id = crk.cve_id)" "reference key index must not contain orphan rows"
    assert_db_at_least "
SELECT count(*)
FROM (
    SELECT crk.reference_key
    FROM cve_reference_keys crk
    JOIN cve_database c ON c.id = crk.cve_id
    WHERE crk.reference_key LIKE 'cve:CVE-%'
      AND c.source NOT IN ('epss', 'cisa-kev')
    GROUP BY crk.reference_key
    HAVING count(DISTINCT c.source) >= 2
) grouped" "$MIN_REFERENCE_MULTI_SOURCE_GROUPS" "direct DB must contain canonical CVE reference groups that merge multiple non-priority sources"
    assert_db_at_least "
SELECT count(*)
FROM (
    SELECT cve.reference_key
    FROM cve_reference_keys cve
    JOIN cve_reference_keys related ON related.cve_id = cve.cve_id
    WHERE cve.reference_key LIKE 'cve:CVE-%'
      AND (
          related.reference_key LIKE 'vendor:%'
          OR related.reference_key LIKE 'debian:%'
          OR related.reference_key LIKE 'ubuntu:%'
          OR related.reference_key LIKE 'rhel:%'
          OR related.reference_key LIKE 'ghsa:%'
    )
    GROUP BY cve.reference_key
    HAVING count(DISTINCT related.reference_key) >= 1
) grouped" "$MIN_REFERENCE_VENDOR_GROUPS" "direct DB must materialize vendor/advisory reference keys alongside canonical CVE keys"
    assert_db_positive "
SELECT count(*)
FROM cve_database
WHERE source = 'epss'
  AND vulnerability_id != ''
  AND (epss_score > 0 OR epss_percentile > 0)" "direct DB must contain loaded EPSS source rows"
    assert_db_positive "
SELECT count(*)
FROM cve_database
WHERE source != 'epss'
  AND vulnerability_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
  AND (epss_score > 0 OR epss_percentile > 0)" "direct DB must expose EPSS as columns on non-EPSS CVE rows"
    osv_packagist_rows="$(db_scalar "
SELECT count(*)
FROM cve_database c
WHERE c.source = 'osv'
  AND (
      lower(c.ecosystem) LIKE 'packagist%'
      OR EXISTS (
          SELECT 1
          FROM jsonb_array_elements(CASE WHEN jsonb_typeof(c.affected_products) = 'array' THEN c.affected_products ELSE '[]'::jsonb END) ap
          WHERE lower(COALESCE(ap->>'ecosystem', '')) LIKE 'packagist%'
      )
  )")"
    if awk -v v="$osv_packagist_rows" -v m="$MIN_OSV_PACKAGIST_SENTINEL_ROWS" 'BEGIN { exit !(v >= m) }'; then
        assert_db_at_least "
SELECT count(*)
FROM cve_affected_packages
WHERE source = 'osv'
  AND package_name = 'phenx/php-svg-lib'
  AND ecosystem = 'packagist'
  AND fixed_version IN ('0.5.1', '0.5.2')" "$MIN_OSV_PACKAGIST_SENTINEL_MATCHES" "OSV Packagist sentinel must preserve phenx/php-svg-lib package/ecosystem/fixed evidence"
        packagist_json="$TMP_DIR/osv-packagist-sentinel.json"
        packagist_time="$TMP_DIR/osv-packagist-sentinel.time"
        api_get_json "/api/cve-db/search?q=phenx%2Fphp-svg-lib&limit=10&matchable=true" "$packagist_json" "$packagist_time"
        assert_elapsed_at_most "$packagist_time" "$MAX_SEARCH_WALL_SECONDS" "OSV Packagist sentinel search"
        assert_jq_numarg "$packagist_json" min "$MIN_OSV_PACKAGIST_SENTINEL_MATCHES" '(.total // 0) >= $min and ([.items[]? | select((.source // "") == "osv" and ((.ecosystem // "") | ascii_downcase) == "packagist" and (.matchable_affected_count // 0) > 0)] | length) >= $min' "CVE Search must return matchable phenx/php-svg-lib Packagist OSV evidence"
    fi
    assert_db_positive "
SELECT count(*)
FROM cve_database
WHERE source = 'osv'
  AND lower(ecosystem) = 'chainguard'
  AND EXISTS (
      SELECT 1
      FROM jsonb_array_elements(CASE WHEN jsonb_typeof(affected_products) = 'array' THEN affected_products ELSE '[]'::jsonb END) ap
      WHERE lower(COALESCE(ap->>'ecosystem', '')) = 'chainguard'
        AND COALESCE(ap->>'name', '') != ''
  )" "direct DB must preserve Chainguard OSV source ecosystem evidence"
    assert_db_at_least "
SELECT count(*)
FROM cve_affected_packages cap
WHERE cap.source = 'osv'
  AND lower(split_part(cap.ecosystem, ':', 1)) = 'wolfi'
  AND trim(cap.package_name) != ''
  AND trim(cap.fixed_version) != ''
  AND cap.vulnerability_id IN (
      SELECT c.vulnerability_id
      FROM cve_database c
      WHERE c.source = 'osv'
        AND lower(c.ecosystem) = 'chainguard'
        AND EXISTS (
            SELECT 1
            FROM jsonb_array_elements(CASE WHEN jsonb_typeof(c.affected_products) = 'array' THEN c.affected_products ELSE '[]'::jsonb END) ap
            WHERE lower(COALESCE(ap->>'ecosystem', '')) = 'chainguard'
              AND COALESCE(ap->>'name', '') != ''
        )
  )" "$MIN_OSV_CHAINGUARD_WOLFI_SENTINEL_MATCHES" "OSV Chainguard sentinel must preserve Wolfi package/ecosystem/fixed match evidence"
else
    if [ "$BONGSU_VERIFY_CVEDB_REQUIRE_DB" = "true" ]; then
        echo "ERROR: BONGSU_DB_DSN is required for direct CVE DB invariant checks" >&2
        exit 1
    fi
    echo "Skipping direct DB invariants; set BONGSU_DB_DSN to enable them"
fi

stats_elapsed="$(elapsed_seconds "$stats_time")"
matchable_elapsed="$(elapsed_seconds "$matchable_time")"
echo "CVE DB quality verification passed"
echo "Records: $(jq -r '(.total_records // .total // 0)' "$stats_json"), matchable: $(jq -r '(.total_matchable // .cve_db_quality.total_matchable // 0)' "$stats_json"), sources: $(jq -r '.source_count // 0' "$stats_json")"
echo "Timings: stats=${stats_elapsed}s, matchable_search=${matchable_elapsed}s"
