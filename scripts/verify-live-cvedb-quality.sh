#!/bin/bash
set -euo pipefail

# verify-live-cvedb-quality.sh - Gate a live CVE DB snapshot for quality,
# matchability, EPSS enrichment, index health, direct DB invariants, and API
# responsiveness.

API_BASE="${BONGSU_API_BASE:-http://127.0.0.1:5677}"
API_KEY="${BONGSU_API_KEY:-test-admin}"
CURL_MAX_TIME="${BONGSU_VERIFY_CURL_MAX_TIME_SECONDS:-60}"
MIN_TOTAL_RECORDS="${BONGSU_VERIFY_CVEDB_MIN_TOTAL_RECORDS:-1000}"
MIN_SOURCE_COUNT="${BONGSU_VERIFY_CVEDB_MIN_SOURCE_COUNT:-3}"
MIN_MATCHABLE_RECORDS="${BONGSU_VERIFY_CVEDB_MIN_MATCHABLE_RECORDS:-1}"
MIN_AFFECTED_INDEX_COVERAGE="${BONGSU_VERIFY_CVEDB_MIN_AFFECTED_INDEX_COVERAGE:-99}"
MIN_REFERENCE_INDEX_COVERAGE="${BONGSU_VERIFY_CVEDB_MIN_REFERENCE_INDEX_COVERAGE:-99}"
MIN_EPSS_NON_EPSS_COVERAGE="${BONGSU_VERIFY_CVEDB_MIN_EPSS_NON_EPSS_COVERAGE:-50}"
MAX_STATS_WALL_SECONDS="${BONGSU_VERIFY_CVEDB_MAX_STATS_WALL_SECONDS:-30}"
MAX_STATS_INTERNAL_MS="${BONGSU_VERIFY_CVEDB_MAX_STATS_INTERNAL_MS:-20000}"
MAX_SEARCH_WALL_SECONDS="${BONGSU_VERIFY_CVEDB_MAX_SEARCH_WALL_SECONDS:-10}"
BONGSU_DB_DSN="${BONGSU_DB_DSN:-}"
BONGSU_DB_PSQL_CONTAINER="${BONGSU_DB_PSQL_CONTAINER:-bongsu-postgres}"
BONGSU_VERIFY_CVEDB_REQUIRE_DB="${BONGSU_VERIFY_CVEDB_REQUIRE_DB:-false}"
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

prepare_db_checks() {
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

echo "[5/7] Checking reference grouping and EPSS-enriched search"
if [ -n "$reference_key" ] && [ "$reference_key" != "null" ]; then
    ref_json="$TMP_DIR/reference-group.json"
    ref_time="$TMP_DIR/reference-group.time"
    api_get_json "/api/cve-db/reference-group?key=${reference_key}" "$ref_json" "$ref_time"
    assert_elapsed_at_most "$ref_time" "$MAX_SEARCH_WALL_SECONDS" "reference group lookup"
    assert_jq_arg "$ref_json" vuln "$matchable_vuln" '(.total // 0) > 0 and (.items[] | select(.vulnerability_id == $vuln))' "reference group must include the sampled matchable CVE"
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
FROM cve_affected_packages cap
WHERE NOT EXISTS (SELECT 1 FROM cve_database c WHERE c.id = cap.cve_id)" "affected package index must not contain orphan rows"
    assert_db_zero "
SELECT count(*)
FROM cve_reference_keys crk
WHERE NOT EXISTS (SELECT 1 FROM cve_database c WHERE c.id = crk.cve_id)" "reference key index must not contain orphan rows"
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
