#!/bin/bash
# sync-all-cvedb.sh — Download from all CVE sources and import into Bongsu
# Sources: CISA KEV, FIRST EPSS, OSV.dev (all ecosystems), NVD, Trivy DB
# Usage: ./sync-all-cvedb.sh [server_url] [api_key]
# Environment: NVD_API_KEY for higher NVD rate limits (optional)

set -euo pipefail

SERVER_URL="${1:-http://localhost:5677}"
API_KEY="${2:-${BONGSU_API_KEY:-}}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TMP_PARENT="${BONGSU_TMPDIR:-${TMPDIR:-/tmp}}"
mkdir -p "${TMP_PARENT}"
TMPDIR="$(mktemp -d "${TMP_PARENT%/}/bongsu-cvedb-sync.XXXXXX")"
trap 'rm -rf "${TMPDIR}"' EXIT

if [ -z "${API_KEY}" ]; then
    echo "ERROR: API key required. Usage: $0 [server_url] [api_key]"
    echo "   or: BONGSU_API_KEY=xxx $0"
    exit 1
fi

IMPORT_URL="${SERVER_URL}/api/admin/cve-db/import"
RECALCULATE_URL="${SERVER_URL}/api/admin/security-db/recalculate"
AFFECTED_INDEX_REBUILD_URL="${SERVER_URL}/api/admin/cve-db/affected-index/rebuild"
REFERENCE_INDEX_REBUILD_URL="${SERVER_URL}/api/admin/cve-db/reference-index/rebuild"
REFRESH_SOURCE_STATUS_URL="${SERVER_URL}/api/admin/cve-db/source"
INDEX_REBUILD_WAIT_SECONDS="${BONGSU_CVE_INDEX_REBUILD_WAIT_SECONDS:-900}"
INDEX_REBUILD_POLL_SECONDS="${BONGSU_CVE_INDEX_REBUILD_POLL_SECONDS:-5}"
INDEX_REBUILD_MIN_SERVER_TIMEOUT_SECONDS="${BONGSU_CVE_INDEX_REBUILD_MIN_SERVER_TIMEOUT_SECONDS:-600}"
BONGSU_OSV_POST_SYNC_VERIFY="${BONGSU_OSV_POST_SYNC_VERIFY:-true}"
WATERMARK_URL_BASE="${SERVER_URL}/api/admin/cve-db/source"

# --- Incremental sync configuration ---
# By default the sync is INCREMENTAL: each source is fetched only from its stored
# watermark (newest modified_date already ingested) minus an overlap window. A
# periodic FULL sync re-pulls everything and prunes upstream deletions, since the
# incremental path detects additions/updates but not removals.
SYNC_OVERLAP_HOURS="${BONGSU_SYNC_OVERLAP_HOURS:-48}"
FULL_SYNC_INTERVAL_DAYS="${BONGSU_SYNC_FULL_INTERVAL_DAYS:-7}"
# Persist the marker under TMP_PARENT (the durable parent dir), NOT ${TMPDIR},
# which was reassigned above to a per-run mktemp dir that the EXIT trap deletes —
# storing it there would make every run a full sync.
FULL_SYNC_MARKER="${BONGSU_SYNC_FULL_MARKER:-${TMP_PARENT%/}/.bongsu-last-full-sync}"

# get_watermark <source> -> prints the source's RFC3339 watermark (empty if none).
get_watermark() {
    local source="$1"
    local resp
    if ! resp=$(curl -fsS -H "X-API-Key: ${API_KEY}" "${WATERMARK_URL_BASE}/${source}/watermark" 2>/dev/null); then
        echo ""
        return 0
    fi
    echo "${resp}" | python3 -c '
import json, sys
try:
    print((json.load(sys.stdin).get("watermark") or "").strip())
except Exception:
    print("")
' 2>/dev/null || echo ""
}

# since_for <source> -> watermark minus overlap, as RFC3339 UTC (empty => full).
# An empty result tells the caller to fall back to a full download for that source.
since_for() {
    local source="$1"
    local wm
    wm="$(get_watermark "${source}")"
    if [ -z "${wm}" ]; then
        echo ""
        return 0
    fi
    OVERLAP_HOURS="${SYNC_OVERLAP_HOURS}" WM="${wm}" python3 -c '
import os, sys, datetime as dt
wm = os.environ["WM"].strip()
if wm.endswith("Z"):
    wm = wm[:-1] + "+00:00"
try:
    t = dt.datetime.fromisoformat(wm).astimezone(dt.timezone.utc)
except Exception:
    print("")
    sys.exit(0)
overlap = float(os.environ.get("OVERLAP_HOURS") or "0")
t = t - dt.timedelta(hours=overlap)
print(t.strftime("%Y-%m-%dT%H:%M:%SZ"))
' 2>/dev/null || echo ""
}

# Decide sync mode. FULL when forced, when no marker exists yet, or when the last
# full sync is older than the configured interval.
determine_sync_mode() {
    if [ "${BONGSU_SYNC_FULL:-0}" = "1" ] || [ "${BONGSU_SYNC_FULL:-}" = "true" ]; then
        echo "full"
        return 0
    fi
    if [ ! -f "${FULL_SYNC_MARKER}" ]; then
        echo "full"
        return 0
    fi
    local marker_epoch now_epoch age_days
    # File mtime, portably: GNU `stat -c`, BSD `stat -f`, else a Python fallback.
    marker_epoch="$(stat -c %Y "${FULL_SYNC_MARKER}" 2>/dev/null \
        || stat -f %m "${FULL_SYNC_MARKER}" 2>/dev/null \
        || python3 -c 'import os,sys; print(int(os.path.getmtime(sys.argv[1])))' "${FULL_SYNC_MARKER}" 2>/dev/null \
        || echo 0)"
    now_epoch="$(date +%s)"
    age_days=$(( (now_epoch - marker_epoch) / 86400 ))
    if [ "${marker_epoch}" -eq 0 ] || [ "${age_days}" -ge "${FULL_SYNC_INTERVAL_DAYS}" ]; then
        echo "full"
    else
        echo "incremental"
    fi
}

TOTAL_IMPORTED=0
FAILED_SOURCES=()
# Sources imported with finalize=false; their registry freshness is refreshed in
# the single deferred finalization pass at the end of the sync.
DEFERRED_SOURCES=()
REQUIRE_TRIVY_SOURCE="${BONGSU_SYNC_REQUIRE_TRIVY_SOURCE:-true}"
TRIVY_BIN_FOR_SYNC="${TRIVY_BIN:-${BONGSU_TRIVY_PATH:-}}"

preflight_index_rebuild_timeouts() {
    local response_file
    local affected_timeout
    local reference_timeout
    response_file="${TMPDIR}/security-db-status-preflight.json"
    if ! curl -fsS -H "X-API-Key: ${API_KEY}" "${SERVER_URL}/api/admin/security-db/status" > "${response_file}"; then
        echo "ERROR: failed to check server CVE index rebuild timeout settings" >&2
        return 1
    fi
    IFS='|' read -r affected_timeout reference_timeout < <(python3 -c '
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    print("0|0")
    sys.exit(0)
print("|".join([
    str((data.get("cve_affected_index") or {}).get("timeout_seconds") or 0),
    str((data.get("cve_reference_index") or {}).get("timeout_seconds") or 0),
]))
' "${response_file}")
    if [ "${affected_timeout}" -lt "${INDEX_REBUILD_MIN_SERVER_TIMEOUT_SECONDS}" ] || [ "${reference_timeout}" -lt "${INDEX_REBUILD_MIN_SERVER_TIMEOUT_SECONDS}" ]; then
        echo "ERROR: server CVE index rebuild timeout is too low for production-sized CVE sync" >&2
        echo "affected_timeout_seconds=${affected_timeout} reference_timeout_seconds=${reference_timeout} required_min_seconds=${INDEX_REBUILD_MIN_SERVER_TIMEOUT_SECONDS}" >&2
        echo "Increase BONGSU_CVE_AFFECTED_INDEX_REBUILD_TIMEOUT_SECONDS and BONGSU_CVE_REFERENCE_INDEX_REBUILD_TIMEOUT_SECONDS, then restart the API." >&2
        return 1
    fi
}

find_trivy_binary() {
    if [ -n "${TRIVY_BIN_FOR_SYNC}" ] && [ -x "${TRIVY_BIN_FOR_SYNC}" ]; then
        return 0
    fi
    if command -v trivy &>/dev/null; then
        TRIVY_BIN_FOR_SYNC="$(command -v trivy)"
        return 0
    fi
    for candidate in \
        /opt/bongsu/bin/trivy \
        "${SCRIPT_DIR}/../bin/trivy" \
        "${SCRIPT_DIR}/trivy" \
        "${PWD}/trivy"; do
        if [ -x "${candidate}" ]; then
            TRIVY_BIN_FOR_SYNC="${candidate}"
            return 0
        fi
    done
    return 1
}

import_cve_file() {
    local file="$1"
    local source="$2"
    local replace="${3:-true}"
    local finalize="${4:-true}"
    local result

    if ! result=$(curl -fsS -X POST -H "X-API-Key: ${API_KEY}" \
        -F "file=@${file}" -F "source=${source}" -F "replace=${replace}" -F "finalize=${finalize}" "${IMPORT_URL}"); then
        echo "ERROR: ${source} import request failed" >&2
        return 1
    fi

    echo "${result}" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception as exc:
    print(f"invalid import response: {exc}", file=sys.stderr)
    sys.exit(2)
if data.get("status") != "ok":
    print(f"import response was not ok: {data}", file=sys.stderr)
    sys.exit(3)
print(int(data.get("imported", 0)))
'
}

queue_index_rebuild() {
    local label="$1"
    local url="$2"
    local field="$3"
    local response_file
    local http_code
    local deadline
    local running
    local status
    local duration_ms
    local indexed
    local error_msg

    response_file="${TMPDIR}/rebuild-${field}.json"
    http_code="$(curl -sS -o "${response_file}" -w "%{http_code}" -X POST -H "X-API-Key: ${API_KEY}" "${url}?async=true")"
    if [ "${http_code}" != "202" ] && [ "${http_code}" != "409" ]; then
        echo "ERROR: ${label} rebuild queue request failed with HTTP ${http_code}" >&2
        cat "${response_file}" >&2 || true
        return 1
    fi

    status="$(python3 -c '
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as exc:
    print(f"invalid rebuild response: {exc}", file=sys.stderr)
    sys.exit(2)
print(data.get("status", ""))
' "${response_file}")"
    echo "  ${label} rebuild ${status}."

    deadline=$(( $(date +%s) + INDEX_REBUILD_WAIT_SECONDS ))
    local empty_status_polls=0
    while true; do
        # fresh=true bypasses the server's short-TTL health cache so a just-queued
        # rebuild is never misread as not-running from a stale cached snapshot.
        if ! curl -fsS -H "X-API-Key: ${API_KEY}" "${SERVER_URL}/api/health?fresh=true" > "${response_file}"; then
            echo "ERROR: failed to poll ${label} rebuild status" >&2
            return 1
        fi
        IFS='|' read -r running status duration_ms indexed error_msg < <(python3 -c '
import json, sys
field = sys.argv[2]
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as exc:
    print(f"false|error|0|0|invalid health response: {exc}")
    sys.exit(0)
state = data.get(field) or {}
last = state.get("last_result") or {}
print("|".join([
    "true" if state.get("running") else "false",
    str(last.get("status") or ""),
    str(state.get("duration_ms") or last.get("duration_ms") or 0),
    str(last.get("indexed") or 0),
    str(last.get("error") or ""),
]))
' "${response_file}" "${field}")
        if [ "${running}" = "false" ]; then
            if [ "${status}" = "ok" ]; then
                echo "  ${label} rebuild complete: indexed=${indexed}, duration_ms=${duration_ms}"
                return 0
            fi
            # running=false with no recorded result yet means the async job has
            # not registered its state; tolerate a few polls before failing so a
            # startup race (no prior last_result) is not misreported as an error.
            if [ -z "${status}" ] && [ "${empty_status_polls}" -lt 6 ] && [ "$(date +%s)" -lt "${deadline}" ]; then
                empty_status_polls=$((empty_status_polls + 1))
                echo "  ${label} rebuild status not yet registered (poll ${empty_status_polls})..."
                sleep "${INDEX_REBUILD_POLL_SECONDS}"
                continue
            fi
            echo "ERROR: ${label} rebuild finished with status '${status:-unknown}' ${error_msg}" >&2
            return 1
        fi
        empty_status_polls=0
        if [ "$(date +%s)" -ge "${deadline}" ]; then
            echo "ERROR: timed out waiting for ${label} rebuild after ${INDEX_REBUILD_WAIT_SECONDS}s" >&2
            return 1
        fi
        echo "  ${label} rebuild running for ${duration_ms}ms..."
        sleep "${INDEX_REBUILD_POLL_SECONDS}"
    done
}

finalize_deferred_cve_imports() {
    # Single finalization pass run AFTER every source has been imported with
    # finalize=false. Deferring finalization to one pass avoids the recalc
    # storm (one full-DB security recalculation per finalize=true import, each
    # up to 2h of RematchCVEs) and, critically, prevents a background recalc
    # from running concurrently with the next source's import transaction —
    # the race that produced the cve_database deadlocks (SQLSTATE 40P01).
    #
    # Args: <reason> [source ...]  — sources whose registry freshness should be
    # refreshed (those imported with finalize=false skip the inline refresh).
    local reason="$1"
    shift || true
    # Each step is checked explicitly with `|| return $?` so a failed index
    # rebuild or status refresh is not masked by a later successful curl (the
    # function runs with errexit disabled because callers invoke it as `if !`).
    echo "  Rebuilding affected package index after deferred imports..."
    queue_index_rebuild "Affected package index" "${AFFECTED_INDEX_REBUILD_URL}" "cve_affected_index_rebuild" || return $?
    echo "  Rebuilding reference key index after deferred imports..."
    queue_index_rebuild "Reference key index" "${REFERENCE_INDEX_REBUILD_URL}" "cve_reference_index_rebuild" || return $?
    local source
    for source in "$@"; do
        [ -n "${source}" ] || continue
        echo "  Refreshing ${source} source registry status after deferred imports..."
        curl -fsS -X POST -H "X-API-Key: ${API_KEY}" \
            "${REFRESH_SOURCE_STATUS_URL}/${source}/refresh-status" >/dev/null || return $?
    done
    echo "  Queuing security recalculation after deferred imports..."
    curl -fsS -X POST -H "X-API-Key: ${API_KEY}" \
        -H "Content-Type: application/json" \
        -d "{\"reason\":\"${reason}\"}" "${RECALCULATE_URL}" >/dev/null || return $?
}

verify_osv_post_sync_freshness() {
    if [ "${BONGSU_OSV_POST_SYNC_VERIFY}" != "true" ]; then
        echo "  Skipping post-sync OSV upstream freshness verification because BONGSU_OSV_POST_SYNC_VERIFY=${BONGSU_OSV_POST_SYNC_VERIFY}."
        return 0
    fi
    if [ "${OSV_PRUNE_FULL_SOURCE}" != "true" ] && [ -z "${BONGSU_DB_DSN:-}" ]; then
        echo "  Skipping post-sync OSV upstream freshness verification for partial OSV sync without BONGSU_DB_DSN."
        echo "  Set BONGSU_DB_DSN to verify selected ecosystems without promoting aggregate OSV freshness."
        return 0
    fi
    echo "  Verifying post-sync OSV upstream freshness..."
    BONGSU_API_BASE="${SERVER_URL}" \
        BONGSU_API_KEY="${API_KEY}" \
        BONGSU_VERIFY_CVEDB_REQUIRE_OSV_UPSTREAM_FRESHNESS=true \
        BONGSU_VERIFY_CVEDB_OSV_UPSTREAM_ECOSYSTEMS="${OSV_ECOSYSTEMS}" \
        "${SCRIPT_DIR}/verify-live-cvedb-quality.sh"
}

SYNC_MODE="$(determine_sync_mode)"

echo "=========================================="
echo " Bongsu CVE Database Sync"
echo " Server: ${SERVER_URL}"
echo " Mode:   ${SYNC_MODE} (overlap ${SYNC_OVERLAP_HOURS}h, full every ${FULL_SYNC_INTERVAL_DAYS}d)"
echo "=========================================="
echo ""
preflight_index_rebuild_timeouts

# --- 1. CISA KEV ---
echo "[1/4] Downloading CISA KEV data..."
CISA_KEV_FILE="${TMPDIR}/cisa-kev.jsonl"
# Tolerate a download failure so already-deferred sources still get finalized at
# the end (a bare command would abort the whole script under set -e).
if ! "${SCRIPT_DIR}/download-cisa-kev.sh" "${CISA_KEV_FILE}"; then
    echo "  ERROR: CISA KEV download failed"
fi

if [ -s "${CISA_KEV_FILE}" ]; then
    # CISA KEV is always imported in full (~2MB / ~1600 rows, ~1s). It is NOT
    # skipped in incremental mode: the source freshness is derived from the newest
    # row's updated_at, so a full re-import (replace=true) keeps KEV freshness
    # green. Skipping it would save nothing meaningful and would let KEV age out.
    echo "  Importing CISA KEV data ($(wc -l < "${CISA_KEV_FILE}") entries, $(du -h "${CISA_KEV_FILE}" | cut -f1))..."
    if IMPORTED=$(import_cve_file "${CISA_KEV_FILE}" "cisa-kev" "true" "false"); then
        echo "  Imported/updated: ${IMPORTED}"
        TOTAL_IMPORTED=$((TOTAL_IMPORTED + IMPORTED))
        DEFERRED_SOURCES+=("cisa-kev")
    else
        echo "  ERROR: CISA KEV import failed"
        FAILED_SOURCES+=("cisa-kev:import")
    fi
else
    echo "  ERROR: no CISA KEV data"
    FAILED_SOURCES+=("cisa-kev:no-data")
fi
echo ""

# --- 2. FIRST EPSS ---
echo "[2/5] Downloading FIRST EPSS data..."
EPSS_FILE="${TMPDIR}/epss.jsonl"
# EPSS is a full daily snapshot (no delta API) where modified_date == the score
# date. Incremental: if we already hold today's UTC date, skip download+import
# outright; otherwise download and skip only the import when the fetched date is
# not newer than what we already have (e.g. today's file isn't published yet).
EPSS_WM_DATE="$(get_watermark epss | cut -dT -f1)"
EPSS_TODAY="$(date -u +%Y-%m-%d)"
EPSS_SKIP=0
if [ "${SYNC_MODE}" = "incremental" ] && [ -n "${EPSS_WM_DATE}" ] && [ "${EPSS_WM_DATE}" = "${EPSS_TODAY}" ]; then
    echo "  EPSS already current for ${EPSS_TODAY} — skipping download and import."
    EPSS_SKIP=1
fi
if [ "${EPSS_SKIP}" -eq 0 ]; then
    # Tolerate a download failure so already-deferred sources still get finalized.
    if ! "${SCRIPT_DIR}/download-epss.sh" "${EPSS_FILE}"; then
        echo "  ERROR: EPSS download failed"
    fi
    if [ -s "${EPSS_FILE}" ]; then
        EPSS_FILE_DATE="$(head -1 "${EPSS_FILE}" | python3 -c 'import json,sys;print((json.load(sys.stdin).get("modified_date") or "")[:10])' 2>/dev/null || echo "")"
        if [ "${SYNC_MODE}" = "incremental" ] && [ -n "${EPSS_WM_DATE}" ] && [ -n "${EPSS_FILE_DATE}" ] && [[ ! "${EPSS_FILE_DATE}" > "${EPSS_WM_DATE}" ]]; then
            echo "  EPSS fetched date ${EPSS_FILE_DATE} is not newer than ${EPSS_WM_DATE} — skipping import."
        else
            echo "  Importing EPSS data ($(wc -l < "${EPSS_FILE}") entries, $(du -h "${EPSS_FILE}" | cut -f1))..."
            if IMPORTED=$(import_cve_file "${EPSS_FILE}" "epss" "true" "false"); then
                echo "  Imported/updated: ${IMPORTED}"
                TOTAL_IMPORTED=$((TOTAL_IMPORTED + IMPORTED))
                DEFERRED_SOURCES+=("epss")
            else
                echo "  ERROR: EPSS import failed"
                FAILED_SOURCES+=("epss:import")
            fi
        fi
    else
        echo "  ERROR: no EPSS data"
        FAILED_SOURCES+=("epss:no-data")
    fi
fi
echo ""

# --- 3. OSV.dev (per-ecosystem to avoid upload timeouts) ---
DEFAULT_OSV_ECOSYSTEMS="PyPI,npm,Go,Maven,crates.io,NuGet,RubyGems,Packagist,Hex,Pub,SwiftURL,Hackage,CRAN,opam,VSCode,GitHub Actions,Alpine,Debian,Ubuntu,SUSE,openSUSE,AlmaLinux,Red Hat,Rocky Linux,Azure Linux,Wolfi,Chainguard,openEuler,Mageia,Android"
OSV_ECOSYSTEMS="${BONGSU_OSV_ECOSYSTEMS:-${DEFAULT_OSV_ECOSYSTEMS}}"
OSV_TOTAL=0
OSV_FAILED=0
OSV_PRUNE_BEFORE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
OSV_PRUNE_FULL_SOURCE="true"
if [ -n "${BONGSU_OSV_ECOSYSTEMS:-}" ] && [ "$(echo "${BONGSU_OSV_ECOSYSTEMS}" | tr -d '[:space:]')" != "$(echo "${DEFAULT_OSV_ECOSYSTEMS}" | tr -d '[:space:]')" ]; then
    OSV_PRUNE_FULL_SOURCE="false"
fi
ECO_COUNT=$(echo "${OSV_ECOSYSTEMS}" | tr ',' '\n' | wc -l)
ECO_IDX=0
# Incremental: a single global OSV watermark (newest modified across all
# ecosystems) minus overlap. download-osv.sh then writes only entries modified at
# or after it. Empty for a full sync (or when OSV has no rows yet).
OSV_SINCE=""
if [ "${SYNC_MODE}" = "incremental" ]; then
    OSV_SINCE="$(since_for osv)"
fi
if [ -n "${OSV_SINCE}" ]; then
    echo "[3/5] Downloading OSV.dev data (${ECO_COUNT} ecosystems, incremental since ${OSV_SINCE})..."
else
    echo "[3/5] Downloading OSV.dev data (${ECO_COUNT} ecosystems, full)..."
fi

IFS=',' read -ra ECO_ARRAY <<< "${OSV_ECOSYSTEMS}"
for eco in "${ECO_ARRAY[@]}"; do
    ECO_IDX=$((ECO_IDX + 1))
    OSV_ECO_FILE="${TMPDIR}/osv-${eco}.jsonl"
    echo "  [${ECO_IDX}/${ECO_COUNT}] ${eco}..."
    if ! "${SCRIPT_DIR}/download-osv.sh" "${OSV_ECO_FILE}" "${eco}" "${OSV_SINCE}"; then
        echo "    ERROR: ${eco} download failed"
        FAILED_SOURCES+=("osv:${eco}")
        OSV_FAILED=1
        continue
    fi
    if [ -s "${OSV_ECO_FILE}" ]; then
        ECO_LINES=$(wc -l < "${OSV_ECO_FILE}")
        ECO_SIZE=$(du -h "${OSV_ECO_FILE}" | cut -f1)
        echo "    Importing ${eco} (${ECO_LINES} entries, ${ECO_SIZE})..."
        if IMPORTED=$(import_cve_file "${OSV_ECO_FILE}" "osv" "false" "false"); then
            echo "    Imported/updated: ${IMPORTED}"
            OSV_TOTAL=$((OSV_TOTAL + IMPORTED))
        else
            echo "    ERROR: ${eco} import failed"
            FAILED_SOURCES+=("osv:${eco}:import")
            OSV_FAILED=1
        fi
        rm -f "${OSV_ECO_FILE}"
    else
        echo "    SKIP: ${eco} produced no data"
    fi
done

TOTAL_IMPORTED=$((TOTAL_IMPORTED + OSV_TOTAL))
if [ "${OSV_TOTAL}" -gt 0 ]; then
    # Prune is FULL-only: it deletes any OSV row not refreshed this run, which is
    # correct only when every ecosystem was fully re-imported. In incremental mode
    # we imported just the delta, so pruning would wrongly delete unchanged rows.
    if [ "${SYNC_MODE}" = "full" ] && [ "${OSV_FAILED}" -eq 0 ] && [ "${OSV_PRUNE_FULL_SOURCE}" = "true" ]; then
        echo "  Pruning stale OSV rows older than ${OSV_PRUNE_BEFORE}..."
        # finalize=false: defer the recalc to the single finalization pass so the
        # prune does not start a background recalc that would race later imports.
        if ! curl -fsS -X POST -H "X-API-Key: ${API_KEY}" \
            "${SERVER_URL}/api/admin/cve-db/source/osv/prune-stale?before=${OSV_PRUNE_BEFORE}&finalize=false" >/dev/null; then
            echo "  ERROR: OSV stale prune failed"
            FAILED_SOURCES+=("osv:prune")
        fi
    elif [ "${SYNC_MODE}" = "full" ] && [ "${OSV_FAILED}" -eq 0 ]; then
        echo "  Skipping stale OSV prune because BONGSU_OSV_ECOSYSTEMS is a partial override."
        echo "  Run a full OSV sync with the default ecosystem list to prune upstream removals safely."
        echo "  Keeping aggregate OSV source freshness unchanged after partial sync."
    fi
    # Defer OSV freshness refresh and the heavy index rebuild / recalculation to
    # the single finalization pass at the end of the whole sync (after NVD and
    # Trivy), so the recalc runs exactly once and never overlaps a later import.
    if [ "${OSV_FAILED}" -eq 0 ] && [ "${OSV_PRUNE_FULL_SOURCE}" = "true" ]; then
        DEFERRED_SOURCES+=("osv")
    fi
fi
if [ "${OSV_FAILED}" -ne 0 ]; then
    echo "  ERROR: incomplete OSV download"
    FAILED_SOURCES+=("osv:partial")
elif [ "${OSV_TOTAL}" -eq 0 ] && [ "${SYNC_MODE}" = "full" ]; then
    echo "  ERROR: no OSV data"
    FAILED_SOURCES+=("osv:no-data")
elif [ "${OSV_TOTAL}" -eq 0 ]; then
    echo "  OSV unchanged since watermark — no delta imported."
fi
echo ""

# --- 4. NVD ---
echo "[4/5] Downloading NVD data..."
CURRENT_YEAR="$(date +%Y)"
NVD_YEAR_WINDOW="${BONGSU_NVD_YEAR_WINDOW:-3}"
NVD_YEARS="${BONGSU_NVD_YEARS:-}"
if [ -z "${NVD_YEARS}" ]; then
    NVD_YEARS="$(seq -s, $((CURRENT_YEAR - NVD_YEAR_WINDOW)) "${CURRENT_YEAR}")"
fi
NVD_FAILED=0
NVD_TOTAL=0
NVD_FILE="${TMPDIR}/nvd.jsonl"
# Incremental: fetch only CVEs modified since the watermark (NVD lastModStartDate)
# and UPSERT them (replace=false). Full: re-pull the whole year window and replace
# the source (replace=true). When there is no watermark yet, since_for is empty
# and download-nvd.sh falls back to the full year window automatically.
NVD_SINCE=""
NVD_REPLACE="true"
if [ "${SYNC_MODE}" = "incremental" ]; then
    NVD_SINCE="$(since_for nvd)"
    if [ -n "${NVD_SINCE}" ]; then
        NVD_REPLACE="false"
        echo "  Incremental since ${NVD_SINCE}..."
    else
        echo "  No NVD watermark yet — full year window ${NVD_YEARS}..."
    fi
else
    echo "  Years ${NVD_YEARS}..."
fi
if ! "${SCRIPT_DIR}/download-nvd.sh" "${NVD_FILE}" "${NVD_YEARS}" "${NVD_SINCE}"; then
    echo "    ERROR: NVD download failed"
    FAILED_SOURCES+=("nvd:download")
    NVD_FAILED=1
elif [ -s "${NVD_FILE}" ]; then
    NVD_LINES=$(wc -l < "${NVD_FILE}")
    NVD_SIZE=$(du -h "${NVD_FILE}" | cut -f1)
    echo "    Importing NVD (${NVD_LINES} entries, ${NVD_SIZE}, replace=${NVD_REPLACE})..."
    if IMPORTED=$(import_cve_file "${NVD_FILE}" "nvd" "${NVD_REPLACE}" "false"); then
        echo "    Imported/updated: ${IMPORTED}"
        NVD_TOTAL=$((NVD_TOTAL + IMPORTED))
        DEFERRED_SOURCES+=("nvd")
    else
        echo "    ERROR: NVD import failed"
        FAILED_SOURCES+=("nvd:import")
        NVD_FAILED=1
    fi
    rm -f "${NVD_FILE}"
elif [ -n "${NVD_SINCE}" ]; then
    echo "    NVD unchanged since ${NVD_SINCE} — no delta imported."
else
    echo "    ERROR: NVD produced no data"
    FAILED_SOURCES+=("nvd:no-data")
    NVD_FAILED=1
fi

TOTAL_IMPORTED=$((TOTAL_IMPORTED + NVD_TOTAL))
if [ "${NVD_FAILED}" -ne 0 ]; then
    echo "  ERROR: incomplete NVD download; preserving existing nvd source"
elif [ "${NVD_TOTAL}" -eq 0 ] && [ -z "${NVD_SINCE}" ]; then
    echo "  ERROR: no NVD data"
    FAILED_SOURCES+=("nvd:no-data")
fi
echo ""

# --- 5. Trivy DB ---
echo "[5/5] Extracting Trivy DB CVE data..."
TRIVY_FILE="${TMPDIR}/trivy-cve.jsonl"
TRIVY_FAILED=0
if find_trivy_binary; then
    if ! TRIVY_BIN="${TRIVY_BIN_FOR_SYNC}" "${SCRIPT_DIR}/extract-trivy-cvedb.sh" "${TRIVY_FILE}"; then
        echo "  ERROR: trivy extraction failed"
        FAILED_SOURCES+=("trivy:extract")
        TRIVY_FAILED=1
    fi

    if [ -s "${TRIVY_FILE}" ]; then
        echo "  Importing Trivy CVEs ($(wc -l < "${TRIVY_FILE}") entries)..."
        if IMPORTED=$(import_cve_file "${TRIVY_FILE}" "trivy" "true" "false"); then
            echo "  Imported/updated: ${IMPORTED}"
            TOTAL_IMPORTED=$((TOTAL_IMPORTED + IMPORTED))
            DEFERRED_SOURCES+=("trivy")
        else
            echo "  ERROR: Trivy import failed"
            FAILED_SOURCES+=("trivy:import")
            TRIVY_FAILED=1
        fi
    elif [ "${TRIVY_FAILED}" -eq 0 ]; then
        echo "  ERROR: no Trivy CVE data"
        FAILED_SOURCES+=("trivy:no-data")
    fi
else
    if [ "${REQUIRE_TRIVY_SOURCE}" = "true" ]; then
        echo "  ERROR: trivy not installed"
        FAILED_SOURCES+=("trivy:not-installed")
    else
        echo "  SKIP: trivy not installed"
    fi
fi
echo ""

# --- Single deferred finalization pass ---
# Every source above was imported with finalize=false so no per-source background
# recalculation could run concurrently with a later import (the cve_database
# deadlock source). Rebuild the affected/reference indexes, refresh source
# freshness, and run exactly one security recalculation now that all writes are
# committed.
if [ "${#DEFERRED_SOURCES[@]}" -gt 0 ]; then
    echo "[finalize] Finalizing deferred imports for: ${DEFERRED_SOURCES[*]}"
    if ! finalize_deferred_cve_imports "full cvedb sync" "${DEFERRED_SOURCES[@]}"; then
        echo "  ERROR: deferred import finalization failed" >&2
        FAILED_SOURCES+=("finalize")
    fi
    echo ""
fi

# --- Summary ---
echo "=========================================="
echo " Sync Complete"
echo " Total imported/updated: ${TOTAL_IMPORTED}"
echo ""

if [ "${#FAILED_SOURCES[@]}" -gt 0 ]; then
    echo "ERROR: source sync incomplete: ${FAILED_SOURCES[*]}" >&2
    exit 1
fi

if [ "${OSV_TOTAL}" -gt 0 ]; then
    verify_osv_post_sync_freshness
fi

# Record a successful FULL sync AFTER post-sync verification passes, so a failed
# verification (which aborts under set -e) does not advance the marker. Incremental
# runs never advance it, so a full sync (with its upstream-deletion prune) always
# happens at least every FULL_SYNC_INTERVAL_DAYS.
if [ "${SYNC_MODE}" = "full" ]; then
    if : > "${FULL_SYNC_MARKER}" 2>/dev/null; then
        echo " Recorded successful full sync marker: ${FULL_SYNC_MARKER}"
    else
        echo " WARNING: could not write full sync marker ${FULL_SYNC_MARKER}; next run may repeat full sync" >&2
    fi
fi

# Show DB stats
STATS=$(curl -fsS -H "X-API-Key: ${API_KEY}" "${SERVER_URL}/api/cve-db/stats")
echo " Current DB stats:"
echo "${STATS}" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for s in data.get('sources', []):
        print(f'  {s[\"source\"].upper():12s} {s[\"count\"]:>8,} records  (last: {s[\"last_update\"][:19] if s.get(\"last_update\") else \"N/A\"})')
except:
    print('  (unable to parse stats)')
"
echo "=========================================="
