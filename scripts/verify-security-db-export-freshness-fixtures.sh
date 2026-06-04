#!/bin/bash
set -euo pipefail

# verify-security-db-export-freshness-fixtures.sh - Exercise the security DB
# export freshness gate without a live API by feeding representative status
# payloads into verify-live-security-db-export-freshness.sh.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-live-security-db-export-freshness.sh"
TMP_DIR="$(mktemp -d)"

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: missing required tool: $1" >&2
        exit 1
    fi
}

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require_tool python3

write_status() {
    local path="$1"
    local export_status="$2"
    local freshness_status="${3:-ok}"
    local include_export="${4:-true}"
    local include_timestamps="${5:-true}"
    python3 - "$path" "$export_status" "$freshness_status" "$include_export" "$include_timestamps" <<'PY'
import json
import sys

path, export_status, freshness_status, include_export, include_timestamps = sys.argv[1:]
payload = {
    "status": "ok",
    "warnings": [],
    "recommended_actions": [],
    "security_db_freshness": {
        "status": freshness_status,
        "missing_sources": [],
        "stale_sources": [],
    },
}
if include_export == "true":
    export = {
        "status": export_status,
        "outdated_source_count": 0,
        "outdated_sources": [],
        "source_count": 5,
    }
    if include_timestamps == "true":
        export["latest_exported_at"] = "2026-06-04T18:37:00Z"
        export["latest_source_update_at"] = "2026-06-04T18:22:28Z"
    if export_status == "stale":
        export["outdated_source_count"] = 1
        export["outdated_sources"] = [{
            "source": "osv",
            "last_exported_at": "2026-06-04T17:34:55Z",
            "last_sync_finished_at": "2026-06-04T18:22:28Z",
            "lag_seconds": 2852,
        }]
    payload["security_db_export"] = export
with open(path, "w", encoding="utf-8") as out:
    json.dump(payload, out)
    out.write("\n")
PY
}

expect_pass() {
    local name="$1"
    local file="$2"
    if ! BONGSU_VERIFY_SECURITY_DB_EXPORT_STATUS_FILE="$file" "$VERIFY" >/"$TMP_DIR/${name}.out" 2>"$TMP_DIR/${name}.err"; then
        echo "ERROR: fixture ${name} should pass" >&2
        cat "$TMP_DIR/${name}.out" "$TMP_DIR/${name}.err" >&2
        exit 1
    fi
}

expect_fail() {
    local name="$1"
    local file="$2"
    local expected="$3"
    if BONGSU_VERIFY_SECURITY_DB_EXPORT_STATUS_FILE="$file" "$VERIFY" >/"$TMP_DIR/${name}.out" 2>"$TMP_DIR/${name}.err"; then
        echo "ERROR: fixture ${name} should fail" >&2
        cat "$TMP_DIR/${name}.out" "$TMP_DIR/${name}.err" >&2
        exit 1
    fi
    if ! grep -q "$expected" "$TMP_DIR/${name}.err"; then
        echo "ERROR: fixture ${name} failed without expected message: ${expected}" >&2
        cat "$TMP_DIR/${name}.out" "$TMP_DIR/${name}.err" >&2
        exit 1
    fi
}

ok="$TMP_DIR/ok.json"
stale="$TMP_DIR/stale.json"
never="$TMP_DIR/never.json"
missing="$TMP_DIR/missing.json"
missing_timestamps="$TMP_DIR/missing-timestamps.json"
stale_freshness="$TMP_DIR/stale-freshness.json"

write_status "$ok" ok ok true true
write_status "$stale" stale ok true true
write_status "$never" never ok true true
write_status "$missing" ok ok false true
write_status "$missing_timestamps" ok ok true false
write_status "$stale_freshness" ok stale true true

expect_pass ok "$ok"
expect_fail stale "$stale" "security DB export is stale"
expect_fail never "$never" "never been exported"
expect_fail missing "$missing" "security_db_export status is missing"
expect_fail missing_timestamps "$missing_timestamps" "timestamps are incomplete"
expect_fail stale_freshness "$stale_freshness" "source freshness is not ok"

echo "Security DB export freshness fixture verification passed"
