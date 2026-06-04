#!/bin/bash
set -euo pipefail

# verify-live-security-db-schedule.sh - Gate the live security DB sync cadence.
# It verifies that the scheduler uses the persisted CVE DB freshness timestamp
# as its baseline after process restarts, so API restarts cannot silently delay
# the required 6-hour source refresh.

API_BASE="${BONGSU_API_BASE:-http://127.0.0.1:5677}"
API_KEY="${BONGSU_API_KEY:-test-admin-key-0123456789}"
CURL_MAX_TIME="${BONGSU_VERIFY_CURL_MAX_TIME_SECONDS:-30}"
GRACE_SECONDS="${BONGSU_VERIFY_SECURITY_DB_SCHEDULE_GRACE_SECONDS:-300}"
REQUIRE_CONFIGURED="${BONGSU_VERIFY_SECURITY_DB_SCHEDULE_REQUIRE_CONFIGURED:-true}"
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

require_tool curl
require_tool jq
require_tool python3

HEALTH_JSON="$TMP_DIR/health.json"
HTTP_STATUS="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$HEALTH_JSON" -w "%{http_code}" \
    -H "X-API-Key: ${API_KEY}" \
    "${API_BASE}/api/health")"
if [[ "$HTTP_STATUS" != 2* ]]; then
    echo "ERROR: /api/health returned HTTP ${HTTP_STATUS}" >&2
    cat "$HEALTH_JSON" >&2 || true
    exit 1
fi

python3 - "$HEALTH_JSON" "$GRACE_SECONDS" "$REQUIRE_CONFIGURED" <<'PY'
from __future__ import annotations

from datetime import datetime, timezone
import json
import re
import sys

path, grace_raw, require_configured_raw = sys.argv[1:]
grace = int(grace_raw)
require_configured = require_configured_raw.lower() == "true"

with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)

security_db = data.get("security_db") or {}
freshness = data.get("security_db_freshness") or {}

def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    print(json.dumps({
        "security_db": security_db,
        "security_db_freshness": freshness,
    }, indent=2, sort_keys=True), file=sys.stderr)
    raise SystemExit(1)

def parse_time(raw: object, field: str) -> datetime | None:
    if raw is None:
        return None
    text = str(raw).strip()
    if not text or text.startswith("0001-01-01"):
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        value = datetime.fromisoformat(text)
    except ValueError as exc:
        fail(f"{field} is not an ISO timestamp: {raw!r}: {exc}")
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)

def parse_go_duration(raw: object) -> float:
    text = str(raw or "").strip()
    if not text:
        fail("security_db.interval is empty")
    total = 0.0
    pos = 0
    for match in re.finditer(r"([0-9]+(?:\.[0-9]+)?)(ms|us|µs|ns|h|m|s)", text):
        if match.start() != pos:
            fail(f"unsupported security_db.interval format: {text!r}")
        amount = float(match.group(1))
        unit = match.group(2)
        if unit == "h":
            total += amount * 3600
        elif unit == "m":
            total += amount * 60
        elif unit == "s":
            total += amount
        elif unit == "ms":
            total += amount / 1000
        elif unit in {"us", "µs"}:
            total += amount / 1_000_000
        elif unit == "ns":
            total += amount / 1_000_000_000
        pos = match.end()
    if pos != len(text) or total <= 0:
        fail(f"unsupported security_db.interval format: {text!r}")
    return total

if require_configured and security_db.get("configured") is not True:
    fail("security DB sync manager is not configured")

freshness_status = str(freshness.get("status", "")).strip().lower()
if freshness_status != "ok":
    fail(f"security DB freshness is not ok: {freshness_status or '(missing)'}")

persisted = parse_time(
    security_db.get("persisted_latest_update") or freshness.get("latest_last_update"),
    "persisted_latest_update",
)
last_sync = parse_time(security_db.get("last_sync"), "last_sync")
next_sync = parse_time(security_db.get("next_sync"), "next_sync")
if persisted is None:
    fail("persisted latest CVE DB update timestamp is missing")
if next_sync is None:
    fail("next security DB sync timestamp is missing")

interval_seconds = parse_go_duration(security_db.get("interval"))
base = persisted
if last_sync is not None and last_sync > base:
    base = last_sync
expected_latest = base.timestamp() + interval_seconds + grace
if next_sync.timestamp() > expected_latest:
    fail(
        "next security DB sync is later than persisted/latest sync baseline "
        f"plus interval and grace: next={next_sync.isoformat()}, "
        f"base={base.isoformat()}, interval_seconds={interval_seconds}, grace={grace}"
    )

now = datetime.now(timezone.utc)
if next_sync.timestamp() < now.timestamp() - grace:
    fail(f"next security DB sync is stale in the past: next={next_sync.isoformat()}, now={now.isoformat()}")

print("Security DB schedule verification passed")
print(f"Baseline: {base.isoformat()}")
print(f"Interval seconds: {interval_seconds:g}")
print(f"Next sync: {next_sync.isoformat()}")
PY
