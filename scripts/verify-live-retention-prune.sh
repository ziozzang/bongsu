#!/bin/bash
set -euo pipefail

# verify-live-retention-prune.sh - Safely verify destructive operational
# retention pruning against synthetic old rows only.

API_BASE="${BONGSU_API_BASE:-http://127.0.0.1:5677}"
API_KEY="${BONGSU_API_KEY:-test-admin-key-0123456789}"
CURL_MAX_TIME="${BONGSU_VERIFY_CURL_MAX_TIME_SECONDS:-30}"
BONGSU_DB_DSN="${BONGSU_DB_DSN:-}"
BONGSU_DB_PSQL_CONTAINER="${BONGSU_DB_PSQL_CONTAINER:-bongsu-postgres}"
RETENTION_DAYS="${BONGSU_VERIFY_RETENTION_DAYS:-8000}"
RUN_ID="retention-$(date -u +%Y%m%dT%H%M%SZ)-$$"
HOST_ID="host-${RUN_ID}"
OLD_SCAN_ID=""
LATEST_SCAN_ID=""
RUNNING_SCAN_ID=""
OLD_REQUEST_ID="request-${RUN_ID}-terminal"
PENDING_REQUEST_ID="request-${RUN_ID}-pending"
OLD_AUDIT_ID="audit-${RUN_ID}-old"
PSQL_MODE=""
TMP_DIR="$(mktemp -d)"

cleanup() {
    set +e
    if [ -n "$PSQL_MODE" ]; then
        db_exec "
DELETE FROM audit_logs WHERE id = $(sql_literal "$OLD_AUDIT_ID") OR resource_id = $(sql_literal "$HOST_ID") OR metadata::text LIKE $(sql_literal "%${RUN_ID}%");
DELETE FROM scan_requests WHERE id IN ($(sql_literal "$OLD_REQUEST_ID"), $(sql_literal "$PENDING_REQUEST_ID")) OR host_id = $(sql_literal "$HOST_ID");
DELETE FROM hosts WHERE id = $(sql_literal "$HOST_ID");
" >/dev/null 2>&1 || true
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

discover_db_dsn() {
    if [ -n "$BONGSU_DB_DSN" ]; then
        return
    fi
    local pid
    for pid in $(pgrep -f 'bongsu-server|cmd/server' 2>/dev/null || true); do
        if [ -r "/proc/${pid}/environ" ]; then
            BONGSU_DB_DSN="$(tr '\0' '\n' <"/proc/${pid}/environ" | sed -n 's/^BONGSU_DB_DSN=//p' | head -n1)"
            if [ -n "$BONGSU_DB_DSN" ]; then
                return
            fi
        fi
    done
}

prepare_db_checks() {
    discover_db_dsn
    if [ -z "$BONGSU_DB_DSN" ]; then
        echo "ERROR: BONGSU_DB_DSN is required for live retention prune verification" >&2
        exit 1
    fi
    if command -v psql >/dev/null 2>&1; then
        PSQL_MODE="local"
        return
    fi
    if command -v docker >/dev/null 2>&1 && docker inspect "$BONGSU_DB_PSQL_CONTAINER" >/dev/null 2>&1; then
        PSQL_MODE="docker"
        return
    fi
    echo "ERROR: neither local psql nor docker container ${BONGSU_DB_PSQL_CONTAINER} is available" >&2
    exit 1
}

db_scalar() {
    local sql="$1"
    if [ "$PSQL_MODE" = "local" ]; then
        psql "$BONGSU_DB_DSN" -X -A -t -v ON_ERROR_STOP=1 -c "$sql"
    else
        docker exec -i "$BONGSU_DB_PSQL_CONTAINER" psql "$BONGSU_DB_DSN" -X -A -t -v ON_ERROR_STOP=1 -c "$sql"
    fi
}

db_exec() {
    db_scalar "$1" >/dev/null
}

sql_literal() {
    python3 - "$1" <<'PY'
import sys
print("'" + sys.argv[1].replace("'", "''") + "'")
PY
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

assert_db_count() {
    local sql="$1"
    local expected="$2"
    local message="$3"
    local got
    got="$(db_scalar "$sql" | tr -d '[:space:]')"
    if [ "$got" != "$expected" ]; then
        echo "ERROR: ${message}: expected ${expected}, got ${got}" >&2
        exit 1
    fi
}

insert_fixture() {
    OLD_SCAN_ID="$(new_uuid)"
    LATEST_SCAN_ID="$(new_uuid)"
    RUNNING_SCAN_ID="$(new_uuid)"
    db_exec "
INSERT INTO hosts (id, hostname, ip_address, os_name, os_version, kernel, arch, cpu_model, cpu_cores, memory_mb, agent_version, api_key_hash, created_at, updated_at, last_seen)
VALUES ($(sql_literal "$HOST_ID"), $(sql_literal "$HOST_ID"), '127.0.0.1', 'Ubuntu', '22.04', 'retention-verifier', 'amd64', 'verifier', 1, 512, 'retention-verifier', 'fixture', now(), now(), now());

INSERT INTO scans (id, host_id, scan_type, status, started_at, finished_at, created_at)
VALUES
  ($(sql_literal "$OLD_SCAN_ID"), $(sql_literal "$HOST_ID"), 'manual', 'completed', '2001-01-02T00:00:00Z', '2001-01-02T00:01:00Z', '2001-01-02T00:00:00Z'),
  ($(sql_literal "$RUNNING_SCAN_ID"), $(sql_literal "$HOST_ID"), 'manual', 'running', '2001-01-03T00:00:00Z', NULL, '2001-01-03T00:00:00Z'),
  ($(sql_literal "$LATEST_SCAN_ID"), $(sql_literal "$HOST_ID"), 'manual', 'completed', now(), now(), now());

INSERT INTO packages (id, scan_id, host_id, source, name, version, pkg_type, ecosystem, asset_type, asset_id, target)
VALUES
  ($(sql_literal "pkg-${RUN_ID}-old"), $(sql_literal "$OLD_SCAN_ID"), $(sql_literal "$HOST_ID"), 'fixture', 'bongsu-retention-old', '1.0.0', 'npm', 'npm', 'host', $(sql_literal "$HOST_ID"), 'old-lock.json'),
  ($(sql_literal "pkg-${RUN_ID}-running"), $(sql_literal "$RUNNING_SCAN_ID"), $(sql_literal "$HOST_ID"), 'fixture', 'bongsu-retention-running', '1.0.0', 'npm', 'npm', 'host', $(sql_literal "$HOST_ID"), 'running-lock.json'),
  ($(sql_literal "pkg-${RUN_ID}-latest"), $(sql_literal "$LATEST_SCAN_ID"), $(sql_literal "$HOST_ID"), 'fixture', 'bongsu-retention-latest', '2.0.0', 'npm', 'npm', 'host', $(sql_literal "$HOST_ID"), 'latest-lock.json');

INSERT INTO vulnerabilities (id, package_id, scan_id, host_id, vulnerability_id, severity, title, pkg_name, installed_version, fixed_version, cvss_score, finding_source)
VALUES ($(sql_literal "vuln-${RUN_ID}-old"), $(sql_literal "pkg-${RUN_ID}-old"), $(sql_literal "$OLD_SCAN_ID"), $(sql_literal "$HOST_ID"), 'BONGSU-RETENTION-OLD', 'HIGH', 'retention fixture', 'bongsu-retention-old', '1.0.0', '1.0.1', 7.1, 'scanner');

INSERT INTO container_assets (id, scan_id, host_id, runtime, container_id, name, image_name, image_id, state)
VALUES ($(sql_literal "container-${RUN_ID}-old"), $(sql_literal "$OLD_SCAN_ID"), $(sql_literal "$HOST_ID"), 'docker', $(sql_literal "container-${RUN_ID}"), 'retention-fixture', 'example/retention:old', 'sha256:retention', 'exited');

INSERT INTO user_accounts (id, scan_id, host_id, username, uid, gid, home_dir, shell)
VALUES ($(sql_literal "user-${RUN_ID}-old"), $(sql_literal "$OLD_SCAN_ID"), $(sql_literal "$HOST_ID"), 'retention-user', 2001, 2001, '/home/retention', '/bin/sh');

INSERT INTO process_snapshots (id, scan_id, host_id, pid, name, cmdline, user_name, cpu_usage, mem_usage)
VALUES ($(sql_literal "process-${RUN_ID}-old"), $(sql_literal "$OLD_SCAN_ID"), $(sql_literal "$HOST_ID"), 2001, 'retention-process', 'retention-process --fixture', 'retention-user', 0.1, 0.2);

INSERT INTO port_info (id, scan_id, host_id, name, port, protocol, address, pid)
VALUES ($(sql_literal "port-${RUN_ID}-old"), $(sql_literal "$OLD_SCAN_ID"), $(sql_literal "$HOST_ID"), 'retention-port', 2001, 'tcp', '127.0.0.1', 2001);

INSERT INTO scan_requests (id, host_id, requested_by, scan_type, packages_only, reason, status, completed_at, created_at)
VALUES
  ($(sql_literal "$OLD_REQUEST_ID"), $(sql_literal "$HOST_ID"), 'retention-verifier', 'manual', true, 'terminal old fixture', 'completed', '2001-01-04T00:01:00Z', '2001-01-04T00:00:00Z'),
  ($(sql_literal "$PENDING_REQUEST_ID"), $(sql_literal "$HOST_ID"), 'retention-verifier', 'manual', true, 'pending old fixture', 'pending', NULL, '2001-01-04T00:00:00Z');

INSERT INTO audit_logs (id, actor_type, actor_id, action, resource_type, resource_id, status, metadata, created_at)
VALUES ($(sql_literal "$OLD_AUDIT_ID"), 'system', 'retention-verifier', 'retention.fixture.old', 'host', $(sql_literal "$HOST_ID"), 'ok', jsonb_build_object('run_id', $(sql_literal "$RUN_ID")), '2001-01-05T00:00:00Z');
"
}

assert_no_non_fixture_targets() {
    local cutoff
    cutoff="$(date -u -d "${RETENTION_DAYS} days ago" +%Y-%m-%dT%H:%M:%SZ)"
    assert_db_count "
WITH old_scans AS (
    SELECT id FROM scans
    WHERE created_at < $(sql_literal "$cutoff")
      AND status IN ('completed','degraded','failed')
      AND id NOT IN (SELECT DISTINCT ON (host_id) id FROM scans WHERE status IN ('completed','degraded') ORDER BY host_id, created_at DESC)
)
SELECT count(*) FROM old_scans os JOIN scans s ON s.id = os.id WHERE s.host_id <> $(sql_literal "$HOST_ID");
" "0" "destructive retention verifier refuses to prune non-fixture scans older than cutoff"
    assert_db_count "
SELECT count(*) FROM scan_requests
WHERE created_at < $(sql_literal "$cutoff")
  AND status IN ('completed','degraded','failed','cancelled')
  AND id <> $(sql_literal "$OLD_REQUEST_ID");
" "0" "destructive retention verifier refuses to prune non-fixture scan requests older than cutoff"
    assert_db_count "
SELECT count(*) FROM audit_logs
WHERE created_at < $(sql_literal "$cutoff")
  AND id <> $(sql_literal "$OLD_AUDIT_ID");
" "0" "destructive retention verifier refuses to prune non-fixture audit logs older than cutoff"
}

require_tool curl
require_tool jq
require_tool python3
prepare_db_checks

echo "=== Bongsu Live Retention Prune Verification ==="
echo "API:  ${API_BASE}"
echo "Host: ${HOST_ID}"
echo "Retention days: ${RETENTION_DAYS}"

echo "[1/5] Checking API readiness"
curl -fsS --max-time "$CURL_MAX_TIME" "${API_BASE}/api/ready" | jq -e '.status == "ready"' >/dev/null

echo "[2/5] Creating old retention fixture rows"
insert_fixture
assert_no_non_fixture_targets

echo "[3/5] Verifying dry-run blast-radius counters"
body="$(jq -nc --argjson days "$RETENTION_DAYS" '{dry_run:true, scan_days:$days, request_days:$days, audit_days:$days}')"
dry_json="$(api_json POST /api/admin/retention/prune "$body")"
assert_json "$dry_json" '.dry_run == true and .scans == 1 and .packages == 1 and .vulnerabilities == 1 and .containers == 1 and .users == 1 and .processes == 1 and .ports == 1 and .scan_requests == 1 and .audit_logs == 1' "retention dry-run must report exact fixture-only blast radius"

echo "[4/5] Executing destructive prune against fixture-only cutoff"
body="$(jq -nc --argjson days "$RETENTION_DAYS" '{dry_run:false, scan_days:$days, request_days:$days, audit_days:$days}')"
prune_json="$(api_json POST /api/admin/retention/prune "$body")"
assert_json "$prune_json" '.dry_run == false and .scans == 1 and .packages == 1 and .vulnerabilities == 1 and .containers == 1 and .users == 1 and .processes == 1 and .ports == 1 and .scan_requests == 1 and .audit_logs == 1' "retention prune must delete exact fixture-only blast radius"

echo "[5/5] Verifying prune effects and audit evidence"
assert_db_count "SELECT count(*) FROM scans WHERE id = $(sql_literal "$OLD_SCAN_ID");" "0" "old terminal scan must be pruned"
assert_db_count "SELECT count(*) FROM packages WHERE id = $(sql_literal "pkg-${RUN_ID}-old");" "0" "old scan package must be pruned"
assert_db_count "SELECT count(*) FROM vulnerabilities WHERE id = $(sql_literal "vuln-${RUN_ID}-old");" "0" "old scan vulnerability must be pruned"
assert_db_count "SELECT count(*) FROM container_assets WHERE id = $(sql_literal "container-${RUN_ID}-old");" "0" "old scan container asset must be pruned"
assert_db_count "SELECT count(*) FROM user_accounts WHERE id = $(sql_literal "user-${RUN_ID}-old");" "0" "old scan user inventory must be pruned"
assert_db_count "SELECT count(*) FROM process_snapshots WHERE id = $(sql_literal "process-${RUN_ID}-old");" "0" "old scan process inventory must be pruned"
assert_db_count "SELECT count(*) FROM port_info WHERE id = $(sql_literal "port-${RUN_ID}-old");" "0" "old scan port inventory must be pruned"
assert_db_count "SELECT count(*) FROM scan_requests WHERE id = $(sql_literal "$OLD_REQUEST_ID");" "0" "old terminal scan request must be pruned"
assert_db_count "SELECT count(*) FROM audit_logs WHERE id = $(sql_literal "$OLD_AUDIT_ID");" "0" "old audit log must be pruned"
assert_db_count "SELECT count(*) FROM scans WHERE id = $(sql_literal "$LATEST_SCAN_ID");" "1" "latest usable scan must be preserved"
assert_db_count "SELECT count(*) FROM packages WHERE id = $(sql_literal "pkg-${RUN_ID}-latest");" "1" "latest inventory package must be preserved"
assert_db_count "SELECT count(*) FROM scans WHERE id = $(sql_literal "$RUNNING_SCAN_ID");" "1" "old running scan must not be pruned"
assert_db_count "SELECT count(*) FROM packages WHERE id = $(sql_literal "pkg-${RUN_ID}-running");" "1" "old running scan package must not be pruned"
assert_db_count "SELECT count(*) FROM scan_requests WHERE id = $(sql_literal "$PENDING_REQUEST_ID");" "1" "old pending scan request must not be pruned"

audit_json="$(api_json GET '/api/admin/audit-logs?action=retention.prune&status=pruned&limit=10')"
assert_json "$audit_json" '.items[] | select(.action == "retention.prune" and .status == "pruned" and .metadata.dry_run == false and .metadata.scans == 1 and .metadata.packages == 1 and .metadata.vulnerabilities == 1 and .metadata.scan_requests == 1 and .metadata.audit_logs == 1)' "destructive retention prune must be audited with blast-radius metadata"

echo "Live retention prune verification passed"
