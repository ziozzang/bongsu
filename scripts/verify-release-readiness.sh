#!/bin/bash
set -euo pipefail

# verify-release-readiness.sh - Run Bongsu release/handoff readiness gates.
#
# Default mode runs non-live gates that should be safe on CI and developer
# machines. Set BONGSU_RELEASE_READINESS_LIVE=true to include live API/web
# verifiers. Set BONGSU_RELEASE_ARCHIVE=<bongsu-*.tar.gz> to validate an
# already generated release archive and rehearse the packaged airgap flow.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIVE="${BONGSU_RELEASE_READINESS_LIVE:-false}"
ALLOW_DIRTY="${BONGSU_RELEASE_READINESS_ALLOW_DIRTY:-false}"
SKIP_HEAVY="${BONGSU_RELEASE_READINESS_SKIP_HEAVY:-false}"
REQUIRE_DB="${BONGSU_RELEASE_READINESS_REQUIRE_DB:-true}"
ARCHIVE="${BONGSU_RELEASE_ARCHIVE:-}"
REPORT_PATH="${BONGSU_RELEASE_READINESS_REPORT:-}"
REPORT_EVENTS=""
REPORT_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
REPORT_STARTED_UNIX="$(date +%s)"
REPORT_FINALIZED="false"

init_report() {
    if [ -z "$REPORT_PATH" ]; then
        return
    fi
    require_tool python3
    mkdir -p "$(dirname "$REPORT_PATH")"
    REPORT_EVENTS="$(mktemp "${TMPDIR:-/tmp}/bongsu-release-readiness-events.XXXXXX")"
    : >"$REPORT_EVENTS"
}

record_gate() {
    if [ -z "$REPORT_PATH" ]; then
        return
    fi
    local name="$1"
    local kind="$2"
    local status="$3"
    local exit_code="$4"
    local started_at="$5"
    local finished_at="$6"
    local duration_seconds="$7"
    python3 - "$REPORT_EVENTS" "$name" "$kind" "$status" "$exit_code" "$started_at" "$finished_at" "$duration_seconds" <<'PY'
import json
import sys

path, name, kind, status, exit_code, started_at, finished_at, duration_seconds = sys.argv[1:]
with open(path, "a", encoding="utf-8") as out:
    out.write(json.dumps({
        "name": name,
        "kind": kind,
        "status": status,
        "exit_code": int(exit_code),
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": int(duration_seconds),
    }, separators=(",", ":")) + "\n")
PY
}

write_report() {
    if [ -z "$REPORT_PATH" ] || [ "$REPORT_FINALIZED" = "true" ]; then
        return
    fi
    local exit_code="$1"
    local finished_at
    local finished_unix
    local git_head
    local git_branch
    local report_status
    finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    finished_unix="$(date +%s)"
    git_head="$(git rev-parse --short=12 HEAD 2>/dev/null || true)"
    git_branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
    if [ "$exit_code" -eq 0 ]; then
        report_status="passed"
    else
        report_status="failed"
    fi
    python3 - "$REPORT_PATH" "$REPORT_EVENTS" "$report_status" "$exit_code" "$ROOT" "$git_head" "$git_branch" "$LIVE" "$SKIP_HEAVY" "$REQUIRE_DB" "$ALLOW_DIRTY" "$ARCHIVE" "$REPORT_STARTED_AT" "$finished_at" "$REPORT_STARTED_UNIX" "$finished_unix" <<'PY'
import json
import os
import sys

(
    report_path,
    events_path,
    status,
    exit_code,
    root,
    git_head,
    git_branch,
    live,
    skip_heavy,
    require_db,
    allow_dirty,
    archive,
    started_at,
    finished_at,
    started_unix,
    finished_unix,
) = sys.argv[1:]

gates = []
if events_path:
    try:
        with open(events_path, "r", encoding="utf-8") as src:
            gates = [json.loads(line) for line in src if line.strip()]
    except FileNotFoundError:
        gates = []

report = {
    "format_version": 1,
    "tool": "verify-release-readiness.sh",
    "status": status,
    "exit_code": int(exit_code),
    "root": root,
    "git": {
        "head": git_head,
        "branch": git_branch,
    },
    "options": {
        "live": live == "true",
        "skip_heavy": skip_heavy == "true",
        "require_db": require_db == "true",
        "allow_dirty": allow_dirty == "true",
        "archive": archive,
    },
    "started_at": started_at,
    "finished_at": finished_at,
    "duration_seconds": int(finished_unix) - int(started_unix),
    "gate_count": len(gates),
    "failed_gate_count": sum(1 for gate in gates if gate.get("status") != "passed"),
    "gates": gates,
}

tmp_path = report_path + ".tmp"
with open(tmp_path, "w", encoding="utf-8") as out:
    json.dump(report, out, indent=2, sort_keys=True)
    out.write("\n")
os.replace(tmp_path, report_path)
PY
    REPORT_FINALIZED="true"
    rm -f "$REPORT_EVENTS"
}

on_exit() {
    local exit_code="$?"
    write_report "$exit_code"
}
trap on_exit EXIT

run() {
    echo ""
    echo ">>> $*"
    local started_at started_unix finished_at finished_unix exit_code status
    started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    started_unix="$(date +%s)"
    set +e
    "$@"
    exit_code="$?"
    set -e
    finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    finished_unix="$(date +%s)"
    if [ "$exit_code" -eq 0 ]; then
        status="passed"
    else
        status="failed"
    fi
    record_gate "$*" "exec" "$status" "$exit_code" "$started_at" "$finished_at" "$((finished_unix - started_unix))"
    if [ "$exit_code" -ne 0 ]; then
        exit "$exit_code"
    fi
}

run_shell() {
    echo ""
    echo ">>> $*"
    local started_at started_unix finished_at finished_unix exit_code status
    started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    started_unix="$(date +%s)"
    set +e
    bash -lc "$*"
    exit_code="$?"
    set -e
    finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    finished_unix="$(date +%s)"
    if [ "$exit_code" -eq 0 ]; then
        status="passed"
    else
        status="failed"
    fi
    record_gate "$*" "shell" "$status" "$exit_code" "$started_at" "$finished_at" "$((finished_unix - started_unix))"
    if [ "$exit_code" -ne 0 ]; then
        exit "$exit_code"
    fi
}

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: missing required tool: $1" >&2
        exit 1
    fi
}

cd "$ROOT"

require_tool git
require_tool go
require_tool npm
require_tool docker
init_report

echo "=== Bongsu Release Readiness Verification ==="
echo "Root:       $ROOT"
echo "Live gates: $LIVE"
if [ "$LIVE" = "true" ]; then
    echo "Live DB invariant gate: $REQUIRE_DB"
fi
if [ -n "$REPORT_PATH" ]; then
    echo "Report:     $REPORT_PATH"
fi

if [ "$ALLOW_DIRTY" != "true" ] && [ -n "$(git status --short)" ]; then
    echo "ERROR: working tree is dirty; commit, stash, or set BONGSU_RELEASE_READINESS_ALLOW_DIRTY=true" >&2
    git status --short >&2
    exit 1
fi

run git status --short --branch
run go test ./...
run ./scripts/verify-migrations.sh
run_shell "env -u BONGSU_DB_PASSWORD -u BONGSU_API_KEY -u BONGSU_AGENT_API_KEY -u BONGSU_INSTALL_TOKEN ./scripts/verify-deploy-config.sh"
run ./scripts/verify-requirements-audit.sh
run ./scripts/verify-operations-runbook.sh
run ./scripts/verify-cve-matching-invariants.sh
run ./scripts/verify-openapi.sh
run ./scripts/verify-package-contents.sh
run ./scripts/verify-backup-restore-archive.sh
run ./scripts/verify-installer-smoke.sh
run ./scripts/verify-static-binaries.sh

if [ "$SKIP_HEAVY" != "true" ]; then
    run npm --prefix web run build
    run npm --prefix web run test:e2e
    run ./scripts/verify-airgap-package-smoke.sh
else
    echo ""
    echo "Skipping heavy web/package gates because BONGSU_RELEASE_READINESS_SKIP_HEAVY=true"
fi

run_shell "BONGSU_DB_PASSWORD=release-db-password-0123456789 BONGSU_API_KEY=release-admin-secret-0123456789 BONGSU_AGENT_API_KEY=release-agent-secret-0123456789 BONGSU_INSTALL_TOKEN=release-install-secret-0123456789 docker compose -f deploy/docker-compose.yml config >/tmp/bongsu-compose.yml"
run_shell "BONGSU_DB_PASSWORD=release-db-password-0123456789 BONGSU_API_KEY=release-admin-secret-0123456789 BONGSU_AGENT_API_KEY=release-agent-secret-0123456789 BONGSU_INSTALL_TOKEN=release-install-secret-0123456789 docker compose -f deploy/docker-compose.airgap.yml config >/tmp/bongsu-compose-airgap.yml"

if [ -n "$ARCHIVE" ]; then
    run ./scripts/verify-airgap-release-archive.sh "$ARCHIVE"
    run ./scripts/verify-airgap-offline-rehearsal.sh "$ARCHIVE"
fi

if [ "$LIVE" = "true" ]; then
    if [ "$REQUIRE_DB" = "true" ] && [ -z "${BONGSU_DB_DSN:-}" ]; then
        echo "ERROR: BONGSU_DB_DSN is required for live release readiness; set BONGSU_RELEASE_READINESS_REQUIRE_DB=false only for non-release smoke runs" >&2
        exit 1
    fi
    run ./scripts/verify-live-server-build.sh
    run ./scripts/verify-live-installer-payload.sh
    run ./scripts/verify-live-security-db-schedule.sh
    run ./scripts/verify-operator-workflow.sh
    run ./scripts/verify-agent-binary-workflow.sh
    run ./scripts/verify-live-agent-token-binding.sh
    run_shell "BONGSU_VERIFY_CVEDB_REQUIRE_FRESH_SOURCES=true BONGSU_VERIFY_CVEDB_REQUIRE_OSV_UPSTREAM_FRESHNESS=true BONGSU_VERIFY_CVEDB_REQUIRE_DB=${REQUIRE_DB} ./scripts/verify-live-cvedb-quality.sh"
    run ./scripts/verify-live-rbac-scope.sh
    run ./scripts/verify-live-web-smoke.sh
fi

run git diff --check

echo ""
echo "Release readiness verification passed"
