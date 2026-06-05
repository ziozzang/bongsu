#!/bin/bash
set -euo pipefail

# verify-release-readiness-report.sh - Verify release readiness JSON evidence
# reports without running the full expensive readiness suite.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bongsu-release-report.XXXXXX")"

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

write_file() {
    local path="$1"
    shift
    mkdir -p "$(dirname "$path")"
    printf '%s\n' "$@" >"$path"
}

write_stub_script() {
    local path="$1"
    local body="${2:-exit 0}"
    write_file "$path" "#!/bin/sh" "set -eu" "$body"
    chmod +x "$path"
}

write_tool_stubs() {
    local bin_dir="$1"
    mkdir -p "$bin_dir"
    write_stub_script "$bin_dir/git" 'case "$*" in
  "rev-parse --short=12 HEAD") echo abcdef123456 ;;
  "rev-parse --abbrev-ref HEAD") echo main ;;
  "status --short") ;;
  "status --short --branch") echo "## main" ;;
  "diff --check") ;;
  *) echo "unexpected git $*" >&2; exit 64 ;;
esac'
    write_stub_script "$bin_dir/go" 'case "$*" in
  "test ./...") ;;
  *) echo "unexpected go $*" >&2; exit 64 ;;
esac'
    write_stub_script "$bin_dir/npm" 'exit 0'
    write_stub_script "$bin_dir/docker" 'case "$*" in
  "compose -f deploy/docker-compose.yml config") ;;
  "compose -f deploy/docker-compose.airgap.yml config") ;;
  *) echo "unexpected docker $*" >&2; exit 64 ;;
esac'
    write_stub_script "$bin_dir/bash" 'if [ "${1:-}" = "-lc" ]; then
  shift
  exec /bin/bash -c "$@"
fi
exec /bin/bash "$@"'
}

prepare_release_root() {
    local target="$1"
    mkdir -p "$target/scripts" "$target/deploy"
    cp "$ROOT/scripts/verify-release-readiness.sh" "$target/scripts/"
    chmod +x "$target/scripts/verify-release-readiness.sh"
    for script in \
        verify-migrations.sh \
        verify-deploy-config.sh \
        verify-requirements-audit.sh \
        verify-operations-runbook.sh \
        verify-cve-matching-invariants.sh \
        verify-openapi.sh \
        verify-package-contents.sh \
        verify-backup-restore-archive.sh \
        verify-airgap-archive-checksum-fixtures.sh \
        verify-installer-smoke.sh \
        verify-static-binaries.sh \
        verify-release-readiness-report.sh \
        verify-live-fixture-cleanup.sh \
        verify-security-db-bundle-file-fixtures.sh \
        verify-security-db-import-helper-fixtures.sh \
        verify-security-db-export-helper-fixtures.sh \
        verify-security-db-export-freshness-fixtures.sh \
        verify-airgap-release-archive.sh \
        verify-airgap-offline-rehearsal.sh \
        verify-live-server-build.sh \
        verify-live-installer-payload.sh \
        verify-live-install-script.sh \
        verify-live-security-db-schedule.sh \
        verify-live-security-db-export-freshness.sh \
        verify-live-session-auth.sh \
        verify-live-oidc-rbac.sh \
        verify-live-trusted-identity-rbac.sh \
        verify-operator-workflow.sh \
        verify-agent-binary-workflow.sh \
        verify-live-agent-token-binding.sh \
        verify-live-scan-request-recovery.sh \
        verify-live-security-db-auto-rescan.sh \
        verify-live-retention-prune.sh \
        verify-live-cve-rematch-workflow.sh \
        verify-live-vulnerability-triage.sh \
        verify-live-report-export-rbac.sh \
        verify-live-sbom-export-rbac.sh \
        verify-live-sbom-export-workflow.sh \
        verify-live-vulnerability-export-rbac.sh \
        verify-live-cvedb-quality.sh \
        verify-live-cvedb-concurrency.sh \
        verify-live-rbac-scope.sh \
        verify-live-web-smoke.sh
    do
        write_stub_script "$target/scripts/$script"
    done
}

assert_report() {
    local report="$1"
    local filter="$2"
    local message="$3"
    if ! jq -e "$filter" "$report" >/dev/null; then
        echo "ERROR: $message" >&2
        jq . "$report" >&2 || cat "$report" >&2
        exit 1
    fi
}

run_success_case() {
    local case_dir="$TMP_DIR/success"
    local root_dir="$case_dir/root"
    local bin_dir="$case_dir/bin"
    local report="$case_dir/report.json"
    local archive="$case_dir/bongsu-release.tar.gz"
    prepare_release_root "$root_dir"
    write_tool_stubs "$bin_dir"
    printf 'fixture release archive\n' >"$archive"
    sha256sum "$archive" >"$archive.sha256"

    PATH="$bin_dir:$PATH" \
        BONGSU_RELEASE_READINESS_REPORT="$report" \
        BONGSU_RELEASE_ARCHIVE="$archive" \
        BONGSU_RELEASE_READINESS_SKIP_HEAVY=true \
        BONGSU_RELEASE_READINESS_LIVE=false \
        BONGSU_RELEASE_READINESS_REQUIRE_DB=true \
        "$root_dir/scripts/verify-release-readiness.sh" >"$case_dir/stdout.log"

    assert_report "$report" '.format_version == 1' "report must include format version"
    assert_report "$report" '.tool == "verify-release-readiness.sh"' "report must identify the release tool"
    assert_report "$report" '.status == "passed" and .exit_code == 0' "successful run must be recorded as passed"
    assert_report "$report" '.git.head == "abcdef123456" and .git.branch == "main"' "report must include git identity"
    assert_report "$report" '.options.skip_heavy == true and .options.live == false and .options.require_db == true and (.options.archive | endswith("bongsu-release.tar.gz"))' "report must include selected options"
    assert_report "$report" '.artifacts.release_archive.path == .options.archive and (.artifacts.release_archive.sha256 | test("^[0-9a-f]{64}$")) and .artifacts.release_archive.sidecar_sha256 == .artifacts.release_archive.sha256 and .artifacts.release_archive.sidecar_matches == true' "report must include verified release archive hashes"
    assert_report "$report" '.gate_count == (.gates | length) and .gate_count >= 12' "report gate count must match recorded gates"
    assert_report "$report" '.failed_gate_count == 0' "successful report must have no failed gates"
    assert_report "$report" 'all(.gates[]; .status == "passed" and (.exit_code | type) == "number")' "all success gates must pass with numeric exit codes"
    assert_report "$report" 'any(.gates[]; .kind == "exec" and .name == "go test ./...")' "report must record exec gates"
    assert_report "$report" 'any(.gates[]; .kind == "shell" and (.name | contains("docker compose -f deploy/docker-compose.yml config")))' "report must record shell gates"
    assert_report "$report" 'all(.gates[]; (.started_at | length) > 0 and (.finished_at | length) > 0 and (.duration_seconds | type) == "number")' "gates must include timestamps and durations"
}

run_live_success_case() {
    local case_dir="$TMP_DIR/live-success"
    local root_dir="$case_dir/root"
    local bin_dir="$case_dir/bin"
    local report="$case_dir/report.json"
    prepare_release_root "$root_dir"
    write_tool_stubs "$bin_dir"

    PATH="$bin_dir:$PATH" \
        BONGSU_RELEASE_READINESS_REPORT="$report" \
        BONGSU_RELEASE_READINESS_SKIP_HEAVY=true \
        BONGSU_RELEASE_READINESS_LIVE=true \
        BONGSU_RELEASE_READINESS_REQUIRE_DB=true \
        BONGSU_DB_DSN="postgres://fixture/fixture" \
        "$root_dir/scripts/verify-release-readiness.sh" >"$case_dir/stdout.log"

    assert_report "$report" '.status == "passed" and .exit_code == 0' "live successful run must be recorded as passed"
    assert_report "$report" '.options.live == true and .options.require_db == true and .options.skip_heavy == true' "live report must include live DB-backed options"
    assert_report "$report" '.gate_count == (.gates | length) and .gate_count >= 34' "live report gate count must include live release gates"
    assert_report "$report" '.failed_gate_count == 0' "live successful report must have no failed gates"
    assert_report "$report" 'any(.gates[]; .kind == "exec" and .name == "./scripts/verify-operator-workflow.sh")' "live report must record operator workflow gate"
    assert_report "$report" 'any(.gates[]; .kind == "exec" and .name == "./scripts/verify-live-retention-prune.sh")' "live report must record destructive retention safety gate"
    assert_report "$report" 'any(.gates[]; .kind == "shell" and (.name | contains("BONGSU_VERIFY_CVEDB_REQUIRE_FRESH_SOURCES=true")) and (.name | contains("BONGSU_VERIFY_CVEDB_REQUIRE_DB=true")) and (.name | contains("./scripts/verify-live-cvedb-quality.sh")))' "live report must record strict DB-backed CVE freshness gate"
    assert_report "$report" 'any(.gates[]; .kind == "exec" and .name == "./scripts/verify-live-web-smoke.sh")' "live report must record deployed web smoke gate"
}

run_failure_case() {
    local case_dir="$TMP_DIR/failure"
    local root_dir="$case_dir/root"
    local bin_dir="$case_dir/bin"
    local report="$case_dir/report.json"
    local exit_code
    prepare_release_root "$root_dir"
    write_tool_stubs "$bin_dir"
    write_stub_script "$root_dir/scripts/verify-openapi.sh" 'exit 7'

    set +e
    PATH="$bin_dir:$PATH" \
        BONGSU_RELEASE_READINESS_REPORT="$report" \
        BONGSU_RELEASE_READINESS_SKIP_HEAVY=true \
        BONGSU_RELEASE_READINESS_LIVE=false \
        BONGSU_RELEASE_READINESS_REQUIRE_DB=true \
        "$root_dir/scripts/verify-release-readiness.sh" >"$case_dir/stdout.log" 2>"$case_dir/stderr.log"
    exit_code="$?"
    set -e
    if [ "$exit_code" -ne 7 ]; then
        echo "ERROR: failing release readiness stub exited $exit_code, want 7" >&2
        cat "$case_dir/stdout.log" >&2 || true
        cat "$case_dir/stderr.log" >&2 || true
        exit 1
    fi

    assert_report "$report" '.status == "failed" and .exit_code == 7' "failed run must be recorded with the failing exit code"
    assert_report "$report" '.gate_count == (.gates | length)' "failed report gate count must match recorded gates"
    assert_report "$report" '.failed_gate_count == 1' "failed report must count one failed gate"
    assert_report "$report" 'any(.gates[]; .name == "./scripts/verify-openapi.sh" and .status == "failed" and .exit_code == 7)' "failed gate must be recorded"
    assert_report "$report" 'all(.gates[]; .name != "./scripts/verify-package-contents.sh")' "gates after the first failure must not run"
}

require_tool jq
require_tool python3

run_success_case
run_live_success_case
run_failure_case

echo "Release readiness report verification passed"
