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

run() {
    echo ""
    echo ">>> $*"
    "$@"
}

run_shell() {
    echo ""
    echo ">>> $*"
    bash -lc "$*"
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

echo "=== Bongsu Release Readiness Verification ==="
echo "Root:       $ROOT"
echo "Live gates: $LIVE"
if [ "$LIVE" = "true" ]; then
    echo "Live DB invariant gate: $REQUIRE_DB"
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
