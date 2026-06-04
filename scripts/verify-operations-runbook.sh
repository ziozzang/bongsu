#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUNBOOK="$ROOT/docs/operations-runbook.md"
ARCH="$ROOT/docs/architecture.md"
AUDIT="$ROOT/docs/requirements-audit.md"
RELEASE="$ROOT/scripts/verify-release-readiness.sh"
PACKAGE="$ROOT/scripts/package.sh"
CONNECTED_COMPOSE="$ROOT/deploy/docker-compose.yml"
AIRGAP_COMPOSE="$ROOT/deploy/docker-compose.airgap.yml"

require_file() {
    if [ ! -f "$1" ]; then
        echo "ERROR: required file missing: $1" >&2
        exit 1
    fi
}

require_text() {
    local file="$1"
    local pattern="$2"
    local message="$3"
    if ! grep -Eq "$pattern" "$file"; then
        echo "ERROR: $message" >&2
        echo "Missing pattern: $pattern in $file" >&2
        exit 1
    fi
}

reject_text() {
    local file="$1"
    local pattern="$2"
    local message="$3"
    if grep -Eq "$pattern" "$file"; then
        echo "ERROR: $message" >&2
        echo "Forbidden pattern: $pattern in $file" >&2
        exit 1
    fi
}

for file in "$RUNBOOK" "$ARCH" "$AUDIT" "$RELEASE" "$PACKAGE" "$CONNECTED_COMPOSE" "$AIRGAP_COMPOSE"; do
    require_file "$file"
done

for pattern in \
    'API listens on `5677`' \
    'web UI listens on `5678`' \
    'Caddy or any external reverse proxy is managed outside Bongsu' \
    'BONGSU_ALLOW_WEAK_SECRETS=false' \
    'BONGSU_WEB_AUTH=true' \
    'BONGSU_AGENT_HOST_BINDING=true' \
    '\./scripts/verify-release-readiness\.sh' \
    'BONGSU_RELEASE_READINESS_LIVE=true' \
    'BONGSU_RELEASE_READINESS_REQUIRE_DB=false' \
    'BONGSU_RELEASE_ARCHIVE=bongsu-0\.1\.0\.tar\.gz' \
    '\./scripts/verify-operations-runbook\.sh' \
    '\./scripts/verify-operator-workflow\.sh' \
    '\./scripts/verify-agent-binary-workflow\.sh' \
    '\./scripts/verify-live-agent-token-binding\.sh' \
    '\./scripts/verify-live-rbac-scope\.sh' \
    '\./scripts/verify-live-cvedb-quality\.sh' \
    '\./scripts/verify-live-web-smoke\.sh' \
    '\./scripts/verify-backup-restore-archive\.sh' \
    '\./scripts/verify-airgap-release-archive\.sh' \
    '\./scripts/verify-airgap-offline-rehearsal\.sh' \
    'BONGSU_DB_DSN="\$BONGSU_DB_DSN"' \
    'BONGSU_ADMIN_METRICS_DB_TIMEOUT_SECONDS' \
    'security_db_freshness\.latest_source' \
    'latest_last_update' \
    'TEMP-\*' \
    'CVD-\*' \
    'bongsu_security_db_source_stale' \
    'bongsu_cve_placeholder_records' \
    'bongsu_security_db_rescan_open' \
    'bongsu_\*_metrics_error' \
    'bongsu_agent_fleet_degraded' \
    'bongsu_agent_outdated_percent'
do
    require_text "$RUNBOOK" "$pattern" "operations runbook missing operational invariant $pattern"
done

for pattern in \
    'BONGSU_PORT: "5677"' \
    '\$\{BONGSU_WEB_PORT:-5678\}:80' \
    'BONGSU_SECURITY_DB_INTERVAL_HOURS: \$\{BONGSU_SECURITY_DB_INTERVAL_HOURS:-6\}'
do
    require_text "$CONNECTED_COMPOSE" "$pattern" "connected compose drifted from runbook default $pattern"
done

for pattern in \
    'BONGSU_TRIVY_DB_INTERVAL_HOURS: "0"' \
    'BONGSU_SECURITY_DB_SYNC_ON_START: "false"' \
    'BONGSU_SECURITY_DB_SYNC_CMD: ""' \
    'BONGSU_SYNC_REQUIRE_TRIVY_SOURCE: \$\{BONGSU_SYNC_REQUIRE_TRIVY_SOURCE:-false\}'
do
    require_text "$AIRGAP_COMPOSE" "$pattern" "airgap compose drifted from runbook default $pattern"
done

for script in \
    verify-release-readiness.sh \
    verify-operations-runbook.sh \
    verify-operator-workflow.sh \
    verify-agent-binary-workflow.sh \
    verify-live-agent-token-binding.sh \
    verify-live-installer-payload.sh \
    verify-live-rbac-scope.sh \
    verify-live-server-build.sh \
    verify-live-cvedb-quality.sh \
    sync-osv-cvedb.sh \
    sync-trivy-cvedb.sh \
    verify-live-web-smoke.sh \
    verify-backup-restore-archive.sh \
    verify-airgap-release-archive.sh \
    verify-airgap-offline-rehearsal.sh
do
    require_text "$PACKAGE" "$script" "airgap package must include runbook-referenced script $script"
done

require_text "$RELEASE" 'verify-operations-runbook\.sh' "release readiness must verify the operations runbook"
require_text "$RELEASE" 'BONGSU_RELEASE_READINESS_REQUIRE_DB' "live release readiness must expose direct DB invariant requirement control"
require_text "$RELEASE" 'BONGSU_VERIFY_CVEDB_REQUIRE_DB=\$\{REQUIRE_DB\}' "live release readiness must require direct CVE DB invariants by default"
require_text "$RELEASE" 'BONGSU_DB_DSN is required for live release readiness' "live release readiness must fail closed when direct DB checks are required but unavailable"
require_text "$AUDIT" 'verify-operations-runbook\.sh' "requirements audit must list the operations runbook verifier"
require_text "$ARCH" 'security_db_freshness\.latest_source' "architecture must document persisted freshness health fields"
reject_text "$RUNBOOK" 'Caddyfile|caddy reload|docker compose .*caddy|systemctl .*caddy' "runbook must not tell operators to manage Caddy from Bongsu"

echo "Operations runbook verification passed"
