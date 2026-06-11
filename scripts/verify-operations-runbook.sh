#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUNBOOK="$ROOT/docs/operations-runbook.md"
ARCH="$ROOT/docs/architecture.md"
AUDIT="$ROOT/docs/requirements-audit.md"
RELEASE="$ROOT/scripts/verify-release-readiness.sh"
ARCHIVE_VERIFIER="$ROOT/scripts/verify-airgap-release-archive.sh"
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
    'BONGSU_RELEASE_READINESS_REPORT' \
    'BONGSU_RELEASE_READINESS_REQUIRE_DB=false' \
    'BONGSU_RELEASE_ARCHIVE=bongsu-0\.2\.0\.tar\.gz' \
    '\./scripts/verify-operations-runbook\.sh' \
    '\./scripts/verify-operator-workflow\.sh' \
    '\./scripts/verify-agent-binary-workflow\.sh' \
    '\./scripts/verify-live-agent-token-binding\.sh' \
    '\./scripts/verify-live-rbac-scope\.sh' \
    '\./scripts/verify-live-cvedb-concurrency\.sh' \
    '\./scripts/verify-live-vulnerability-triage\.sh' \
    '\./scripts/verify-live-retention-prune\.sh' \
    '\./scripts/verify-live-sbom-export-rbac\.sh' \
    '\./scripts/verify-live-scan-request-recovery\.sh' \
    '\./scripts/verify-live-cvedb-quality\.sh' \
    '\./scripts/verify-live-security-db-schedule\.sh' \
    '\./scripts/verify-live-security-db-export-freshness\.sh' \
    '\./scripts/verify-security-db-bundle-file\.sh' \
    '\./scripts/verify-security-db-bundle-file-fixtures\.sh' \
    '\./scripts/verify-security-db-import-helper-fixtures\.sh' \
    'CVE JSONL checksum and record count' \
    'Trivy DB checksum before operators move the bundle across an airgap' \
    'import-security-db-bundle\.sh` runs the same local bundle verification before upload by default' \
    '\./scripts/verify-live-fixture-cleanup\.sh' \
    'RBAC subjects or policies must visibly delete those RBAC fixtures' \
    'scan-request fixtures must visibly cancel or remove those queue entries' \
    'abandoned pending/claimed scan requests' \
    '\./scripts/verify-security-db-export-helper-fixtures\.sh' \
    '\./scripts/verify-security-db-export-freshness-fixtures\.sh' \
    '\./scripts/verify-live-web-smoke\.sh' \
    '\./scripts/verify-live-trusted-identity-rbac\.sh' \
    '\./scripts/verify-backup-restore-archive\.sh' \
    '\./scripts/verify-airgap-archive-checksum-fixtures\.sh' \
    'BONGSU_BACKUP_VALIDATE_ARCHIVE=false' \
    '\./scripts/verify-airgap-release-archive\.sh' \
    '\./scripts/verify-airgap-offline-rehearsal\.sh' \
    'BONGSU_DB_DSN="\$BONGSU_DB_DSN"' \
    'BONGSU_ADMIN_METRICS_DB_TIMEOUT_SECONDS' \
    'BONGSU_VERIFY_CURL_MAX_TIME_SECONDS' \
    'BONGSU_SECURITY_DB_REVISION_CACHE_SECONDS' \
    'BONGSU_VERIFY_CVEDB_OSV_UPSTREAM_GRACE_SECONDS=3600' \
    'BONGSU_AGENT_RETRY_ATTEMPTS' \
    'BONGSU_AGENT_RETRY_MAX_BACKOFF_SECONDS' \
    'Retry-After` response headers are honored' \
    'BONGSU_VERIFY_CVEDB_CONCURRENCY_STATS_REQUESTS' \
    'stale-claim path' \
    'BONGSU_NOTIFICATION_RETRY_ATTEMPTS' \
    'BONGSU_NOTIFICATION_RETRY_DELAY_MS' \
    'signed retry path' \
    'security_db_freshness\.latest_source' \
    'security_db_updated_at' \
    'latest_last_update' \
    'security_db\.effective_status' \
    'effective_source' \
    'effective_last_sync' \
    'security_db_bundle_import\.last_result' \
    'stale scan-request counts' \
    'current security DB stale rescan counts' \
    'agent daemons that are not claiming pending scan requests' \
    'latest_source' \
    'latest_last_update' \
    'server_match' \
    'mixed-SBOM aggregation failure' \
    'TEMP-\*' \
    'CVD-\*' \
    'bongsu_security_db_source_stale' \
    'bongsu_security_db_effective_status' \
    'bongsu_security_db_effective_source_info' \
    'bongsu_security_db_effective_last_sync_timestamp_seconds' \
    'bongsu_security_db_sync_persisted_last_success_timestamp_seconds' \
    'bongsu_security_source_registry_ok_sources' \
    'bongsu_security_source_registry_enabled_sources' \
    'bongsu_security_source_registry_records' \
    'bongsu_security_source_registry_last_export_timestamp_seconds' \
    'bongsu_security_source_registry_export_stale_sources' \
    'bongsu_cve_placeholder_records' \
    'bongsu_security_db_rescan_open' \
    'bongsu_security_db_rescan_stale' \
    'bongsu_\*_metrics_error' \
    'bongsu_agent_fleet_degraded' \
    'bongsu_agent_outdated_percent' \
    '/api/admin/retention/prune' \
    'audited dry-runs'
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
    verify-live-agent-fleet-rollout.sh \
    verify-live-agent-token-binding.sh \
    verify-live-install-script.sh \
    verify-live-installer-payload.sh \
    verify-live-rbac-scope.sh \
    verify-live-cvedb-concurrency.sh \
    verify-live-cve-rematch-workflow.sh \
    verify-live-vulnerability-triage.sh \
    verify-live-retention-prune.sh \
    verify-live-report-export-rbac.sh \
    verify-live-sbom-export-rbac.sh \
    verify-live-sbom-export-workflow.sh \
    verify-live-server-build.sh \
    verify-live-scan-request-recovery.sh \
    verify-live-security-db-auto-rescan.sh \
    verify-live-security-db-schedule.sh \
    verify-live-security-db-export-freshness.sh \
    verify-live-fixture-cleanup.sh \
    verify-security-db-export-helper-fixtures.sh \
    verify-security-db-export-freshness-fixtures.sh \
    verify-live-session-auth.sh \
    verify-live-oidc-rbac.sh \
    verify-live-trusted-identity-rbac.sh \
    verify-live-cvedb-quality.sh \
    verify-live-vulnerability-export-rbac.sh \
    sync-nvd-cvedb.sh \
    sync-osv-cvedb.sh \
    sync-trivy-cvedb.sh \
    verify-live-web-smoke.sh \
    verify-backup-restore-archive.sh \
    verify-airgap-archive-checksum-fixtures.sh \
    verify-airgap-release-archive.sh \
    verify-airgap-offline-rehearsal.sh
do
    require_text "$PACKAGE" "$script" "airgap package must include runbook-referenced script $script"
done

require_text "$RELEASE" 'verify-operations-runbook\.sh' "release readiness must verify the operations runbook"
require_text "$RELEASE" 'BONGSU_RELEASE_READINESS_REQUIRE_DB' "live release readiness must expose direct DB invariant requirement control"
require_text "$RELEASE" 'BONGSU_RELEASE_READINESS_REPORT' "release readiness must support JSON evidence reports"
require_text "$RELEASE" '"failed_gate_count"' "release readiness report must include failed gate count"
require_text "$RELEASE" '"release_archive"' "release readiness report must include release archive artifact evidence"
require_text "$RELEASE" '"sidecar_matches"' "release readiness report must include release archive sidecar match state"
require_text "$RELEASE" 'verify-release-readiness-report\.sh' "release readiness must verify JSON evidence report behavior"
require_text "$ARCHIVE_VERIFIER" 'verify-release-readiness-report\.sh' "airgap archive verifier must require the release readiness report verifier"
require_text "$RELEASE" 'BONGSU_VERIFY_CVEDB_REQUIRE_DB=\$\{REQUIRE_DB\}' "live release readiness must require direct CVE DB invariants by default"
require_text "$RELEASE" 'BONGSU_VERIFY_CVEDB_OSV_UPSTREAM_GRACE_SECONDS=3600' "live release readiness must bound OSV upstream freshness grace to one hour"
require_text "$RELEASE" 'verify-live-cvedb-concurrency\.sh' "live release readiness must verify concurrent CVE DB observability"
require_text "$RELEASE" 'verify-live-cve-rematch-workflow\.sh' "live release readiness must verify CVE DB rematch workflow"
require_text "$RELEASE" 'verify-live-vulnerability-triage\.sh' "live release readiness must verify vulnerability triage lifecycle"
require_text "$RELEASE" 'verify-live-retention-prune\.sh' "live release readiness must verify destructive retention prune lifecycle"
require_text "$RELEASE" 'verify-live-report-export-rbac\.sh' "live release readiness must verify report export RBAC scoping"
require_text "$RELEASE" 'verify-live-sbom-export-rbac\.sh' "live release readiness must verify SBOM export RBAC scoping"
require_text "$RELEASE" 'verify-live-sbom-export-workflow\.sh' "live release readiness must verify live SBOM export workflow"
require_text "$RELEASE" 'verify-live-install-script\.sh' "live release readiness must verify one-line install script downloads"
require_text "$RELEASE" 'verify-live-scan-request-recovery\.sh' "live release readiness must verify stale scan-request recovery"
require_text "$RELEASE" 'verify-live-security-db-auto-rescan\.sh' "live release readiness must verify security DB auto-rescan queueing"
require_text "$RELEASE" 'verify-live-security-db-schedule\.sh' "live release readiness must verify security DB sync scheduling"
require_text "$RELEASE" 'verify-live-security-db-export-freshness\.sh' "live release readiness must verify security DB export freshness"
require_text "$RELEASE" 'verify-live-fixture-cleanup\.sh' "release readiness must verify live fixture cleanup hygiene"
require_text "$RELEASE" 'verify-live-session-auth\.sh' "live release readiness must verify local session login"
require_text "$RELEASE" 'verify-live-oidc-rbac\.sh' "live release readiness must verify OIDC bearer RBAC login"
require_text "$RELEASE" 'verify-live-trusted-identity-rbac\.sh' "live release readiness must verify trusted identity RBAC login"
require_text "$RELEASE" 'verify-live-vulnerability-export-rbac\.sh' "live release readiness must verify vulnerability export RBAC scoping"
require_text "$RELEASE" 'BONGSU_DB_DSN is required for live release readiness' "live release readiness must fail closed when direct DB checks are required but unavailable"
require_text "$RUNBOOK" 'BONGSU_VULNERABILITY_EXPORT_TIMEOUT_SECONDS' "runbook must document vulnerability export timeout tuning"
require_text "$RUNBOOK" '504 vulnerability export timeout' "runbook must document vulnerability export timeout behavior"
require_text "$RUNBOOK" 'publishes the final bundle filename plus `\.sha256` sidecar only after that verifier passes' "runbook must document safe security DB bundle publication"
require_text "$RUNBOOK" 'bongsu-0\.2\.0\.tar\.gz\.sha256' "runbook must require transferring the airgap release archive checksum sidecar"
require_text "$RUNBOOK" 'BONGSU_SECURITY_DB_REVISION_TIMEOUT_SECONDS' "runbook must document security DB revision timeout tuning"
require_text "$RUNBOOK" 'OIDC bearer token authentication' "runbook must document OIDC bearer token authentication"
require_text "$RUNBOOK" 'BONGSU_OIDC_ISSUER' "runbook must document OIDC issuer configuration"
require_text "$RUNBOOK" 'BONGSU_OIDC_CLIENT_ID' "runbook must document OIDC audience/client configuration"
require_text "$RUNBOOK" 'BONGSU_OIDC_ADMIN_GROUPS' "runbook must document OIDC admin group configuration"
require_text "$RUNBOOK" 'BONGSU_TRUSTED_IDENTITY_HEADER' "runbook must document trusted identity header configuration"
require_text "$RUNBOOK" 'BONGSU_TRUSTED_GROUPS_HEADER' "runbook must document trusted groups header configuration"
require_text "$RUNBOOK" 'BONGSU_TRUSTED_IDENTITY_PROXY_CIDRS' "runbook must document trusted identity proxy CIDR configuration"
require_text "$RUNBOOK" 'BONGSU_TRUSTED_ADMIN_GROUPS' "runbook must document trusted identity admin group configuration"
require_text "$RUNBOOK" 'BONGSU_CVE_REFERENCE_INDEX_REBUILD_TIMEOUT_SECONDS' "runbook must document reference index rebuild timeout tuning"
require_text "$AUDIT" 'verify-operations-runbook\.sh' "requirements audit must list the operations runbook verifier"
require_text "$ARCH" 'security_db_freshness\.latest_source' "architecture must document persisted freshness health fields"
require_text "$ARCH" 'bundle creation timestamp' "architecture must document security DB bundle provenance metadata"
require_text "$ARCH" 'source count, CVE record count, and Trivy inclusion state' "architecture must document airgap import provenance audit fields"
reject_text "$RUNBOOK" 'Caddyfile|caddy reload|docker compose .*caddy|systemctl .*caddy' "runbook must not tell operators to manage Caddy from Bongsu"

echo "Operations runbook verification passed"
