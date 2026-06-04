#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AUDIT="$ROOT/docs/requirements-audit.md"
ARCH="$ROOT/docs/architecture.md"
MATCHING="$ROOT/docs/vulnerability-matching-rules.md"
README="$ROOT/README.md"
CI="$ROOT/.github/workflows/ci.yml"
RUNBOOK="$ROOT/docs/operations-runbook.md"
PACKAGE_SCRIPT="$ROOT/scripts/package.sh"

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

for file in "$AUDIT" "$ARCH" "$MATCHING" "$README" "$CI" "$RUNBOOK" "$PACKAGE_SCRIPT"; do
    require_file "$file"
done

for id in $(seq 1 19); do
    require_text "$AUDIT" "^\\| R${id} \\|" "requirements audit must include R${id}"
done

require_text "$AUDIT" 'Requirement Matrix' "requirements audit must contain the matrix"
require_text "$AUDIT" 'Required Verification Suite' "requirements audit must list verification commands"
require_text "$AUDIT" 'Remaining Commercial-Readiness Gaps' "requirements audit must keep the goal open"
require_text "$AUDIT" 'not a completion claim' "requirements audit must not imply completion"
reject_text "$AUDIT" '(^|[^[:alpha:]])Complete([^[:alpha:]]|$)' "requirements audit should not mark the product complete"

for command in \
    'go test \./\.\.\.' \
    '\./scripts/verify-migrations\.sh' \
    '\./scripts/verify-deploy-config\.sh' \
    '\./scripts/verify-requirements-audit\.sh' \
    '\./scripts/verify-operations-runbook\.sh' \
    '\./scripts/verify-cve-matching-invariants\.sh' \
    '\./scripts/verify-release-readiness\.sh' \
    'BONGSU_RELEASE_READINESS_REPORT=/tmp/bongsu-release-readiness\.json \./scripts/verify-release-readiness\.sh' \
    '\./scripts/verify-openapi\.sh' \
    '\./scripts/verify-backup-restore-archive\.sh' \
    '\./scripts/verify-operator-workflow\.sh' \
    '\./scripts/verify-agent-binary-workflow\.sh' \
    '\./scripts/verify-live-agent-token-binding\.sh' \
    '\./scripts/verify-live-cvedb-quality\.sh' \
    '\./scripts/verify-live-cve-rematch-workflow\.sh' \
    '\./scripts/verify-live-install-script\.sh' \
    '\./scripts/verify-live-installer-payload\.sh' \
    '\./scripts/verify-live-rbac-scope\.sh' \
    '\./scripts/verify-live-security-db-schedule\.sh' \
    '\./scripts/verify-live-session-auth\.sh' \
    '\./scripts/verify-live-server-build\.sh' \
    '\./scripts/verify-live-web-smoke\.sh' \
    '\./scripts/verify-package-contents\.sh' \
    '\./scripts/verify-airgap-package-smoke\.sh' \
    '\./scripts/verify-airgap-offline-rehearsal\.sh <generated-bongsu-archive\.tar\.gz>' \
    '\./scripts/verify-installer-smoke\.sh' \
    '\./scripts/verify-static-binaries\.sh' \
    'npm --prefix web run build' \
    'npm --prefix web run test:e2e' \
    'docker compose -f deploy/docker-compose\.yml config' \
    'docker compose -f deploy/docker-compose\.airgap\.yml config' \
    'git diff --check'
do
    require_text "$AUDIT" "$command" "requirements audit verification suite missing $command"
done

require_text "$AUDIT" 'BONGSU_DB_DSN="\$BONGSU_DB_DSN" BONGSU_RELEASE_READINESS_LIVE=true \./scripts/verify-release-readiness\.sh' "requirements audit must include DB-backed live release readiness"
require_text "$AUDIT" 'direct PostgreSQL CVE DB invariants by default' "requirements audit must document DB-backed live release readiness"

for keyword in \
    '5677' \
    '5678' \
    'air-gapped' \
    '봉수대' \
    'product intro' \
    'TEMP-\*' \
    'CVD-\*' \
    'EPSS' \
    'match' \
    'same-name OS/library collisions' \
    'numeric epoch' \
    'RBAC' \
    'live RBAC' \
    'two-host/two-container' \
    'dynamic asset-group' \
    'live CVE DB' \
    'direct DB invariant' \
    'security DB schedule' \
    'multi-source canonical CVE' \
    'vendor/advisory key' \
    'live browser' \
    'Scan History' \
    'Notifications' \
    'signed notification rule webhook retry' \
    'BONGSU_HOST_ID' \
    'host-token binding' \
    'two logical host' \
    'force scan' \
    'one-line installer' \
    'systemd' \
    'Docker Compose' \
    'release readiness' \
    'JSON evidence report' \
    'audited retention dry-run'
do
    require_text "$AUDIT" "$keyword" "requirements audit missing keyword $keyword"
done

require_text "$CI" 'verify-requirements-audit\.sh' "CI must run the requirements audit verifier"
require_text "$CI" 'verify-operations-runbook\.sh' "CI must run the operations runbook verifier"
require_text "$CI" 'verify-cve-matching-invariants\.sh' "CI must run the CVE matching invariant verifier"
require_text "$CI" 'verify-release-readiness\.sh' "CI must run the consolidated release readiness verifier"
require_text "$CI" 'verify-openapi\.sh' "CI must run the OpenAPI verifier"
require_text "$CI" 'verify-package-contents\.sh' "CI must run the package contents verifier"
require_text "$CI" 'verify-airgap-package-smoke\.sh' "CI must run the airgap package smoke verifier"
require_text "$README" 'requirements-audit\.md' "README must link the requirements audit"
require_text "$README" 'operations-runbook\.md' "README must link the operations runbook"
require_text "$ARCH" 'BONGSU_SYSTEMD_DIR' "architecture must document systemd installer test hooks"
require_text "$MATCHING" 'package/ecosystem/fixed evidence' "matching rules must describe package evidence"
require_text "$PACKAGE_SCRIPT" 'cp -r docs' "airgap package must include docs"
require_text "$PACKAGE_SCRIPT" 'verify-release-readiness\.sh' "airgap package must include release readiness verifier"
require_text "$PACKAGE_SCRIPT" 'verify-release-readiness-report\.sh' "airgap package must include release readiness report verifier"
require_text "$PACKAGE_SCRIPT" 'verify-operations-runbook\.sh' "airgap package must include operations runbook verifier"
require_text "$PACKAGE_SCRIPT" 'verify-cve-matching-invariants\.sh' "airgap package must include CVE matching invariant verifier"
require_text "$PACKAGE_SCRIPT" 'verify-backup-restore-archive\.sh' "airgap package must include backup/restore archive verifier"
require_text "$PACKAGE_SCRIPT" 'verify-live-agent-token-binding\.sh' "airgap package must include live agent token binding verifier"
require_text "$PACKAGE_SCRIPT" 'verify-live-cve-rematch-workflow\.sh' "airgap package must include live CVE rematch workflow verifier"
require_text "$PACKAGE_SCRIPT" 'verify-live-sbom-export-workflow\.sh' "airgap package must include live SBOM export workflow verifier"
require_text "$PACKAGE_SCRIPT" 'verify-live-install-script\.sh' "airgap package must include live install script verifier"
require_text "$PACKAGE_SCRIPT" 'verify-live-installer-payload\.sh' "airgap package must include live installer payload verifier"
require_text "$PACKAGE_SCRIPT" 'verify-live-security-db-schedule\.sh' "airgap package must include live security DB schedule verifier"
require_text "$PACKAGE_SCRIPT" 'verify-live-session-auth\.sh' "airgap package must include live session auth verifier"
require_text "$PACKAGE_SCRIPT" 'verify-live-server-build\.sh' "airgap package must include live server build verifier"
require_text "$PACKAGE_SCRIPT" 'verify-live-vulnerability-export-rbac\.sh' "airgap package must include live vulnerability export RBAC verifier"

for section in \
    'Production Readiness Checklist' \
    'Install' \
    'Upgrade' \
    'Backup And Restore' \
    'Security DB Operations' \
    'Monitoring And Alerting' \
    'Incident Response' \
    'Routine Maintenance'
do
    require_text "$RUNBOOK" "^## ${section}$" "operations runbook missing section $section"
done

for keyword in \
    '5677' \
    '5678' \
    'Caddy' \
    'BONGSU_ALLOW_WEAK_SECRETS=false' \
    'BONGSU_WEB_AUTH=true' \
    'BONGSU_AGENT_HOST_BINDING=true' \
    'BONGSU_HOST_ID' \
    'docker compose' \
    'air-gapped' \
    'SHA256SUMS' \
    'pg_dump' \
    'restore' \
    'verify-backup-restore-archive\.sh' \
    'admin/metrics' \
    'TEMP-\*' \
    'CVD-\*' \
    'EPSS' \
    'BONGSU_DB_DSN' \
    'direct DB invariant' \
    'canonical CVE reference keys' \
    'vendor/advisory keys' \
    'requeue-stale' \
    'agent-token/reset' \
    'verify-live-agent-token-binding\.sh' \
    'verify-live-cve-rematch-workflow\.sh' \
    'verify-live-sbom-export-workflow\.sh' \
    'verify-live-install-script\.sh' \
    'verify-live-installer-payload\.sh' \
    'verify-live-security-db-schedule\.sh' \
    'verify-live-session-auth\.sh' \
    'verify-live-server-build\.sh' \
    'verify-live-vulnerability-export-rbac\.sh' \
    'verify-release-readiness\.sh' \
    'verify-live-web-smoke\.sh' \
    'two-host/two-container' \
    'dynamic `asset_group` policy'
do
    require_text "$RUNBOOK" "$keyword" "operations runbook missing keyword $keyword"
done

echo "Requirements audit verification passed"
