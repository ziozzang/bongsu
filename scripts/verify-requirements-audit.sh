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
    '\./scripts/verify-release-readiness\.sh' \
    '\./scripts/verify-openapi\.sh' \
    '\./scripts/verify-operator-workflow\.sh' \
    '\./scripts/verify-agent-binary-workflow\.sh' \
    '\./scripts/verify-live-agent-token-binding\.sh' \
    '\./scripts/verify-live-cvedb-quality\.sh' \
    '\./scripts/verify-live-rbac-scope\.sh' \
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

for keyword in \
    '5677' \
    '5678' \
    'air-gapped' \
    'TEMP-\*' \
    'CVD-\*' \
    'EPSS' \
    'match' \
    'RBAC' \
    'live RBAC' \
    'two-host/two-container' \
    'live CVE DB' \
    'direct DB invariant' \
    'live browser' \
    'BONGSU_HOST_ID' \
    'host-token binding' \
    'two logical host' \
    'force scan' \
    'one-line installer' \
    'systemd' \
    'Docker Compose' \
    'release readiness'
do
    require_text "$AUDIT" "$keyword" "requirements audit missing keyword $keyword"
done

require_text "$CI" 'verify-requirements-audit\.sh' "CI must run the requirements audit verifier"
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
require_text "$PACKAGE_SCRIPT" 'verify-live-agent-token-binding\.sh' "airgap package must include live agent token binding verifier"

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
    'admin/metrics' \
    'TEMP-\*' \
    'CVD-\*' \
    'EPSS' \
    'BONGSU_DB_DSN' \
    'direct DB invariant' \
    'requeue-stale' \
    'agent-token/reset' \
    'verify-live-agent-token-binding\.sh' \
    'verify-release-readiness\.sh' \
    'verify-live-web-smoke\.sh' \
    'two-host/two-container'
do
    require_text "$RUNBOOK" "$keyword" "operations runbook missing keyword $keyword"
done

echo "Requirements audit verification passed"
