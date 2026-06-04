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

for id in $(seq 1 18); do
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
    '\./scripts/verify-openapi\.sh' \
    '\./scripts/verify-operator-workflow\.sh' \
    '\./scripts/verify-agent-binary-workflow\.sh' \
    '\./scripts/verify-live-rbac-scope\.sh' \
    '\./scripts/verify-package-contents\.sh' \
    '\./scripts/verify-airgap-package-smoke\.sh' \
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
    'force scan' \
    'one-line installer' \
    'systemd' \
    'Docker Compose'
do
    require_text "$AUDIT" "$keyword" "requirements audit missing keyword $keyword"
done

require_text "$CI" 'verify-requirements-audit\.sh' "CI must run the requirements audit verifier"
require_text "$CI" 'verify-openapi\.sh' "CI must run the OpenAPI verifier"
require_text "$CI" 'verify-package-contents\.sh' "CI must run the package contents verifier"
require_text "$CI" 'verify-airgap-package-smoke\.sh' "CI must run the airgap package smoke verifier"
require_text "$README" 'requirements-audit\.md' "README must link the requirements audit"
require_text "$README" 'operations-runbook\.md' "README must link the operations runbook"
require_text "$ARCH" 'BONGSU_SYSTEMD_DIR' "architecture must document systemd installer test hooks"
require_text "$MATCHING" 'package/ecosystem/fixed evidence' "matching rules must describe package evidence"
require_text "$PACKAGE_SCRIPT" 'cp -r docs' "airgap package must include docs"

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
    'docker compose' \
    'air-gapped' \
    'SHA256SUMS' \
    'pg_dump' \
    'restore' \
    'admin/metrics' \
    'TEMP-\*' \
    'CVD-\*' \
    'EPSS' \
    'requeue-stale' \
    'agent-token/reset'
do
    require_text "$RUNBOOK" "$keyword" "operations runbook missing keyword $keyword"
done

echo "Requirements audit verification passed"
