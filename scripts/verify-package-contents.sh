#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PACKAGE_SCRIPT="$ROOT/scripts/package.sh"
RUNBOOK="$ROOT/docs/operations-runbook.md"

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

require_file "$PACKAGE_SCRIPT"
require_file "$RUNBOOK"

for path in \
    'images/bongsu-server.tar.gz' \
    'images/bongsu-agent.tar.gz' \
    'bin/bongsu-agent' \
    'bin/bongsu-server' \
    'deploy/docker-compose.yml' \
    'deploy/docker-compose.airgap.yml' \
    'deploy/.env.example' \
    'migrations' \
    'docs' \
    'README.md' \
    'web/dist' \
    'load-images.sh' \
    'SHA256SUMS'
do
    require_text "$PACKAGE_SCRIPT" "$path" "package script must include $path"
done

for script in \
    'install-agent.sh' \
    'download-trivy-db.sh' \
    'download-cisa-kev.sh' \
    'download-epss.sh' \
    'download-nvd.sh' \
    'download-osv.sh' \
    'extract-trivy-cvedb.sh' \
    'sync-all-cvedb.sh' \
    'export-security-db-bundle.sh' \
    'import-security-db-bundle.sh' \
    'verify-static-binaries.sh'
do
    require_text "$PACKAGE_SCRIPT" "$script" "package script must include scripts/$script"
done

for pattern in \
    'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build' \
    'docker save "bongsu-server' \
    'docker save "bongsu-agent' \
    'cp -r migrations' \
    'cp -r docs' \
    'cp README.md' \
    'find \. -type f ! -name SHA256SUMS' \
    'sha256sum > SHA256SUMS' \
    'tar -C /tmp -czf' \
    'sha256sum "\$\{PACKAGE_NAME\}\.tar\.gz"' \
    'sha256sum -c SHA256SUMS' \
    'docker compose -f docker-compose\.airgap\.yml up -d' \
    'import-security-db-bundle\.sh http://localhost:5677'
do
    require_text "$PACKAGE_SCRIPT" "$pattern" "package script missing release invariant $pattern"
done

for pattern in \
    'sha256sum -c bongsu-0\.1\.0\.tar\.gz\.sha256' \
    'sha256sum -c SHA256SUMS' \
    'load-images\.sh' \
    'docker-compose\.airgap\.yml' \
    'import-security-db-bundle\.sh' \
    'BONGSU_SECURITY_DB_SYNC_ON_START=false'
do
    require_text "$RUNBOOK" "$pattern" "operations runbook missing airgap package operation $pattern"
done

echo "Package contents verification passed"
