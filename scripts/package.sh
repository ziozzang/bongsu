#!/bin/bash
set -euo pipefail

# package.sh — Build air-gapped deployment package
# Usage: ./scripts/package.sh [version]
#
# trivy-db is managed via docker-compose init container.
# For air-gapped: use scripts/download-trivy-db.sh + scripts/update-trivy-db.sh

VERSION="${1:-${BONGSU_VERSION:-0.1.0}}"
COMMIT="${BONGSU_COMMIT:-$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)}"
BUILD_DATE="${BONGSU_BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
PACKAGE_NAME="bongsu-${VERSION}"
STAGING="/tmp/${PACKAGE_NAME}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cleanup() {
    if [ -d "$STAGING" ]; then
        rm -rf "$STAGING"
    fi
}
trap cleanup EXIT

echo "=== Bongsu Air-Gapped Packaging ==="
echo "Version: $VERSION"
echo "Commit:  $COMMIT"

cd "$ROOT"

# Step 1: Build binaries
echo ""
echo "[1/6] Building binaries..."
LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="${LDFLAGS}" -o bin/bongsu-agent-linux-amd64 ./cmd/agent
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="${LDFLAGS}" -o bin/bongsu-server-linux-amd64 ./cmd/server
echo "  bin/bongsu-agent-linux-amd64 ($(du -h bin/bongsu-agent-linux-amd64 | cut -f1))"
echo "  bin/bongsu-server-linux-amd64 ($(du -h bin/bongsu-server-linux-amd64 | cut -f1))"

# Step 2: Build frontend
echo ""
echo "[2/6] Building frontend..."
cd web && npm ci --quiet && npm run build && cd "$ROOT"
echo "  web/dist/ ($(du -sh web/dist | cut -f1))"

# Step 3: Build Docker images
echo ""
echo "[3/6] Building Docker images..."
docker build -t "bongsu-server:${VERSION}" -t "bongsu-server:latest" \
    --build-arg "BONGSU_VERSION=${VERSION}" \
    --build-arg "BONGSU_COMMIT=${COMMIT}" \
    --build-arg "BONGSU_BUILD_DATE=${BUILD_DATE}" \
    -f deploy/Dockerfile.server . 2>&1 | tail -3

docker build -t "bongsu-agent:${VERSION}" -t "bongsu-agent:latest" \
    --build-arg "BONGSU_VERSION=${VERSION}" \
    --build-arg "BONGSU_COMMIT=${COMMIT}" \
    --build-arg "BONGSU_BUILD_DATE=${BUILD_DATE}" \
    -f deploy/Dockerfile.agent . 2>&1 | tail -3

docker build -t "bongsu-web:${VERSION}" -t "bongsu-web:latest" \
    -f deploy/Dockerfile.web . 2>&1 | tail -3

# Step 4: Create staging directory
echo ""
echo "[4/6] Staging files..."
rm -rf "$STAGING"
mkdir -p "$STAGING"/{images,bin,scripts,deploy,web,docs}

# Save Docker images
echo "  Saving Docker images..."
docker save "bongsu-server:${VERSION}" | gzip > "$STAGING/images/bongsu-server.tar.gz"
docker save "bongsu-agent:${VERSION}" | gzip > "$STAGING/images/bongsu-agent.tar.gz"
docker save "bongsu-web:${VERSION}" | gzip > "$STAGING/images/bongsu-web.tar.gz"
docker save "postgres:16-alpine" | gzip > "$STAGING/images/postgres-16-alpine.tar.gz"

# Copy binaries
cp bin/bongsu-agent-linux-amd64 "$STAGING/bin/bongsu-agent"
cp bin/bongsu-server-linux-amd64 "$STAGING/bin/bongsu-server"
chmod +x "$STAGING/bin/bongsu-agent"
chmod +x "$STAGING/bin/bongsu-server"

# Copy scripts
for script in \
    backup.sh \
    restore.sh \
    install-agent.sh \
    update-trivy-db.sh \
    download-trivy-db.sh \
    download-cisa-kev.sh \
    download-epss.sh \
    download-nvd.sh \
    download-osv.sh \
    extract-trivy-cvedb.sh \
    sync-all-cvedb.sh \
    sync-osv-cvedb.sh \
    sync-trivy-cvedb.sh \
    export-security-db-bundle.sh \
    import-security-db-bundle.sh \
    verify-release-readiness.sh \
    verify-operations-runbook.sh \
    verify-cve-matching-invariants.sh \
    verify-backup-restore-archive.sh \
    verify-agent-binary-workflow.sh \
    verify-airgap-release-archive.sh \
    verify-airgap-offline-rehearsal.sh \
    verify-airgap-package-smoke.sh \
    verify-live-agent-token-binding.sh \
    verify-live-cvedb-concurrency.sh \
    verify-live-cvedb-quality.sh \
    verify-live-install-script.sh \
    verify-live-installer-payload.sh \
    verify-live-rbac-scope.sh \
    verify-live-scan-request-recovery.sh \
    verify-live-security-db-schedule.sh \
    verify-live-server-build.sh \
    verify-live-web-smoke.sh \
    verify-operator-workflow.sh \
    verify-static-binaries.sh
do
    cp "scripts/${script}" "$STAGING/scripts/"
done
chmod +x "$STAGING/scripts/"*.sh

# Copy deploy configs
cp deploy/docker-compose.yml "$STAGING/deploy/"
cp deploy/docker-compose.airgap.yml "$STAGING/deploy/"
cp deploy/.env.example "$STAGING/deploy/"

# Copy migrations
cp -r migrations "$STAGING/"

# Copy docs
cp -r docs "$STAGING/"
cp README.md "$STAGING/"

# Copy web dist
cp -r web/dist "$STAGING/web/"

# Step 5: Create loader script
cat > "$STAGING/load-images.sh" << 'EOF'
#!/bin/bash
set -euo pipefail
echo "Loading Docker images..."
docker load < images/bongsu-server.tar.gz
docker load < images/bongsu-agent.tar.gz
docker load < images/bongsu-web.tar.gz
docker load < images/postgres-16-alpine.tar.gz
echo "Done. Run: cd deploy && docker compose up -d"
EOF
chmod +x "$STAGING/load-images.sh"

# Create package manifest before the outer archive is built.
(cd "$STAGING" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)

# Step 6: Create archive
echo ""
echo "[5/6] Creating archive..."
tar -C /tmp -czf "${PACKAGE_NAME}.tar.gz" "${PACKAGE_NAME}"
SHA=$(sha256sum "${PACKAGE_NAME}.tar.gz" | cut -d" " -f1)
echo "${SHA}  ${PACKAGE_NAME}.tar.gz" > "${PACKAGE_NAME}.tar.gz.sha256"

# Summary
echo ""
echo "[6/6] Done!"
echo ""
echo "=== Package: ${PACKAGE_NAME}.tar.gz ==="
echo "Size:   $(du -h "${PACKAGE_NAME}.tar.gz" | cut -f1)"
echo "SHA256: ${SHA}"
echo ""
echo "Contents:"
echo "  images/              Docker images (server with trivy, web, agent, postgres)"
echo "  bin/                 Static server and agent binaries"
echo "  scripts/             installer, source sync, and security DB bundle tools"
echo "  deploy/              docker-compose.yml, .env.example"
echo "  migrations/          Database migrations"
echo "  docs/                Architecture, matching rules, audit, and operations runbook"
echo "  SHA256SUMS           Integrity manifest for packaged files"
echo "  load-images.sh       Load Docker images on target"
echo ""
echo "Air-gapped deployment:"
echo "  1. Transfer ${PACKAGE_NAME}.tar.gz to target"
echo "  2. tar xzf ${PACKAGE_NAME}.tar.gz"
echo "  3. cd ${PACKAGE_NAME} && sha256sum -c SHA256SUMS"
echo "  4. ./load-images.sh"
echo "  5. cp deploy/.env.example deploy/.env && edit .env"
echo "  6. cd deploy && docker compose -f docker-compose.airgap.yml up -d"
echo "  7. Import security DB bundle:"
echo "     ./scripts/import-security-db-bundle.sh http://localhost:5677 <api-key> bongsu-security-db-bundle.tar.gz"

# Cleanup
rm -rf "$STAGING"
