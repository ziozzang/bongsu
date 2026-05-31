#!/bin/bash
set -euo pipefail

# package.sh — Build air-gapped deployment package
# Usage: ./scripts/package.sh [version]
#
# trivy-db is managed via docker-compose init container.
# For air-gapped: use scripts/download-trivy-db.sh + scripts/update-trivy-db.sh

VERSION="${1:-${BONGSU_VERSION:-0.1.0}}"
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

cd "$ROOT"

# Step 1: Build binaries
echo ""
echo "[1/6] Building binaries..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X main.version=${VERSION}" -o bin/bongsu-agent-linux-amd64 ./cmd/agent
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X main.version=${VERSION}" -o bin/bongsu-server-linux-amd64 ./cmd/server
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
    -f deploy/Dockerfile.server . 2>&1 | tail -3

docker build -t "bongsu-agent:${VERSION}" -t "bongsu-agent:latest" \
    --build-arg "BONGSU_VERSION=${VERSION}" \
    -f deploy/Dockerfile.agent . 2>&1 | tail -3

# Step 4: Create staging directory
echo ""
echo "[4/6] Staging files..."
rm -rf "$STAGING"
mkdir -p "$STAGING"/{images,bin,scripts,deploy,web}

# Save Docker images
echo "  Saving Docker images..."
docker save "bongsu-server:${VERSION}" | gzip > "$STAGING/images/bongsu-server.tar.gz"
docker save "bongsu-agent:${VERSION}" | gzip > "$STAGING/images/bongsu-agent.tar.gz"

# Copy binaries
cp bin/bongsu-agent-linux-amd64 "$STAGING/bin/bongsu-agent"
chmod +x "$STAGING/bin/bongsu-agent"

# Copy scripts
cp scripts/install-agent.sh "$STAGING/scripts/"
cp scripts/update-trivy-db.sh "$STAGING/scripts/"
cp scripts/download-trivy-db.sh "$STAGING/scripts/"
cp scripts/download-cisa-kev.sh "$STAGING/scripts/"
cp scripts/download-epss.sh "$STAGING/scripts/"
cp scripts/export-security-db-bundle.sh "$STAGING/scripts/"
cp scripts/import-security-db-bundle.sh "$STAGING/scripts/"
chmod +x "$STAGING/scripts/"*.sh

# Copy deploy configs
cp deploy/docker-compose.yml "$STAGING/deploy/"
cp deploy/docker-compose.airgap.yml "$STAGING/deploy/"
cp deploy/.env.example "$STAGING/deploy/"

# Copy migrations
cp -r migrations "$STAGING/"

# Copy web dist
cp -r web/dist "$STAGING/web/"

# Step 5: Create loader script
cat > "$STAGING/load-images.sh" << 'EOF'
#!/bin/bash
set -euo pipefail
echo "Loading Docker images..."
docker load < images/bongsu-server.tar.gz
docker load < images/bongsu-agent.tar.gz
echo "Done. Run: cd deploy && docker compose up -d"
EOF
chmod +x "$STAGING/load-images.sh"

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
echo "  images/              Docker images (server with trivy, agent)"
echo "  bin/                 Agent binary for direct host install"
echo "  scripts/             installer and security DB bundle import/export tools"
echo "  deploy/              docker-compose.yml, .env.example"
echo "  migrations/          Database migrations"
echo "  load-images.sh       Load Docker images on target"
echo ""
echo "Air-gapped deployment:"
echo "  1. Transfer ${PACKAGE_NAME}.tar.gz to target"
echo "  2. tar xzf ${PACKAGE_NAME}.tar.gz"
echo "  3. cd ${PACKAGE_NAME} && ./load-images.sh"
echo "  4. cp deploy/.env.example deploy/.env && edit .env"
echo "  5. cd deploy && docker compose -f docker-compose.airgap.yml up -d"
echo "  6. Import security DB bundle:"
echo "     ./scripts/import-security-db-bundle.sh http://localhost:8080 <api-key> bongsu-security-db-bundle.tar.gz"

# Cleanup
rm -rf "$STAGING"
