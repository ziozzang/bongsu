#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="${BONGSU_DEPLOY_VERIFY_DIR:-$(mktemp -d)}"

cleanup() {
    if [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

CONNECTED_CONFIG="$TMP_DIR/connected.yml"
AIRGAP_CONFIG="$TMP_DIR/airgap.yml"

export BONGSU_DB_PASSWORD="${BONGSU_DB_PASSWORD:-dbp-9f4c2b7a8e6d5c3b1a0f}"
export BONGSU_API_KEY="${BONGSU_API_KEY:-adm-9f4c2b7a8e6d5c3b1a0f}"
export BONGSU_AGENT_API_KEY="${BONGSU_AGENT_API_KEY:-agt-1a0f3b5c7d9e2c4b6a8f}"
export BONGSU_INSTALL_TOKEN="${BONGSU_INSTALL_TOKEN:-ins-6a8f4c2b0e1d3c5b7a9f}"

docker compose -f "$ROOT/deploy/docker-compose.yml" config > "$CONNECTED_CONFIG"
docker compose -f "$ROOT/deploy/docker-compose.airgap.yml" config > "$AIRGAP_CONFIG"

require_line() {
    local file="$1"
    local pattern="$2"
    local message="$3"
    if ! grep -Eq "$pattern" "$file"; then
        echo "ERROR: $message" >&2
        echo "Missing pattern: $pattern" >&2
        exit 1
    fi
}

reject_line() {
    local file="$1"
    local pattern="$2"
    local message="$3"
    if grep -Eq "$pattern" "$file"; then
        echo "ERROR: $message" >&2
        echo "Forbidden pattern: $pattern" >&2
        exit 1
    fi
}

for config in "$CONNECTED_CONFIG" "$AIRGAP_CONFIG"; do
    require_line "$config" 'BONGSU_PORT: "5677"' "API service must listen on 5677"
    require_line "$config" 'published: "5677"' "API compose port must publish 5677"
    require_line "$config" 'published: "5678"' "Web compose port must publish 5678"
    require_line "$config" 'BONGSU_WEB_AUTH: "true"' "Web auth must default to enabled"
    require_line "$config" 'BONGSU_ALLOW_WEAK_SECRETS: "false"' "Weak-secret override must default to false"
    require_line "$config" 'BONGSU_AGENT_HOST_BINDING: "true"' "Agent host token binding must default to true"
    require_line "$config" 'BONGSU_CORS_ALLOWED_ORIGINS: ""' "CORS must default to same-origin only"
    reject_line "$config" 'BONGSU_API_KEY: .*(change-me|your-|example|admin-key)' "Admin key rendered with a weak placeholder"
    reject_line "$config" 'BONGSU_AGENT_API_KEY: .*(change-me|your-|example|agent-key)' "Agent key rendered with a weak placeholder"
    reject_line "$config" 'BONGSU_INSTALL_TOKEN: .*(change-me|your-|example|install-token)' "Install token rendered with a weak placeholder"
done

require_line "$CONNECTED_CONFIG" 'BONGSU_TRIVY_DB_INTERVAL_HOURS: "6"' "Connected compose must refresh Trivy DB every 6 hours by default"
require_line "$CONNECTED_CONFIG" 'BONGSU_SECURITY_DB_SYNC_ON_START: "true"' "Connected compose must sync security DB on start"
require_line "$CONNECTED_CONFIG" 'BONGSU_SECURITY_DB_SYNC_CMD: /app/scripts/sync-all-cvedb.sh http://localhost:5677' "Connected compose must use bundled CVE sync command"
require_line "$CONNECTED_CONFIG" 'BONGSU_SYNC_REQUIRE_TRIVY_SOURCE: "true"' "Connected compose must fail closed when Trivy source is missing"

require_line "$AIRGAP_CONFIG" 'BONGSU_TRIVY_DB_INTERVAL_HOURS: "0"' "Airgap compose must disable connected Trivy DB refresh"
require_line "$AIRGAP_CONFIG" 'BONGSU_SECURITY_DB_SYNC_ON_START: "false"' "Airgap compose must not sync security DB on start"
require_line "$AIRGAP_CONFIG" 'BONGSU_SECURITY_DB_SYNC_CMD: ""' "Airgap compose must not run connected CVE sync"
require_line "$AIRGAP_CONFIG" 'BONGSU_SYNC_REQUIRE_TRIVY_SOURCE: "false"' "Airgap compose must not require online Trivy source sync"

ENV_EXAMPLE="$ROOT/deploy/.env.example"
require_line "$ENV_EXAMPLE" '^BONGSU_API_KEY=change-me-to-a-strong-random-string$' ".env.example must mark admin key as operator-provided"
require_line "$ENV_EXAMPLE" '^BONGSU_AGENT_API_KEY=change-me-to-a-different-agent-string$' ".env.example must mark agent key as operator-provided"
require_line "$ENV_EXAMPLE" '^BONGSU_INSTALL_TOKEN=change-me-to-an-install-token$' ".env.example must mark install token as operator-provided"
require_line "$ENV_EXAMPLE" '^BONGSU_ALLOW_WEAK_SECRETS=false$' ".env.example must keep weak-secret override disabled"
require_line "$ENV_EXAMPLE" '^BONGSU_WEB_AUTH=true$' ".env.example must keep web auth enabled"

GO_MINOR="$(awk '$1 == "go" { split($2, v, "."); print v[1] "." v[2]; exit }' "$ROOT/go.mod")"
if [ -z "$GO_MINOR" ]; then
    echo "ERROR: go.mod must declare a Go version" >&2
    exit 1
fi
require_line "$ROOT/deploy/Dockerfile.server" "^FROM golang:${GO_MINOR}-alpine AS backend$" "Server Dockerfile Go image must match go.mod minor version"
require_line "$ROOT/deploy/Dockerfile.agent" "^FROM golang:${GO_MINOR}-alpine AS builder$" "Agent Dockerfile Go image must match go.mod minor version"

echo "Deployment configuration verification passed"
