#!/bin/bash
set -euo pipefail

# verify-e2e-api.sh - Run the Python API end-to-end robustness suite against a
# live server.
#
# Usage: ./verify-e2e-api.sh [server_url] [api_key]
#   BONGSU_E2E_VIEWER_KEY      optional viewer key for RBAC tests
#   BONGSU_E2E_SMTP_SINK_LOG   optional SMTP sink capture for email assertions
#   BONGSU_E2E_HEAVY=1         include slow tests (bundle export)

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERVER_URL="${1:-${BONGSU_E2E_BASE_URL:-http://localhost:5677}}"
API_KEY="${2:-${BONGSU_E2E_API_KEY:-${BONGSU_API_KEY:-}}}"

if [ -z "${API_KEY}" ]; then
    echo "Usage: $0 [server_url] [api_key]  (or set BONGSU_E2E_API_KEY)" >&2
    exit 2
fi

BONGSU_E2E_BASE_URL="${SERVER_URL}" BONGSU_E2E_API_KEY="${API_KEY}" \
    python3 "${ROOT}/tests/e2e/api_e2e.py"

echo "API E2E verification passed"
