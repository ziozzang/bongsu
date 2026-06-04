#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SPEC="$ROOT/internal/server/api/openapi.yaml"
DOC_SPEC="$ROOT/docs/openapi.yaml"

echo "=== OpenAPI Specification Verification ==="

# Check spec file exists
if [ ! -f "$SPEC" ]; then
    echo "FAIL: openapi.yaml not found at $SPEC"
    exit 1
fi
echo "OK: Spec file exists ($SPEC)"

if [ ! -f "$DOC_SPEC" ]; then
    echo "FAIL: documentation openapi.yaml not found at $DOC_SPEC"
    exit 1
fi
echo "OK: Documentation spec file exists ($DOC_SPEC)"

# Validate YAML syntax
if ! python3 -c "import yaml; yaml.safe_load(open('$SPEC'))" 2>/dev/null; then
    echo "FAIL: openapi.yaml is not valid YAML"
    exit 1
fi
echo "OK: Valid YAML"

if ! cmp -s "$SPEC" "$DOC_SPEC"; then
    echo "FAIL: docs/openapi.yaml is out of sync with internal/server/api/openapi.yaml"
    exit 1
fi
echo "OK: Documentation spec is synchronized"

# Check all routes from api.go are documented
ROUTES=$(grep -oP 'HandleFunc\("\K[^"]+' "$ROOT/internal/server/api/api.go" | grep '^/' | sort -u)
MISSING=0
for route in $ROUTES; do
    # Skip the catch-all dashboard route
    if [ "$route" = "/" ]; then
        continue
    fi
    # Convert route pattern to OpenAPI path format ({id} stays as {id})
    if ! grep -q "$route" "$SPEC" 2>/dev/null; then
        echo "MISSING: $route not found in openapi.yaml"
        MISSING=$((MISSING + 1))
    fi
done
if [ "$MISSING" -gt 0 ]; then
    echo "FAIL: $MISSING routes not documented in openapi.yaml"
    exit 1
fi
echo "OK: All routes documented"

# Verify //go:embed reference exists
if ! grep -q 'go:embed openapi.yaml' "$ROOT/internal/server/api/api.go"; then
    echo "FAIL: //go:embed openapi.yaml not found in api.go"
    exit 1
fi
echo "OK: Embedded in Go binary"

echo "OpenAPI verification passed"
