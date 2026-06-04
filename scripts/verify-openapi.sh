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

python3 - "$SPEC" <<'PY'
import sys
import yaml

spec_path = sys.argv[1]
with open(spec_path, "r", encoding="utf-8") as f:
    spec = yaml.safe_load(f)

allowed_public = {
    ("post", "/api/auth/login"),
    ("get", "/api/health"),
    ("get", "/api/ready"),
    ("get", "/api/live"),
    ("get", "/api/docs/openapi.yaml"),
}

expected = {
    ("post", "/api/report"): {"AgentKey"},
    ("post", "/api/agent/scan-requests/claim"): {"AgentKey"},
    ("post", "/api/agent/scan-requests/{id}/complete"): {"AgentKey"},
    ("get", "/api/install.sh"): {"InstallToken", "AdminKey"},
    ("get", "/api/downloads/bongsu-agent"): {"InstallToken", "AdminKey"},
    ("get", "/api/downloads/trivy"): {"InstallToken", "AdminKey"},
}

failures = []
for path, item in sorted((spec.get("paths") or {}).items()):
    for method, op in sorted(item.items()):
        if method.startswith("x-") or method == "parameters":
            continue
        if not isinstance(op, dict):
            continue
        key = (method.lower(), path)
        security = op.get("security")
        schemes = {name for entry in (security or []) for name in entry.keys()}
        if key in allowed_public:
            continue
        if not security:
            failures.append(f"{method.upper()} {path} is not an allowed public endpoint and has no security requirement")
            continue
        if path.startswith("/api/admin/") and "AdminKey" not in schemes:
            failures.append(f"{method.upper()} {path} must require AdminKey")
        if path.startswith("/api/agent/") and "AgentKey" not in schemes:
            failures.append(f"{method.upper()} {path} must require AgentKey")
        if key in expected and not expected[key].issubset(schemes):
            failures.append(f"{method.upper()} {path} must include {sorted(expected[key])}, got {sorted(schemes)}")
        if path.endswith("/export") or path.endswith("/sbom"):
            if "AdminKey" not in schemes and "ViewerKey" not in schemes:
                failures.append(f"{method.upper()} {path} export surface must require AdminKey or ViewerKey")

if failures:
    print("FAIL: OpenAPI security requirements are incomplete", file=sys.stderr)
    for failure in failures:
        print(f"  - {failure}", file=sys.stderr)
    sys.exit(1)
print("OK: Sensitive OpenAPI operations declare security requirements")
PY

# Verify //go:embed reference exists
if ! grep -q 'go:embed openapi.yaml' "$ROOT/internal/server/api/api.go"; then
    echo "FAIL: //go:embed openapi.yaml not found in api.go"
    exit 1
fi
echo "OK: Embedded in Go binary"

echo "OpenAPI verification passed"
