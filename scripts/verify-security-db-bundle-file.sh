#!/bin/bash
set -euo pipefail

# verify-security-db-bundle-file.sh - Validate a downloaded Bongsu security DB
# bundle before transferring it into an air-gapped environment.

BUNDLE="${1:-bongsu-security-db-bundle.tar.gz}"
REQUIRE_SIDECAR="${BONGSU_VERIFY_SECURITY_DB_BUNDLE_REQUIRE_SIDECAR:-true}"
REQUIRED_SOURCES="${BONGSU_VERIFY_SECURITY_DB_BUNDLE_REQUIRED_SOURCES:-cisa-kev,epss,osv,nvd,trivy}"
VALIDATE_JSONL="${BONGSU_VERIFY_SECURITY_DB_BUNDLE_VALIDATE_JSONL:-true}"

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: missing required tool: $1" >&2
        exit 1
    fi
}

require_tool tar
require_tool jq
require_tool sha256sum
require_tool wc
require_tool grep
require_tool sort
require_tool uniq

if [ ! -f "$BUNDLE" ]; then
    echo "ERROR: security DB bundle does not exist: $BUNDLE" >&2
    exit 1
fi

if [ "$REQUIRE_SIDECAR" = "true" ]; then
    if [ ! -f "${BUNDLE}.sha256" ]; then
        echo "ERROR: missing security DB bundle checksum sidecar: ${BUNDLE}.sha256" >&2
        exit 1
    fi
    (cd "$(dirname "$BUNDLE")" && sha256sum -c "$(basename "${BUNDLE}.sha256")")
fi

listing="$(tar -tzf "$BUNDLE")"
for entry in manifest.json cve-database.jsonl; do
    if [ "$(printf '%s\n' "$listing" | grep -xc "$entry")" -ne 1 ]; then
        echo "ERROR: bundle must contain exactly one $entry" >&2
        printf '%s\n' "$listing" >&2
        exit 1
    fi
done

duplicates="$(printf '%s\n' "$listing" | sort | uniq -d)"
if [ -n "$duplicates" ]; then
    echo "ERROR: bundle contains duplicate entries" >&2
    printf '%s\n' "$duplicates" >&2
    exit 1
fi

unexpected="$(printf '%s\n' "$listing" | grep -Ev '^(manifest\.json|cve-database\.jsonl|trivy-db\.tar\.gz)$' || true)"
if [ -n "$unexpected" ]; then
    echo "ERROR: bundle contains unexpected entries" >&2
    printf '%s\n' "$unexpected" >&2
    exit 1
fi

manifest_json="$(tar -xOzf "$BUNDLE" manifest.json)"
printf '%s\n' "$manifest_json" | jq -e '
  .format == "bongsu-security-db-bundle"
  and .version == 1
  and ((.created_at // "") | length > 0)
  and ((.security_db_revision // "") | length > 0)
  and ((.cve_records // 0) > 0)
  and ((.cve_database_sha256 // "") | test("^[0-9a-f]{64}$"))
  and (.trivy_db_included | type == "boolean")
  and (.sources | type == "array")
  and ((.sources | length) > 0)
' >/dev/null || {
    echo "ERROR: invalid security DB bundle manifest" >&2
    printf '%s\n' "$manifest_json" | jq . >&2 || true
    exit 1
}

created_at="$(printf '%s\n' "$manifest_json" | jq -r '.created_at')"
if ! date -u -d "$created_at" >/dev/null 2>&1; then
    echo "ERROR: invalid bundle created_at timestamp: $created_at" >&2
    exit 1
fi

IFS=',' read -ra required_sources <<< "$REQUIRED_SOURCES"
for source in "${required_sources[@]}"; do
    source="$(printf '%s' "$source" | xargs)"
    if [ -z "$source" ]; then
        continue
    fi
    if ! printf '%s\n' "$manifest_json" | jq -e --arg source "$source" '.sources[] | select(.source == $source and (.count // 0) > 0 and ((.last_update // "") | length > 0))' >/dev/null; then
        echo "ERROR: bundle manifest is missing required source with count/last_update: $source" >&2
        exit 1
    fi
done

expected_cve_sha="$(printf '%s\n' "$manifest_json" | jq -r '.cve_database_sha256')"
actual_cve_sha="$(tar -xOzf "$BUNDLE" cve-database.jsonl | sha256sum | awk '{print $1}')"
if [ "$actual_cve_sha" != "$expected_cve_sha" ]; then
    echo "ERROR: cve-database.jsonl checksum mismatch" >&2
    echo "manifest=$expected_cve_sha actual=$actual_cve_sha" >&2
    exit 1
fi

expected_records="$(printf '%s\n' "$manifest_json" | jq -r '.cve_records')"
actual_records="$(tar -xOzf "$BUNDLE" cve-database.jsonl | wc -l | tr -d '[:space:]')"
if [ "$actual_records" != "$expected_records" ]; then
    echo "ERROR: cve-database.jsonl record count mismatch" >&2
    echo "manifest=$expected_records actual=$actual_records" >&2
    exit 1
fi

if [ "$VALIDATE_JSONL" = "true" ]; then
    tar -xOzf "$BUNDLE" cve-database.jsonl | jq -c . >/dev/null
fi

trivy_included="$(printf '%s\n' "$manifest_json" | jq -r '.trivy_db_included')"
if [ "$trivy_included" = "true" ]; then
    if [ "$(printf '%s\n' "$listing" | grep -xc 'trivy-db.tar.gz')" -ne 1 ]; then
        echo "ERROR: manifest says Trivy DB is included but trivy-db.tar.gz is missing" >&2
        exit 1
    fi
    expected_trivy_sha="$(printf '%s\n' "$manifest_json" | jq -r '.trivy_db_sha256 // ""')"
    if ! printf '%s' "$expected_trivy_sha" | grep -Eq '^[0-9a-f]{64}$'; then
        echo "ERROR: invalid Trivy DB checksum in manifest" >&2
        exit 1
    fi
    actual_trivy_sha="$(tar -xOzf "$BUNDLE" trivy-db.tar.gz | sha256sum | awk '{print $1}')"
    if [ "$actual_trivy_sha" != "$expected_trivy_sha" ]; then
        echo "ERROR: trivy-db.tar.gz checksum mismatch" >&2
        echo "manifest=$expected_trivy_sha actual=$actual_trivy_sha" >&2
        exit 1
    fi
elif printf '%s\n' "$listing" | grep -qx 'trivy-db.tar.gz'; then
    echo "ERROR: trivy-db.tar.gz is present but manifest says Trivy DB is not included" >&2
    exit 1
fi

echo "Security DB bundle file verification passed"
printf 'Bundle: %s\n' "$BUNDLE"
printf 'Revision: %s\n' "$(printf '%s\n' "$manifest_json" | jq -r '.security_db_revision')"
printf 'CVE records: %s\n' "$expected_records"
printf 'Sources: %s\n' "$(printf '%s\n' "$manifest_json" | jq -r '[.sources[].source] | join(",")')"
