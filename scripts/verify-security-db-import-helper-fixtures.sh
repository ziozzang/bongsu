#!/bin/bash
set -euo pipefail

# verify-security-db-import-helper-fixtures.sh - Exercise the security DB bundle
# import helper's pre-upload local bundle verification behavior.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d)"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

mkdir -p "$TMP_DIR/scripts" "$TMP_DIR/bin" "$TMP_DIR/out"
cp "$ROOT/scripts/import-security-db-bundle.sh" "$TMP_DIR/scripts/import-security-db-bundle.sh"
chmod +x "$TMP_DIR/scripts/import-security-db-bundle.sh"

cat >"$TMP_DIR/scripts/verify-security-db-bundle-file.sh" <<'EOF'
#!/bin/bash
set -euo pipefail
printf 'verify %s\n' "$1" >> "${BONGSU_FIXTURE_VERIFY_LOG:?}"
if [ "${BONGSU_FIXTURE_VERIFY_FAIL:-false}" = "true" ]; then
    echo "fixture bundle verification failure" >&2
    exit 32
fi
echo "fixture bundle verification ok"
EOF
chmod +x "$TMP_DIR/scripts/verify-security-db-bundle-file.sh"

cat >"$TMP_DIR/bin/curl" <<'EOF'
#!/bin/bash
set -euo pipefail
printf 'curl %s\n' "$*" >> "${BONGSU_FIXTURE_CURL_LOG:?}"
echo '{"status":"ok"}'
EOF
chmod +x "$TMP_DIR/bin/curl"

export PATH="$TMP_DIR/bin:$PATH"

bundle="$TMP_DIR/out/security-db.tar.gz"
printf 'fixture bundle\n' >"$bundle"
verify_log="$TMP_DIR/verify.log"
curl_log="$TMP_DIR/curl.log"

BONGSU_FIXTURE_VERIFY_LOG="$verify_log" \
BONGSU_FIXTURE_CURL_LOG="$curl_log" \
    "$TMP_DIR/scripts/import-security-db-bundle.sh" http://fixture.invalid fixture-key "$bundle" >"$TMP_DIR/success.out"
grep -q "verify $bundle" "$verify_log"
grep -q 'bundle=@' "$curl_log"
grep -q 'Import submitted' "$TMP_DIR/success.out"

>"$verify_log"
>"$curl_log"
if BONGSU_FIXTURE_VERIFY_FAIL=true \
    BONGSU_FIXTURE_VERIFY_LOG="$verify_log" \
    BONGSU_FIXTURE_CURL_LOG="$curl_log" \
    "$TMP_DIR/scripts/import-security-db-bundle.sh" http://fixture.invalid fixture-key "$bundle" >"$TMP_DIR/fail.out" 2>"$TMP_DIR/fail.err"; then
    echo "ERROR: import helper should fail when local bundle verification fails" >&2
    exit 1
fi
grep -q "verify $bundle" "$verify_log"
if [ -s "$curl_log" ]; then
    echo "ERROR: import helper uploaded a bundle after failed local verification" >&2
    cat "$curl_log" >&2
    exit 1
fi

>"$verify_log"
>"$curl_log"
BONGSU_BUNDLE_VERIFY_BEFORE_IMPORT=false \
BONGSU_FIXTURE_VERIFY_LOG="$verify_log" \
BONGSU_FIXTURE_CURL_LOG="$curl_log" \
    "$TMP_DIR/scripts/import-security-db-bundle.sh" http://fixture.invalid fixture-key "$bundle" >"$TMP_DIR/skip.out"
if [ -s "$verify_log" ]; then
    echo "ERROR: import helper should skip local verification when explicitly disabled" >&2
    cat "$verify_log" >&2
    exit 1
fi
grep -q 'bundle=@' "$curl_log"

echo "Security DB import helper fixture verification passed"
