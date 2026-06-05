#!/bin/bash
set -euo pipefail

# verify-security-db-export-helper-fixtures.sh - Exercise the security DB bundle
# export helper's local file-publish behavior without requiring a live API.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d)"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

mkdir -p "$TMP_DIR/scripts" "$TMP_DIR/bin" "$TMP_DIR/out"
cp "$ROOT/scripts/export-security-db-bundle.sh" "$TMP_DIR/scripts/export-security-db-bundle.sh"
chmod +x "$TMP_DIR/scripts/export-security-db-bundle.sh"

cat >"$TMP_DIR/scripts/verify-live-security-db-export-freshness.sh" <<'EOF'
#!/bin/bash
set -euo pipefail
counter_file="${BONGSU_FIXTURE_VERIFY_COUNTER_FILE:-}"
if [ -n "$counter_file" ]; then
    count=0
    if [ -f "$counter_file" ]; then
        count="$(cat "$counter_file")"
    fi
    count=$((count + 1))
    printf '%s\n' "$count" >"$counter_file"
    if [ "$count" -le "${BONGSU_FIXTURE_VERIFY_FAIL_ATTEMPTS:-0}" ]; then
        echo "fixture delayed freshness failure" >&2
        exit 24
    fi
fi
if [ "${BONGSU_FIXTURE_VERIFY_FAIL:-false}" = "true" ]; then
    echo "fixture freshness failure" >&2
    exit 23
fi
echo "fixture freshness ok"
EOF
chmod +x "$TMP_DIR/scripts/verify-live-security-db-export-freshness.sh"

cat >"$TMP_DIR/bin/curl" <<'EOF'
#!/bin/bash
set -euo pipefail
out=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o)
            shift
            out="${1:-}"
            ;;
    esac
    shift || true
done
if [ -z "$out" ]; then
    echo "missing -o output" >&2
    exit 2
fi
printf 'fixture security db bundle\n' >"$out"
EOF
chmod +x "$TMP_DIR/bin/curl"

assert_no_tmp_outputs() {
    local pattern="$1"
    if find "$TMP_DIR/out" -maxdepth 1 -name "$pattern" | grep -q .; then
        echo "ERROR: temporary export files were not cleaned up" >&2
        find "$TMP_DIR/out" -maxdepth 1 -name "$pattern" >&2
        exit 1
    fi
}

export PATH="$TMP_DIR/bin:$PATH"

success_out="$TMP_DIR/out/security-db-ok.tar.gz"
"$TMP_DIR/scripts/export-security-db-bundle.sh" http://fixture.invalid fixture-key "$success_out" >/"$TMP_DIR/success.out"
grep -q 'fixture security db bundle' "$success_out"
sha256sum -c "$success_out.sha256" >/dev/null
assert_no_tmp_outputs '.security-db-ok.tar.gz.tmp.*'

retry_out="$TMP_DIR/out/security-db-retry.tar.gz"
retry_counter="$TMP_DIR/retry.counter"
BONGSU_FIXTURE_VERIFY_COUNTER_FILE="$retry_counter" \
BONGSU_FIXTURE_VERIFY_FAIL_ATTEMPTS=1 \
BONGSU_BUNDLE_VERIFY_FRESHNESS_ATTEMPTS=3 \
BONGSU_BUNDLE_VERIFY_FRESHNESS_RETRY_SECONDS=0 \
    "$TMP_DIR/scripts/export-security-db-bundle.sh" http://fixture.invalid fixture-key "$retry_out" >/"$TMP_DIR/retry.out" 2>"$TMP_DIR/retry.err"
grep -q 'fixture security db bundle' "$retry_out"
grep -q 'Export freshness not visible yet; retrying' "$TMP_DIR/retry.err"
if [ "$(cat "$retry_counter")" != "2" ]; then
    echo "ERROR: export helper did not retry delayed freshness verification" >&2
    exit 1
fi
sha256sum -c "$retry_out.sha256" >/dev/null
assert_no_tmp_outputs '.security-db-retry.tar.gz.tmp.*'

fail_out="$TMP_DIR/out/security-db-fail.tar.gz"
printf 'previous bundle\n' >"$fail_out"
sha256sum "$fail_out" >"$fail_out.sha256"
previous_sum="$(cut -d' ' -f1 "$fail_out.sha256")"
if BONGSU_FIXTURE_VERIFY_FAIL=true \
    BONGSU_BUNDLE_VERIFY_FRESHNESS_ATTEMPTS=2 \
    BONGSU_BUNDLE_VERIFY_FRESHNESS_RETRY_SECONDS=0 \
    "$TMP_DIR/scripts/export-security-db-bundle.sh" http://fixture.invalid fixture-key "$fail_out" >/"$TMP_DIR/fail.out" 2>"$TMP_DIR/fail.err"; then
    echo "ERROR: export helper should fail when freshness verification fails" >&2
    exit 1
fi
grep -q 'exported bundle freshness verification failed after 2 attempts' "$TMP_DIR/fail.err"
grep -q 'previous bundle' "$fail_out"
current_sum="$(sha256sum "$fail_out" | cut -d' ' -f1)"
if [ "$current_sum" != "$previous_sum" ]; then
    echo "ERROR: failed freshness verification overwrote the existing final bundle" >&2
    exit 1
fi
sha256sum -c "$fail_out.sha256" >/dev/null
assert_no_tmp_outputs '.security-db-fail.tar.gz.tmp.*'

echo "Security DB export helper fixture verification passed"
