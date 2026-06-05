#!/bin/bash
set -euo pipefail

# verify-live-oidc-rbac.sh - Verify OIDC bearer JWT auth against a real
# Bongsu API process without changing the main live 5677 server.

API_PORT="${BONGSU_VERIFY_OIDC_API_PORT:-15677}"
API_BASE="http://127.0.0.1:${API_PORT}"
JWKS_PORT="${BONGSU_VERIFY_OIDC_JWKS_PORT:-15678}"
ISSUER="http://127.0.0.1:${JWKS_PORT}/issuer"
AUDIENCE="${BONGSU_VERIFY_OIDC_AUDIENCE:-bongsu-live-oidc}"
ADMIN_GROUP="${BONGSU_VERIFY_OIDC_ADMIN_GROUP:-security-admins}"
ADMIN_USER="${BONGSU_VERIFY_OIDC_ADMIN_USER:-oidc-admin@example.test}"
VIEWER_USER="${BONGSU_VERIFY_OIDC_VIEWER_USER:-oidc-viewer@example.test}"
CURL_MAX_TIME="${BONGSU_VERIFY_OIDC_CURL_MAX_TIME_SECONDS:-20}"
SERVER_BIN="${BONGSU_VERIFY_OIDC_SERVER_BIN:-}"
DB_DSN="${BONGSU_DB_DSN:-}"
TMP_DIR="$(mktemp -d)"
SERVER_PID=""
JWKS_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" >/dev/null 2>&1; then
        kill "$SERVER_PID" >/dev/null 2>&1 || true
        wait "$SERVER_PID" >/dev/null 2>&1 || true
    fi
    if [ -n "$JWKS_PID" ] && kill -0 "$JWKS_PID" >/dev/null 2>&1; then
        kill "$JWKS_PID" >/dev/null 2>&1 || true
        wait "$JWKS_PID" >/dev/null 2>&1 || true
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: missing required tool: $1" >&2
        exit 1
    fi
}

discover_db_dsn() {
    if [ -n "$DB_DSN" ]; then
        return
    fi
    local pid
    for pid in $(pgrep -f 'bongsu-server|cmd/server' 2>/dev/null || true); do
        if [ -r "/proc/${pid}/environ" ]; then
            DB_DSN="$(tr '\0' '\n' <"/proc/${pid}/environ" | sed -n 's/^BONGSU_DB_DSN=//p' | head -n1)"
            if [ -n "$DB_DSN" ]; then
                return
            fi
        fi
    done
    DB_DSN="postgres://bongsu:bongsu@localhost:5432/bongsu?sslmode=disable"
}

write_oidc_fixture_generator() {
    cat >"$TMP_DIR/generate-oidc-fixtures.go" <<'GO'
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"
)

func b64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func b64int(n *big.Int) string {
	return b64(n.Bytes())
}

func token(key *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := b64(h) + "." + b64(c)
	sum := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + b64(sig), nil
}

func write(path string, data string) {
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) != 8 {
		panic("usage: generator <outdir> <issuer> <audience> <admin-user> <viewer-user> <admin-group> <kid>")
	}
	out, issuer, audience, adminUser, viewerUser, adminGroup, kid := os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6], os.Args[7]
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	jwks := map[string]any{"keys": []map[string]any{{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   b64int(key.PublicKey.N),
		"e":   b64int(big.NewInt(int64(key.PublicKey.E))),
	}}}
	j, err := json.Marshal(jwks)
	if err != nil {
		panic(err)
	}
	write(out+"/jwks.json", string(j)+"\n")

	now := time.Now().Unix()
	base := func(user string, groups []string, aud any, exp int64) map[string]any {
		return map[string]any{
			"iss":                issuer,
			"aud":                aud,
			"preferred_username": user,
			"groups":             groups,
			"iat":                now,
			"nbf":                now - 60,
			"exp":                exp,
		}
	}
	for name, claims := range map[string]map[string]any{
		"admin.jwt":     base(adminUser, []string{adminGroup, "platform"}, []string{audience, "secondary-audience"}, now+3600),
		"viewer.jwt":    base(viewerUser, []string{"platform"}, audience, now+3600),
		"wrong-aud.jwt": base(adminUser, []string{adminGroup}, "wrong-audience", now+3600),
		"expired.jwt":   base(adminUser, []string{adminGroup}, audience, now-60),
	} {
		t, err := token(key, kid, claims)
		if err != nil {
			panic(err)
		}
		write(out+"/"+name, t+"\n")
	}
	fmt.Println("ok")
}
GO
}

wait_for_ready() {
    local deadline=$(( $(date +%s) + 60 ))
    local status
    while true; do
        status="$(curl -s --max-time 2 -o "$TMP_DIR/ready.json" -w "%{http_code}" "${API_BASE}/api/ready" || true)"
        if [ "$status" = "200" ]; then
            return
        fi
        if [ "$(date +%s)" -ge "$deadline" ]; then
            echo "ERROR: temporary OIDC API server did not become ready" >&2
            cat "$TMP_DIR/server.log" >&2 || true
            exit 1
        fi
        sleep 1
    done
}

assert_status() {
    local status="$1"
    local want="$2"
    local message="$3"
    local body="$4"
    if [ "$status" != "$want" ]; then
        echo "ERROR: ${message}: got HTTP ${status}, want ${want}" >&2
        cat "$body" >&2 || true
        exit 1
    fi
}

require_tool curl
require_tool go
require_tool jq
require_tool python3
discover_db_dsn

echo "=== Bongsu Live OIDC RBAC Verification ==="
echo "API: ${API_BASE}"
echo "Issuer: ${ISSUER}"
echo "Audience: ${AUDIENCE}"
echo "Admin group: ${ADMIN_GROUP}"

write_oidc_fixture_generator
go run "$TMP_DIR/generate-oidc-fixtures.go" "$TMP_DIR" "$ISSUER" "$AUDIENCE" "$ADMIN_USER" "$VIEWER_USER" "$ADMIN_GROUP" "bongsu-oidc-live-test" >/dev/null

(cd "$TMP_DIR" && python3 -m http.server "$JWKS_PORT" --bind 127.0.0.1 >"$TMP_DIR/jwks.log" 2>&1) &
JWKS_PID="$!"
sleep 1
curl -fsS --max-time "$CURL_MAX_TIME" "http://127.0.0.1:${JWKS_PORT}/jwks.json" >/dev/null

if [ -z "$SERVER_BIN" ]; then
    SERVER_BIN="$TMP_DIR/bongsu-server"
    CGO_ENABLED=0 go build -trimpath -o "$SERVER_BIN" ./cmd/server
fi

BONGSU_PORT="$API_PORT" \
BONGSU_DB_DSN="$DB_DSN" \
BONGSU_AUTO_MIGRATE=false \
BONGSU_WEB_AUTH=true \
BONGSU_API_KEY="bongsu-oidc-live-admin-access-0123456789" \
BONGSU_AGENT_API_KEY="bongsu-oidc-live-agent-access-0123456789" \
BONGSU_INSTALL_TOKEN="bongsu-oidc-live-install-access-0123456789" \
BONGSU_ALLOW_WEAK_SECRETS=false \
BONGSU_SECURITY_DB_SYNC_CMD="" \
BONGSU_SECURITY_DB_SYNC_ON_START=false \
BONGSU_TRIVY_PATH="$TMP_DIR/no-trivy" \
BONGSU_STARTUP_RECALC_TIMEOUT_SECONDS=1 \
BONGSU_WEB_DIST="$TMP_DIR/no-web-dist" \
BONGSU_OIDC_ISSUER="$ISSUER" \
BONGSU_OIDC_JWKS_URL="http://127.0.0.1:${JWKS_PORT}/jwks.json" \
BONGSU_OIDC_CLIENT_ID="$AUDIENCE" \
BONGSU_OIDC_SUBJECT_CLAIM=preferred_username \
BONGSU_OIDC_GROUPS_CLAIM=groups \
BONGSU_OIDC_ADMIN_GROUPS="$ADMIN_GROUP" \
"$SERVER_BIN" >"$TMP_DIR/server.log" 2>&1 &
SERVER_PID="$!"
wait_for_ready

admin_token="$(tr -d '\n' <"$TMP_DIR/admin.jwt")"
viewer_token="$(tr -d '\n' <"$TMP_DIR/viewer.jwt")"
wrong_aud_token="$(tr -d '\n' <"$TMP_DIR/wrong-aud.jwt")"
expired_token="$(tr -d '\n' <"$TMP_DIR/expired.jwt")"

echo "  checking unauthenticated admin access is rejected"
status="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$TMP_DIR/unauth.json" -w "%{http_code}" "${API_BASE}/api/admin/rbac/status")"
assert_status "$status" "401" "unauthenticated admin RBAC status" "$TMP_DIR/unauth.json"

echo "  checking wrong-audience and expired JWTs are rejected"
status="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$TMP_DIR/wrong-aud.json" -w "%{http_code}" -H "Authorization: Bearer ${wrong_aud_token}" "${API_BASE}/api/admin/rbac/status")"
assert_status "$status" "401" "wrong-audience OIDC token" "$TMP_DIR/wrong-aud.json"
status="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$TMP_DIR/expired.json" -w "%{http_code}" -H "Authorization: Bearer ${expired_token}" "${API_BASE}/api/admin/rbac/status")"
assert_status "$status" "401" "expired OIDC token" "$TMP_DIR/expired.json"

echo "  checking non-admin OIDC viewer authenticates web but not admin"
status="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$TMP_DIR/viewer-admin.json" -w "%{http_code}" -H "Authorization: Bearer ${viewer_token}" "${API_BASE}/api/admin/rbac/status")"
assert_status "$status" "401" "viewer OIDC token admin RBAC status" "$TMP_DIR/viewer-admin.json"
status="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$TMP_DIR/viewer-hosts.json" -w "%{http_code}" -H "Authorization: Bearer ${viewer_token}" "${API_BASE}/api/hosts")"
assert_status "$status" "200" "viewer OIDC token web hosts access" "$TMP_DIR/viewer-hosts.json"
jq -e 'type == "array" or (.items | type == "array")' "$TMP_DIR/viewer-hosts.json" >/dev/null || {
    echo "ERROR: viewer OIDC hosts response must be an array or contain an items array" >&2
    cat "$TMP_DIR/viewer-hosts.json" >&2
    exit 1
}

echo "  checking admin-group OIDC token authorizes admin RBAC status"
status="$(curl -sS --max-time "$CURL_MAX_TIME" -o "$TMP_DIR/admin-rbac.json" -w "%{http_code}" -H "Authorization: Bearer ${admin_token}" "${API_BASE}/api/admin/rbac/status")"
assert_status "$status" "200" "admin OIDC token RBAC status" "$TMP_DIR/admin-rbac.json"
jq -e --arg admin_group "$ADMIN_GROUP" '
  .status == "ok"
  and .auth.oidc_configured == true
  and .auth.oidc_jwks_configured == true
  and .auth.oidc_admin_group_count >= 1
  and (.stats.subject_count | type == "number")
' "$TMP_DIR/admin-rbac.json" >/dev/null || {
    echo "ERROR: OIDC admin RBAC status response missing expected auth counters" >&2
    cat "$TMP_DIR/admin-rbac.json" >&2
    exit 1
}

echo "  checking local API key admin auth still works with OIDC enabled"
curl -fsS --max-time "$CURL_MAX_TIME" -H "X-API-Key: bongsu-oidc-live-admin-access-0123456789" "${API_BASE}/api/admin/rbac/status" >"$TMP_DIR/api-key-rbac.json"
jq -e '.status == "ok" and .auth.oidc_configured == true' "$TMP_DIR/api-key-rbac.json" >/dev/null || {
    echo "ERROR: local API key admin auth did not work with OIDC enabled" >&2
    cat "$TMP_DIR/api-key-rbac.json" >&2
    exit 1
}

echo "Live OIDC RBAC verification passed"
