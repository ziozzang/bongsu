package api

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOIDCTokenVerifierMapsJWTToRBACSubjectsAndAdmin(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{testRSAJWK("kid-1", &key.PublicKey)}})
	}))
	defer jwks.Close()

	v := &oidcTokenVerifier{
		issuer:       "https://issuer.example.test",
		clientID:     "bongsu",
		jwksURL:      jwks.URL,
		subjectClaim: "preferred_username",
		groupsClaim:  "groups",
		adminUsers:   map[string]bool{},
		adminGroups:  map[string]bool{"security-admins": true},
		httpClient:   jwks.Client(),
		now:          func() time.Time { return time.Unix(1000, 0) },
	}
	token := testOIDCToken(t, key, "kid-1", map[string]any{
		"iss":                "https://issuer.example.test",
		"sub":                "subject-123",
		"preferred_username": "alice",
		"aud":                []string{"other", "bongsu"},
		"exp":                int64(1100),
		"nbf":                int64(900),
		"groups":             []string{"developers", "security-admins"},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/admin/rbac/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	s := &Server{oidcAuth: v, webAuth: true}

	if !s.authenticateAdmin(req) {
		t.Fatal("OIDC admin group should authorize admin access")
	}
	subjects := s.viewerSubjects(req)
	for _, want := range []string{"user:alice", "group:developers", "group:security-admins"} {
		if !containsString(subjects, want) {
			t.Fatalf("OIDC subjects missing %q: %#v", want, subjects)
		}
	}
	if got := s.actorType(req); got != "admin" {
		t.Fatalf("actor type = %q, want admin", got)
	}
}

func TestOIDCTokenVerifierRejectsWrongAudience(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{testRSAJWK("kid-1", &key.PublicKey)}})
	}))
	defer jwks.Close()
	v := &oidcTokenVerifier{
		issuer:       "https://issuer.example.test",
		clientID:     "bongsu",
		jwksURL:      jwks.URL,
		subjectClaim: "sub",
		groupsClaim:  "groups",
		adminUsers:   map[string]bool{"subject-123": true},
		adminGroups:  map[string]bool{},
		httpClient:   jwks.Client(),
		now:          func() time.Time { return time.Unix(1000, 0) },
	}
	token := testOIDCToken(t, key, "kid-1", map[string]any{
		"iss": "https://issuer.example.test",
		"sub": "subject-123",
		"aud": "wrong-client",
		"exp": int64(1100),
	})
	if _, err := v.verify(context.Background(), token); err == nil {
		t.Fatal("wrong audience token should be rejected")
	}
}

func testOIDCToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func testRSAJWK(kid string, key *rsa.PublicKey) map[string]string {
	e := big.NewInt(int64(key.E)).Bytes()
	return map[string]string{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(e),
	}
}
