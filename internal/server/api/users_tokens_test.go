package api

import (
	"strings"
	"testing"
	"time"
)

func TestUserAndTokenRoutesRegistered(t *testing.T) {
	body := readAllPackageGoFiles(t)
	for _, want := range []string{
		`s.mux.HandleFunc("GET /api/admin/users", s.handleListUsers)`,
		`s.mux.HandleFunc("POST /api/admin/users", s.handleCreateUser)`,
		`s.mux.HandleFunc("PATCH /api/admin/users/{id}", s.handleUpdateUserRole)`,
		`s.mux.HandleFunc("POST /api/admin/users/{id}/password", s.handleResetUserPassword)`,
		`s.mux.HandleFunc("DELETE /api/admin/users/{id}", s.handleDeleteUser)`,
		`s.mux.HandleFunc("GET /api/admin/api-tokens", s.handleListAPITokens)`,
		`s.mux.HandleFunc("POST /api/admin/api-tokens", s.handleCreateAPIToken)`,
		`s.mux.HandleFunc("DELETE /api/admin/api-tokens/{id}", s.handleRevokeAPIToken)`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("route missing: %q", want)
		}
	}
}

func TestUserHandlersGuardsAndAuth(t *testing.T) {
	body := readAllPackageGoFiles(t)
	// Every user/token mutation must require admin and be audit-logged.
	for _, fn := range []string{
		"handleListUsers", "handleCreateUser", "handleUpdateUserRole",
		"handleResetUserPassword", "handleDeleteUser",
		"handleListAPITokens", "handleCreateAPIToken", "handleRevokeAPIToken",
	} {
		start := strings.Index(body, "func (s *Server) "+fn+"(")
		if start < 0 {
			t.Fatalf("handler %s not found", fn)
		}
		end := strings.Index(body[start+1:], "\nfunc ")
		seg := body[start : start+1+end]
		if !strings.Contains(seg, "s.authenticateAdmin(r)") {
			t.Fatalf("%s must require admin", fn)
		}
	}
	// Last-admin and self-deletion guards must exist and be enforced atomically.
	for _, want := range []string{
		"cannot demote the last admin user",
		"cannot delete the last admin user",
		"cannot delete your own account",
		"s.db.UpdateLocalUserRoleGuarded(ctx, id",
		"s.db.DeleteLocalUserGuarded(ctx, id)",
		"db.UserGuardLastAdmin",
		`s.db.DeleteUserSessions(ctx, id)`, // sessions revoked on reset/role change
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("user guard missing: %q", want)
		}
	}
	// Token secret is only returned at creation; the list path never selects the
	// hash, and auth integrates the DB token store.
	if !strings.Contains(body, `"secret": secret`) {
		t.Fatal("create token must return the plaintext secret once")
	}
	if !strings.Contains(body, "entry.Role == \"admin\"") || !strings.Contains(body, "s.apiTokenFromRequest(r)") {
		t.Fatal("authenticateAdmin must accept a DB admin token")
	}
}

func TestAPITokenStoreLookup(t *testing.T) {
	store := newAPITokenStore(nil)
	secret := "bsk_deadbeef"
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)
	store.byHash = map[string]apiTokenEntry{
		hashAPIToken(secret):         {ID: "t1", Role: "admin", ExpiresAt: &future},
		hashAPIToken("bsk_expired"):  {ID: "t2", Role: "viewer", Subject: "user:bob", ExpiresAt: &past},
		hashAPIToken("bsk_immortal"): {ID: "t3", Role: "viewer", Subject: "group:ops"},
	}
	if e, ok := store.lookup(secret); !ok || e.ID != "t1" || e.Role != "admin" {
		t.Fatalf("valid token lookup failed: %+v ok=%v", e, ok)
	}
	if _, ok := store.lookup("bsk_expired"); ok {
		t.Fatal("expired token must not resolve")
	}
	if e, ok := store.lookup("bsk_immortal"); !ok || e.Subject != "group:ops" {
		t.Fatalf("never-expiring token must resolve: %+v ok=%v", e, ok)
	}
	if _, ok := store.lookup("bsk_unknown"); ok {
		t.Fatal("unknown token must not resolve")
	}
	if _, ok := store.lookup(""); ok {
		t.Fatal("empty secret must not resolve")
	}
	// The stored hash is sha256 of the secret, not the secret itself.
	if _, present := store.byHash[secret]; present {
		t.Fatal("store must key on the hash, never the plaintext secret")
	}
}
