package api

import (
	"net"
	"net/http"
	"testing"
)

// Behavioral tests for the unified credential resolver over the env-credential
// sources (bootstrap admin key, agent key, install token, legacy viewer key).
// DB/session/OIDC sources are exercised by the live + handler tests.
func TestResolvePrincipalEnvSources(t *testing.T) {
	s := &Server{
		apiKey:       "admin-key",
		agentKey:     "agent-key",
		installToken: "install-tok",
		viewerKeys:   map[string]string{"viewer-key": "user:alice"},
	}
	req := func(apiKey, installTok string) *http.Request {
		r, _ := http.NewRequest("GET", "/", nil)
		if apiKey != "" {
			r.Header.Set("X-API-Key", apiKey)
		}
		if installTok != "" {
			r.Header.Set("X-Install-Token", installTok)
		}
		return r
	}

	t.Run("bootstrap admin key", func(t *testing.T) {
		p := s.resolvePrincipal(req("admin-key", ""))
		if !p.Admin || !p.has(ScopeAdmin) || p.Kind != "bootstrap" {
			t.Fatalf("admin key must grant admin: %+v", p)
		}
		// admin implies every scope via has()
		if !p.has(ScopeViewer) || !p.has(ScopeAgent) || !p.has(ScopeExport) {
			t.Fatalf("admin must imply all scopes: %+v", p)
		}
	})

	t.Run("agent key", func(t *testing.T) {
		p := s.resolvePrincipal(req("agent-key", ""))
		if p.Admin || !p.has(ScopeAgent) {
			t.Fatalf("agent key must grant only agent: %+v", p)
		}
		if p.Scopes[ScopeAdmin] {
			t.Fatalf("agent key must not grant admin: %+v", p)
		}
	})

	t.Run("legacy viewer key", func(t *testing.T) {
		p := s.resolvePrincipal(req("viewer-key", ""))
		if p.Admin {
			t.Fatalf("viewer key must not be admin: %+v", p)
		}
		if !p.has(ScopeViewer) || !p.has(ScopeExport) {
			t.Fatalf("viewer key must grant viewer+export: %+v", p)
		}
		if len(p.Subjects) != 1 || p.Subjects[0] != "user:alice" {
			t.Fatalf("viewer key must carry its RBAC subject: %+v", p)
		}
	})

	t.Run("install token", func(t *testing.T) {
		p := s.resolvePrincipal(req("", "install-tok"))
		if p.Admin || !p.has(ScopeInstall) {
			t.Fatalf("install token must grant only install: %+v", p)
		}
	})

	t.Run("anonymous", func(t *testing.T) {
		p := s.resolvePrincipal(req("bogus", ""))
		if p.authenticated() || p.has(ScopeAdmin) || p.has(ScopeViewer) || p.has(ScopeAgent) {
			t.Fatalf("unknown credential must be anonymous: %+v", p)
		}
	})

	t.Run("empty agent key never matches empty", func(t *testing.T) {
		s2 := &Server{apiKey: "admin-key"} // agentKey == ""
		// A request with no key must not accidentally match the empty agentKey.
		p := s2.resolvePrincipal(req("", ""))
		if p.has(ScopeAgent) || p.has(ScopeAdmin) {
			t.Fatalf("empty credentials must grant nothing: %+v", p)
		}
	})

	t.Run("additive install capability does not change identity", func(t *testing.T) {
		// A legacy viewer key (identity) plus a valid install token (capability):
		// the principal stays the viewer identity AND gains ScopeInstall.
		p := s.resolvePrincipal(req("viewer-key", "install-tok"))
		if p.Kind != "viewer-key" {
			t.Fatalf("identity must remain viewer-key, not be replaced by install: %+v", p)
		}
		if !p.has(ScopeViewer) || !p.has(ScopeInstall) {
			t.Fatalf("viewer identity must keep viewer scope and gain install: %+v", p)
		}
		if p.Admin {
			t.Fatalf("a narrow capability must never confer admin: %+v", p)
		}
	})
}

// The core security property of the redesign: identities are FIRST-WINS and are
// never unioned across trust domains. A lower-priority identity present on the
// same request must not contribute its Admin flag or its RBAC subjects.
func TestResolvePrincipalFirstWinsNoEscalation(t *testing.T) {
	_, loopback, _ := net.ParseCIDR("127.0.0.0/8")
	s := &Server{
		apiKey:     "boot-admin",
		viewerKeys: map[string]string{"vk-alice": "user:alice"},
		trustedAuth: trustedIdentityConfig{
			userHeader:  "X-Auth-User",
			adminUsers:  map[string]bool{}, // bob is a plain viewer via the proxy
			adminGroups: map[string]bool{},
			proxyNets:   []*net.IPNet{loopback},
		},
	}
	newReq := func() *http.Request {
		r, _ := http.NewRequest("GET", "/", nil)
		r.RemoteAddr = "127.0.0.1:5555" // inside the trusted proxy network
		return r
	}

	t.Run("trusted viewer wins over lower-priority viewer-key; subjects do not merge", func(t *testing.T) {
		r := newReq()
		r.Header.Set("X-Auth-User", "bob")    // source 4 (trusted), subject user:bob
		r.Header.Set("X-API-Key", "vk-alice") // source 6 (viewer-key), subject user:alice
		p := s.resolvePrincipal(r)
		if p.Kind != "trusted" {
			t.Fatalf("higher-priority trusted identity must win: %+v", p)
		}
		if !p.MultiIdentity {
			t.Fatalf("two identities present must be flagged MultiIdentity: %+v", p)
		}
		// The escalation that the old UNION semantics caused: subjects merging.
		for _, sub := range p.Subjects {
			if sub == "user:alice" {
				t.Fatalf("lower-priority viewer-key subject must NOT merge in: %+v", p.Subjects)
			}
		}
		if len(p.Subjects) != 1 || p.Subjects[0] != "user:bob" {
			t.Fatalf("subjects must come only from the selected identity: %+v", p.Subjects)
		}
	})

	t.Run("selected admin identity is not polluted by a lower source's subjects", func(t *testing.T) {
		// X-API-Key matches BOTH the bootstrap admin key path is impossible (one
		// header value), so drive bootstrap via its key and the viewer-key via a
		// second distinct identity: bootstrap (1) is selected; the viewer-key (6)
		// subject user:alice must NOT leak into the admin principal's Subjects.
		r := newReq()
		r.Header.Set("X-API-Key", "boot-admin") // source 1 bootstrap admin
		r.Header.Set("X-Auth-User", "carol")    // source 4 trusted (lower than 1)
		p := s.resolvePrincipal(r)
		if p.Kind != "bootstrap" || !p.Admin {
			t.Fatalf("bootstrap admin must win: %+v", p)
		}
		if len(p.Subjects) != 0 {
			t.Fatalf("admin identity must not absorb a lower source's subjects: %+v", p.Subjects)
		}
		if !p.MultiIdentity {
			t.Fatalf("bootstrap + trusted are two identities: %+v", p)
		}
	})
}
