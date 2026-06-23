package api

import (
	"net/http"
	"reflect"
	"testing"
)

// Phase A v2: same-identity subject enrichment + cross-identity reject. These
// drive buildPrincipal directly with the policy flags ON (production default via
// New()); the legacy flags-off path is covered by TestResolvePrincipalFirstWinsNoEscalation.
func v2Server() *Server {
	return &Server{authEnrichSameIdentity: true, authRejectMismatch: true}
}

func dummyReq() *http.Request {
	r, _ := http.NewRequest("GET", "/", nil)
	return r
}

func TestBuildPrincipalV2(t *testing.T) {
	s := v2Server()

	t.Run("same user session+oidc enriches subjects only", func(t *testing.T) {
		p := s.buildPrincipal(dummyReq(), []SourceMatch{
			{Kind: "session", ID: "user:alice", Scopes: []Scope{ScopeViewer}, Subjects: []string{"user:alice"}},
			{Kind: "oidc", ID: "oidc", Scopes: []Scope{ScopeViewer, ScopeAdmin}, Admin: true, Subjects: []string{"user:alice", "group:eng"}},
		})
		if p.Rejected {
			t.Fatalf("same identity must not be rejected: %+v", p)
		}
		if p.Kind != "session" || p.Admin {
			t.Fatalf("first-wins identity (non-admin session) must stand, no admin escalation: %+v", p)
		}
		if !p.Enriched {
			t.Fatalf("expected Enriched=true: %+v", p)
		}
		want := []string{"group:eng", "user:alice"} // normalized + sorted
		if !reflect.DeepEqual(p.Subjects, want) {
			t.Fatalf("subjects = %v, want %v (union of same-identity subjects)", p.Subjects, want)
		}
		// Scope must come only from the selected source — oidc's ScopeAdmin must NOT leak.
		if p.Scopes[ScopeAdmin] {
			t.Fatalf("enrichment must never add scope/admin: %+v", p.Scopes)
		}
		if !p.has(ScopeViewer) || !p.has(ScopeExport) {
			t.Fatalf("viewer+export expected: %+v", p.Scopes)
		}
	})

	t.Run("different user is rejected and stripped of authority", func(t *testing.T) {
		p := s.buildPrincipal(dummyReq(), []SourceMatch{
			{Kind: "session", ID: "user:alice", Scopes: []Scope{ScopeViewer}, Subjects: []string{"user:alice"}},
			{Kind: "trusted", ID: "trusted:bob", Admin: true, Scopes: []Scope{ScopeAdmin}, Subjects: []string{"user:bob"}},
		})
		if !p.Rejected || p.RejectReason == "" {
			t.Fatalf("cross-identity must be rejected: %+v", p)
		}
		if p.authenticated() || p.has(ScopeViewer) || p.has(ScopeAdmin) || len(p.Subjects) != 0 {
			t.Fatalf("rejected principal must carry no authority: %+v", p)
		}
	})

	t.Run("bootstrap is isolated and rejects any co-presented identity", func(t *testing.T) {
		p := s.buildPrincipal(dummyReq(), []SourceMatch{
			{Kind: "bootstrap", ID: "bootstrap:admin", Admin: true, Scopes: []Scope{ScopeAdmin}},
			{Kind: "session", ID: "user:alice", Scopes: []Scope{ScopeViewer}, Subjects: []string{"user:alice"}},
		})
		if !p.Rejected {
			t.Fatalf("bootstrap + another identity must reject: %+v", p)
		}
	})

	t.Run("rejected request also drops narrow capabilities", func(t *testing.T) {
		p := s.buildPrincipal(dummyReq(), []SourceMatch{
			{Kind: "session", ID: "user:alice", Subjects: []string{"user:alice"}},
			{Kind: "trusted", ID: "trusted:bob", Subjects: []string{"user:bob"}},
			{Kind: "install", ID: "install", Scopes: []Scope{ScopeInstall}},
		})
		if p.has(ScopeInstall) {
			t.Fatalf("a rejected request must not retain the install capability: %+v", p)
		}
	})

	t.Run("single identity + capability is unaffected", func(t *testing.T) {
		p := s.buildPrincipal(dummyReq(), []SourceMatch{
			{Kind: "session", ID: "user:alice", Scopes: []Scope{ScopeViewer}, Subjects: []string{"user:alice"}},
			{Kind: "agent", ID: "agent", Scopes: []Scope{ScopeAgent}},
		})
		if p.Rejected || p.Kind != "session" {
			t.Fatalf("one identity + capability must resolve cleanly: %+v", p)
		}
		if !p.has(ScopeViewer) || !p.has(ScopeAgent) || !p.has(ScopeExport) {
			t.Fatalf("viewer identity must keep viewer+export and gain agent: %+v", p.Scopes)
		}
	})

	t.Run("same identity with no new subjects is ignored not enriched", func(t *testing.T) {
		p := s.buildPrincipal(dummyReq(), []SourceMatch{
			{Kind: "session", ID: "user:alice", Scopes: []Scope{ScopeViewer}, Subjects: []string{"user:alice"}},
			{Kind: "oidc", ID: "oidc", Scopes: []Scope{ScopeViewer}, Subjects: []string{"user:alice"}},
		})
		if p.Rejected || p.Enriched {
			t.Fatalf("identical subjects must be a no-op (not enriched, not rejected): %+v", p)
		}
		if d := p.Decisions[1].Decision; d != SourceIgnoredSameIdentity {
			t.Fatalf("second source decision = %q, want ignored_same_identity", d)
		}
	})
}

// The escape hatch: with reject disabled, a cross-identity request falls back to
// legacy first-wins-ignore instead of 401.
func TestBuildPrincipalRejectEscapeHatch(t *testing.T) {
	s := &Server{authEnrichSameIdentity: false, authRejectMismatch: false}
	p := s.buildPrincipal(dummyReq(), []SourceMatch{
		{Kind: "session", ID: "user:alice", Scopes: []Scope{ScopeViewer}, Subjects: []string{"user:alice"}},
		{Kind: "trusted", ID: "trusted:bob", Admin: true, Scopes: []Scope{ScopeAdmin}, Subjects: []string{"user:bob"}},
	})
	if p.Rejected {
		t.Fatalf("with reject disabled, cross-identity must fall back to first-wins, not reject: %+v", p)
	}
	if p.Kind != "session" || p.Admin {
		t.Fatalf("first-wins session must stand and not absorb trusted admin: %+v", p)
	}
	if !p.MultiIdentity {
		t.Fatalf("multi-identity must still be flagged for audit: %+v", p)
	}
}
