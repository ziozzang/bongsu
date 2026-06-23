package api

import (
	"context"
	"log"
	"net/http"
	"sync"
)

// Scope is a coarse capability a principal may hold. RBAC host scoping is layered
// on top via Subjects + AccessScope.
type Scope string

const (
	ScopeAdmin   Scope = "admin"   // full administrative control
	ScopeViewer  Scope = "viewer"  // read access (further narrowed by RBAC subjects)
	ScopeAgent   Scope = "agent"   // agent report ingest
	ScopeInstall Scope = "install" // installer script + binary downloads
	ScopeExport  Scope = "export"  // bulk data export
)

// Principal is the unified, resolved-once identity of a request's caller. Every
// credential source — bootstrap key, DB API token, session, trusted header,
// OIDC, agent key, install token, legacy viewer key — is normalized into this
// one shape, and ALL authorization reads from it. This replaces the previously
// scattered authenticate{Admin,Web,Agent,Install,Export}/viewerSubjects paths
// with a single resolution + capability model.
type Principal struct {
	Kind     string         // bootstrap|token|session|trusted|oidc|viewer-key|agent|install|anonymous
	ID       string         // stable identity for audit (token:<id>, user:<id>, host:<id>, ...)
	Admin    bool           // convenience: holds ScopeAdmin
	Scopes   map[Scope]bool // capabilities granted
	Subjects []string       // RBAC subjects (user:alice, group:platform)

	// Presented records EVERY credential source detected on the request, including
	// the ones that did NOT determine the principal. Authorization reads only the
	// single selected identity (first-wins, see resolvePrincipal); Presented exists
	// purely so the audit log can show what else the caller offered.
	Presented []SourceMatch
	// MultiIdentity is true when more than one distinct *identity* source matched
	// (e.g. a viewer session AND a trusted-proxy admin header). Such requests used
	// to silently union into an escalated principal; they no longer do, but they
	// are flagged so operators can detect credential confusion / spoofing attempts.
	MultiIdentity bool
}

// SourceMatch is one credential source that authenticated on a request. Kind/ID
// mirror Principal; Selected marks the one source that actually determined the
// principal's identity (or the additive capability that was applied).
type SourceMatch struct {
	Kind     string
	ID       string
	Admin    bool
	Scopes   []Scope
	Subjects []string
	Selected bool
}

// identitySources are the credential kinds that assert WHO the caller is and may
// therefore carry Admin and RBAC subjects. Exactly one of these is selected per
// request (highest priority wins); they are never unioned. agent/install are NOT
// here — they are narrow, separately-keyed machine capabilities (see below).
func isIdentityKind(kind string) bool {
	switch kind {
	case "bootstrap", "token", "session", "trusted", "oidc", "viewer-key":
		return true
	}
	return false
}

func (p *Principal) has(s Scope) bool {
	if p == nil {
		return false
	}
	if p.Admin {
		return true
	}
	return p.Scopes[s]
}

func (p *Principal) authenticated() bool {
	return p != nil && (p.Admin || len(p.Scopes) > 0 || len(p.Subjects) > 0)
}

type principalCacheKey struct{}

type principalCache struct {
	mu   sync.Mutex
	done bool
	p    *Principal
}

// principalCacheMiddleware memoizes the resolved principal for the request so the
// (potentially DB/OIDC-touching) resolution runs at most once per request.
func (s *Server) principalCacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), principalCacheKey{}, &principalCache{})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// principal returns the caller's unified Principal, memoized per request.
func (s *Server) principal(r *http.Request) *Principal {
	if c, ok := r.Context().Value(principalCacheKey{}).(*principalCache); ok {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.done {
			return c.p
		}
		c.p = s.resolvePrincipal(r)
		c.done = true
		return c.p
	}
	return s.resolvePrincipal(r)
}

// resolvePrincipal evaluates every credential source ONCE and builds the caller's
// principal under a strict, escalation-safe policy (designed via the jikji Trinity
// multi-model design panel, which flagged the previous union semantics as a
// cross-trust-domain privilege escalation):
//
//   - IDENTITY is first-wins. The six identity sources (bootstrap > token >
//     session > trusted > oidc > viewer-key, in that priority) are evaluated, but
//     only the single highest-priority match determines Kind/ID/Admin/Scopes/
//     Subjects. Identities are NEVER unioned: a viewer session presented alongside
//     a spoofed trusted-proxy "admin" header yields the viewer, not an admin, and
//     two different RBAC subjects from two sources never merge into a wider scope.
//   - CAPABILITIES are additive but narrow. The agent key and install token live
//     in their own dedicated, separately-secret-gated inputs and only ever grant
//     their single scope (ScopeAgent / ScopeInstall) — never Admin, never RBAC
//     subjects — so adding them to whatever identity also proved it cannot widen
//     data access. If no identity matched, the capability also names the principal.
//
// DB tokens are the primary rotatable path; env keys are bootstrap/break-glass.
func (s *Server) resolvePrincipal(r *http.Request) *Principal {
	key := r.Header.Get("X-API-Key")
	var matches []SourceMatch
	add := func(kind, id string, admin bool, scopes []Scope, subjects []string) {
		matches = append(matches, SourceMatch{Kind: kind, ID: id, Admin: admin, Scopes: scopes, Subjects: subjects})
	}

	// 1. Bootstrap break-glass admin key (env BONGSU_API_KEY). Documented as
	//    bootstrap-only; rotatable DB tokens are the operational path.
	if s.apiKey != "" && s.matchKey(key, s.apiKey) {
		add("bootstrap", "bootstrap:admin", true, []Scope{ScopeAdmin}, nil)
	}

	// 2. DB-backed API token (X-API-Key or Authorization: Bearer): rotatable,
	//    scoped, expiring, audited — the primary credential model.
	if entry, ok := s.apiTokenFromRequest(r); ok {
		switch entry.Role {
		case "admin":
			add("token", "token:"+entry.ID, true, []Scope{ScopeAdmin}, nil)
		case "viewer":
			var subs []string
			if entry.Subject != "" {
				subs = []string{entry.Subject}
			}
			add("token", "token:"+entry.ID, false, []Scope{ScopeViewer}, subs)
		}
	}

	// 3. Session user. The RBAC subject is keyed by username (the access-subject
	//    external_id convention, matching trusted/OIDC), NOT the internal UUID, so
	//    a local viewer actually receives any host scopes granted to user:<name>.
	//    (Audit ID stays the stable UUID.)
	if u := s.sessionUser(r); u != nil {
		subject := "user:" + u.Username
		if u.Role == "admin" {
			add("session", "user:"+u.ID, true, []Scope{ScopeAdmin}, []string{subject})
		} else {
			add("session", "user:"+u.ID, false, []Scope{ScopeViewer}, []string{subject})
		}
	}

	// 4. Trusted reverse-proxy identity header (gated by proxy-network CIDR).
	if ti := s.trustedIdentity(r); ti.User != "" || len(ti.Subjects) > 0 || ti.Admin {
		if ti.Admin {
			add("trusted", "trusted:"+ti.User, true, []Scope{ScopeAdmin}, ti.Subjects)
		} else {
			add("trusted", "trusted:"+ti.User, false, []Scope{ScopeViewer}, ti.Subjects)
		}
	}

	// 5. OIDC bearer token.
	if oi := s.oidcIdentity(r); len(oi.Subjects) > 0 || oi.Admin {
		if oi.Admin {
			add("oidc", "oidc", true, []Scope{ScopeAdmin}, oi.Subjects)
		} else {
			add("oidc", "oidc", false, []Scope{ScopeViewer}, oi.Subjects)
		}
	}

	// 6. Legacy env viewer keys (deprecated; prefer DB viewer tokens).
	if key != "" {
		if subject := s.viewerKeys[key]; subject != "" {
			add("viewer-key", "viewer:"+subject, false, []Scope{ScopeViewer}, []string{subject})
		}
	}

	// 7. Agent credential (env agent key, or bootstrap admin key as fallback) —
	//    additive narrow capability, in the shared X-API-Key input.
	if s.matchKey(key, s.agentKey) || (s.apiKey != "" && s.matchKey(key, s.apiKey)) {
		add("agent", "agent", false, []Scope{ScopeAgent}, nil)
	}

	// 8. Installer token — additive narrow capability, in its own X-Install-Token.
	if tok := r.Header.Get("X-Install-Token"); tok != "" && s.installToken != "" && s.matchKey(tok, s.installToken) {
		add("install", "install", false, []Scope{ScopeInstall}, nil)
	}

	return s.buildPrincipal(r, matches)
}

// buildPrincipal applies the first-wins-identity + additive-capability policy to
// the raw set of matched sources and records every match for audit.
func (s *Server) buildPrincipal(r *http.Request, matches []SourceMatch) *Principal {
	p := &Principal{Kind: "anonymous", Scopes: map[Scope]bool{}}

	// Pass 1 — select the single highest-priority IDENTITY source. matches are
	// appended in priority order, so the first identity match is authoritative.
	identityChosen := false
	identityCount := 0
	for i := range matches {
		m := &matches[i]
		if !isIdentityKind(m.Kind) {
			continue
		}
		identityCount++
		if identityChosen {
			continue // a higher-priority identity already won; never union.
		}
		identityChosen = true
		m.Selected = true
		p.Kind, p.ID, p.Admin = m.Kind, m.ID, m.Admin
		for _, sc := range m.Scopes {
			p.Scopes[sc] = true
		}
		p.Subjects = append(p.Subjects, m.Subjects...)
	}
	p.MultiIdentity = identityCount > 1

	// Pass 2 — apply additive narrow capabilities (agent/install). These never
	// carry Admin or subjects, so they cannot widen the selected identity.
	for i := range matches {
		m := &matches[i]
		if isIdentityKind(m.Kind) {
			continue
		}
		m.Selected = true
		for _, sc := range m.Scopes {
			p.Scopes[sc] = true
		}
		if p.Kind == "anonymous" {
			p.Kind, p.ID = m.Kind, m.ID
		}
	}

	// Viewer + subjects are read capabilities; any read principal can export.
	if p.has(ScopeViewer) || len(p.Subjects) > 0 {
		p.Scopes[ScopeExport] = true
	}

	p.Presented = matches
	if p.MultiIdentity {
		// Credential confusion: the request carried two+ distinct identities. We
		// did not escalate (first-wins), but surface it for detection/forensics.
		kinds := make([]string, 0, len(matches))
		for _, m := range matches {
			if isIdentityKind(m.Kind) {
				kinds = append(kinds, m.Kind)
			}
		}
		log.Printf("auth multi-identity request_id=%s selected=%s presented=%v",
			requestIDFromRequest(r), p.Kind, kinds)
	}
	return p
}
