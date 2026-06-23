package api

import (
	"context"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ziozzang/bongsu/internal/server/db"
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

	// IdentityKey is the normalized key (e.g. "user:alice") of the selected
	// identity, used to decide whether other sources prove the SAME identity.
	IdentityKey string
	// Enriched is true when a same-identity source contributed extra RBAC
	// subjects to the first-wins identity (subjects-only union; never scope/admin).
	Enriched bool
	// Rejected is true when the request presented two DIFFERENT identities and the
	// reject-mismatch policy denied it. A rejected principal carries no effective
	// authority (Admin=false, empty Scopes/Subjects) so every gate returns 401.
	Rejected     bool
	RejectReason string
	// Decisions is the per-source audit trail (selected / enriched / ignored /
	// rejected / capability) recorded for every credential the request presented.
	Decisions []AuthDecision
}

// SourceDecision is how buildPrincipal treated one presented credential source.
type SourceDecision string

const (
	SourceSelected             SourceDecision = "selected"                   // Pass1 first-wins identity
	SourceEnrichedSameIdentity SourceDecision = "enriched_same_identity"     // same identity, added subjects
	SourceIgnoredSameIdentity  SourceDecision = "ignored_same_identity"      // same identity, no new subjects
	SourceRejectedMismatch     SourceDecision = "rejected_identity_mismatch" // different identity -> deny
	SourceAddedCapability      SourceDecision = "added_capability"           // agent/install scope added
	SourceIgnoredCapability    SourceDecision = "ignored_capability"         // capability not applied
)

// SourceMatch is one credential source that authenticated on a request. Kind/ID
// mirror Principal; Selected marks the one source that actually determined the
// principal's identity (or the additive capability that was applied).
type SourceMatch struct {
	Kind        string
	ID          string
	Admin       bool
	Scopes      []Scope
	Subjects    []string
	Selected    bool
	IdentityKey string         // normalized identity key (identity sources only)
	Decision    SourceDecision // how this source was treated
	Reason      string         // audit detail for ignore/reject
}

// AuthDecision is the compact, serializable audit record for one source.
type AuthDecision struct {
	Kind        string         `json:"kind"`
	ID          string         `json:"id"`
	IdentityKey string         `json:"identity_key,omitempty"`
	Decision    SourceDecision `json:"decision"`
	Reason      string         `json:"reason,omitempty"`
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
	if p == nil || p.Rejected {
		return false
	}
	if p.Admin {
		return true
	}
	return p.Scopes[s]
}

func (p *Principal) authenticated() bool {
	return p != nil && !p.Rejected && (p.Admin || len(p.Scopes) > 0 || len(p.Subjects) > 0)
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

// buildPrincipal applies the escalation-safe identity policy (Phase A v2) to the
// raw set of matched sources and records a per-source audit trail:
//
//   - Pass 0 normalizes subjects and computes each identity source's IdentityKey.
//   - Pass 1 selects the single highest-priority IDENTITY (first-wins) and then,
//     for each *additional* identity source, either ENRICHES the selected
//     identity with extra RBAC subjects (only when it proves the SAME identity —
//     never adding scope or admin) or, when it proves a DIFFERENT identity and
//     the reject-mismatch policy is on, REJECTS the whole request (401). A
//     rejected principal is stripped of all effective authority.
//   - Pass 2 adds the narrow agent/install capabilities (skipped entirely if the
//     request was rejected).
//   - Pass 3 derives ScopeExport.
func (s *Server) buildPrincipal(r *http.Request, matches []SourceMatch) *Principal {
	p := &Principal{Kind: "anonymous", Scopes: map[Scope]bool{}}

	// Pass 0 — normalize subjects + identity keys.
	for i := range matches {
		matches[i].Subjects = normalizeSubjects(matches[i].Subjects)
		if key, ok := identityKeyForSource(matches[i]); ok {
			matches[i].IdentityKey = key
		}
	}

	// Pass 1 — first-wins identity + same-identity enrichment / mismatch reject.
	var selected *SourceMatch
	identityCount := 0
	for i := range matches {
		m := &matches[i]
		if !isIdentityKind(m.Kind) {
			continue
		}
		identityCount++
		if selected == nil {
			selected = m
			m.Selected = true
			m.Decision = SourceSelected
			p.Kind, p.ID, p.Admin = m.Kind, m.ID, m.Admin
			p.IdentityKey = m.IdentityKey
			for _, sc := range m.Scopes {
				p.Scopes[sc] = true
			}
			p.Subjects = unionSubjects(nil, m.Subjects)
			continue
		}

		// A second (or later) identity matched.
		if s.authEnrichSameIdentity && sameIdentity(*selected, *m) {
			before := len(p.Subjects)
			p.Subjects = unionSubjects(p.Subjects, m.Subjects)
			if len(p.Subjects) != before {
				m.Decision = SourceEnrichedSameIdentity
				m.Reason = "subjects_union_only"
				p.Enriched = true
			} else {
				m.Decision = SourceIgnoredSameIdentity
				m.Reason = "same_identity_no_new_subjects"
			}
			continue
		}

		// Different identity (or enrichment disabled): never union. Reject when the
		// policy is on; otherwise fall back to legacy first-wins-ignore.
		if s.authRejectMismatch {
			m.Decision = SourceRejectedMismatch
			m.Reason = "identity_mismatch"
			p.Rejected = true
			p.RejectReason = "multiple distinct identity credentials presented"
		} else {
			m.Decision = SourceIgnoredSameIdentity
			m.Reason = "ignored_mismatch_reject_disabled"
		}
	}
	p.MultiIdentity = identityCount > 1

	if p.Rejected {
		clearEffectiveAuth(p)
	} else {
		// Pass 2 — additive narrow capabilities (agent/install). These never carry
		// Admin or subjects, so they cannot widen the selected identity.
		for i := range matches {
			m := &matches[i]
			if isIdentityKind(m.Kind) {
				continue
			}
			if p.Admin {
				m.Decision = SourceIgnoredCapability
				m.Reason = "admin_implies_all"
				continue
			}
			m.Selected = true
			m.Decision = SourceAddedCapability
			for _, sc := range m.Scopes {
				p.Scopes[sc] = true
			}
			if p.Kind == "anonymous" {
				p.Kind, p.ID = m.Kind, m.ID
			}
		}

		// Pass 3 — viewer + subjects are read capabilities; any read principal can export.
		if p.has(ScopeViewer) || len(p.Subjects) > 0 {
			p.Scopes[ScopeExport] = true
		}
	}

	p.Presented = matches
	p.Decisions = auditDecisions(matches)
	s.logAuthDecision(r, p)
	return p
}

// clearEffectiveAuth strips a rejected principal of all authority while keeping
// Kind/ID and the audit trail for forensics.
func clearEffectiveAuth(p *Principal) {
	p.Admin = false
	p.Scopes = map[Scope]bool{}
	p.Subjects = nil
}

// auditDecisions projects the matched sources into the compact audit records.
func auditDecisions(matches []SourceMatch) []AuthDecision {
	if len(matches) == 0 {
		return nil
	}
	out := make([]AuthDecision, 0, len(matches))
	for _, m := range matches {
		d := m.Decision
		if d == "" {
			d = SourceIgnoredCapability
		}
		out = append(out, AuthDecision{Kind: m.Kind, ID: m.ID, IdentityKey: m.IdentityKey, Decision: d, Reason: m.Reason})
	}
	return out
}

// logAuthDecision emits a structured audit line for any non-trivial resolution
// (rejection, enrichment, or multi-identity) and best-effort persists it to the
// auth_events table. Single-source requests are silent. The DB write is async and
// non-fatal: an audit-store failure never affects the auth decision.
func (s *Server) logAuthDecision(r *http.Request, p *Principal) {
	if !p.Rejected && !p.Enriched && !p.MultiIdentity {
		return
	}
	requestID := requestIDFromRequest(r)
	switch {
	case p.Rejected:
		log.Printf("auth reject request_id=%s reason=%q presented=%v",
			requestID, p.RejectReason, presentedIdentityKinds(p.Presented))
	case p.Enriched:
		log.Printf("auth enrich request_id=%s identity=%s subjects=%v",
			requestID, p.IdentityKey, p.Subjects)
	default:
		log.Printf("auth multi-identity request_id=%s selected=%s presented=%v",
			requestID, p.Kind, presentedIdentityKinds(p.Presented))
	}
	s.persistAuthEvent(r, requestID, p)
}

// persistAuthEvent asynchronously writes the audit record. Request fields are
// captured synchronously (r must not be touched after the handler returns); the
// write runs on a background context so a finished request doesn't cancel it.
func (s *Server) persistAuthEvent(r *http.Request, requestID string, p *Principal) {
	if s == nil || s.db == nil {
		return
	}
	ev := db.AuthEvent{
		RequestID:     requestID,
		RemoteAddr:    r.RemoteAddr,
		Method:        r.Method,
		Path:          r.URL.Path,
		FinalKind:     p.Kind,
		FinalID:       p.ID,
		FinalAdmin:    p.Admin,
		FinalIdentity: p.IdentityKey,
		Rejected:      p.Rejected,
		RejectReason:  p.RejectReason,
		MultiIdentity: p.MultiIdentity,
		Enriched:      p.Enriched,
		Presented:     p.Presented,
		Decisions:     p.Decisions,
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.db.InsertAuthEvent(ctx, ev); err != nil {
			log.Printf("auth audit write failed request_id=%s: %v", requestID, err)
		}
	}()
}

func presentedIdentityKinds(matches []SourceMatch) []string {
	kinds := make([]string, 0, len(matches))
	for _, m := range matches {
		if isIdentityKind(m.Kind) {
			kinds = append(kinds, m.Kind)
		}
	}
	return kinds
}

// identityKeyForSource computes the normalized identity key for an identity
// source: a user:* subject if present, else Kind+ID. Capability sources have no
// identity key.
func identityKeyForSource(m SourceMatch) (string, bool) {
	if !isIdentityKind(m.Kind) {
		return "", false
	}
	if u := primaryUserSubject(m.Subjects); u != "" {
		return u, true
	}
	if m.ID != "" {
		return m.Kind + ":" + strings.ToLower(strings.TrimSpace(m.ID)), true
	}
	return "", false
}

// sameIdentity reports whether two identity sources prove the SAME principal.
// bootstrap is always treated as an isolated identity (any other identity
// alongside it is a mismatch). Otherwise a shared user:* subject is authoritative;
// failing that, an identical Kind+ID.
func sameIdentity(a, b SourceMatch) bool {
	if !isIdentityKind(a.Kind) || !isIdentityKind(b.Kind) {
		return false
	}
	if a.Kind == "bootstrap" || b.Kind == "bootstrap" {
		return false // break-glass key never merges with any other identity
	}
	au, bu := primaryUserSubject(a.Subjects), primaryUserSubject(b.Subjects)
	if au != "" && bu != "" {
		return au == bu
	}
	if a.Kind == b.Kind && a.ID != "" && b.ID != "" {
		return strings.EqualFold(strings.TrimSpace(a.ID), strings.TrimSpace(b.ID))
	}
	return false
}

// primaryUserSubject returns a lowercased "user:<name>" key for the first
// user:* subject, or "". The lowercasing is for case-insensitive IDENTITY
// comparison only — it is never written back into a Principal's Subjects, which
// must preserve their original case for the case-sensitive RBAC external_id match.
func primaryUserSubject(subjects []string) string {
	for _, s := range subjects {
		s = strings.TrimSpace(s)
		if strings.HasPrefix(strings.ToLower(s), "user:") {
			return strings.ToLower(s)
		}
	}
	return ""
}

// normalizeSubjects preserves subject VALUES (case and bare, colon-less names
// like a legacy viewer-key "alice" are kept — RBAC matches external_id exactly),
// dropping only blanks and exact duplicates and sorting for determinism. It does
// NOT lowercase or require a "kind:" prefix; subject normalization for identity
// comparison happens separately in primaryUserSubject.
func normalizeSubjects(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// unionSubjects merges b into a, dedups (case-sensitive) and re-sorts.
func unionSubjects(a, b []string) []string {
	merged := append(append([]string(nil), a...), b...)
	return normalizeSubjects(merged)
}
