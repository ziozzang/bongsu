package api

import (
	"strings"
	"testing"
)

// The graph endpoints are RBAC-scoped, read-only projections. These tests pin the
// route wiring, the static ontology contract, and the scope/auth guards so the
// UI's assumptions about node/edge types and access control cannot silently drift.

func TestGraphRoutesRegistered(t *testing.T) {
	body := readAllPackageGoFiles(t)
	for _, want := range []string{
		`s.mux.HandleFunc("GET /api/graph/schema", s.handleGraphSchema)`,
		`s.mux.HandleFunc("GET /api/graph/overview", s.handleGraphOverview)`,
		`s.mux.HandleFunc("GET /api/graph/blast-radius", s.handleGraphBlastRadius)`,
		`s.mux.HandleFunc("GET /api/graph/host/{id}", s.handleGraphHost)`,
		`s.mux.HandleFunc("GET /api/graph/group/{id}", s.handleGraphGroup)`,
		`s.mux.HandleFunc("GET /api/graph/cve/{id}", s.handleGraphCVE)`,
		`s.mux.HandleFunc("GET /api/graph/exposure", s.handleGraphExposure)`,
		`s.mux.HandleFunc("GET /api/graph/images", s.handleGraphImages)`,
		`s.mux.HandleFunc("GET /api/graph/org", s.handleGraphOrg)`,
		`s.mux.HandleFunc("GET /api/graph/remediation", s.handleGraphRemediation)`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("graph route missing: %q", want)
		}
	}
}

func TestGraphHandlersAuthAndScope(t *testing.T) {
	body := readAllPackageGoFiles(t)
	for _, fn := range []string{
		"handleGraphSchema", "handleGraphOverview", "handleGraphBlastRadius",
		"handleGraphHost", "handleGraphGroup", "handleGraphCVE",
		"handleGraphExposure", "handleGraphImages", "handleGraphOrg", "handleGraphRemediation",
	} {
		start := strings.Index(body, "func (s *Server) "+fn+"(")
		if start < 0 {
			t.Fatalf("handler %s not found", fn)
		}
		end := strings.Index(body[start+1:], "\nfunc ")
		seg := body[start:]
		if end > 0 {
			seg = body[start : start+1+end]
		}
		if !strings.Contains(seg, "s.authenticateWeb(r)") {
			t.Fatalf("%s must require authenticateWeb", fn)
		}
	}
	// The data-bearing handlers must derive an RBAC scope, not query unscoped.
	for _, fn := range []string{"handleGraphOverview", "handleGraphBlastRadius", "handleGraphHost", "handleGraphGroup",
		"handleGraphExposure", "handleGraphImages", "handleGraphOrg", "handleGraphRemediation"} {
		start := strings.Index(body, "func (s *Server) "+fn+"(")
		end := strings.Index(body[start+1:], "\nfunc ")
		seg := body[start : start+1+end]
		if !strings.Contains(seg, "s.accessScope(r)") {
			t.Fatalf("%s must apply s.accessScope(r)", fn)
		}
	}
}

func TestGraphOntologyContract(t *testing.T) {
	// node types and relations the UI legend depends on.
	wantNodes := map[string]bool{"host": false, "container": false, "package": false, "service": false, "cve": false, "group": false}
	for _, n := range graphOntologyNodeTypes {
		if _, ok := wantNodes[n.Type]; !ok {
			t.Fatalf("unexpected node type %q", n.Type)
		}
		wantNodes[n.Type] = true
		if n.Label == "" || n.Description == "" {
			t.Fatalf("node type %q missing label/description", n.Type)
		}
	}
	for nt, seen := range wantNodes {
		if !seen {
			t.Fatalf("ontology missing node type %q", nt)
		}
	}
	wantRels := map[string]bool{"runs": false, "installs": false, "contains": false, "exposes": false, "member_of": false, "affected_by": false, "exposed_to": false}
	for _, rel := range graphOntologyRelations {
		if _, ok := wantRels[rel.Rel]; !ok {
			t.Fatalf("unexpected relation %q", rel.Rel)
		}
		wantRels[rel.Rel] = true
		if rel.Src == "" || rel.Dst == "" {
			t.Fatalf("relation %q missing src/dst", rel.Rel)
		}
	}
	for r, seen := range wantRels {
		if !seen {
			t.Fatalf("ontology missing relation %q", r)
		}
	}
}
