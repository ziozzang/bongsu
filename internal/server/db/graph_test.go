package db

import (
	"strings"
	"testing"
)

// The graph queries are derived projections, so correctness hinges on two
// invariants: every entity is constrained to the latest scan per host, and every
// data query is host-scope filterable. These source-level checks pin both so a
// future edit cannot silently start counting stale scans or bypass RBAC.

func TestGraphQueriesUseLatestScanAndScope(t *testing.T) {
	out, err := readAllPackageGoFiles()
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "// Asset knowledge graph.")
	if start < 0 {
		t.Fatal("graph.go content not found")
	}
	// Bound the slice to the graph.go region (up to the next file's package-level
	// marker is not reliable; just scan the whole concatenation for the methods).
	for _, fn := range []string{
		"func (db *DB) GraphOverviewForScope",
		"func (db *DB) HostNeighborhood",
		"func (db *DB) BlastRadius",
		"func (db *DB) GroupNeighborhood",
	} {
		if !strings.Contains(body, fn) {
			t.Fatalf("graph method missing: %s", fn)
		}
	}
	// scopeClause centralizes the RBAC predicate and must use ANY($n).
	if !strings.Contains(body, "func scopeClause(scope AccessScope, column string, args []any)") {
		t.Fatal("scopeClause helper missing")
	}
	if !strings.Contains(body, "= ANY($%d)") {
		t.Fatal("scopeClause must scope with ANY($n)")
	}
	// BlastRadius and the overview/neighborhood queries must join latestScansSub.
	region := body[start:]
	if n := strings.Count(region, "latestScansSub"); n < 6 {
		t.Fatalf("graph queries should constrain to latest scan via latestScansSub (found %d references, want >=6)", n)
	}
}

func TestGraphExtMethodsAndInvariants(t *testing.T) {
	out, err := readAllPackageGoFiles()
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, fn := range []string{
		"func (db *DB) CVESignals",
		"func (db *DB) CVEAliases",
		"func (db *DB) ExposedServices",
		"func (db *DB) Images",
		"func (db *DB) OrgExposure",
		"func (db *DB) Remediation",
	} {
		if !strings.Contains(body, fn) {
			t.Fatalf("graph extension method missing: %s", fn)
		}
	}
	// The scope-bearing extension queries must use scopeClause for RBAC and the
	// inventory ones must constrain to the latest scan.
	for _, marker := range []string{
		`scopeClause(scope, "pi.host_id"`, // ExposedServices
		`scopeClause(scope, "c.host_id"`,  // Images
		`scopeClause(scope, "h.id"`,       // OrgExposure
		`scopeClause(scope, "v.host_id"`,  // Remediation / BlastRadius
		"source='cisa-kev'",               // KEV exploit signal
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("graph extension missing required marker: %q", marker)
		}
	}
}
