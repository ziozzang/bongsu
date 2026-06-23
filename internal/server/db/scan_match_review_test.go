package db

import "testing"

// Tests for the scanning-mechanism review fixes: each guards a specific
// false-negative/false-positive correctness improvement in the CVE matcher.

// #1 — a ranges-only advisory that encodes the affected window with
// last_affected (no fixed version, e.g. an unpatched vuln) must still match.
// Previously the len(fixedVersions)==0 pre-gate dropped it before versionInRange
// (which understands last_affected) ever ran.
func TestCompatibleSecurityCandidateMatchesLastAffectedOnlyRange(t *testing.T) {
	affected := `[{"name":"foo","ecosystem":"npm","ranges":[{"events":[{"introduced":"0"},{"last_affected":"4.9.9"}]}]}]`
	if _, ok := compatibleSecurityCandidate("foo", "npm", "npm", "4.5.0", "code-library", "", affected); !ok {
		t.Fatal("install inside a last_affected-only range must match (unfixed-vuln false negative)")
	}
	if _, ok := compatibleSecurityCandidate("foo", "npm", "npm", "5.0.0", "code-library", "", affected); ok {
		t.Fatal("install above last_affected must NOT match")
	}
}

// #2 — multiple fixed versions with no ranges == per-branch backports. The
// matcher must flag an install below its OWN branch's fix without flagging an
// install already at/above its branch's fix.
func TestVersionIsAffectedMultiBranchFixes(t *testing.T) {
	p := affectedProduct{Fixed: []string{"1.2.8", "1.3.4"}}
	cases := []struct {
		installed string
		want      bool
		why       string
	}{
		{"1.2.5", true, "below the 1.2 branch fix"},
		{"1.2.9", false, "at/above the 1.2 branch fix (patched)"},
		{"1.3.0", true, "below the 1.3 branch fix"},
		{"1.3.4", false, "exactly the 1.3 branch fix (patched)"},
		{"1.1.0", true, "predates all branches -> below the lowest fix"},
		{"2.0.0", false, "above every branch fix"},
	}
	for _, c := range cases {
		if got := versionIsAffected("npm", c.installed, p); got != c.want {
			t.Fatalf("versionIsAffected(%s) = %v, want %v (%s)", c.installed, got, c.want, c.why)
		}
	}
}

// #5 — a detector that sets pkg_type but leaves ecosystem empty (e.g. a bare jar)
// must still match a Maven advisory via the type->ecosystem fallback.
func TestCompatibleSecurityCandidateDerivesEcosystemFromType(t *testing.T) {
	affected := `[{"name":"log4j-core","ecosystem":"Maven","fixed":["2.17.0"]}]`
	if _, ok := compatibleSecurityCandidate("log4j-core", "jar", "", "2.14.0", "code-library", "Maven", affected); !ok {
		t.Fatal("jar with empty ecosystem must match a Maven advisory (type-derived ecosystem)")
	}
	if _, ok := compatibleSecurityCandidate("log4j-core", "jar", "", "2.17.1", "code-library", "Maven", affected); ok {
		t.Fatal("patched jar must not match")
	}
}

// #8 — a CPE exact-version field carrying a wildcard tail ("1.2.*") must match
// any patch of that minor, not require literal equality (which never hits).
func TestCpeVersionAffectedWildcardExact(t *testing.T) {
	p := affectedProduct{Version: "1.2.*"}
	if !cpeVersionAffected("1.2.3", p) {
		t.Fatal("1.2.3 must match the 1.2.* wildcard exact")
	}
	if !cpeVersionAffected("1.2.0", p) {
		t.Fatal("1.2.0 must match 1.2.*")
	}
	if cpeVersionAffected("1.3.0", p) {
		t.Fatal("1.3.0 must NOT match 1.2.*")
	}
	if cpeVersionAffected("1.20.0", p) {
		t.Fatal("1.20.0 must NOT match 1.2.* (segment-boundary, not string prefix)")
	}
}

// OSV ranges may encode several disjoint affected intervals in one event list,
// and the schema requires consumers to process events in ascending version order.
// versionInRange must sort first — iterating the raw (possibly unsorted) order
// previously gave wrong answers for multi-interval ranges.
func TestVersionInRangeSortsMultiInterval(t *testing.T) {
	// Two intervals [1.0,1.2) and [3.0,3.5) with events deliberately NOT globally
	// sorted (both introduceds before both fixeds).
	unsorted := []affectedRangeEvent{
		{Introduced: "1.0"},
		{Introduced: "3.0"},
		{Fixed: "3.5"},
		{Fixed: "1.2"},
	}
	cases := []struct {
		v    string
		want bool
	}{
		{"1.1", true},  // inside first interval — the regression case
		{"1.2", false}, // exactly the first fix
		{"2.0", false}, // between intervals
		{"3.2", true},  // inside second interval
		{"3.5", false}, // exactly the second fix
		{"4.0", false}, // above all
		{"0.9", false}, // below all
	}
	for _, c := range cases {
		if got := versionInRange("npm", c.v, unsorted); got != c.want {
			t.Fatalf("versionInRange(%s) over unsorted multi-interval = %v, want %v", c.v, got, c.want)
		}
	}
	// Same intervals already sorted must give identical answers.
	sorted := []affectedRangeEvent{
		{Introduced: "1.0"}, {Fixed: "1.2"}, {Introduced: "3.0"}, {Fixed: "3.5"},
	}
	for _, c := range cases {
		if got := versionInRange("npm", c.v, sorted); got != c.want {
			t.Fatalf("versionInRange(%s) over sorted multi-interval = %v, want %v", c.v, got, c.want)
		}
	}
}

func TestVersionLineage(t *testing.T) {
	cases := map[string]string{
		"1.2.3":          "1.2",
		"1.2":            "1.2",
		"1:1.1.1k-14.el8": "1.1",
		"v2.0.0-rc1":     "2.0",
		"1":              "", // only one numeric segment -> no lineage
		"abc":            "",
	}
	for in, want := range cases {
		if got := versionLineage(in); got != want {
			t.Fatalf("versionLineage(%q) = %q, want %q", in, got, want)
		}
	}
}
