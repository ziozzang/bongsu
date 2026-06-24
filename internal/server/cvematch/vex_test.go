package cvematch

import (
	"encoding/json"
	"testing"
)

func TestVEXStateRoundTrip(t *testing.T) {
	// Bongsu status -> VEX state -> Bongsu status. Some are lossy (ignored ->
	// not_affected -> false_positive), which is expected and documented.
	cases := []struct {
		status   string
		wantBack string // status after a round trip through VEX
	}{
		{"false_positive", "false_positive"},
		{"fixed", "fixed"},
		{"in_progress", "in_progress"},
		{"accepted_risk", "accepted_risk"},
		{"ignored", "false_positive"}, // not_affected collapses to false_positive
	}
	for _, c := range cases {
		state, _, _ := vexStateForTriage(c.status)
		back, ok := triageFromVEXState(state)
		if !ok {
			t.Errorf("status %q -> state %q has no inverse", c.status, state)
			continue
		}
		if back != c.wantBack {
			t.Errorf("status %q -> state %q -> %q, want %q", c.status, state, back, c.wantBack)
		}
	}
}

func TestBuildAndParseCycloneDXVEX(t *testing.T) {
	stmts := []VEXStatement{
		{VulnerabilityID: "CVE-2024-1", ComponentPURL: "pkg:pypi/requests@2.19.1", PkgName: "requests", Status: "false_positive", Reason: "not in attack path"},
		{VulnerabilityID: "CVE-2024-2", PkgName: "openssl", Status: "accepted_risk", Reason: "mitigated by network policy"},
	}
	doc, err := BuildCycloneDXVEX(stmts, "2026-06-24T00:00:00Z")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Sanity: it is a CycloneDX doc with a vulnerabilities array.
	var probe struct {
		BOMFormat       string `json:"bomFormat"`
		Vulnerabilities []struct {
			ID       string `json:"id"`
			Analysis struct {
				State    string   `json:"state"`
				Response []string `json:"response"`
			} `json:"analysis"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(doc, &probe); err != nil {
		t.Fatalf("unmarshal built doc: %v", err)
	}
	if probe.BOMFormat != "CycloneDX" || len(probe.Vulnerabilities) != 2 {
		t.Fatalf("built doc wrong: %s", doc)
	}
	if probe.Vulnerabilities[0].Analysis.State != "false_positive" {
		t.Fatalf("CVE-2024-1 state = %q", probe.Vulnerabilities[0].Analysis.State)
	}
	if probe.Vulnerabilities[1].Analysis.State != "exploitable" || len(probe.Vulnerabilities[1].Analysis.Response) != 1 {
		t.Fatalf("CVE-2024-2 must be exploitable+will_not_fix: %+v", probe.Vulnerabilities[1].Analysis)
	}

	// Re-parse: states map back to Bongsu statuses, component purl preserved.
	parsed, err := ParseCycloneDXVEX(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("want 2 statements, got %d", len(parsed))
	}
	if parsed[0].VulnerabilityID != "CVE-2024-1" || parsed[0].Status != "false_positive" || parsed[0].ComponentPURL != "pkg:pypi/requests@2.19.1" {
		t.Fatalf("parsed[0] wrong: %+v", parsed[0])
	}
	if parsed[0].PkgName != "requests" {
		t.Fatalf("pkg_name property must round-trip: %+v", parsed[0])
	}
	if parsed[1].Status != "accepted_risk" {
		t.Fatalf("parsed[1] status = %q, want accepted_risk", parsed[1].Status)
	}
}

func TestParseVEXSkipsUnmappableAndIDLess(t *testing.T) {
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"vulnerabilities":[
	  {"id":"CVE-1","analysis":{"state":"resolved"}},
	  {"id":"","analysis":{"state":"false_positive"}},
	  {"id":"CVE-3","analysis":{"state":"weird_state"}}
	]}`
	stmts, err := ParseCycloneDXVEX([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(stmts) != 1 || stmts[0].VulnerabilityID != "CVE-1" || stmts[0].Status != "fixed" {
		t.Fatalf("only the resolvable, id-bearing statement should survive: %+v", stmts)
	}
}
