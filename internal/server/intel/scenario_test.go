package intel

import (
	"strings"
	"testing"
)

func TestScenariosRegistered(t *testing.T) {
	reg := NewScenarioRegistry()
	RegisterScenarios(reg)
	want := []string{"campaign", "correlate", "nl_query", "remediate", "report", "triage", "verify"}
	got := reg.Names()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("scenarios = %v, want %v", got, want)
	}
}

// Every tool a scenario requires must be a real registered tool — otherwise a
// run would inject a tool the MCP server can't serve. This keeps the scenario
// and tool registries consistent.
func TestScenarioRequiredToolsExist(t *testing.T) {
	known := map[string]bool{
		"advisory_for": true, "exposure_lookup": true,
		"query_vulns": true, "dependents_of": true, "sbom_at": true, "asset_graph": true,
	}
	sreg := NewScenarioRegistry()
	RegisterScenarios(sreg)
	for _, name := range sreg.Names() {
		s, _ := sreg.Get(name)
		if len(s.RequiredTools) == 0 {
			t.Errorf("scenario %q declares no tools", name)
		}
		for _, tool := range s.RequiredTools {
			if !known[tool] {
				t.Errorf("scenario %q requires unknown tool %q", name, tool)
			}
		}
		if s.MaxSteps <= 0 || s.Timeout <= 0 {
			t.Errorf("scenario %q has non-positive budget", name)
		}
	}
}

// BuildPrompt must be deterministic and require its mandatory params.
func TestScenarioBuildPromptDeterministicAndValidated(t *testing.T) {
	sreg := NewScenarioRegistry()
	RegisterScenarios(sreg)

	correlate, _ := sreg.Get("correlate")
	p := map[string]any{"cve": "CVE-2024-3094"}
	a, err := correlate.BuildPrompt(p)
	if err != nil {
		t.Fatalf("BuildPrompt: %v", err)
	}
	b, _ := correlate.BuildPrompt(p)
	if a != b {
		t.Fatal("BuildPrompt must be deterministic")
	}
	if !strings.Contains(a, "CVE-2024-3094") || !strings.Contains(a, "advisory_for") {
		t.Fatalf("prompt missing inputs/tool: %s", a)
	}
	// Missing required param errors.
	if _, err := correlate.BuildPrompt(map[string]any{}); err == nil {
		t.Fatal("missing 'cve' must error")
	}

	// triage allows optional scan_id/package.
	triage, _ := sreg.Get("triage")
	full, err := triage.BuildPrompt(map[string]any{"cve": "CVE-1", "scan_id": "s1", "package": "lodash"})
	if err != nil {
		t.Fatalf("triage BuildPrompt: %v", err)
	}
	if !strings.Contains(full, "s1") || !strings.Contains(full, "lodash") {
		t.Fatalf("triage prompt missing optional params: %s", full)
	}
}
