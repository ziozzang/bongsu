package intel

import (
	"strings"
	"testing"
)

func TestInjectPriorResults(t *testing.T) {
	// No priors -> base prompt is returned verbatim (standalone runs unchanged).
	if got := injectPriorResults("BASE", nil); got != "BASE" {
		t.Fatalf("nil priors must return the base prompt, got %q", got)
	}
	// With priors -> anti-echo header + each stage's distilled findings appended.
	priors := []StageResult{
		{Stage: "triage", Status: "completed", Findings: map[string]any{"verdict": "reachable", "confidence": 0.8}},
	}
	got := injectPriorResults("BASE", priors)
	for _, want := range []string{"BASE", "PRIOR STAGE RESULTS", "do NOT copy", "triage", "reachable"} {
		if !strings.Contains(got, want) {
			t.Fatalf("injected prompt missing %q:\n%s", want, got)
		}
	}
}

func TestDistillFindings(t *testing.T) {
	findings := map[string]any{
		"finding":         "CVE-2024-3094",
		"verdict":         "reachable",
		"confidence":      0.8,
		"evidence":        []any{"a", "b", "c"},          // bulky tool-derived array -> dropped
		"affected_assets": []any{map[string]any{"h": 1}}, // dropped
		"sources":         []any{"nvd"},                  // dropped
	}
	got := distillFindings(findings)
	for _, want := range []string{"finding", "verdict", "reachable", "confidence"} {
		if !strings.Contains(got, want) {
			t.Errorf("distilled findings must keep scalar %q: %s", want, got)
		}
	}
	for _, drop := range []string{"evidence", "affected_assets", "sources"} {
		if strings.Contains(got, drop) {
			t.Errorf("distilled findings must drop bulky key %q: %s", drop, got)
		}
	}
}
