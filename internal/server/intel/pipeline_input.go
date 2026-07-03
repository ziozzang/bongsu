package intel

import (
	"encoding/json"
	"strings"
)

// Pipeline stage isolation: each stage runs in an INDEPENDENT backbone session
// (session-threading let later stages echo the earlier stage's raw tool output).
// The prior stages' validated, synthesized results are instead injected into the
// next stage's prompt as reference facts — never as a shared conversation.

// StageResult is one completed pipeline stage's validated output, carried forward
// to inform later stages (verify sees triage, report sees triage+verify).
type StageResult struct {
	Stage    string         `json:"stage"`
	Status   string         `json:"status"`
	Findings map[string]any `json:"findings"`
}

// bulkyKeys hold tool-derived arrays (evidence, source lists, asset lists). They
// are dropped when forwarding a result so a downstream stage can't re-echo a
// large tool dump and so the prompt stays compact — the scalar verdict fields are
// what later stages actually need.
var bulkyKeys = map[string]bool{
	"evidence": true, "sources": true, "affected_assets": true,
	"attack_chain": true, "propagation_paths": true, "affected_dependents": true,
}

// distillFindings returns a compact JSON of a stage's result: its synthesized
// scalar fields (verdict, confidence, summary, …) minus the bulky tool-derived
// arrays. It is the model's OWN structured output, not raw tool data, so it is
// safe to show downstream as reference.
func distillFindings(findings map[string]any) string {
	slim := make(map[string]any, len(findings))
	for k, v := range findings {
		if bulkyKeys[k] {
			continue
		}
		slim[k] = v
	}
	b, err := json.Marshal(slim)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// injectPriorResults appends the prior stages' distilled results to a scenario
// prompt with a strong "reference only — do not echo" header, so the stage
// synthesizes its OWN schema-conforming output rather than parroting a prior
// stage. With no priors it returns the base prompt unchanged (standalone runs).
func injectPriorResults(basePrompt string, priors []StageResult) string {
	if len(priors) == 0 {
		return basePrompt
	}
	var b strings.Builder
	b.WriteString(basePrompt)
	b.WriteString("\n\n---\nPRIOR STAGE RESULTS (reference facts only — do NOT copy or echo these; ")
	b.WriteString("they are earlier analysis, not your answer. Produce your OWN output matching the requested schema):\n")
	for _, p := range priors {
		b.WriteString("- ")
		b.WriteString(p.Stage)
		b.WriteString(": ")
		b.WriteString(distillFindings(p.Findings))
		b.WriteString("\n")
	}
	return b.String()
}
