package intel

import (
	"sort"
	"sync"
)

// A Pipeline is a code-registered, named chain of scenarios run under one
// backbone session. Pipelines are DELIBERATELY not caller-definable: the API
// accepts a pipeline NAME, never an arbitrary scenario list, so a caller cannot
// compose an unbounded DAG or fan out the backbone. Each pipeline is a fixed,
// reviewed sequence (recon -> ... -> verify -> report) whose stages all share
// the run's params and RBAC scope.
type Pipeline struct {
	Name          string
	Description   string
	Scenarios     []string
	StopOnFailure bool
}

// PipelineRegistry is a concurrency-safe set of named pipelines.
type PipelineRegistry struct {
	mu        sync.RWMutex
	pipelines map[string]Pipeline
}

func NewPipelineRegistry() *PipelineRegistry {
	return &PipelineRegistry{pipelines: map[string]Pipeline{}}
}

func (r *PipelineRegistry) Register(p Pipeline) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pipelines[p.Name] = p
}

func (r *PipelineRegistry) Get(name string) (Pipeline, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.pipelines[name]
	return p, ok
}

func (r *PipelineRegistry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.pipelines))
	for n := range r.pipelines {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// PipelineInfo is the API-facing description of a registered pipeline.
type PipelineInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Scenarios   []string `json:"scenarios"`
}

func (r *PipelineRegistry) Describe() []PipelineInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]PipelineInfo, 0, len(r.pipelines))
	for _, p := range r.pipelines {
		out = append(out, PipelineInfo{
			Name: p.Name, Description: p.Description,
			Scenarios: append([]string(nil), p.Scenarios...),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// RegisterPipelines registers the built-in, reviewed pipelines. Each stage list
// references scenarios that must exist in the ScenarioRegistry (validated at run
// time). The canonical pattern is find -> adversarially verify -> report.
func RegisterPipelines(reg *PipelineRegistry) {
	// The AutoCVE-style triage audit: judge reachability, adversarially refute,
	// then emit a CVE-grade dedup'd report. Stop early if triage itself fails.
	reg.Register(Pipeline{
		Name:          "audit",
		Description:   "Full finding audit: triage (reachability) -> verify (adversarial refute) -> report (CVE-grade).",
		Scenarios:     []string{"triage", "verify", "report"},
		StopOnFailure: true,
	})
	// Cross-source assessment then a fix plan.
	reg.Register(Pipeline{
		Name:          "assess",
		Description:   "Advisory assessment: correlate (cross-source severity) -> remediate (fix plan).",
		Scenarios:     []string{"correlate", "remediate"},
		StopOnFailure: true,
	})
	// Supply-chain campaign sweep: estimate blast radius, then verify and report.
	reg.Register(Pipeline{
		Name:          "campaign_sweep",
		Description:   "Supply-chain sweep: campaign (blast radius) -> verify (adversarial) -> report.",
		Scenarios:     []string{"campaign", "verify", "report"},
		StopOnFailure: true,
	})
}
