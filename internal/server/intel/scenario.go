package intel

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// A Scenario is a named intelligence task the backbone agent performs by calling
// the injected tools. Each declares the tools it needs, a DETERMINISTIC prompt
// builder (so a run is reproducible given its inputs), an output JSON Schema the
// result is validated against, and step/time budgets. New scenarios plug in via
// Register — no core change. The RBAC boundary is enforced per-tool-call (see
// MCPServer / tools_scoped), so a scenario cannot widen access by composing tools.
type Scenario struct {
	Name          string
	Description   string
	RequiredTools []string
	OutputSchema  json.RawMessage
	MaxSteps      int
	Timeout       time.Duration
	BuildPrompt   func(params map[string]any) (string, error)
}

// ScenarioRegistry is a concurrency-safe set of scenarios.
type ScenarioRegistry struct {
	mu        sync.RWMutex
	scenarios map[string]Scenario
}

func NewScenarioRegistry() *ScenarioRegistry {
	return &ScenarioRegistry{scenarios: map[string]Scenario{}}
}

func (r *ScenarioRegistry) Register(s Scenario) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scenarios[s.Name] = s
}

func (r *ScenarioRegistry) Get(name string) (Scenario, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.scenarios[name]
	return s, ok
}

func (r *ScenarioRegistry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.scenarios))
	for n := range r.scenarios {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// reqParam fetches a required string parameter, erroring if absent.
func reqParam(params map[string]any, key string) (string, error) {
	if v, ok := params[key].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v), nil
	}
	return "", fmt.Errorf("scenario requires parameter %q", key)
}

func optParam(params map[string]any, key string) string {
	if v, ok := params[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

const toolPreamble = "You are Bongsu's security-intelligence agent. Use ONLY the provided tools to gather facts; never invent data. " +
	"Tools enforce the caller's access scope — if a tool returns a forbidden/empty result, do not speculate about hidden data. " +
	"Return EXACTLY one JSON object matching the requested schema and nothing else."

// RegisterScenarios registers the built-in scenarios. Each BuildPrompt is a pure
// function of its params (deterministic) so runs are reproducible.
func RegisterScenarios(reg *ScenarioRegistry) {
	// (a) cross-source advisory correlation / dedup
	reg.Register(Scenario{
		Name:          "correlate",
		Description:   "Reconcile a CVE's metadata across sources (OSV/NVD/Trivy) and decide a canonical severity/CVSS with a confidence and conflict list.",
		RequiredTools: []string{"advisory_for"},
		MaxSteps:      5,
		Timeout:       90 * time.Second,
		OutputSchema:  json.RawMessage(`{"type":"object","required":["cve","canonical"],"properties":{"cve":{"type":"string"},"sources":{"type":"array"},"canonical":{"type":"object"},"conflicts":{"type":"array"}}}`),
		BuildPrompt: func(p map[string]any) (string, error) {
			cve, err := reqParam(p, "cve")
			if err != nil {
				return "", err
			}
			return toolPreamble + "\n\nTask: call advisory_for for " + cve +
				", compare the per-source severity/CVSS/exploited/EPSS, and decide the canonical assessment. " +
				`Output: {"cve","sources":[{name,cvss,severity}],"canonical":{cvss,severity,confidence},"conflicts":[{field,values,resolution}]}.`, nil
		},
	})

	// (b) AI triage — reachability / false-positive judgement
	reg.Register(Scenario{
		Name:          "triage",
		Description:   "Judge whether a finding is reachable / a false positive using the dependency graph, advisory, exposure and SBOM context.",
		RequiredTools: []string{"query_vulns", "dependents_of", "advisory_for", "sbom_at"},
		MaxSteps:      10,
		Timeout:       180 * time.Second,
		OutputSchema:  json.RawMessage(`{"type":"object","required":["verdict","confidence"],"properties":{"finding":{"type":"string"},"verdict":{"type":"string","enum":["false_positive","reachable","not_reachable"]},"confidence":{"type":"number"},"reasoning":{"type":"string"},"evidence":{"type":"array"}}}`),
		BuildPrompt: func(p map[string]any) (string, error) {
			cve, err := reqParam(p, "cve")
			if err != nil {
				return "", err
			}
			scan := optParam(p, "scan_id")
			pkg := optParam(p, "package")
			b := strings.Builder{}
			b.WriteString(toolPreamble)
			b.WriteString("\n\nTask: triage finding " + cve)
			if pkg != "" {
				b.WriteString(" on package " + pkg)
			}
			if scan != "" {
				b.WriteString(" in scan " + scan)
			}
			b.WriteString(". Use advisory_for for severity/exploited/EPSS; if a scan_id and package are given, use dependents_of for reachability and sbom_at for presence. ")
			b.WriteString(`Output: {"finding","verdict":"false_positive|reachable|not_reachable","confidence":0..1,"reasoning","evidence":[{tool,fact}]}.`)
			return b.String(), nil
		},
	})

	// (c) supply-chain campaign correlation
	reg.Register(Scenario{
		Name:          "campaign",
		Description:   "Estimate supply-chain compromise propagation from an exposure (IOC) using the exposure catalog and dependency graph.",
		RequiredTools: []string{"exposure_lookup", "dependents_of", "query_vulns"},
		MaxSteps:      15,
		Timeout:       240 * time.Second,
		OutputSchema:  json.RawMessage(`{"type":"object","required":["package"],"properties":{"package":{"type":"string"},"affected_assets":{"type":"array"},"propagation_paths":{"type":"array"}}}`),
		BuildPrompt: func(p map[string]any) (string, error) {
			eco, err := reqParam(p, "ecosystem")
			if err != nil {
				return "", err
			}
			pkg, err := reqParam(p, "package")
			if err != nil {
				return "", err
			}
			return toolPreamble + "\n\nTask: assess supply-chain campaign exposure for " + eco + " package " + pkg +
				". Use exposure_lookup to confirm compromised versions, then dependents_of / query_vulns to estimate blast radius. " +
				`Output: {"package","affected_assets":[{host,path,blast_radius}],"propagation_paths":[["pkg->pkg"]]}.`, nil
		},
	})

	// (d) remediation planning
	reg.Register(Scenario{
		Name:          "remediate",
		Description:   "Produce a fix plan (fixed version, upgrade path, affected dependents) for a finding.",
		RequiredTools: []string{"advisory_for", "dependents_of", "query_vulns"},
		MaxSteps:      8,
		Timeout:       120 * time.Second,
		OutputSchema:  json.RawMessage(`{"type":"object","required":["finding"],"properties":{"finding":{"type":"string"},"fixed_version":{"type":"string"},"upgrade_path":{"type":"array"},"affected_dependents":{"type":"array"}}}`),
		BuildPrompt: func(p map[string]any) (string, error) {
			cve, err := reqParam(p, "cve")
			if err != nil {
				return "", err
			}
			return toolPreamble + "\n\nTask: build a remediation plan for " + cve +
				". Use advisory_for for the fixed version and dependents_of for impacted packages. " +
				`Output: {"finding","fixed_version","upgrade_path":[{pkg,current,target,breaking_changes}],"affected_dependents":[{pkg,version}]}.`, nil
		},
	})

	// (e) natural-language security query
	reg.Register(Scenario{
		Name:          "nl_query",
		Description:   "Answer a free-form security question about the caller's assets using the available tools.",
		RequiredTools: []string{"query_vulns", "dependents_of", "exposure_lookup", "sbom_at", "advisory_for"},
		MaxSteps:      12,
		Timeout:       180 * time.Second,
		OutputSchema:  json.RawMessage(`{"type":"object","required":["answer"],"properties":{"question":{"type":"string"},"answer":{"type":"string"},"sources":{"type":"array"},"confidence":{"type":"number"}}}`),
		BuildPrompt: func(p map[string]any) (string, error) {
			q, err := reqParam(p, "question")
			if err != nil {
				return "", err
			}
			return toolPreamble + "\n\nQuestion: " + q +
				"\nChoose and call the tools needed to answer it from the caller's scoped data. " +
				`Output: {"question","answer","sources":[{tool,result_summary}],"confidence":0..1}.`, nil
		},
	})
}
