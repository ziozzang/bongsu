package intel

import (
	"context"
	"fmt"
	"os"

	"github.com/ziozzang/bongsu/internal/server/db"
)

// Service is the intelligence layer's runtime entrypoint: it turns a scenario +
// params into a backbone run, persists it, and returns the outcome. It owns the
// HTTP backbone runner, the run/audit store, and the scenario registry. Failure
// is isolated — the scan/match pipeline never depends on it.
type Service struct {
	runner       *Runner
	store        *Store
	scenarios    *ScenarioRegistry
	requireAdmin bool
}

// NewServiceFromEnv builds the service from BONGSU_INTEL_* config. It is
// "enabled" only when a backbone URL is configured; otherwise the API degrades.
func NewServiceFromEnv(database *db.DB) *Service {
	sc := NewScenarioRegistry()
	RegisterScenarios(sc)
	return &Service{
		runner:       NewRunnerFromEnv(),
		store:        NewStore(database, envInt("BONGSU_INTEL_AUDIT_BUFFER", 1024)),
		scenarios:    sc,
		requireAdmin: os.Getenv("BONGSU_INTEL_REQUIRE_ADMIN") != "false",
	}
}

func (s *Service) Enabled() bool      { return s != nil && s.runner.Enabled() }
func (s *Service) RequireAdmin() bool { return s == nil || s.requireAdmin }
func (s *Service) Scenarios() []string {
	if s == nil {
		return nil
	}
	return s.scenarios.Names()
}

// Health reports backbone reachability for graceful degrade.
func (s *Service) Health(ctx context.Context) error {
	if !s.Enabled() {
		return ErrBackboneDisabled
	}
	return s.runner.Health(ctx)
}

// Close drains the audit writer.
func (s *Service) Close() {
	if s != nil && s.store != nil {
		s.store.Close()
	}
}

// RunRequest triggers a scenario.
type RunRequest struct {
	Scenario    string
	Params      map[string]any
	PrincipalID string
	Scope       *Scope
}

// RunOutcome is the API-facing result of a run.
type RunOutcome struct {
	RunID       string `json:"run_id"`
	Scenario    string `json:"scenario"`
	Status      string `json:"status"`
	Response    string `json:"response"`
	ToolSteps   int    `json:"tool_steps"`
	TotalTokens int    `json:"total_tokens"`
}

// RunScenario builds the scenario prompt, creates the run (snapshotting the
// caller's scope), drives the backbone, and persists the outcome. The run is
// bounded by the scenario's timeout. A backbone failure marks the run failed but
// never panics or affects other subsystems.
func (s *Service) RunScenario(ctx context.Context, req RunRequest) (RunOutcome, error) {
	if !s.Enabled() {
		return RunOutcome{}, ErrBackboneDisabled
	}
	scen, ok := s.scenarios.Get(req.Scenario)
	if !ok {
		return RunOutcome{}, fmt.Errorf("intel: unknown scenario %q", req.Scenario)
	}
	prompt, err := scen.BuildPrompt(req.Params)
	if err != nil {
		return RunOutcome{}, err
	}
	runID, err := s.store.CreateRun(ctx, RunRecord{
		Scenario: req.Scenario, Goal: scen.Description, PrincipalID: req.PrincipalID,
		PrincipalScope: req.Scope, ToolsInjected: scen.RequiredTools,
	})
	if err != nil {
		return RunOutcome{}, fmt.Errorf("intel: create run: %w", err)
	}

	runCtx := ctx
	if scen.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, scen.Timeout)
		defer cancel()
	}
	res, runErr := s.runner.Run(runCtx, prompt)
	if runErr != nil {
		_ = s.store.FinishRun(ctx, runID, "failed", nil, nil, runErr.Error())
		return RunOutcome{RunID: runID, Scenario: req.Scenario, Status: "failed"}, runErr
	}

	status := res.Status
	if status == "" {
		status = "completed"
	}
	// Reconstruct the per-tool audit from the run's events (HTTP model has no
	// per-run MCP id to correlate; see design §11).
	for i, tc := range res.ToolCalls {
		name := tc.Name
		if name == "" {
			name = "unknown"
		}
		s.store.RecordToolCall(runID, i+1, name, tc.Args, tc.Result, false, 0, "")
	}
	output := map[string]any{"response": res.Response}
	usage := map[string]any{
		"prompt_tokens": res.PromptTokens, "completion_tokens": res.CompletionTokens,
		"total_tokens": res.TotalTokens, "context_tokens": res.ContextTokens, "tool_steps": res.ToolSteps,
	}
	if err := s.store.FinishRun(ctx, runID, status, output, usage, ""); err != nil {
		// Persistence failure is non-fatal to returning the result.
		_ = err
	}
	return RunOutcome{
		RunID: runID, Scenario: req.Scenario, Status: status,
		Response: res.Response, ToolSteps: res.ToolSteps, TotalTokens: res.TotalTokens,
	}, nil
}

// GetRun reads a persisted run for the API.
func (s *Service) GetRun(ctx context.Context, runID string) (RunView, error) {
	if s == nil || s.store == nil {
		return RunView{}, ErrBackboneDisabled
	}
	return s.store.GetRun(ctx, runID)
}
