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
	pipelines    *PipelineRegistry
	requireAdmin bool
}

// NewServiceFromEnv builds the service from BONGSU_INTEL_* config. It is
// "enabled" only when a backbone URL is configured; otherwise the API degrades.
func NewServiceFromEnv(database *db.DB) *Service {
	sc := NewScenarioRegistry()
	RegisterScenarios(sc)
	pl := NewPipelineRegistry()
	RegisterPipelines(pl)
	return &Service{
		runner:       NewRunnerFromEnv(),
		store:        NewStore(database, envInt("BONGSU_INTEL_AUDIT_BUFFER", 1024)),
		scenarios:    sc,
		pipelines:    pl,
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

// Pipelines lists the registered named pipelines for the API.
func (s *Service) Pipelines() []PipelineInfo {
	if s == nil || s.pipelines == nil {
		return nil
	}
	return s.pipelines.Describe()
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

// RunRequest triggers a scenario. A non-empty SessionID continues an interactive
// audit session — the follow-up run builds on the earlier conversation.
type RunRequest struct {
	Scenario    string
	Params      map[string]any
	PrincipalID string
	Scope       *Scope
	SessionID   string
}

// RunOutcome is the API-facing result of a run.
type RunOutcome struct {
	RunID       string `json:"run_id"`
	SessionID   string `json:"session_id,omitempty"`
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
		PrincipalScope: req.Scope, ToolsInjected: scen.RequiredTools, SessionID: req.SessionID,
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
	// Structured termination: validate the output against the scenario schema and
	// do one corrective retry (nudge) if it doesn't conform. The corrective retry
	// stays in the same session so the agent sees its own prior (invalid) answer.
	const maxAttempts = 2
	var res Result
	var runErr error
	var outputValid bool
	var validationErr string
	attemptPrompt := prompt
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		res, runErr = s.runner.RunSession(runCtx, attemptPrompt, req.SessionID)
		if runErr != nil {
			_ = s.store.FinishRun(ctx, runID, "failed", nil, nil, runErr.Error())
			return RunOutcome{RunID: runID, SessionID: req.SessionID, Scenario: req.Scenario, Status: "failed"}, runErr
		}
		if res.SessionID != "" {
			req.SessionID = res.SessionID // thread session into the retry
		}
		outputValid, validationErr = validateScenarioOutput(scen.OutputSchema, res.Response)
		if outputValid || attempt == maxAttempts {
			break
		}
		attemptPrompt = prompt + "\n\nCORRECTION: your previous answer was invalid (" + validationErr +
			"). Return ONLY a single JSON object with the required fields and nothing else."
	}
	s.store.SetRunSession(ctx, runID, res.SessionID)
	s.store.SetRunValidation(ctx, runID, outputValid, validationErr)

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
	sessionID := res.SessionID
	if sessionID == "" {
		sessionID = req.SessionID
	}
	return RunOutcome{
		RunID: runID, SessionID: sessionID, Scenario: req.Scenario, Status: status,
		Response: res.Response, ToolSteps: res.ToolSteps, TotalTokens: res.TotalTokens,
	}, nil
}

// PipelineRequest chains scenarios into one audit. The stages run in order under
// a single backbone session, so each agent builds on the prior stages' context
// (the orchestration pattern: recon -> ... -> verify -> report). Authorization is
// the caller's; every stage is a normal, persisted run linked by the session id.
type PipelineRequest struct {
	Scenarios     []string
	Params        map[string]any
	PrincipalID   string
	Scope         *Scope
	StopOnFailure bool
}

// PipelineStage is one scenario run within a pipeline.
type PipelineStage struct {
	Scenario string `json:"scenario"`
	RunID    string `json:"run_id"`
	Status   string `json:"status"`
	Response string `json:"response,omitempty"`
	Error    string `json:"error,omitempty"`
}

// PipelineOutcome is the API-facing result of a pipeline.
type PipelineOutcome struct {
	SessionID string          `json:"session_id"`
	Status    string          `json:"status"` // completed | partial | failed
	Stages    []PipelineStage `json:"stages"`
}

const maxPipelineStages = 8

// RunNamedPipeline runs a code-registered pipeline by name. This is the only
// pipeline entrypoint the API exposes: the caller picks from a fixed set of
// reviewed chains, never supplies an arbitrary scenario list, so the backbone
// cannot be driven into an unbounded fan-out. Unknown names are rejected before
// any backbone call.
func (s *Service) RunNamedPipeline(ctx context.Context, name string, params map[string]any, principalID string, scope *Scope) (PipelineOutcome, error) {
	if !s.Enabled() {
		return PipelineOutcome{}, ErrBackboneDisabled
	}
	pl, ok := s.pipelines.Get(name)
	if !ok {
		return PipelineOutcome{}, fmt.Errorf("intel: unknown pipeline %q", name)
	}
	return s.RunPipeline(ctx, PipelineRequest{
		Scenarios:     pl.Scenarios,
		Params:        params,
		PrincipalID:   principalID,
		Scope:         scope,
		StopOnFailure: pl.StopOnFailure,
	})
}

// RunPipeline runs the scenarios in order under one session. A stage failure
// stops the pipeline when StopOnFailure is set (otherwise it continues); the
// outcome is "completed" if all stages succeeded, "failed" if the first stage
// failed, else "partial".
func (s *Service) RunPipeline(ctx context.Context, req PipelineRequest) (PipelineOutcome, error) {
	if !s.Enabled() {
		return PipelineOutcome{}, ErrBackboneDisabled
	}
	if len(req.Scenarios) == 0 {
		return PipelineOutcome{}, fmt.Errorf("intel: pipeline requires at least one scenario")
	}
	if len(req.Scenarios) > maxPipelineStages {
		return PipelineOutcome{}, fmt.Errorf("intel: pipeline exceeds %d stages", maxPipelineStages)
	}
	// Fail fast on an unknown scenario before spending backbone calls.
	for _, name := range req.Scenarios {
		if _, ok := s.scenarios.Get(name); !ok {
			return PipelineOutcome{}, fmt.Errorf("intel: unknown scenario %q", name)
		}
	}

	out := PipelineOutcome{Status: "completed"}
	session := ""
	failures := 0
	for i, name := range req.Scenarios {
		outcome, err := s.RunScenario(ctx, RunRequest{
			Scenario: name, Params: req.Params, PrincipalID: req.PrincipalID,
			Scope: req.Scope, SessionID: session,
		})
		if outcome.SessionID != "" {
			session = outcome.SessionID // thread the session through the pipeline
		}
		stage := PipelineStage{Scenario: name, RunID: outcome.RunID, Status: outcome.Status, Response: outcome.Response}
		if err != nil {
			stage.Status = "failed"
			stage.Error = err.Error()
			failures++
			out.Stages = append(out.Stages, stage)
			if req.StopOnFailure {
				break
			}
			continue
		}
		out.Stages = append(out.Stages, stage)
		_ = i
	}
	out.SessionID = session
	switch {
	case failures == 0:
		out.Status = "completed"
	case failures == len(out.Stages):
		out.Status = "failed"
	default:
		out.Status = "partial"
	}
	return out, nil
}

// GetRun reads a persisted run for the API.
func (s *Service) GetRun(ctx context.Context, runID string) (RunView, error) {
	if s == nil || s.store == nil {
		return RunView{}, ErrBackboneDisabled
	}
	return s.store.GetRun(ctx, runID)
}
