// Package intel is Bongsu's security-intelligence layer: it drives an external
// intelligence backbone (the jikji server — used over its HTTP API, never
// imported as source, never shelled out to) to run agentic reasoning over
// Bongsu's own security data. This file is the backbone adapter — a bounded,
// timeout-guarded client of jikji's POST /v1/runs agent endpoint.
//
// The backbone is configured ONCE at Bongsu boot (BONGSU_INTEL_JIKJI_URL points
// at a jikji server that has been configured — at ITS boot — with the tools it
// may use, e.g. Bongsu's MCP tool server). At runtime Bongsu only makes HTTP
// calls; it does not spawn jikjictl or reconfigure jikji.
//
// Design invariants:
//   - OPTIONAL: no BONGSU_INTEL_JIKJI_URL -> ErrBackboneDisabled; callers degrade
//     gracefully. Core scanning/matching never depends on the backbone.
//   - Bounded concurrency + per-run timeout: a run carries large fixed context
//     overhead, so concurrent runs are capped and each is deadline-guarded.
//   - Secret safety: only the caller-supplied prompt/goal is sent; the adapter
//     adds no credentials and does not log prompts.
package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// ErrBackboneDisabled is returned when no backbone URL is configured.
var ErrBackboneDisabled = errors.New("intel: backbone disabled (set BONGSU_INTEL_JIKJI_URL)")

// RunnerConfig configures the backbone adapter from BONGSU_INTEL_* env (resolved
// at Bongsu boot).
type RunnerConfig struct {
	BaseURL        string        // jikji server base URL (e.g. http://127.0.0.1:1385); empty disables
	MaxConcurrency int           // concurrent runs cap
	Timeout        time.Duration // per-run wall-clock deadline
	MaxSteps       int           // agent step budget (jikji caps at 64)
}

// RunnerConfigFromEnv reads the backbone configuration.
func RunnerConfigFromEnv() RunnerConfig {
	return RunnerConfig{
		BaseURL:        strings.TrimRight(strings.TrimSpace(os.Getenv("BONGSU_INTEL_JIKJI_URL")), "/"),
		MaxConcurrency: envInt("BONGSU_INTEL_MAX_CONCURRENCY", 4),
		Timeout:        time.Duration(envInt("BONGSU_INTEL_TIMEOUT_SECONDS", 120)) * time.Second,
		MaxSteps:       envInt("BONGSU_INTEL_MAX_STEPS", 8),
	}
}

// Runner is an HTTP client of jikji's agent-run endpoint, under a concurrency bound.
type Runner struct {
	cfg  RunnerConfig
	sem  chan struct{}
	http *http.Client
}

// NewRunner builds a bounded runner.
func NewRunner(cfg RunnerConfig) *Runner {
	if cfg.MaxConcurrency <= 0 {
		cfg.MaxConcurrency = 4
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 120 * time.Second
	}
	if cfg.MaxSteps <= 0 {
		cfg.MaxSteps = 8
	}
	if cfg.MaxSteps > 64 {
		cfg.MaxSteps = 64
	}
	return &Runner{
		cfg:  cfg,
		sem:  make(chan struct{}, cfg.MaxConcurrency),
		http: &http.Client{Timeout: cfg.Timeout + 10*time.Second},
	}
}

// NewRunnerFromEnv is the env-configured constructor.
func NewRunnerFromEnv() *Runner { return NewRunner(RunnerConfigFromEnv()) }

// Enabled reports whether a backbone URL is configured.
func (r *Runner) Enabled() bool { return r != nil && r.cfg.BaseURL != "" }

// Health reports whether the backbone is reachable (GET /health). Used for
// graceful degrade — the intelligence API returns 503 when this fails while the
// scan/match pipeline keeps working.
func (r *Runner) Health(ctx context.Context) error {
	if !r.Enabled() {
		return ErrBackboneDisabled
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, r.cfg.BaseURL+"/health", nil)
	resp, err := r.http.Do(req)
	if err != nil {
		return fmt.Errorf("intel: backbone unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("intel: backbone health %d", resp.StatusCode)
	}
	return nil
}

// Result is the parsed outcome of an agent run.
type Result struct {
	RunID            string
	SessionID        string // backbone session id (for interactive follow-up runs)
	Status           string // jikji run status (e.g. "completed")
	Response         string
	ToolSteps        int
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
	ContextTokens    int
	// ToolCalls is the per-tool audit reconstructed from the run's events. In the
	// HTTP /v1/runs model jikji uses a fixed boot-configured MCP, so per-run tool
	// audit is derived here from the run response rather than from the MCP
	// connection (see design §11).
	ToolCalls []ToolCall
}

// ToolCall is one tool invocation observed in a run's event stream. Fields are
// best-effort: the agent event schema varies, so the raw action/observation JSON
// is preserved for audit even when the name can't be extracted.
type ToolCall struct {
	Name   string
	ID     string
	Args   json.RawMessage
	Result json.RawMessage
}

// Run executes one agentic backbone run for the given prompt via POST /v1/runs.
// It blocks on the concurrency semaphore (honoring ctx) and enforces the
// per-run timeout. The prompt is the only caller data sent; callers must not
// embed secrets in it.
func (r *Runner) Run(ctx context.Context, prompt string) (Result, error) {
	return r.RunSession(ctx, prompt, "")
}

// RunSession is Run with a backbone session id: passing the same session across
// runs lets the agent build on the earlier conversation (interactive follow-up
// auditing). An empty sessionID is a fresh, stateless run.
func (r *Runner) RunSession(ctx context.Context, prompt, sessionID string) (Result, error) {
	if !r.Enabled() {
		return Result{}, ErrBackboneDisabled
	}
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
	runCtx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	payload := map[string]any{"prompt": prompt, "max_steps": r.cfg.MaxSteps}
	if sessionID != "" {
		payload["session_id"] = sessionID
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(runCtx, http.MethodPost, r.cfg.BaseURL+"/v1/runs", bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.http.Do(req)
	if err != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			return Result{}, fmt.Errorf("intel: backbone run timed out after %s", r.cfg.Timeout)
		}
		return Result{}, fmt.Errorf("intel: backbone run failed: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := readLimited(resp.Body, 16*1024*1024)
	if resp.StatusCode/100 != 2 {
		return Result{}, fmt.Errorf("intel: backbone run HTTP %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	return parseRunResponse(raw)
}

// parseRunResponse extracts the final response, status and token usage from the
// jikji /v1/runs JSON ({id, status, response, context_tokens, events:[...]}).
func parseRunResponse(raw []byte) (Result, error) {
	var resp struct {
		ID            string `json:"id"`
		SessionID     string `json:"session_id"`
		Status        string `json:"status"`
		Response      string `json:"response"`
		ContextTokens int    `json:"context_tokens"`
		Events        []struct {
			Action      json.RawMessage `json:"action"`
			Observation json.RawMessage `json:"observation"`
			Usage       struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
				TotalTokens      int `json:"total_tokens"`
			} `json:"usage"`
		} `json:"events"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return Result{}, fmt.Errorf("intel: parse run response: %w", err)
	}
	res := Result{RunID: resp.ID, SessionID: resp.SessionID, Status: resp.Status, Response: resp.Response, ContextTokens: resp.ContextTokens}
	var pending *ToolCall
	var lastRespond string
	for i := range resp.Events {
		e := &resp.Events[i]
		if e.Usage.TotalTokens > 0 || e.Usage.PromptTokens > 0 {
			res.PromptTokens += e.Usage.PromptTokens
			res.CompletionTokens += e.Usage.CompletionTokens
			res.TotalTokens += e.Usage.TotalTokens
		}
		if len(e.Action) > 0 {
			var a struct {
				Kind     string          `json:"kind"`
				Name     string          `json:"name"`
				Tool     string          `json:"tool"`
				ToolName string          `json:"tool_name"`
				Args     json.RawMessage `json:"arguments"`
				Input    json.RawMessage `json:"input"`
				Response string          `json:"response"`
				// jikji's /v1/runs nests the tool identity here: the name (e.g.
				// "bongsu.advisory_for"), a correlation id, and an input hash (jikji
				// hashes tool inputs, so raw args are not echoed back).
				ToolCall struct {
					ID        string `json:"id"`
					Name      string `json:"name"`
					InputHash string `json:"input_hash"`
				} `json:"tool_call"`
			}
			if json.Unmarshal(e.Action, &a) == nil {
				switch a.Kind {
				case "tool":
					res.ToolSteps++
					if pending != nil { // flush a prior tool call missing its observation
						res.ToolCalls = append(res.ToolCalls, *pending)
					}
					args := a.Args
					if len(args) == 0 {
						args = a.Input
					}
					if len(args) == 0 && a.ToolCall.InputHash != "" {
						args = json.RawMessage(`{"input_hash":` + strconv.Quote(a.ToolCall.InputHash) + `}`)
					}
					pending = &ToolCall{
						Name: firstNonEmpty(a.Name, a.Tool, a.ToolName, a.ToolCall.Name),
						ID:   a.ToolCall.ID,
						Args: args,
					}
				case "respond":
					if a.Response != "" {
						lastRespond = a.Response
					}
				}
			}
		}
		if len(e.Observation) > 0 && pending != nil {
			// jikji observations carry the tool result under "content" (a string)
			// and correlate to the action via "action_id". Prefer that; fall back to
			// the raw observation for other event shapes (e.g. httptest fakes).
			var obs struct {
				Kind     string `json:"kind"`
				ActionID string `json:"action_id"`
				Content  string `json:"content"`
			}
			result := e.Observation
			if json.Unmarshal(e.Observation, &obs) == nil && obs.Content != "" {
				result = json.RawMessage(obs.Content)
			}
			// Only pair the observation with this tool call when it is a tool
			// observation (or unlabeled); a non-tool observation (e.g. a thought)
			// should not become the tool's result.
			if obs.Kind == "" || obs.Kind == "tool" {
				pending.Result = result
				res.ToolCalls = append(res.ToolCalls, *pending)
				pending = nil
			}
		}
	}
	if pending != nil {
		res.ToolCalls = append(res.ToolCalls, *pending)
	}
	// Top-level response is authoritative; fall back to the final respond event.
	if res.Response == "" {
		res.Response = lastRespond
	}
	// A run with a status but no text is a valid (if empty) completion. Only a
	// truly malformed body (no status AND no text) is an error; include a snippet
	// to aid diagnosis.
	if res.Status == "" && res.Response == "" {
		return Result{}, fmt.Errorf("intel: backbone produced no response or status: %s", truncate(string(raw), 200))
	}
	return res, nil
}

func readLimited(r interface{ Read([]byte) (int, error) }, max int64) ([]byte, error) {
	buf := bytes.Buffer{}
	_, err := buf.ReadFrom(&limitedReader{r: r, n: max})
	return buf.Bytes(), err
}

type limitedReader struct {
	r interface{ Read([]byte) (int, error) }
	n int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, nil
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func envInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
