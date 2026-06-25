// Package intel is Bongsu's security-intelligence layer: it drives an external
// intelligence backbone (the jikji binary/server — used as a compiled binary,
// never imported as source) to run agentic reasoning over Bongsu's own security
// data. This file is the backbone adapter — a bounded, timeout-guarded runner
// that execs the jikji agent CLI and parses its JSONL stream. Scenarios (triage,
// correlation, remediation, NL query) compose on top of this runner; tools are
// injected into runs over MCP (see the tool registry / MCP server).
//
// Design invariants:
//   - The backbone is OPTIONAL: when unconfigured or unreachable, Run returns
//     ErrBackboneDisabled / an error and callers degrade gracefully — core
//     scanning/matching never depends on it.
//   - Bounded concurrency + per-run timeout: a backbone call carries a large
//     fixed context overhead, so concurrent runs are capped and each is
//     deadline-guarded to protect the process under load.
//   - Secret safety: only the caller-supplied prompt and explicit flags reach the
//     subprocess; the runner adds no credentials to argv and does not log prompts.
package intel

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// ErrBackboneDisabled is returned when no backbone binary is configured.
var ErrBackboneDisabled = errors.New("intel: backbone disabled (set BONGSU_INTEL_JIKJICTL)")

// RunnerConfig configures the backbone adapter. All fields come from
// BONGSU_INTEL_* env vars, resolved by RunnerConfigFromEnv.
type RunnerConfig struct {
	BinPath        string        // path to the jikjictl binary; empty disables the runner
	Model          string        // backbone model id (e.g. deepseek-v4-flash:cloud)
	APIURL         string        // jikji server URL (optional; jikjictl default used if empty)
	MaxConcurrency int           // concurrent runs cap
	Timeout        time.Duration // per-run wall-clock deadline
	MaxSteps       int           // agent step budget
}

// RunnerConfigFromEnv reads the backbone configuration from the environment.
func RunnerConfigFromEnv() RunnerConfig {
	return RunnerConfig{
		BinPath:        strings.TrimSpace(os.Getenv("BONGSU_INTEL_JIKJICTL")),
		Model:          strings.TrimSpace(envOr("BONGSU_INTEL_MODEL", "deepseek-v4-flash:cloud")),
		APIURL:         strings.TrimSpace(os.Getenv("BONGSU_INTEL_API_URL")),
		MaxConcurrency: envInt("BONGSU_INTEL_MAX_CONCURRENCY", 4),
		Timeout:        time.Duration(envInt("BONGSU_INTEL_TIMEOUT_SECONDS", 120)) * time.Second,
		MaxSteps:       envInt("BONGSU_INTEL_MAX_STEPS", 8),
	}
}

// Runner execs the jikji agent CLI under a concurrency bound.
type Runner struct {
	cfg RunnerConfig
	sem chan struct{}
}

// NewRunner builds a bounded runner. A non-positive MaxConcurrency defaults to 4.
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
	return &Runner{cfg: cfg, sem: make(chan struct{}, cfg.MaxConcurrency)}
}

// NewRunnerFromEnv is the env-configured constructor.
func NewRunnerFromEnv() *Runner { return NewRunner(RunnerConfigFromEnv()) }

// Enabled reports whether a backbone binary is configured.
func (r *Runner) Enabled() bool { return r != nil && r.cfg.BinPath != "" }

// Result is the parsed outcome of an agent run.
type Result struct {
	RunID            string
	Response         string
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
	Steps            int
}

// Run executes one agentic backbone run for the given prompt and returns the
// final response. It blocks on the concurrency semaphore (honoring ctx) and
// enforces the configured per-run timeout. The prompt is the only caller data
// placed on the command line; callers must not embed secrets in it.
func (r *Runner) Run(ctx context.Context, prompt string) (Result, error) {
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

	args := []string{"chat", "--mode", "jsonl", "--prompt", prompt,
		"--timeout", r.cfg.Timeout.String()}
	if r.cfg.Model != "" {
		args = append(args, "--model", r.cfg.Model)
	}
	if r.cfg.APIURL != "" {
		args = append(args, "--api-url", r.cfg.APIURL)
	}

	cmd := exec.CommandContext(runCtx, r.cfg.BinPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			return Result{}, fmt.Errorf("intel: backbone run timed out after %s", r.cfg.Timeout)
		}
		return Result{}, fmt.Errorf("intel: backbone run failed: %w (%s)", err, truncate(stderr.String(), 200))
	}
	return parseJSONLStream(stdout.Bytes())
}

// parseJSONLStream extracts the final response and token usage from the jikji
// agent JSONL stream (run.started / run.step / run.completed events).
func parseJSONLStream(out []byte) (Result, error) {
	var res Result
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var lastContent string
	sawCompleted := false
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var ev struct {
			Type   string `json:"type"`
			RunID  string `json:"run_id"`
			Action struct {
				Kind     string `json:"kind"`
				Response string `json:"response"`
			} `json:"action"`
			Metadata struct {
				Response string `json:"response"`
			} `json:"metadata"`
			Usage struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
				TotalTokens      int `json:"total_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal(line, &ev) != nil {
			continue
		}
		if ev.RunID != "" {
			res.RunID = ev.RunID
		}
		switch ev.Type {
		case "run.step":
			if ev.Action.Kind == "content" && ev.Action.Response != "" {
				lastContent = ev.Action.Response
				res.Steps++
			} else {
				res.Steps++
			}
		case "run.completed":
			sawCompleted = true
			if ev.Metadata.Response != "" {
				res.Response = ev.Metadata.Response
			}
			res.PromptTokens = ev.Usage.PromptTokens
			res.CompletionTokens = ev.Usage.CompletionTokens
			res.TotalTokens = ev.Usage.TotalTokens
		}
	}
	if err := sc.Err(); err != nil {
		return Result{}, fmt.Errorf("intel: read backbone stream: %w", err)
	}
	if res.Response == "" {
		res.Response = lastContent
	}
	if !sawCompleted && res.Response == "" {
		return Result{}, errors.New("intel: backbone produced no completion")
	}
	return res, nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
