package intel

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeJikjictl writes a stub binary that emits a canned jikji-agent JSONL stream,
// so the runner is tested without a live backbone.
func fakeJikjictl(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "jikjictl")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunnerDisabledWithoutBin(t *testing.T) {
	r := NewRunner(RunnerConfig{})
	if r.Enabled() {
		t.Fatal("runner with no bin path must be disabled")
	}
	if _, err := r.Run(context.Background(), "hi"); err != ErrBackboneDisabled {
		t.Fatalf("want ErrBackboneDisabled, got %v", err)
	}
}

func TestRunnerParsesJSONLStream(t *testing.T) {
	bin := fakeJikjictl(t, `cat <<'EOF'
{"type":"run.started","run_id":"run-abc","metadata":{"status":"running"}}
{"type":"run.step","run_id":"run-abc","action":{"kind":"think","thought":"..."}}
{"type":"run.step","run_id":"run-abc","action":{"kind":"content","response":"partial"}}
{"type":"run.completed","run_id":"run-abc","metadata":{"response":"FINAL_ANSWER","status":"completed"},"usage":{"prompt_tokens":16000,"completion_tokens":40,"total_tokens":16040}}
EOF`)
	r := NewRunner(RunnerConfig{BinPath: bin, Model: "m", MaxConcurrency: 2, Timeout: 10 * time.Second})
	if !r.Enabled() {
		t.Fatal("runner must be enabled with a bin path")
	}
	res, err := r.Run(context.Background(), "analyze CVE-2024-1")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.RunID != "run-abc" || res.Response != "FINAL_ANSWER" {
		t.Fatalf("parsed result wrong: %+v", res)
	}
	if res.PromptTokens != 16000 || res.TotalTokens != 16040 {
		t.Fatalf("usage parse wrong: %+v", res)
	}
	if res.Steps < 2 {
		t.Fatalf("steps should count run.step events: %+v", res)
	}
}

// When run.completed carries no response, the runner falls back to the last
// content step.
func TestRunnerFallsBackToLastContent(t *testing.T) {
	bin := fakeJikjictl(t, `cat <<'EOF'
{"type":"run.step","run_id":"r","action":{"kind":"content","response":"only content"}}
{"type":"run.completed","run_id":"r","metadata":{"status":"completed"}}
EOF`)
	r := NewRunner(RunnerConfig{BinPath: bin})
	res, err := r.Run(context.Background(), "x")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Response != "only content" {
		t.Fatalf("fallback response wrong: %q", res.Response)
	}
}

func TestRunnerErrorsOnEmptyStream(t *testing.T) {
	bin := fakeJikjictl(t, `printf ''`)
	r := NewRunner(RunnerConfig{BinPath: bin})
	if _, err := r.Run(context.Background(), "x"); err == nil {
		t.Fatal("empty backbone output must error")
	}
}

// The prompt is passed as an explicit argv element; the runner adds no
// credentials to the command line. This guards against secret leakage via argv.
func TestRunnerArgvCarriesOnlyPromptAndFlags(t *testing.T) {
	bin := fakeJikjictl(t, `for a in "$@"; do printf '%s\n' "$a" >> "$ARGV_LOG"; done
cat <<'EOF'
{"type":"run.completed","run_id":"r","metadata":{"response":"ok"}}
EOF`)
	argvLog := filepath.Join(t.TempDir(), "argv")
	t.Setenv("ARGV_LOG", argvLog)
	r := NewRunner(RunnerConfig{BinPath: bin, Model: "deepseek", APIURL: "http://127.0.0.1:1385/v1"})
	if _, err := r.Run(context.Background(), "SECRETLESS PROMPT"); err != nil {
		t.Fatalf("run: %v", err)
	}
	data, err := os.ReadFile(argvLog)
	if err != nil {
		t.Fatalf("read argv: %v", err)
	}
	got := string(data)
	for _, want := range []string{"chat", "--mode", "jsonl", "--prompt", "SECRETLESS PROMPT", "--model", "deepseek"} {
		if !containsLine(got, want) {
			t.Fatalf("argv missing %q; argv=%q", want, got)
		}
	}
}

func containsLine(haystack, needle string) bool {
	for _, line := range splitLines(haystack) {
		if line == needle {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
