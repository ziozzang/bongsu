package intel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeJikji serves a canned POST /v1/runs response and records the request body,
// so the runner is tested without a live backbone.
func fakeJikji(t *testing.T, runResp string, captured *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(200)
		case "/v1/runs":
			if captured != nil {
				b, _ := io.ReadAll(r.Body)
				*captured = string(b)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, runResp)
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestRunnerDisabledWithoutURL(t *testing.T) {
	r := NewRunner(RunnerConfig{})
	if r.Enabled() {
		t.Fatal("runner with no base URL must be disabled")
	}
	if _, err := r.Run(context.Background(), "hi"); err != ErrBackboneDisabled {
		t.Fatalf("want ErrBackboneDisabled, got %v", err)
	}
}

func TestRunnerParsesRunResponse(t *testing.T) {
	resp := `{"id":"run-abc","status":"completed","response":"FINAL_ANSWER","context_tokens":16000,
	  "events":[
	    {"type":"run.step","action":{"kind":"think"}},
	    {"type":"run.step","action":{"kind":"tool"}},
	    {"type":"run.step","action":{"kind":"tool"}},
	    {"type":"run.step","action":{"kind":"respond","response":"FINAL_ANSWER"}},
	    {"type":"run.usage","usage":{"prompt_tokens":16000,"completion_tokens":40,"total_tokens":16040}}
	  ]}`
	var body string
	srv := fakeJikji(t, resp, &body)
	defer srv.Close()

	r := NewRunner(RunnerConfig{BaseURL: srv.URL, MaxConcurrency: 2, Timeout: 10 * time.Second, MaxSteps: 8})
	if !r.Enabled() {
		t.Fatal("runner must be enabled with a base URL")
	}
	if err := r.Health(context.Background()); err != nil {
		t.Fatalf("health: %v", err)
	}
	res, err := r.Run(context.Background(), "analyze CVE-2024-1")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.RunID != "run-abc" || res.Status != "completed" || res.Response != "FINAL_ANSWER" {
		t.Fatalf("parsed result wrong: %+v", res)
	}
	if res.ToolSteps != 2 {
		t.Fatalf("tool steps = %d, want 2", res.ToolSteps)
	}
	if res.PromptTokens != 16000 || res.TotalTokens != 16040 {
		t.Fatalf("usage parse wrong: %+v", res)
	}

	// The request carries the prompt + max_steps and no credentials.
	var sent struct {
		Prompt   string `json:"prompt"`
		MaxSteps int    `json:"max_steps"`
	}
	if err := json.Unmarshal([]byte(body), &sent); err != nil {
		t.Fatalf("decode sent body: %v (%s)", err, body)
	}
	if sent.Prompt != "analyze CVE-2024-1" || sent.MaxSteps != 8 {
		t.Fatalf("request body wrong: %+v", sent)
	}
}

func TestRunnerHTTPErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = io.WriteString(w, "boom")
	}))
	defer srv.Close()
	r := NewRunner(RunnerConfig{BaseURL: srv.URL})
	if _, err := r.Run(context.Background(), "x"); err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("want HTTP 500 error, got %v", err)
	}
}

func TestRunnerMaxStepsClamped(t *testing.T) {
	r := NewRunner(RunnerConfig{BaseURL: "http://x", MaxSteps: 1000})
	if r.cfg.MaxSteps != 64 {
		t.Fatalf("max steps must clamp to jikji's 64, got %d", r.cfg.MaxSteps)
	}
}
