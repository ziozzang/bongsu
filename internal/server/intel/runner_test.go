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

// Tool calls are reconstructed from the run's events (tool action followed by an
// observation), so the run can be audited even though jikji uses a fixed MCP.
func TestRunnerReconstructsToolCalls(t *testing.T) {
	resp := `{"id":"r","status":"completed","response":"done","events":[
	  {"action":{"kind":"tool","name":"advisory_for","arguments":{"cve":"CVE-1"}}},
	  {"observation":{"result":"{\"exploited_kev\":true}"}},
	  {"action":{"kind":"tool","tool":"dependents_of","input":{"package":"lodash"}}},
	  {"observation":{"result":"[]"}},
	  {"action":{"kind":"respond","response":"done"}}
	]}`
	srv := fakeJikji(t, resp, nil)
	defer srv.Close()
	r := NewRunner(RunnerConfig{BaseURL: srv.URL})
	res, err := r.Run(context.Background(), "triage")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.ToolSteps != 2 || len(res.ToolCalls) != 2 {
		t.Fatalf("want 2 tool calls, got steps=%d calls=%d", res.ToolSteps, len(res.ToolCalls))
	}
	if res.ToolCalls[0].Name != "advisory_for" || res.ToolCalls[1].Name != "dependents_of" {
		t.Fatalf("tool names wrong: %+v", res.ToolCalls)
	}
	if !strings.Contains(string(res.ToolCalls[0].Result), "exploited_kev") {
		t.Fatalf("tool result not captured: %s", res.ToolCalls[0].Result)
	}
	if !strings.Contains(string(res.ToolCalls[1].Args), "lodash") {
		t.Fatalf("tool args (input fallback) not captured: %s", res.ToolCalls[1].Args)
	}
}

// TestRunnerReconstructsJikjiToolCalls uses jikji's REAL /v1/runs event shape:
// the tool identity is nested under action.tool_call.{id,name,input_hash} and the
// result arrives as observation.{kind,action_id,content}. This is what a live
// jikji backbone actually emits (verified against a running server), so the audit
// trail must capture the real tool name — not "unknown".
func TestRunnerReconstructsJikjiToolCalls(t *testing.T) {
	resp := `{"id":"run-x","status":"completed","response":"done","events":[
	  {"type":"run.step","action":{"kind":"tool","tool_call":{"id":"call_abc","name":"bongsu.advisory_for","input_hash":"sha256:deadbeef"}}},
	  {"type":"run.observation","observation":{"kind":"tool","action_id":"call_abc","content":"{\"cve\":\"CVE-2024-3094\",\"sources\":[{\"severity\":\"CRITICAL\"}]}"}},
	  {"type":"run.step","action":{"kind":"respond","response":"done"}}
	]}`
	srv := fakeJikji(t, resp, nil)
	defer srv.Close()
	r := NewRunner(RunnerConfig{BaseURL: srv.URL})
	res, err := r.Run(context.Background(), "report")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.ToolSteps != 1 || len(res.ToolCalls) != 1 {
		t.Fatalf("want 1 tool call, got steps=%d calls=%d", res.ToolSteps, len(res.ToolCalls))
	}
	tc := res.ToolCalls[0]
	if tc.Name != "bongsu.advisory_for" {
		t.Fatalf("tool name must come from tool_call.name, got %q", tc.Name)
	}
	if tc.ID != "call_abc" {
		t.Fatalf("tool call id not captured, got %q", tc.ID)
	}
	if !strings.Contains(string(tc.Result), "CRITICAL") {
		t.Fatalf("observation.content not captured as result: %s", tc.Result)
	}
	if !strings.Contains(string(tc.Args), "input_hash") {
		t.Fatalf("input_hash not captured into args: %s", tc.Args)
	}
}

// TestRunnerSendsBearerToken verifies the runner authenticates to a backbone
// that requires a token: with a configured token every request carries
// Authorization: Bearer <token>; without one, no auth header is sent.
func TestRunnerSendsBearerToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"r","status":"completed","response":"ok","events":[]}`)
	}))
	defer srv.Close()

	r := NewRunner(RunnerConfig{BaseURL: srv.URL, Token: "secret-tok"})
	if _, err := r.Run(context.Background(), "triage"); err != nil {
		t.Fatalf("run: %v", err)
	}
	if gotAuth != "Bearer secret-tok" {
		t.Fatalf("Authorization header = %q, want %q", gotAuth, "Bearer secret-tok")
	}

	gotAuth = ""
	r2 := NewRunner(RunnerConfig{BaseURL: srv.URL})
	if _, err := r2.Run(context.Background(), "triage"); err != nil {
		t.Fatalf("run: %v", err)
	}
	if gotAuth != "" {
		t.Fatalf("no token configured, but sent Authorization %q", gotAuth)
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
