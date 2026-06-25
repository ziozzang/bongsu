//go:build integration

package intel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestServiceRunScenarioEndToEnd drives the full runtime path: Service.RunScenario
// builds the scenario prompt, POSTs to the (fake) jikji /v1/runs, persists the
// run, and GetRun reads it back. This is the API path minus the HTTP handler.
func TestServiceRunScenarioEndToEnd(t *testing.T) {
	database := openIntelDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var sentPrompt string
	jikji := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(200)
		case "/v1/runs":
			var body struct {
				Prompt string `json:"prompt"`
			}
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &body)
			sentPrompt = body.Prompt
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"run-e2e-1","status":"completed","response":"{\"cve\":\"CVE-2024-3094\",\"canonical\":{\"severity\":\"critical\"}}","context_tokens":16000,"events":[{"action":{"kind":"tool"}},{"action":{"kind":"respond","response":"..."}},{"usage":{"prompt_tokens":16000,"completion_tokens":50,"total_tokens":16050}}]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer jikji.Close()

	t.Setenv("BONGSU_INTEL_JIKJI_URL", jikji.URL)
	svc := NewServiceFromEnv(database)
	defer svc.Close()
	if !svc.Enabled() {
		t.Fatal("service must be enabled with a backbone URL")
	}
	if err := svc.Health(ctx); err != nil {
		t.Fatalf("health: %v", err)
	}

	outcome, err := svc.RunScenario(ctx, RunRequest{
		Scenario:    "correlate",
		Params:      map[string]any{"cve": "CVE-2024-3094"},
		PrincipalID: "user:admin",
		Scope:       &Scope{Admin: true},
	})
	if err != nil {
		t.Fatalf("RunScenario: %v", err)
	}
	if outcome.Status != "completed" || outcome.RunID == "" {
		t.Fatalf("outcome wrong: %+v", outcome)
	}
	if outcome.ToolSteps != 1 || outcome.TotalTokens != 16050 {
		t.Fatalf("outcome metrics wrong: %+v", outcome)
	}
	// The scenario prompt must have reached the backbone with the CVE.
	if sentPrompt == "" || !contains(sentPrompt, "CVE-2024-3094") || !contains(sentPrompt, "advisory_for") {
		t.Fatalf("prompt not built/sent correctly: %q", sentPrompt)
	}

	// Read the persisted run back.
	view, err := svc.GetRun(ctx, outcome.RunID)
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if view.Status != "completed" || view.Scenario != "correlate" {
		t.Fatalf("persisted run wrong: %+v", view)
	}
	var out struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal(view.Output, &out); err != nil {
		t.Fatalf("decode output: %v (%s)", err, view.Output)
	}
	if !contains(out.Response, "canonical") {
		t.Fatalf("stored response wrong: %s", out.Response)
	}
}

// TestServiceFailedRunPersisted: a backbone error marks the run failed and still
// persists it.
func TestServiceFailedRunPersisted(t *testing.T) {
	database := openIntelDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	jikji := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(500)
		_, _ = io.WriteString(w, "backbone boom")
	}))
	defer jikji.Close()

	t.Setenv("BONGSU_INTEL_JIKJI_URL", jikji.URL)
	svc := NewServiceFromEnv(database)
	defer svc.Close()

	outcome, err := svc.RunScenario(ctx, RunRequest{Scenario: "correlate", Params: map[string]any{"cve": "CVE-1"}, PrincipalID: "user:admin", Scope: &Scope{Admin: true}})
	if err == nil {
		t.Fatal("backbone 500 must surface an error")
	}
	if outcome.RunID == "" || outcome.Status != "failed" {
		t.Fatalf("failed run should still have an id+status: %+v", outcome)
	}
	view, gerr := svc.GetRun(ctx, outcome.RunID)
	if gerr != nil || view.Status != "failed" || view.Error == "" {
		t.Fatalf("failed run must persist with error: view=%+v err=%v", view, gerr)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
