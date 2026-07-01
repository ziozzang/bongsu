//go:build integration

package intel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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

	// The tool-call audit is written asynchronously; drain the writer before
	// asserting it landed.
	svc.Close()
	var auditCount int
	if err := database.QueryRowContext(ctx,
		`SELECT count(*) FROM intel_tool_calls WHERE run_id=$1`, outcome.RunID).Scan(&auditCount); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("expected 1 reconstructed tool-call audit row, got %d", auditCount)
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

// TestServiceLiveJikjiSmoke runs a real scenario against the live jikji backbone.
// Guarded by BONGSU_INTEL_LIVE=1 so it never runs in normal CI (it makes a real
// LLM call). It confirms the HTTP /v1/runs loop, response parsing and run
// persistence work end-to-end against the real server. The agent has no Bongsu
// MCP tools here, so it answers from the prompt alone — we only assert the run
// completes and persists, not the content.
func TestServiceLiveJikjiSmoke(t *testing.T) {
	if os.Getenv("BONGSU_INTEL_LIVE") != "1" {
		t.Skip("set BONGSU_INTEL_LIVE=1 to smoke the live jikji backbone")
	}
	database := openIntelDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	liveURL := os.Getenv("BONGSU_INTEL_JIKJI_URL")
	if liveURL == "" {
		liveURL = "http://127.0.0.1:1385"
	}
	t.Setenv("BONGSU_INTEL_JIKJI_URL", liveURL)
	t.Setenv("BONGSU_INTEL_MAX_STEPS", "3")
	svc := NewServiceFromEnv(database)
	defer svc.Close()
	if err := svc.Health(ctx); err != nil {
		t.Fatalf("live backbone health: %v", err)
	}
	outcome, err := svc.RunScenario(ctx, RunRequest{
		Scenario: "correlate", Params: map[string]any{"cve": "CVE-2024-3094"},
		PrincipalID: "user:admin", Scope: &Scope{Admin: true},
	})
	if err != nil {
		t.Fatalf("live RunScenario: %v", err)
	}
	t.Logf("live run %s status=%s tokens=%d response=%.200s", outcome.RunID, outcome.Status, outcome.TotalTokens, outcome.Response)
	if outcome.RunID == "" {
		t.Fatal("live run must persist a run id")
	}
	view, err := svc.GetRun(ctx, outcome.RunID)
	if err != nil || view.ID == "" {
		t.Fatalf("live run must be readable: view=%+v err=%v", view, err)
	}
}

// TestServiceSessionThreading verifies interactive-audit sessions: the first run
// yields a session id (jikji-generated), and a follow-up run carries it back to
// the backbone and persists it, so the agent can build on prior context.
func TestServiceSessionThreading(t *testing.T) {
	database := openIntelDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var gotSessions []string
	jikji := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(200)
			return
		}
		var body struct {
			SessionID string `json:"session_id"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		gotSessions = append(gotSessions, body.SessionID)
		// The backbone assigns a session when none is supplied.
		sess := body.SessionID
		if sess == "" {
			sess = "sess-generated-1"
		}
		w.Header().Set("Content-Type", "application/json")
		// Schema-valid nl_query output (required: answer) so no corrective retry fires.
		_, _ = io.WriteString(w, `{"id":"run-x","session_id":"`+sess+`","status":"completed","response":"{\"answer\":\"ok\"}","events":[]}`)
	}))
	defer jikji.Close()

	t.Setenv("BONGSU_INTEL_JIKJI_URL", jikji.URL)
	svc := NewServiceFromEnv(database)
	defer svc.Close()

	// First run: no session -> backbone generates one, returned + persisted.
	first, err := svc.RunScenario(ctx, RunRequest{Scenario: "nl_query", Params: map[string]any{"question": "hi"}, PrincipalID: "user:admin", Scope: &Scope{Admin: true}})
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if first.SessionID != "sess-generated-1" {
		t.Fatalf("first run should surface the backbone session id, got %q", first.SessionID)
	}
	// Follow-up run: reuse the session id.
	second, err := svc.RunScenario(ctx, RunRequest{Scenario: "nl_query", Params: map[string]any{"question": "and then?"}, PrincipalID: "user:admin", Scope: &Scope{Admin: true}, SessionID: first.SessionID})
	if err != nil {
		t.Fatalf("follow-up run: %v", err)
	}
	if second.SessionID != "sess-generated-1" {
		t.Fatalf("follow-up must keep the session id, got %q", second.SessionID)
	}
	// The backbone saw: "" (first, generated) then the reused id (follow-up).
	if len(gotSessions) != 2 || gotSessions[0] != "" || gotSessions[1] != "sess-generated-1" {
		t.Fatalf("backbone session threading wrong: %v", gotSessions)
	}
	// Both runs are persisted under the session.
	var n int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM intel_runs WHERE session_id='sess-generated-1'`).Scan(&n); err != nil {
		t.Fatalf("count session runs: %v", err)
	}
	if n != 2 {
		t.Fatalf("both runs should persist under the session, got %d", n)
	}
}

// TestServiceRunPipeline verifies pipeline orchestration: scenarios run in order
// under one threaded session, all stages persist under it, and a mid-pipeline
// failure yields "partial" (continue) unless StopOnFailure.
func TestServiceRunPipeline(t *testing.T) {
	database := openIntelDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Fail the report stage deterministically (by prompt), return schema-valid
	// output for the others so no corrective retry fires and skews call ordering.
	jikji := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(200)
			return
		}
		var body struct {
			Prompt string `json:"prompt"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		if contains(body.Prompt, "CVE-grade report") {
			w.WriteHeader(500)
			_, _ = io.WriteString(w, "stage boom")
			return
		}
		var inner string
		switch {
		case contains(body.Prompt, "ADVERSARIALLY verify"):
			inner = `{\"finding\":\"CVE-2024-3094\",\"valid\":true,\"confidence\":0.5}`
		default: // triage
			inner = `{\"verdict\":\"reachable\",\"confidence\":0.5}`
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"run-p","session_id":"sess-pipe","status":"completed","response":"`+inner+`","events":[]}`)
	}))
	defer jikji.Close()

	t.Setenv("BONGSU_INTEL_JIKJI_URL", jikji.URL)
	svc := NewServiceFromEnv(database)
	defer svc.Close()

	out, err := svc.RunPipeline(ctx, PipelineRequest{
		Scenarios: []string{"triage", "report", "verify"}, Params: map[string]any{"cve": "CVE-2024-3094"},
		PrincipalID: "user:admin", Scope: &Scope{Admin: true},
	})
	if err != nil {
		t.Fatalf("RunPipeline: %v", err)
	}
	if len(out.Stages) != 3 {
		t.Fatalf("want 3 stages (continue on failure), got %d", len(out.Stages))
	}
	if out.Status != "partial" {
		t.Fatalf("one failed stage -> partial, got %q", out.Status)
	}
	if out.Stages[0].Status != "completed" || out.Stages[1].Status != "failed" || out.Stages[2].Status != "completed" {
		t.Fatalf("stage statuses wrong: %+v", out.Stages)
	}
	if out.SessionID != "sess-pipe" {
		t.Fatalf("pipeline must thread the session, got %q", out.SessionID)
	}
	// All stages persist under the shared session.
	var n int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM intel_runs WHERE session_id='sess-pipe'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 3 {
		t.Fatalf("all 3 stage runs should persist under the session, got %d", n)
	}

	// Unknown scenario fails fast.
	if _, err := svc.RunPipeline(ctx, PipelineRequest{Scenarios: []string{"nope"}, PrincipalID: "u", Scope: &Scope{Admin: true}}); err == nil {
		t.Fatal("unknown scenario must fail fast")
	}
}

// TestServiceCorrectiveRetry verifies structured termination: an invalid first
// output triggers one corrective retry (in-session), the valid retry is accepted,
// and output_valid is recorded.
func TestServiceCorrectiveRetry(t *testing.T) {
	database := openIntelDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var attempts int
	var sawCorrection bool
	jikji := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(200)
			return
		}
		attempts++
		var body struct {
			Prompt string `json:"prompt"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		w.Header().Set("Content-Type", "application/json")
		if attempts == 1 {
			// invalid: prose, no JSON — must trigger a corrective retry
			_, _ = io.WriteString(w, `{"id":"r1","status":"completed","response":"I think it is critical.","events":[]}`)
			return
		}
		if contains(body.Prompt, "CORRECTION") {
			sawCorrection = true
		}
		// valid on the retry (correlate requires cve + canonical)
		_, _ = io.WriteString(w, `{"id":"r2","status":"completed","response":"{\"cve\":\"CVE-1\",\"canonical\":{\"severity\":\"high\"}}","events":[]}`)
	}))
	defer jikji.Close()

	t.Setenv("BONGSU_INTEL_JIKJI_URL", jikji.URL)
	svc := NewServiceFromEnv(database)
	defer svc.Close()

	outcome, err := svc.RunScenario(ctx, RunRequest{Scenario: "correlate", Params: map[string]any{"cve": "CVE-1"}, PrincipalID: "user:admin", Scope: &Scope{Admin: true}})
	if err != nil {
		t.Fatalf("RunScenario: %v", err)
	}
	if attempts != 2 || !sawCorrection {
		t.Fatalf("invalid output must trigger one corrective retry: attempts=%d sawCorrection=%v", attempts, sawCorrection)
	}
	var valid bool
	if err := database.QueryRowContext(ctx, `SELECT output_valid FROM intel_runs WHERE id=$1`, outcome.RunID).Scan(&valid); err != nil {
		t.Fatalf("read output_valid: %v", err)
	}
	if !valid {
		t.Fatalf("retry produced valid output; output_valid must be true")
	}
}

// TestServiceRunVerification drives majority-vote verification: three lens-diverse
// voters run in parallel (accuracy=valid, reachability=valid, version=refuted) ->
// verdict=valid; the aggregate persists to intel_verifications and each voter run
// is linked back by FK.
func TestServiceRunVerification(t *testing.T) {
	database := openIntelDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	jikji := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(200)
			return
		}
		var body struct {
			Prompt string `json:"prompt"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		// Vote by lens: 2 valid, 1 refuted -> majority valid.
		valid, conf := true, 0.9
		switch {
		case contains(body.Prompt, "VERSION-PRESENCE lens"):
			valid, conf = false, 0.7
		case contains(body.Prompt, "REACHABILITY lens"):
			valid, conf = true, 0.8
		case contains(body.Prompt, "ACCURACY lens"):
			valid, conf = true, 0.9
		}
		inner, _ := json.Marshal(map[string]any{"finding": "CVE-2024-3094", "valid": valid, "confidence": conf, "refutation": "", "evidence": []any{}})
		run, _ := json.Marshal(map[string]any{"id": "run-vote", "status": "completed", "response": string(inner), "events": []any{}})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(run)
	}))
	defer jikji.Close()

	t.Setenv("BONGSU_INTEL_JIKJI_URL", jikji.URL)
	svc := NewServiceFromEnv(database)
	defer svc.Close()

	out, err := svc.RunVerification(ctx, VerificationRequest{
		CVE: "CVE-2024-3094", Voters: 3, PrincipalID: "user:admin", Scope: &Scope{Admin: true},
	})
	if err != nil {
		t.Fatalf("RunVerification: %v", err)
	}
	if out.Verdict != VerdictValid || out.Status != StatusComplete || !out.Valid {
		t.Fatalf("want valid/complete, got verdict=%q status=%q valid=%v", out.Verdict, out.Status, out.Valid)
	}
	if out.Counts.Succeeded != 3 || out.Counts.Valid != 2 || out.Counts.Refuted != 1 {
		t.Fatalf("counts wrong: %+v", out.Counts)
	}
	if len(out.Voters) != 3 {
		t.Fatalf("want 3 voter records, got %d", len(out.Voters))
	}
	// Every voter must have been assigned a distinct default lens.
	lenses := map[Lens]bool{}
	for _, v := range out.Voters {
		lenses[v.Lens] = true
	}
	if len(lenses) != 3 {
		t.Fatalf("voters must get distinct lenses, got %v", lenses)
	}
	// Aggregate persisted.
	var status, verdict string
	var succeeded int
	if err := database.QueryRowContext(ctx,
		`SELECT status, verdict, succeeded_voters FROM intel_verifications WHERE id=$1`, out.VerificationID).
		Scan(&status, &verdict, &succeeded); err != nil {
		t.Fatalf("read verification: %v", err)
	}
	if status != "complete" || verdict != "valid" || succeeded != 3 {
		t.Fatalf("persisted aggregate wrong: status=%q verdict=%q succeeded=%d", status, verdict, succeeded)
	}
	// Voter runs linked back by FK.
	var linked int
	if err := database.QueryRowContext(ctx,
		`SELECT count(*) FROM intel_runs WHERE verification_id=$1`, out.VerificationID).Scan(&linked); err != nil {
		t.Fatalf("count linked runs: %v", err)
	}
	if linked != 3 {
		t.Fatalf("want 3 voter runs linked by FK, got %d", linked)
	}
}

// TestServiceRunVerificationInconclusive verifies that when too few voters
// succeed (backbone failing), the verdict is inconclusive, not a false verdict.
func TestServiceRunVerificationInconclusive(t *testing.T) {
	database := openIntelDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var n int
	jikji := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(200)
			return
		}
		n++
		// Only the first voter succeeds; the rest fail (HTTP 500).
		if n == 1 {
			inner, _ := json.Marshal(map[string]any{"finding": "CVE-1", "valid": true, "confidence": 0.9})
			run, _ := json.Marshal(map[string]any{"id": "run-ok", "status": "completed", "response": string(inner), "events": []any{}})
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(run)
			return
		}
		w.WriteHeader(500)
		_, _ = io.WriteString(w, "boom")
	}))
	defer jikji.Close()

	t.Setenv("BONGSU_INTEL_JIKJI_URL", jikji.URL)
	svc := NewServiceFromEnv(database)
	defer svc.Close()

	out, err := svc.RunVerification(ctx, VerificationRequest{
		CVE: "CVE-1", Voters: 3, PrincipalID: "user:admin", Scope: &Scope{Admin: true},
	})
	if err != nil {
		t.Fatalf("RunVerification: %v", err)
	}
	if out.Status != StatusInconclusive || out.Verdict != VerdictInconclusive {
		t.Fatalf("too few successes must be inconclusive, got status=%q verdict=%q", out.Status, out.Verdict)
	}
	if out.Counts.Succeeded != 1 || out.Counts.Failed != 2 {
		t.Fatalf("counts wrong: %+v", out.Counts)
	}
}
