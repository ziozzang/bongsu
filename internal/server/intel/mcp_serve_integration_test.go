//go:build integration

package intel

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// TestMCPServeEndToEnd exercises the exact composition the intel-mcp subcommand
// performs: create a run (scope snapshot) -> LoadRunScope -> DefaultRegistry ->
// MCP serve with audit-to-store -> a real tools/call lands a result and an audit
// row for the run. This is the autonomous-review path minus the flag dispatch.
func TestMCPServeEndToEnd(t *testing.T) {
	database := openIntelDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Seed an advisory + signals for advisory_for to return.
	entries := []models.CveEntry{
		{ID: "osv-CVE-E2E", VulnerabilityID: "CVE-E2E-1", Source: "osv", Severity: "CRITICAL", CVSSScore: 9.8, Title: "e2e", AffectedProducts: `[]`, References: `[]`, RawData: `{}`},
		{ID: "kev-CVE-E2E", VulnerabilityID: "CVE-E2E-1", Source: "cisa-kev", AffectedProducts: `[]`, References: `[]`, RawData: `{}`},
	}
	if _, err := database.UpsertCveEntries(ctx, entries); err != nil {
		t.Fatalf("seed cve: %v", err)
	}
	if _, err := database.SyncEPSSPriorityColumns(ctx); err != nil {
		t.Fatalf("refresh signals: %v", err)
	}

	store := NewStore(database, 64)
	runID, err := store.CreateRun(ctx, RunRecord{
		Scenario: "correlate", Goal: "e2e", PrincipalID: "user:admin",
		PrincipalScope: &Scope{Admin: true}, ToolsInjected: []string{"advisory_for"},
	})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}

	// The subcommand loads the scope from the run, not from the caller.
	scope, err := store.LoadRunScope(ctx, runID)
	if err != nil {
		t.Fatalf("load scope: %v", err)
	}
	if !scope.Admin {
		t.Fatalf("loaded scope should be admin: %+v", scope)
	}

	reg := DefaultRegistry(database)
	if names := reg.Names(); len(names) != 6 {
		t.Fatalf("default registry should have 6 tools, got %v", names)
	}

	srv := NewMCPServer(reg, scope).WithAudit(func(seq int, tool string, args, result []byte, isErr bool, dur time.Duration) {
		store.RecordToolCall(runID, seq, tool, args, result, false, dur, "")
	})
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"advisory_for","arguments":{"cve":"CVE-E2E-1"}}}` + "\n")
	var out strings.Builder
	if err := srv.Serve(ctx, in, &out); err != nil {
		t.Fatalf("serve: %v", err)
	}
	// Decode the JSON-RPC envelope -> content text -> the inner tool JSON.
	var resp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		t.Fatalf("decode rpc: %v (%s)", err, out.String())
	}
	if len(resp.Result.Content) == 0 {
		t.Fatalf("no content: %s", out.String())
	}
	var adv struct {
		CVE       string `json:"cve"`
		Exploited bool   `json:"exploited_kev"`
	}
	if err := json.Unmarshal([]byte(resp.Result.Content[0].Text), &adv); err != nil {
		t.Fatalf("decode tool result: %v (%s)", err, resp.Result.Content[0].Text)
	}
	if adv.CVE != "CVE-E2E-1" || !adv.Exploited {
		t.Fatalf("tool result should carry the KEV signal: %+v", adv)
	}

	if err := store.FinishRun(ctx, runID, "completed", nil, nil, ""); err != nil {
		t.Fatalf("finish: %v", err)
	}
	store.Close()

	var tool string
	if err := database.QueryRowContext(ctx,
		`SELECT tool_name FROM intel_tool_calls WHERE run_id=$1`, runID).Scan(&tool); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if tool != "advisory_for" {
		t.Fatalf("audit row tool = %q, want advisory_for", tool)
	}
}
