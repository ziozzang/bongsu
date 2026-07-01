//go:build integration

package intel

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestIntelLiveSmoke exercises the intel layer against a REAL jikji backbone
// (not an httptest fake), verifying the runner parses the live /v1/runs shape and
// that the new features — report persistence and majority-vote verification —
// work end-to-end against the actual server. It is dormant by default: set
// BONGSU_INTEL_LIVE=1 and BONGSU_INTEL_JIKJI_URL=http://127.0.0.1:1385 (+
// BONGSU_TEST_DB) to run it. It makes a handful of real LLM calls.
func TestIntelLiveSmoke(t *testing.T) {
	if os.Getenv("BONGSU_INTEL_LIVE") != "1" {
		t.Skip("set BONGSU_INTEL_LIVE=1 (with a real BONGSU_INTEL_JIKJI_URL) to run the live jikji smoke")
	}
	if os.Getenv("BONGSU_INTEL_JIKJI_URL") == "" {
		t.Skip("BONGSU_INTEL_JIKJI_URL must point at a running jikji server")
	}
	database := openIntelDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	svc := NewServiceFromEnv(database)
	defer svc.Close()
	if !svc.Enabled() {
		t.Fatal("service must be enabled with a backbone URL")
	}
	if err := svc.Health(ctx); err != nil {
		t.Fatalf("backbone health: %v", err)
	}

	// 1) report scenario -> runner parse + output validation + persistence path.
	rep, err := svc.RunScenario(ctx, RunRequest{
		Scenario: "report", Params: map[string]any{"cve": "CVE-2024-3094"},
		PrincipalID: "smoke", Scope: &Scope{Admin: true},
	})
	if err != nil {
		t.Fatalf("live report run: %v", err)
	}
	t.Logf("[live] report: status=%s tokens=%d persisted=%v dedup=%q run=%s",
		rep.Status, rep.TotalTokens, rep.ReportPersisted, rep.ReportDedupKey, rep.RunID)
	if rep.Status == "" {
		t.Fatal("live report run produced no status (runner parse failure)")
	}
	if rep.ReportPersisted {
		got, err := svc.GetFindingReport(ctx, rep.ReportDedupKey)
		if err != nil {
			t.Fatalf("persisted report must be readable back: %v", err)
		}
		t.Logf("[live] persisted report finding=%q severity=%q seen=%d", got.Finding, got.Severity, got.SeenCount)
	}

	// 2) verify voting -> parallel independent voters against the live backbone.
	ver, err := svc.RunVerification(ctx, VerificationRequest{
		CVE: "CVE-2024-3094", Voters: 3, PrincipalID: "smoke", Scope: &Scope{Admin: true},
	})
	if err != nil {
		t.Fatalf("live verification: %v", err)
	}
	t.Logf("[live] verify: status=%s verdict=%s confidence=%.2f counts=%+v",
		ver.Status, ver.Verdict, ver.Confidence, ver.Counts)
	if ver.Counts.Requested != 3 {
		t.Fatalf("expected 3 voters, got %d", ver.Counts.Requested)
	}
	for _, v := range ver.Voters {
		t.Logf("[live]   voter lens=%s status=%s valid=%v conf=%.2f err=%q", v.Lens, v.Status, v.Valid, v.Confidence, v.Error)
	}
}
