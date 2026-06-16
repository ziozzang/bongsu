package api

import (
	"strings"
	"testing"
)

func TestAIActionRoutesAndGuards(t *testing.T) {
	body := readAllPackageGoFiles(t)
	for _, want := range []string{
		`s.mux.HandleFunc("GET /api/admin/ai-policy", s.handleAIPolicyStatus)`,
		`s.mux.HandleFunc("GET /api/admin/ai-approvals", s.handleListAIApprovals)`,
		`s.mux.HandleFunc("POST /api/admin/ai-approvals/{id}/approve", s.handleApproveAIApproval)`,
		`s.mux.HandleFunc("POST /api/admin/ai-approvals/{id}/reject", s.handleRejectAIApproval)`,
		// Atomic claim closes the double-execution race.
		"s.db.ClaimAIApprovalForApproval(r.Context(), id, actor)",
		"s.db.RevertAIApproval(r.Context(), id)",
		// Executor restricts triage.suppress to suppressing statuses + rebuilds summaries.
		`p.TriageStatus != "accepted_risk" && p.TriageStatus != "false_positive"`,
		"s.db.RebuildPackageVulnerabilitySummariesForTriage",
		// Pending dedup is per finding, not per CVE.
		`fmt.Sprintf("%s|%s|%s", c.VulnerabilityID, c.HostID, c.PkgName)`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("ai-action wiring missing: %q", want)
		}
	}
	// All policy/approval handlers are admin-gated; the executor mutates triage.
	for _, fn := range []string{"handleAIPolicyStatus", "handleListAIApprovals", "handleDecideAIApproval"} {
		start := strings.Index(body, "func (s *Server) "+fn+"(")
		if start < 0 {
			t.Fatalf("handler %s not found", fn)
		}
		end := strings.Index(body[start+1:], "\nfunc ")
		if !strings.Contains(body[start:start+1+end], "s.authenticateAdmin(r)") {
			t.Fatalf("%s must require admin", fn)
		}
	}
}
