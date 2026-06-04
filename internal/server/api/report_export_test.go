package api

import (
	"strings"
	"testing"
)

func TestReportRoutesAreRegistered(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		`"GET /api/reports/executive-summary"`,
		`"GET /api/reports/risk-breakdown"`,
		`"GET /api/reports/sla-compliance"`,
		`"GET /api/reports/export"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("route missing %q", want)
		}
	}
}

func TestReportHandlersExist(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		"handleGetExecutiveSummary",
		"handleGetRiskBreakdown",
		"handleGetSLACompliance",
		"handleExportReport",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q", want)
		}
	}
}

func TestReportDBMethodsExist(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		"GetExecutiveSummary",
		"GetSLAComplianceReport",
		"GetRiskBreakdown",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q", want)
		}
	}
}

func TestReportHandlersRequireAuth(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, fn := range []string{"handleGetExecutiveSummary", "handleGetRiskBreakdown", "handleGetSLACompliance"} {
		idx := strings.Index(out, "func (s *Server) "+fn)
		if idx < 0 {
			t.Fatalf("%s not found", fn)
		}
		body := extractFuncBody(out, idx)
		if !strings.Contains(body, "authenticateWeb") {
			t.Fatalf("%s does not check authenticateWeb", fn)
		}
	}
}

func TestReportExportRequiresExportAuth(t *testing.T) {
	out := readAllPackageGoFiles(t)
	idx := strings.Index(out, "func (s *Server) handleExportReport")
	if idx < 0 {
		t.Fatal("handleExportReport not found")
	}
	body := extractFuncBody(out, idx)
	if !strings.Contains(body, "authenticateExport") {
		t.Fatal("handleExportReport does not check authenticateExport")
	}
}

func TestReportExportUsesStableArrayFields(t *testing.T) {
	out := readAllPackageGoFiles(t)
	idx := strings.Index(out, "func (s *Server) handleExportReport")
	if idx < 0 {
		t.Fatal("handleExportReport not found")
	}
	body := extractFuncBody(out, idx)
	for _, want := range []string{
		"rows = []db.RiskBreakdownRow{}",
		`json.Marshal(map[string]any{"items": rows, "group_by": groupBy})`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("report export must preserve stable JSON array field %q: %s", want, body)
		}
	}
}

func TestReportGeneratesAudit(t *testing.T) {
	out := readAllPackageGoFiles(t)
	idx := strings.Index(out, "func (s *Server) handleGetExecutiveSummary")
	if idx < 0 {
		t.Fatal("handleGetExecutiveSummary not found")
	}
	body := extractFuncBody(out, idx)
	if !strings.Contains(body, "s.audit") {
		t.Fatal("handleGetExecutiveSummary does not call s.audit")
	}
}
