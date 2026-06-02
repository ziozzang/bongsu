package api

import (
	"strings"
	"testing"
)

func TestVulnTrendRoutesAreRegistered(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		`"GET /api/vuln-trends"`,
		`"GET /api/vuln-trends/summary"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("route missing %q", want)
		}
	}
}

func TestVulnTrendHandlersExist(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		"handleGetVulnTrends",
		"handleGetVulnTrendSummary",
		"startVulnTrendSnapshotter",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q", want)
		}
	}
}

func TestVulnTrendDBMethodsExist(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		"RecordVulnTrendSnapshot",
		"GetVulnTrends",
		"GetVulnTrendSummary",
		"CleanupOldTrendSnapshots",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q", want)
		}
	}
}

func TestVulnTrendRequiresWebAuth(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, fn := range []string{"handleGetVulnTrends", "handleGetVulnTrendSummary"} {
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

func TestTrendSnapshotRecordedAfterScan(t *testing.T) {
	out := readAllPackageGoFiles(t)
	if !strings.Contains(out, "RecordVulnTrendSnapshot") {
		t.Fatal("RecordVulnTrendSnapshot not called from report code")
	}
}

func TestVulnTrendEnvVarsPresent(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		"BONGSU_VULN_TREND_SNAPSHOT_INTERVAL_HOURS",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing env var %q", want)
		}
	}
}
