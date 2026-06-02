package api

import (
	"strings"
	"testing"
)

func TestIntelligenceRoutesAreRegistered(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		`"GET /api/intelligence/top-risk"`,
		`"GET /api/intelligence/recommendations"`,
		`"GET /api/intelligence/posture"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("route missing %q", want)
		}
	}
}

func TestIntelligenceHandlersExist(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		"handleGetTopAtRiskHosts",
		"handleGetRecommendations",
		"handleGetVulnPosture",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q", want)
		}
	}
}

func TestIntelligenceDBMethodsExist(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		"GetTopAtRiskHosts",
		"GetRecommendations",
		"GetVulnPostureComparison",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q", want)
		}
	}
}

func TestIntelligenceRequiresWebAuth(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, fn := range []string{"handleGetTopAtRiskHosts", "handleGetRecommendations", "handleGetVulnPosture"} {
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

func TestIntelligenceEnvVarsPresent(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		"BONGSU_INTELLIGENCE_TOP_RISK_LIMIT",
		"BONGSU_INTELLIGENCE_POSTURE_COMPARISON_DAYS",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing env var %q", want)
		}
	}
}
