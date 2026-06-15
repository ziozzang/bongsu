package api

import (
	"strings"
	"testing"
)

// The /metrics endpoint reuses the comprehensive admin Prometheus exposition but
// must be reachable by a scraper without an admin credential and must not be
// public by default. These source-level checks pin the wiring + scrape-auth
// policy + the self-contained Go runtime metrics.

func TestMetricsEndpointWiring(t *testing.T) {
	body := readAllPackageGoFiles(t)
	for _, want := range []string{
		`s.mux.HandleFunc("GET /metrics", s.handleMetrics)`,
		"func (s *Server) handleMetrics(",
		"func (s *Server) metricsScrapeAuthorized(",
		"func (s *Server) serveMetrics(",
		"func (s *Server) writeRuntimeMetrics(",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics endpoint wiring missing: %q", want)
		}
	}
}

func TestMetricsScrapeAuthPolicy(t *testing.T) {
	body := readAllPackageGoFiles(t)
	start := strings.Index(body, "func (s *Server) metricsScrapeAuthorized(")
	if start < 0 {
		t.Fatal("metricsScrapeAuthorized not found")
	}
	end := strings.Index(body[start+1:], "\nfunc ")
	fn := body[start : start+1+end]
	for _, want := range []string{
		`envBool("BONGSU_METRICS_PUBLIC", false)`, // opt-in public
		`os.Getenv("BONGSU_METRICS_TOKEN")`,       // dedicated scrape token
		"subtle.ConstantTimeCompare",              // timing-safe token compare
		`r.Header.Get("Authorization")`,           // Bearer support
		`strings.HasPrefix(auth, "Bearer ")`,      // Bearer scheme
		"s.authenticateAdmin(r)",                  // admin fallback (secure default)
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("metricsScrapeAuthorized must implement %q", want)
		}
	}
	// handleMetrics must gate on the scrape authorizer, not bare admin auth.
	hStart := strings.Index(body, "func (s *Server) handleMetrics(")
	hEnd := strings.Index(body[hStart+1:], "\nfunc ")
	h := body[hStart : hStart+1+hEnd]
	if !strings.Contains(h, "s.metricsScrapeAuthorized(r)") {
		t.Fatal("handleMetrics must authorize via metricsScrapeAuthorized")
	}
}

func TestMetricsIncludeRuntimeGauges(t *testing.T) {
	body := readAllPackageGoFiles(t)
	for _, want := range []string{
		"bongsu_process_goroutines",
		"bongsu_process_uptime_seconds",
		"bongsu_process_memory_alloc_bytes",
		"bongsu_process_gc_total",
		"runtime.ReadMemStats(&m)",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("runtime metrics missing: %q", want)
		}
	}
}
