package api

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ziozzang/bongsu/internal/server/db"
	"github.com/ziozzang/bongsu/internal/server/trivydb"
	"github.com/ziozzang/bongsu/internal/shared/models"
)

func readAllPackageGoFiles(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
			data, err := os.ReadFile(e.Name())
			if err != nil {
				t.Fatal(err)
			}
			buf.Write(data)
			buf.WriteByte('\n')
		}
	}
	return buf.String()
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func extractFuncBody(src string, start int) string {
	depth := 0
	inFunc := false
	for i := start; i < len(src); i++ {
		if src[i] == '{' {
			depth++
			inFunc = true
		} else if src[i] == '}' {
			depth--
			if inFunc && depth == 0 {
				return src[start : i+1]
			}
		}
	}
	return src[start:]
}

func TestAuthSeparation(t *testing.T) {
	s := &Server{
		apiKey:       "admin-key",
		agentKey:     "agent-key",
		installToken: "install-token",
		webAuth:      true,
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "admin-key")
	if !s.authenticateAdmin(req) {
		t.Fatal("admin key should authenticate admin")
	}
	if s.authenticateAgent(req) == false {
		t.Fatal("admin key should be accepted for agent compatibility")
	}

	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "agent-key")
	if !s.authenticateAgent(req) {
		t.Fatal("agent key should authenticate agent")
	}
	if s.authenticateAdmin(req) {
		t.Fatal("agent key must not authenticate admin")
	}

	req = httptest.NewRequest("GET", "/api/install.sh", nil)
	req.Header.Set("X-Install-Token", "install-token")
	if !s.authenticateInstall(req) {
		t.Fatal("install token should authenticate installer")
	}

	req = httptest.NewRequest("GET", "/api/install.sh?token=install-token", nil)
	if s.authenticateInstall(req) {
		t.Fatal("install token query parameter must not authenticate installer")
	}

	req = httptest.NewRequest("GET", "/api/install.sh?api_key=admin-key", nil)
	if s.authenticateInstall(req) {
		t.Fatal("api_key query parameter must not authenticate installer")
	}
}

func TestAdminAuthenticationAcceptsLocalAdminSession(t *testing.T) {
	out := readAllPackageGoFiles(t)
	start := strings.Index(out, "func (s *Server) authenticateAdmin")
	if start < 0 {
		t.Fatal("authenticateAdmin not found")
	}
	end := strings.Index(out[start:], "func (s *Server) authenticateAgent")
	if end < 0 {
		t.Fatal("authenticateAgent not found")
	}
	fn := out[start : start+end]
	for _, want := range []string{
		"s.matchKey(r.Header.Get(\"X-API-Key\"), s.apiKey)",
		"s.sessionUser(r)",
		`u.Role == "admin"`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("authenticateAdmin must accept local admin sessions; missing %q in %s", want, fn)
		}
	}
}

func TestInstallAuthRequiresTokenOrAdminHeader(t *testing.T) {
	s := &Server{apiKey: "admin-key", agentKey: "agent-key"}

	req := httptest.NewRequest("GET", "/api/install.sh", nil)
	if s.authenticateInstall(req) {
		t.Fatal("installer must not be public when install token is unset")
	}

	req = httptest.NewRequest("GET", "/api/install.sh", nil)
	req.Header.Set("X-API-Key", "admin-key")
	if !s.authenticateInstall(req) {
		t.Fatal("admin header should authenticate installer for manual downloads")
	}

	s.installToken = "install-token"
	req = httptest.NewRequest("GET", "/api/install.sh", nil)
	req.Header.Set("X-Install-Token", "install-token")
	if !s.authenticateInstall(req) {
		t.Fatal("install token should authenticate installer")
	}
}

func TestSecurityHeadersMiddlewareSetsBrowserHardeningHeaders(t *testing.T) {
	t.Setenv("BONGSU_HSTS_ENABLED", "true")
	s := &Server{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest("GET", "https://example.com/", nil)
	rr := httptest.NewRecorder()

	s.securityHeadersMiddleware(next).ServeHTTP(rr, req)

	for name, want := range map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	} {
		if got := rr.Header().Get(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	csp := rr.Header().Get("Content-Security-Policy")
	for _, want := range []string{
		"default-src 'self'",
		"script-src 'self'",
		"connect-src 'self'",
		"object-src 'none'",
		"frame-ancestors 'none'",
	} {
		if !strings.Contains(csp, want) {
			t.Fatalf("CSP missing %q: %s", want, csp)
		}
	}
	permissions := rr.Header().Get("Permissions-Policy")
	for _, want := range []string{"camera=()", "microphone=()", "geolocation=()", "payment=()", "usb=()"} {
		if !strings.Contains(permissions, want) {
			t.Fatalf("Permissions-Policy missing %q: %s", want, permissions)
		}
	}
}

func TestAdminMetricsRequiresAdminAndReportsRuntimeState(t *testing.T) {
	s := &Server{apiKey: "admin-key"}
	s.securityRecalcRunning = true
	s.securityRecalcPending = true

	unauthorized := httptest.NewRecorder()
	s.handleAdminMetrics(unauthorized, httptest.NewRequest("GET", "/api/admin/metrics", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized metrics status = %d, want %d", unauthorized.Code, http.StatusUnauthorized)
	}

	req := httptest.NewRequest("GET", "/api/admin/metrics", nil)
	req.Header.Set("X-API-Key", "admin-key")
	authorized := httptest.NewRecorder()
	s.handleAdminMetrics(authorized, req)
	if authorized.Code != http.StatusOK {
		t.Fatalf("authorized metrics status = %d, want %d", authorized.Code, http.StatusOK)
	}
	if got := authorized.Header().Get("Content-Type"); !strings.Contains(got, "text/plain") {
		t.Fatalf("metrics content type = %q, want text/plain", got)
	}
	body := authorized.Body.String()
	for _, want := range []string{
		"# TYPE bongsu_build_info gauge",
		`bongsu_build_info{service="bongsu"} 1`,
		"bongsu_security_recalculation_running 1",
		"bongsu_security_recalculation_pending 1",
		"bongsu_trivy_db_ready 0",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics body missing %q: %s", want, body)
		}
	}
}

func TestAdminMetricsUsesBoundedDatabaseContext(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleAdminMetrics")
	if start < 0 {
		t.Fatal("handleAdminMetrics not found")
	}
	end := strings.Index(body[start:], "func (s *Server) adminMetrics")
	if end < 0 {
		t.Fatal("adminMetrics not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		`envInt("BONGSU_ADMIN_METRICS_DB_TIMEOUT_SECONDS", 30)`,
		"context.WithTimeout(r.Context(), time.Duration(metricsTimeout)*time.Second)",
		"s.adminMetrics(ctx)",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("admin metrics handler must bound DB work, missing %q: %s", want, fn)
		}
	}
}

func TestAdminMetricsExposeActiveRiskLevelBacklog(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) adminMetrics")
	if start < 0 {
		t.Fatal("adminMetrics not found")
	}
	end := strings.Index(body[start:], "func boolMetric")
	if end < 0 {
		t.Fatal("boolMetric not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"GetCurrentActionableVulnRiskCountsByHost(ctx, nil)",
		"bongsu_active_vulnerabilities_by_risk_level",
		"GetCurrentActionableOverdueRiskCountsByHost(ctx, nil)",
		"bongsu_overdue_sla_vulnerabilities_by_risk_level",
		`map[string]string{"risk_level": riskLevel}`,
		`[]string{"critical", "high", "medium", "low"}`,
		"bongsu_active_vulnerability_risk_metrics_error",
		"bongsu_overdue_sla_vulnerability_risk_metrics_error",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("admin metrics risk backlog missing %q: %s", want, fn)
		}
	}
}

func TestAdminMetricsExposeStaleScanRequestBacklog(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) adminMetrics")
	if start < 0 {
		t.Fatal("adminMetrics not found")
	}
	end := strings.Index(body[start:], "func boolMetric")
	if end < 0 {
		t.Fatal("boolMetric not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"CountStaleScanRequestsByState(ctx, nil, true, scanRequestClaimTimeoutSeconds())",
		"bongsu_scan_request_stale",
		`map[string]string{"state": state}`,
		`[]string{"pending", "claimed"}`,
		"bongsu_scan_request_stale_metrics_error",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("admin metrics stale scan request backlog missing %q: %s", want, fn)
		}
	}
}

func TestAdminMetricsExposeTriageLifecycle(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) adminMetrics")
	if start < 0 {
		t.Fatal("adminMetrics not found")
	}
	end := strings.Index(body[start:], "func boolMetric")
	if end < 0 {
		t.Fatal("boolMetric not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		`BONGSU_TRIAGE_EXPIRING_SOON_DAYS`,
		"CountVulnerabilityTriageByStatus(ctx)",
		"CountVulnerabilityTriageExpiringSoonByStatus(ctx, triageExpiringSoonDays)",
		"bongsu_vulnerability_triage_decisions",
		`map[string]string{"status": count.Status, "state": count.State}`,
		"bongsu_vulnerability_triage_expiring_soon",
		"bongsu_vulnerability_triage_expiring_soon_days",
		"bongsu_vulnerability_triage_metrics_error",
		"bongsu_vulnerability_triage_expiring_soon_metrics_error",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("admin metrics triage lifecycle missing %q: %s", want, fn)
		}
	}
}

func TestAdminMetricsExposeAgentFleetState(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) adminMetrics")
	if start < 0 {
		t.Fatal("adminMetrics not found")
	}
	end := strings.Index(body[start:], "func boolMetric")
	if end < 0 {
		t.Fatal("boolMetric not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"ListHosts(ctx)",
		"applyAgentStatus(&host, now)",
		"bongsu_agent_hosts",
		`map[string]string{"status": status}`,
		`[]string{"online", "stale", "offline", "unknown"}`,
		"bongsu_agent_version_hosts",
		`map[string]string{"version": version}`,
		"bongsu_agent_version_drift_hosts",
		`map[string]string{"state": state}`,
		"agentVersionDriftCounts(agentVersionCounts, latestVersion)",
		"agentFleetOperationalStatus(len(hosts), agentStatusCounts, driftCounts, s.installToken != \"\", agentInstaller, trivyInstaller)",
		"bongsu_agent_fleet_degraded",
		"bongsu_agent_fleet_warnings",
		"bongsu_agent_fleet_total_hosts",
		"bongsu_agent_outdated_percent",
		"bongsu_agent_metrics_error",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("admin metrics agent fleet state missing %q: %s", want, fn)
		}
	}
}

func TestAdminMetricsExposeInventoryQuality(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) adminMetrics")
	if start < 0 {
		t.Fatal("adminMetrics not found")
	}
	end := strings.Index(body[start:], "func boolMetric")
	if end < 0 {
		t.Fatal("boolMetric not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"GetHostInventorySummaries(ctx)",
		"BONGSU_INVENTORY_STALE_HOURS",
		"hostInventoryStatus(summary, now, inventoryStaleAfter)",
		"bongsu_inventory_hosts",
		`map[string]string{"status": status}`,
		`[]string{"healthy", "degraded", "stale", "empty", "none"}`,
		"bongsu_inventory_latest_packages",
		"bongsu_inventory_latest_vulnerabilities",
		"bongsu_inventory_latest_containers",
		"bongsu_inventory_metrics_error",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("admin metrics inventory quality missing %q: %s", want, fn)
		}
	}
}

func TestPrometheusLabelValueEscapesUnsafeCharacters(t *testing.T) {
	var b strings.Builder
	writePromGauge(&b, "bongsu_test_info", map[string]string{"revision": "rev\"x\\y\nz"}, 1)
	if got, want := b.String(), `revision="rev\"x\\y\nz"`; !strings.Contains(got, want) {
		t.Fatalf("escaped label missing %q in %s", want, got)
	}
}

func TestSecurityHeadersMiddlewareDoesNotSetHSTSOnPlainHTTP(t *testing.T) {
	t.Setenv("BONGSU_HSTS_ENABLED", "true")
	s := &Server{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	rr := httptest.NewRecorder()

	s.securityHeadersMiddleware(next).ServeHTTP(rr, req)

	if got := rr.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("plain HTTP response should not set HSTS, got %q", got)
	}
}

func TestSecurityHeadersMiddlewareHonorsForwardedHTTPSAndHSTSDisable(t *testing.T) {
	s := &Server{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	t.Setenv("BONGSU_HSTS_ENABLED", "true")
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	s.securityHeadersMiddleware(next).ServeHTTP(rr, req)
	if got := rr.Header().Get("Strict-Transport-Security"); got != "max-age=31536000; includeSubDomains" {
		t.Fatalf("forwarded HTTPS HSTS = %q", got)
	}

	t.Setenv("BONGSU_HSTS_ENABLED", "false")
	req = httptest.NewRequest("GET", "https://example.com/", nil)
	rr = httptest.NewRecorder()
	s.securityHeadersMiddleware(next).ServeHTTP(rr, req)
	if got := rr.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("disabled HSTS should not be set, got %q", got)
	}
}

func TestSecurityHeadersMiddlewareMarksAPIResponsesNoStore(t *testing.T) {
	s := &Server{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest("GET", "http://example.com/api/vulnerabilities", nil)
	rr := httptest.NewRecorder()

	s.securityHeadersMiddleware(next).ServeHTTP(rr, req)

	for name, want := range map[string]string{
		"Cache-Control": "no-store",
		"Pragma":        "no-cache",
		"Expires":       "0",
	} {
		if got := rr.Header().Get(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestSecurityHeadersMiddlewareLeavesDashboardAssetsCacheable(t *testing.T) {
	s := &Server{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest("GET", "http://example.com/assets/app.js", nil)
	rr := httptest.NewRecorder()

	s.securityHeadersMiddleware(next).ServeHTTP(rr, req)

	if got := rr.Header().Get("Cache-Control"); got != "" {
		t.Fatalf("non-API asset cache header = %q, want empty", got)
	}
}

func TestRequestIDMiddlewarePropagatesAndGeneratesIDs(t *testing.T) {
	s := &Server{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := requestIDFromRequest(r); got != "scan-req-123" {
			t.Fatalf("request context id = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest("GET", "http://example.com/api/hosts", nil)
	req.Header.Set("X-Request-ID", "scan-req-123")
	rr := httptest.NewRecorder()

	s.requestIDMiddleware(next).ServeHTTP(rr, req)

	if got := rr.Header().Get("X-Request-ID"); got != "scan-req-123" {
		t.Fatalf("response request id = %q", got)
	}

	req = httptest.NewRequest("GET", "http://example.com/api/hosts", nil)
	req.Header.Set("X-Request-ID", "bad id with spaces")
	rr = httptest.NewRecorder()
	var generated string
	s.requestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		generated = requestIDFromRequest(r)
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rr, req)
	if generated == "" || generated == "bad id with spaces" {
		t.Fatalf("invalid request id was not replaced: %q", generated)
	}
	if got := rr.Header().Get("X-Request-ID"); got != generated {
		t.Fatalf("generated response request id = %q, want %q", got, generated)
	}
}

func TestAuditAddsRequestIDMetadata(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) audit(")
	if start < 0 {
		t.Fatal("audit function not found")
	}
	end := strings.Index(body[start:], "func (s *Server) auditSystem")
	if end < 0 {
		t.Fatal("audit function end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"requestIDFromRequest(r)",
		`metadata["request_id"]`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("audit request id metadata missing %q: %s", want, fn)
		}
	}
}

func TestAccessLogMiddlewareLogsRequestIDStatusAndDuration(t *testing.T) {
	t.Setenv("BONGSU_ACCESS_LOG", "true")
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	s := &Server{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("ok"))
	})
	req := httptest.NewRequest("POST", "http://example.com/api/report", nil)
	req.Header.Set("X-Request-ID", "req-123")
	req.RemoteAddr = "192.0.2.1:12345"
	rr := httptest.NewRecorder()

	s.accessLogMiddleware(s.requestIDMiddleware(next)).ServeHTTP(rr, req)

	out := buf.String()
	for _, want := range []string{
		"access request_id=req-123",
		"method=POST",
		"path=/api/report",
		"status=201",
		"bytes=2",
		"duration_ms=",
		"ip=192.0.2.1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("access log missing %q: %s", want, out)
		}
	}
}

func TestAccessLogMiddlewareSkipsHealthByDefault(t *testing.T) {
	t.Setenv("BONGSU_ACCESS_LOG", "true")
	t.Setenv("BONGSU_ACCESS_LOG_HEALTH", "false")
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	s := &Server{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "http://example.com/api/health", nil)
	rr := httptest.NewRecorder()

	s.accessLogMiddleware(s.requestIDMiddleware(next)).ServeHTTP(rr, req)

	if got := buf.String(); got != "" {
		t.Fatalf("health access log should be skipped by default, got %q", got)
	}
}

func TestReportBodyLimitIsConfigured(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		`BONGSU_AGENT_REPORT_MAX_BYTES`,
		`512<<20`,
		`http.MaxBytesReader`,
		`http.StatusRequestEntityTooLarge`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("report body limit missing %q", want)
		}
	}
}

func TestSecurityDBUploadLimitsAreConfigured(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		"maxTrivyDBUploadBytes()",
		"maxCveDBImportBytes()",
		"maxSecurityDBBundleBytes()",
		"maxJSONBodyBytes()",
		`envBytes("BONGSU_TRIVY_DB_UPLOAD_MAX_BYTES", 2<<30)`,
		`envBytes("BONGSU_CVE_DB_IMPORT_MAX_BYTES", 2<<30)`,
		`envBytes("BONGSU_SECURITY_DB_BUNDLE_MAX_BYTES", 4<<30)`,
		`envBytes("BONGSU_MULTIPART_MEMORY_MAX_BYTES", 32<<20)`,
		`envBytes("BONGSU_JSON_BODY_MAX_BYTES", 1<<20)`,
		"ParseMultipartForm(maxMultipartMemoryBytes())",
		"decodeJSONBody",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("security DB upload limit missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"MaxBytesReader(w, r.Body, 2<<30)",
		"MaxBytesReader(w, r.Body, 4<<30)",
		"ParseMultipartForm(2 << 30)",
		"ParseMultipartForm(4 << 30)",
		"ParseMultipartForm(uploadLimit)",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("security DB uploads must not use hard-coded body limit %q", forbidden)
		}
	}
}

func TestMaxAgentReportBytes(t *testing.T) {
	t.Setenv("BONGSU_AGENT_REPORT_MAX_BYTES", "1048576")
	if got := maxAgentReportBytes(); got != 1048576 {
		t.Fatalf("maxAgentReportBytes() = %d, want 1048576", got)
	}

	for _, value := range []string{"0", "-1", "invalid"} {
		t.Setenv("BONGSU_AGENT_REPORT_MAX_BYTES", value)
		if got := maxAgentReportBytes(); got != 512<<20 {
			t.Fatalf("maxAgentReportBytes(%q) = %d, want %d", value, got, 512<<20)
		}
	}
}

func TestMaxSecurityDBUploadBytes(t *testing.T) {
	t.Setenv("BONGSU_TRIVY_DB_UPLOAD_MAX_BYTES", "12345")
	if got := maxTrivyDBUploadBytes(); got != 12345 {
		t.Fatalf("trivy upload max = %d, want 12345", got)
	}
	t.Setenv("BONGSU_CVE_DB_IMPORT_MAX_BYTES", "23456")
	if got := maxCveDBImportBytes(); got != 23456 {
		t.Fatalf("cve import max = %d, want 23456", got)
	}
	t.Setenv("BONGSU_SECURITY_DB_BUNDLE_MAX_BYTES", "34567")
	if got := maxSecurityDBBundleBytes(); got != 34567 {
		t.Fatalf("bundle max = %d, want 34567", got)
	}
	t.Setenv("BONGSU_MULTIPART_MEMORY_MAX_BYTES", "45678")
	if got := maxMultipartMemoryBytes(); got != 45678 {
		t.Fatalf("multipart memory max = %d, want 45678", got)
	}
	t.Setenv("BONGSU_JSON_BODY_MAX_BYTES", "56789")
	if got := maxJSONBodyBytes(); got != 56789 {
		t.Fatalf("json body max = %d, want 56789", got)
	}

	for _, tt := range []struct {
		key  string
		def  int64
		call func() int64
	}{
		{"BONGSU_TRIVY_DB_UPLOAD_MAX_BYTES", 2 << 30, maxTrivyDBUploadBytes},
		{"BONGSU_CVE_DB_IMPORT_MAX_BYTES", 2 << 30, maxCveDBImportBytes},
		{"BONGSU_SECURITY_DB_BUNDLE_MAX_BYTES", 4 << 30, maxSecurityDBBundleBytes},
		{"BONGSU_MULTIPART_MEMORY_MAX_BYTES", 32 << 20, maxMultipartMemoryBytes},
		{"BONGSU_JSON_BODY_MAX_BYTES", 1 << 20, maxJSONBodyBytes},
	} {
		for _, value := range []string{"0", "-1", "invalid"} {
			t.Setenv(tt.key, value)
			if got := tt.call(); got != tt.def {
				t.Fatalf("%s=%q got %d, want %d", tt.key, value, got, tt.def)
			}
		}
	}
}

func TestJSONControlBodyLimitReturns413(t *testing.T) {
	t.Setenv("BONGSU_JSON_BODY_MAX_BYTES", "8")
	s := &Server{apiKey: "admin-key", webAuth: true}
	req := httptest.NewRequest("POST", "/api/hosts/host-1/metadata", strings.NewReader(`{"owner":"too-large"}`))
	req.SetPathValue("id", "host-1")
	req.Header.Set("X-API-Key", "admin-key")
	rr := httptest.NewRecorder()

	s.handleUpdateHostMetadata(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized JSON body status = %d, want %d; body=%s", rr.Code, http.StatusRequestEntityTooLarge, rr.Body.String())
	}
}

func TestTrivyDBLoadErrorHTTPMapping(t *testing.T) {
	invalid := fmt.Errorf("%w: missing db", trivydb.ErrInvalidArchive)
	if got := trivyDBLoadErrorStatus(invalid); got != http.StatusBadRequest {
		t.Fatalf("invalid archive status = %d, want %d", got, http.StatusBadRequest)
	}
	if got := trivyDBLoadErrorMessage(invalid); got != "invalid trivy db archive" {
		t.Fatalf("invalid archive message = %q", got)
	}
	if got := trivyDBLoadErrorStatus(errors.New("disk full")); got != http.StatusInternalServerError {
		t.Fatalf("internal load status = %d, want %d", got, http.StatusInternalServerError)
	}
}

func TestTrivyDBUploadAuditsLoadFailures(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleTrivyDBUpload")
	if start < 0 {
		t.Fatal("handleTrivyDBUpload not found")
	}
	end := strings.Index(body[start:], "func trivyDBLoadErrorStatus")
	if end < 0 {
		t.Fatal("trivyDBLoadErrorStatus not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"trivyDBLoadErrorStatus(err)",
		"trivyDBLoadErrorMessage(err)",
		`"trivy_db.upload"`,
		`"error"`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("trivy upload failure handling missing %q: %s", want, fn)
		}
	}
}

func TestPaginationParamsAreBounded(t *testing.T) {
	t.Setenv("BONGSU_API_MAX_PAGE_LIMIT", "500")
	t.Setenv("BONGSU_API_MAX_PAGE_OFFSET", "10000")

	req := httptest.NewRequest("GET", "/?limit=999999&offset=999999999", nil)
	if got := limitParam(req, 100); got != 500 {
		t.Fatalf("limitParam capped = %d, want 500", got)
	}
	if got := offsetParam(req); got != 10000 {
		t.Fatalf("offsetParam capped = %d, want 10000", got)
	}

	req = httptest.NewRequest("GET", "/?limit=-1&offset=-10&min_cvss=-3", nil)
	if got := limitParam(req, 100); got != 100 {
		t.Fatalf("negative limit = %d, want default 100", got)
	}
	if got := offsetParam(req); got != 0 {
		t.Fatalf("negative offset = %d, want 0", got)
	}
	if got := floatParam(req, "min_cvss", 0.1); got != 0.1 {
		t.Fatalf("negative float = %.1f, want default 0.1", got)
	}
}

func TestWebAuthCanBeDisabledWithoutOpeningAdmin(t *testing.T) {
	s := &Server{apiKey: "admin-key", agentKey: "agent-key", webAuth: false}
	req := httptest.NewRequest("GET", "/", nil)
	if !s.authenticateWeb(req) {
		t.Fatal("web auth disabled should allow web reads")
	}
	if s.authenticateAdmin(req) {
		t.Fatal("web auth disabled must not open admin API")
	}
	if s.authenticateAgent(req) {
		t.Fatal("web auth disabled must not open agent API")
	}
	if s.authenticateExport(req) {
		t.Fatal("web auth disabled must not open export APIs")
	}
	req.Header.Set("X-API-Key", "admin-key")
	if !s.authenticateExport(req) {
		t.Fatal("admin key should authenticate export APIs")
	}
}

func TestViewerKeys(t *testing.T) {
	keys := parseViewerKeys("viewer-key:alice, team-key:group:devops, malformed")
	if keys["viewer-key"] != "alice" {
		t.Fatalf("viewer-key subject = %q", keys["viewer-key"])
	}
	if keys["team-key"] != "group:devops" {
		t.Fatalf("team-key subject = %q", keys["team-key"])
	}

	s := &Server{apiKey: "admin-key", viewerKeys: keys, webAuth: true}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "viewer-key")
	if !s.authenticateWeb(req) {
		t.Fatal("viewer key should authenticate web")
	}
	if s.authenticateAdmin(req) {
		t.Fatal("viewer key must not authenticate admin")
	}
	if got := s.viewerSubject(req); got != "alice" {
		t.Fatalf("viewer subject = %q", got)
	}
}

func TestCveDBReadUsesRBACResource(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		"func (s *Server) canReadCveDB",
		`HasResourcePermission(r.Context(), subject, "cve_db", []string{"read", "admin"})`,
		"if !s.canReadCveDB(r)",
		`writeError(w, http.StatusForbidden, "forbidden")`,
		`case "host", "container", "image", "asset_group", "cve_db", "all":`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("cve_db RBAC enforcement missing %q", want)
		}
	}
}

func TestCorsRequiresExplicitAllowedOrigin(t *testing.T) {
	s := &Server{corsOrigins: parseAllowedOrigins("https://console.example.com")}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://console.example.com")
	rr := httptest.NewRecorder()
	s.corsMiddleware(next).ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("allowed CORS status = %d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://console.example.com" {
		t.Fatalf("allowed origin header = %q", got)
	}

	req = httptest.NewRequest("OPTIONS", "/", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rr = httptest.NewRecorder()
	s.corsMiddleware(next).ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("disallowed preflight status = %d, want %d", rr.Code, http.StatusForbidden)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("disallowed origin must not be reflected, got %q", got)
	}
}

func TestCorsWildcardIsExplicit(t *testing.T) {
	if !allowsAllOrigins("https://console.example.com, *") {
		t.Fatal("wildcard CORS should require explicit *")
	}
	if allowsAllOrigins("") {
		t.Fatal("empty CORS config must not allow all origins")
	}
}

func TestAuditActorAndClientIP(t *testing.T) {
	s := &Server{
		apiKey:     "admin-key",
		agentKey:   "agent-key",
		viewerKeys: map[string]string{"viewer-key": "alice"},
		webAuth:    true,
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "viewer-key")
	req.Header.Set("X-Forwarded-For", "203.0.113.10, 10.0.0.1")
	if got := s.actorType(req); got != "viewer" {
		t.Fatalf("actor type = %q", got)
	}
	if got := s.actorID(req); got != "alice" {
		t.Fatalf("actor id = %q", got)
	}
	if got := clientIP(req); got != "203.0.113.10" {
		t.Fatalf("client ip = %q", got)
	}

	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "agent-key")
	if got := s.actorType(req); got != "agent" {
		t.Fatalf("agent actor type = %q", got)
	}
}

func TestApplyAgentStatus(t *testing.T) {
	t.Setenv("BONGSU_AGENT_ONLINE_MINUTES", "60")
	t.Setenv("BONGSU_AGENT_OFFLINE_MINUTES", "180")
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		seen time.Time
		want string
	}{
		{"online", now.Add(-30 * time.Minute), "online"},
		{"stale", now.Add(-2 * time.Hour), "stale"},
		{"offline", now.Add(-4 * time.Hour), "offline"},
		{"future clock skew", now.Add(5 * time.Minute), "online"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := models.Host{LastSeen: tt.seen}
			applyAgentStatus(&h, now)
			if h.AgentStatus != tt.want {
				t.Fatalf("status = %q, want %q", h.AgentStatus, tt.want)
			}
			if h.LastSeenAgeS < 0 {
				t.Fatalf("age should not be negative: %d", h.LastSeenAgeS)
			}
		})
	}
}

func TestRematchOptionsFromEnv(t *testing.T) {
	t.Setenv("BONGSU_CVE_MATCH_SOURCES", "OSV, nvd,osv, ")
	t.Setenv("BONGSU_CVE_MATCH_MIN_SOURCE_MATCHABLE_PERCENT", "175.5")
	t.Setenv("BONGSU_CVE_MATCH_CANDIDATE_LIMIT", "123")

	opts := rematchOptionsFromEnv()
	if len(opts.Sources) != 2 || opts.Sources[0] != "osv" || opts.Sources[1] != "nvd" {
		t.Fatalf("sources = %#v", opts.Sources)
	}
	if opts.MinSourceMatchablePercent != 100 {
		t.Fatalf("min quality = %.1f", opts.MinSourceMatchablePercent)
	}
	if opts.CandidateLimit != 123 {
		t.Fatalf("candidate limit = %d, want 123", opts.CandidateLimit)
	}

	opts, err := normalizeRematchOptions(db.RematchOptions{ScanID: " scan-1 ", CandidateLimit: -1})
	if err != nil {
		t.Fatal(err)
	}
	if opts.ScanID != "scan-1" {
		t.Fatalf("scan id = %q, want trimmed scan-1", opts.ScanID)
	}
	if opts.CandidateLimit != 50000 {
		t.Fatalf("default candidate limit = %d, want 50000", opts.CandidateLimit)
	}
	opts, err = normalizeRematchOptions(db.RematchOptions{CandidateLimit: 2000000})
	if err != nil {
		t.Fatal(err)
	}
	if opts.CandidateLimit != 1000000 {
		t.Fatalf("max candidate limit = %d, want 1000000", opts.CandidateLimit)
	}
	if _, err := normalizeRematchOptions(db.RematchOptions{Sources: []string{"nvd feed"}}); !errors.Is(err, errInvalidCveSource) {
		t.Fatalf("invalid rematch source err = %v", err)
	}
}

func TestCoalesceSecurityRecalcReason(t *testing.T) {
	if got := coalesceSecurityRecalcReason("", "osv import"); got != "osv import" {
		t.Fatalf("empty previous = %q", got)
	}
	if got := coalesceSecurityRecalcReason("osv import", "osv import"); got != "osv import" {
		t.Fatalf("duplicate reason = %q", got)
	}
	if got := coalesceSecurityRecalcReason("osv import", "nvd import"); got != "osv import; nvd import" {
		t.Fatalf("merged reason = %q", got)
	}
}

func TestValidateSecurityDBBundleChecksums(t *testing.T) {
	sum := sha256.Sum256([]byte("cve"))
	cveSHA := hex.EncodeToString(sum[:])
	trivySum := sha256.Sum256([]byte("trivy"))
	trivySHA := hex.EncodeToString(trivySum[:])

	manifest := &securityDBBundleManifest{
		Format:            "bongsu-security-db-bundle",
		Version:           1,
		CveDatabaseSHA256: cveSHA,
		TrivyDBIncluded:   true,
		TrivyDBSHA256:     trivySHA,
	}
	if err := validateSecurityDBBundle(manifest, "/tmp/cve.jsonl", cveSHA, "/tmp/trivy.tar.gz", trivySHA); err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}
	if err := validateSecurityDBBundle(nil, "/tmp/cve.jsonl", cveSHA, "", ""); err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("missing manifest error = %v", err)
	}
	if err := validateSecurityDBBundle(manifest, "/tmp/cve.jsonl", "bad", "/tmp/trivy.tar.gz", trivySHA); err == nil || !strings.Contains(err.Error(), "cve database checksum") {
		t.Fatalf("cve checksum error = %v", err)
	}
	if err := validateSecurityDBBundle(manifest, "/tmp/cve.jsonl", cveSHA, "/tmp/trivy.tar.gz", "bad"); err == nil || !strings.Contains(err.Error(), "trivy db checksum") {
		t.Fatalf("trivy checksum error = %v", err)
	}
}

func TestValidateSecurityDBBundleImportedCount(t *testing.T) {
	manifest := &securityDBBundleManifest{CveRecords: 2}
	if err := validateSecurityDBBundleImportedCount(manifest, 2); err != nil {
		t.Fatalf("validateSecurityDBBundleImportedCount: %v", err)
	}
	if err := validateSecurityDBBundleImportedCount(manifest, 1); err == nil || !strings.Contains(err.Error(), "record count mismatch") {
		t.Fatalf("expected record count mismatch, got %v", err)
	}
	if err := validateSecurityDBBundleImportedCount(nil, 1); err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("expected missing manifest error, got %v", err)
	}
}

func TestSecurityDBBundleManifestCarriesRevision(t *testing.T) {
	manifest := securityDBBundleManifest{SecurityDBRevision: "rev-123"}
	if manifest.SecurityDBRevision != "rev-123" {
		t.Fatalf("manifest revision = %q", manifest.SecurityDBRevision)
	}

	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleSecurityDbExport")
	if start < 0 {
		t.Fatal("handleSecurityDbExport not found")
	}
	end := strings.Index(body[start:], "func (s *Server) handleSecurityDbImport")
	if end < 0 {
		t.Fatal("handleSecurityDbImport not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"GetSecurityDBRevision",
		"SecurityDBRevision: revision",
		`"security_db_revision": revision`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("bundle export revision handling missing %q: %s", want, fn)
		}
	}
}

func TestValidateSecurityDBBundleEntryRejectsUnexpectedTarMembers(t *testing.T) {
	valid := []string{"manifest.json", "cve-database.jsonl", "trivy-db.tar.gz"}
	for _, name := range valid {
		if err := validateSecurityDBBundleEntry(&tar.Header{Name: name, Typeflag: tar.TypeReg}); err != nil {
			t.Fatalf("valid bundle entry %s rejected: %v", name, err)
		}
	}
	tests := []tar.Header{
		{Name: "../manifest.json", Typeflag: tar.TypeReg},
		{Name: "extra.txt", Typeflag: tar.TypeReg},
		{Name: "manifest.json", Typeflag: tar.TypeDir},
	}
	for _, hdr := range tests {
		if err := validateSecurityDBBundleEntry(&hdr); err == nil {
			t.Fatalf("invalid bundle entry accepted: %#v", hdr)
		}
	}
}

func TestSecurityDBBundleImportRejectsDuplicateEntries(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleSecurityDbImport")
	if start < 0 {
		t.Fatal("handleSecurityDbImport not found")
	}
	end := strings.Index(body[start:], "func writeBundleEntryTemp")
	if end < 0 {
		t.Fatal("writeBundleEntryTemp not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"validateSecurityDBBundleEntry(hdr)",
		`"duplicate manifest.json"`,
		`"duplicate cve-database.jsonl"`,
		`"duplicate trivy-db.tar.gz"`,
		`"security_db_revision": manifest.SecurityDBRevision`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("bundle import duplicate/entry guard missing %q: %s", want, fn)
		}
	}
	if strings.Contains(fn, "os.Remove(cveFile)\n\t\t\t}") || strings.Contains(fn, "os.Remove(trivyArchive)\n\t\t\t}") {
		t.Fatal("bundle import must reject duplicate payload entries instead of replacing staged files")
	}
}

func TestSecurityDBBundleImportUsesSingleCveTransaction(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		"s.db.BeginTx",
		"s.db.DeleteAllCveEntriesTx",
		"s.importCveJSONLTx",
		"validateSecurityDBBundleImportedCount(manifest, imported)",
		"s.db.SyncEPSSPriorityColumnsTx",
		"s.db.RefreshCveAffectedPackagesForSourceTx",
		"s.db.RefreshCveReferenceKeysForSourceTx",
		"tx.Rollback()",
		"tx.Commit()",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("bundle import must use one CVE transaction, missing %q", want)
		}
	}
}

func TestSecurityDBBundleImportValidatesTrivyBeforeCommitAndLoadsAfter(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleSecurityDbImport")
	if start < 0 {
		t.Fatal("handleSecurityDbImport not found")
	}
	end := strings.Index(body[start:], "type securityDBBundleManifest")
	if end < 0 {
		t.Fatal("securityDBBundleManifest not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"s.dbMgr.ValidateArchive(trivyArchive)",
		`"validate_trivy"`,
		"tx.Commit()",
		"s.dbMgr.LoadFromFile(trivyArchive)",
		`"trivy db import failed after cve commit"`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("bundle import trivy ordering missing %q: %s", want, fn)
		}
	}
	if strings.Index(fn, "s.dbMgr.ValidateArchive(trivyArchive)") > strings.Index(fn, "tx.Commit()") {
		t.Fatal("trivy archive must be validated before committing CVE transaction")
	}
	if strings.Index(fn, "s.dbMgr.LoadFromFile(trivyArchive)") < strings.Index(fn, "tx.Commit()") {
		t.Fatal("trivy cache must not be activated before CVE transaction commit")
	}
}

func TestSecurityDBBundleImportAuditsFailures(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		"fail := func",
		`"security_db.import"`,
		`"error"`,
		`"stage"`,
		`"validate"`,
		`"import_cve"`,
		`"import_trivy"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("bundle import failure audit missing %q", want)
		}
	}
}

func TestInstallScriptHardensAgentCredentialFile(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		"umask 077",
		"AGENT_TOKEN=",
		"generate_agent_token()",
		`agent_token: ${AGENT_TOKEN}`,
		`scan_root: %%s`,
		`trivy_timeout_seconds: %%s`,
		`container_timeout_seconds: %%s`,
		`skip_containers: %%s`,
		`max_containers: %%s`,
		`chmod 600 "$WORK_DIR/agent.token"`,
		`chmod 600 "$WORK_DIR/config.yaml"`,
		"UMask=0077",
		"ProtectSystem=strict",
		"ReadWritePaths=$WORK_DIR",
		"PrivateTmp=true",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("install script hardening missing %q", want)
		}
	}
}

func TestAgentHostTokenBindingValidation(t *testing.T) {
	t.Setenv("BONGSU_AGENT_HOST_BINDING", "true")
	token := strings.Repeat("a", 32)
	req := httptest.NewRequest("POST", "/api/report", nil)
	req.Header.Set("X-Bongsu-Agent-Token", token)
	req.Header.Set("X-Bongsu-Host-ID", "host-1")
	got, err := (&Server{}).agentHostTokenHash(req, "host-1")
	if err != nil {
		t.Fatalf("agentHostTokenHash: %v", err)
	}
	sum := sha256.Sum256([]byte(token))
	if got != hex.EncodeToString(sum[:]) {
		t.Fatalf("token hash = %q", got)
	}

	req.Header.Set("X-Bongsu-Host-ID", "other")
	if _, err := (&Server{}).agentHostTokenHash(req, "host-1"); err == nil {
		t.Fatal("host id header mismatch should fail")
	}
	req.Header.Set("X-Bongsu-Host-ID", "host-1")
	req.Header.Set("X-Bongsu-Agent-Token", "short")
	if _, err := (&Server{}).agentHostTokenHash(req, "host-1"); err == nil {
		t.Fatal("short token should fail")
	}
	t.Setenv("BONGSU_AGENT_HOST_BINDING", "false")
	if got, err := (&Server{}).agentHostTokenHash(req, "host-1"); err != nil || got != "" {
		t.Fatalf("disabled binding = (%q, %v), want empty nil", got, err)
	}
}

func TestInstallerDownloadsVerifyBinaryChecksums(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		`curl -fsSL --config "$curl_config" -D "$headers" "$url" -o "$output"`,
		`curl -fsSL -D "$headers" "$url" -o "$output"`,
		`verify_download_sha256 "$headers" "$output"`,
		`tolower($1)=="x-bongsu-sha256:"`,
		`sha256sum "$1"`,
		`shasum -a 256 "$1"`,
		`missing X-Bongsu-SHA256 header for $output`,
		`checksum mismatch for $output`,
		`rm -f "$output"`,
		`w.Header().Set("X-Bongsu-SHA256", digest)`,
		`"sha256": digest`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("installer checksum verification missing %q", want)
		}
	}

	tmp, err := os.CreateTemp(t.TempDir(), "sha256-*")
	if err != nil {
		t.Fatal(err)
	}
	defer tmp.Close()
	if _, err := tmp.WriteString("bongsu"); err != nil {
		t.Fatal(err)
	}
	got, err := fileSHA256Hex(tmp)
	if err != nil {
		t.Fatalf("fileSHA256Hex: %v", err)
	}
	want := "75ca98a595553036263404b3659d462bcbe4e49e9bc148158cd90e935d3a08cb"
	if got != want {
		t.Fatalf("sha256 = %q, want %q", got, want)
	}
	pos, err := tmp.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatal(err)
	}
	if pos != 0 {
		t.Fatalf("file position = %d, want reset to 0", pos)
	}
}

func TestInstallerStatusReportsBinaryReadiness(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		`"GET /api/admin/installer/status"`,
		"func (s *Server) handleInstallerStatus",
		"s.authenticateAdmin(r)",
		"install_token_configured",
		"installerBinaryReadiness(\"bongsu-agent\", agentBinaryPath())",
		"installerBinaryReadiness(\"trivy\", trivyBinaryPath())",
		"type installerBinaryStatus struct",
		`Version string ` + "`json:\"version,omitempty\"`",
		`SHA256  string ` + "`json:\"sha256,omitempty\"`",
		"fileSHA256Hex(f)",
		"binaryVersion(path)",
		"exec.CommandContext(ctx, path, \"--version\")",
		"agentBinaryPath()",
		"trivyBinaryPath()",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("installer status missing %q", want)
		}
	}
	webAPI, err := os.ReadFile("../../../web/src/api.ts")
	if err != nil {
		t.Fatal(err)
	}
	webApp, err := os.ReadFile("../../../web/src/App.tsx")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"InstallerStatus",
		"InstallerBinaryStatus",
		"version?: string",
		"agent_version_counts?: Record<string, number>",
		"agent_version_drift_counts?: Record<string, number>",
		"latest_agent_version?: string",
		"installerStatus: () => request<InstallerStatus>('/admin/installer/status')",
		"SecurityDbOperationalStatus",
		"AgentFleetStatus",
		"recommended_actions?: string[]",
		"securityDbStatus: () => request<SecurityDbOperationalStatus>('/admin/security-db/status')",
		"agentFleetStatus: () => request<AgentFleetStatus>('/admin/agent-fleet/status')",
	} {
		if !strings.Contains(string(webAPI), want) {
			t.Fatalf("web installer status API missing %q", want)
		}
	}
	for _, want := range []string{
		"api.installerStatus().then(setInstallerStatus)",
		"installerStatus.ready",
		"installerStatus.agent.ready",
		"installerStatus.agent.version",
		"installerStatus.trivy.ready",
		"Agent Version",
		"Agent Version Drift",
		"agentVersionDriftCounts.outdated",
		"agentFleetStatus?.agent_version_drift_counts",
		"Agent fleet:",
		"securityDbStatus?.warnings",
		"Security DB:",
		"outdatedAgentCount",
		"unknownAgentVersionCount",
		"dashboardHosts.filter",
	} {
		if !strings.Contains(string(webApp), want) {
			t.Fatalf("dashboard installer status missing %q", want)
		}
	}
}

func TestAgentFleetStatusEndpointReportsVersionDrift(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		`"GET /api/admin/agent-fleet/status"`,
		"func (s *Server) handleAgentFleetStatus",
		"s.authenticateAdmin(r)",
		"s.db.ListHosts(r.Context())",
		"applyAgentStatus(&host, now)",
		"installerBinaryReadiness(\"bongsu-agent\", agentBinaryPath())",
		"installerBinaryReadiness(\"trivy\", trivyBinaryPath())",
		"agentVersionDriftCounts(agentVersionCounts, latestVersion)",
		"agentFleetOperationalStatus",
		`"agent_status_counts"`,
		`"agent_version_counts"`,
		`"agent_version_drift_counts"`,
		`"outdated_percent"`,
		`"warnings"`,
		`"recommended_actions"`,
		`"latest_agent_version"`,
		`"installer"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("agent fleet status endpoint missing %q", want)
		}
	}
}

func TestHostDeleteEndpointCleansHostScopedOperationalData(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		`"DELETE /api/hosts/{id}"`,
		"func (s *Server) handleDeleteHost",
		"s.authenticateAdmin(r)",
		"s.db.DeleteHost(r.Context(), hostID)",
		`"host.delete"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("host delete endpoint missing %q", want)
		}
	}
	dbFile, err := os.ReadFile("../db/host.go")
	if err != nil {
		t.Fatalf("read host db file: %v", err)
	}
	dbFiles := string(dbFile)
	for _, want := range []string{
		"func (db *DB) DeleteHost",
		"db.BeginTx(ctx, nil)",
		"DELETE FROM scan_requests WHERE host_id=$1 OR claimed_by_host_id=$1",
		"DELETE FROM vulnerability_triage WHERE host_id=$1",
		"DELETE FROM hosts WHERE id=$1",
		"sql.ErrNoRows",
		"tx.Commit()",
	} {
		if !strings.Contains(dbFiles, want) {
			t.Fatalf("host delete DB cleanup missing %q", want)
		}
	}
}

func TestLiveVerifiersCleanUpFixtureHosts(t *testing.T) {
	for _, path := range []string{
		"../../../scripts/verify-operator-workflow.sh",
		"../../../scripts/verify-live-rbac-scope.sh",
		"../../../scripts/verify-live-agent-token-binding.sh",
		"../../../scripts/verify-agent-binary-workflow.sh",
	} {
		out, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(out), "-X DELETE") || !strings.Contains(string(out), "/api/hosts/") {
			t.Fatalf("%s must delete fixture hosts during cleanup", path)
		}
	}
}

func TestLiveVerifiersDefaultToLocalLiveKeys(t *testing.T) {
	for _, path := range []string{
		"../../../scripts/verify-operator-workflow.sh",
		"../../../scripts/verify-live-rbac-scope.sh",
		"../../../scripts/verify-live-agent-token-binding.sh",
		"../../../scripts/verify-agent-binary-workflow.sh",
	} {
		out, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		body := string(out)
		for _, want := range []string{
			`BONGSU_API_KEY:-test-admin-key-0123456789`,
			`BONGSU_AGENT_API_KEY:-test-agent-key-0123456789`,
		} {
			if !strings.Contains(body, want) {
				t.Fatalf("%s must default to local live verifier keys, missing %q", path, want)
			}
		}
	}
	for _, path := range []string{
		"../../../scripts/verify-live-cvedb-quality.sh",
		"../../../scripts/verify-live-installer-payload.sh",
		"../../../scripts/verify-live-server-build.sh",
		"../../../scripts/verify-live-web-smoke.sh",
	} {
		out, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(out), `BONGSU_API_KEY:-test-admin-key-0123456789`) {
			t.Fatalf("%s must default to the local live admin verifier key", path)
		}
	}
	rbacVerifier, err := os.ReadFile("../../../scripts/verify-live-rbac-scope.sh")
	if err != nil {
		t.Fatal(err)
	}
	rbacBody := string(rbacVerifier)
	for _, want := range []string{
		`BONGSU_VIEWER_API_KEY:-viewer-test-key`,
		`BONGSU_VIEWER_SUBJECT:-rbac-live-viewer`,
	} {
		if !strings.Contains(rbacBody, want) {
			t.Fatalf("live RBAC verifier must default viewer fixture identity, missing %q", want)
		}
	}
}

func TestAgentFleetOperationalStatusDegradesOnActionableIssues(t *testing.T) {
	status, warnings, actions := agentFleetOperationalStatus(
		3,
		map[string]int{"online": 1, "stale": 1, "offline": 1, "unknown": 0},
		map[string]int{"current": 1, "outdated": 1, "unknown": 1},
		false,
		installerBinaryStatus{Name: "bongsu-agent", Ready: false},
		installerBinaryStatus{Name: "trivy", Ready: false},
	)
	if status != "degraded" {
		t.Fatalf("status = %q, want degraded", status)
	}
	for _, want := range []string{
		"install token is not configured",
		"bongsu-agent installer binary is not ready",
		"trivy installer binary is not ready",
		"one or more agents are offline",
		"one or more agents have stale heartbeats",
		"one or more agents run an outdated version",
		"one or more agents did not report a version",
	} {
		if !containsString(warnings, want) {
			t.Fatalf("warnings missing %q: %#v", want, warnings)
		}
	}
	if len(actions) != len(warnings) {
		t.Fatalf("actions should track warnings, warnings=%#v actions=%#v", warnings, actions)
	}
	status, warnings, actions = agentFleetOperationalStatus(
		1,
		map[string]int{"online": 1, "stale": 0, "offline": 0, "unknown": 0},
		map[string]int{"current": 1, "outdated": 0, "unknown": 0},
		true,
		installerBinaryStatus{Name: "bongsu-agent", Ready: true},
		installerBinaryStatus{Name: "trivy", Ready: true},
	)
	if status != "ok" || len(warnings) != 0 || len(actions) != 0 {
		t.Fatalf("healthy fleet status=%q warnings=%#v actions=%#v", status, warnings, actions)
	}
}

func TestAgentVersionDriftCountsClassifyFleet(t *testing.T) {
	got := agentVersionDriftCounts(map[string]int{
		"1.0.0+abc": 2,
		"0.9.0+old": 3,
		"":          1,
		"unknown":   4,
	}, "1.0.0+abc")
	if got["current"] != 2 || got["outdated"] != 3 || got["unknown"] != 5 {
		t.Fatalf("drift counts = %#v", got)
	}
	got = agentVersionDriftCounts(map[string]int{"1.0.0": 1}, "")
	if got["current"] != 0 || got["outdated"] != 1 || got["unknown"] != 0 {
		t.Fatalf("missing latest version should classify known agents as outdated: %#v", got)
	}
	if got := agentVersionState("", "1.0.0"); got != "unknown" {
		t.Fatalf("empty version state = %q", got)
	}
	if got := agentVersionState("1.0.0", "1.0.0"); got != "current" {
		t.Fatalf("current version state = %q", got)
	}
	if got := agentVersionState("0.9.0", "1.0.0"); got != "outdated" {
		t.Fatalf("outdated version state = %q", got)
	}
}

func TestShellQuoteEscapesInstallerCredentials(t *testing.T) {
	got := shellQuote(`agent'key"$HOME`)
	want := `'agent'"'"'key"$HOME'`
	if got != want {
		t.Fatalf("shellQuote = %q, want %q", got, want)
	}
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		"shellQuote(serverURL)",
		"shellQuote(apiKey)",
		"shellQuote(s.installToken)",
		`if [ -n "${BONGSU_AGENT_API_KEY:-}" ]; then`,
		`API_KEY="$BONGSU_AGENT_API_KEY"`,
		`w.Header().Set("Cache-Control", "no-store")`,
		`printf 'header = "X-Install-Token: %%s"\n' "$INSTALL_TOKEN" > "$curl_config"`,
		`curl_download "$SERVER/api/downloads/bongsu-agent" "$WORK_DIR/bin/bongsu-agent"`,
		`curl_download "$SERVER/api/downloads/trivy" "$WORK_DIR/bin/trivy"`,
		`rm -f "$WORK_DIR/bin/bongsu-agent"`,
		`SYSTEMD_DIR="${BONGSU_SYSTEMD_DIR:-/etc/systemd/system}"`,
		`SYSTEMCTL_BIN="${BONGSU_SYSTEMCTL_BIN:-systemctl}"`,
		`command -v "$SYSTEMCTL_BIN"`,
		`mkdir -p "$SYSTEMD_DIR"`,
		`cat > "$SYSTEMD_DIR/bongsu-agent.service"`,
		`cat > "$SYSTEMD_DIR/bongsu-agent.timer"`,
		`cat > "$SYSTEMD_DIR/bongsu-agent-daemon.service"`,
		`AGENT_SCAN_ROOT="${BONGSU_AGENT_SCAN_ROOT:-}"`,
		`AGENT_MAX_CONTAINERS="${BONGSU_AGENT_MAX_CONTAINERS:-}"`,
		`"$SYSTEMCTL_BIN" daemon-reload`,
		`"$SYSTEMCTL_BIN" enable --now bongsu-agent.timer`,
		`"$SYSTEMCTL_BIN" enable --now bongsu-agent-daemon.service`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("installer credential rendering missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"INSTALL_TOKEN_QUERY",
		`$SERVER/api/downloads/bongsu-agent$INSTALL_TOKEN_QUERY`,
		`$SERVER/api/downloads/trivy$INSTALL_TOKEN_QUERY`,
		"url.QueryEscape(s.installToken)",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("installer must not use token-bearing download URLs: found %q", forbidden)
		}
	}
}

func TestFallbackHostIDUsesStableInventoryIdentity(t *testing.T) {
	if got := fallbackHostID(models.Host{Hostname: "App-01 "}); got != "hostname:app-01" {
		t.Fatalf("hostname fallback = %q", got)
	}
	if got := fallbackHostID(models.Host{IPAddress: "10.0.0.5"}); got != "ip:10.0.0.5" {
		t.Fatalf("ip fallback = %q", got)
	}
	if got := fallbackHostID(models.Host{}); got == "" {
		t.Fatal("empty host fallback should still create an id")
	}
}

func TestNormalizeScanReportValidatesIdentityAndType(t *testing.T) {
	report := models.ScanReport{
		ScanID:   " 550e8400-e29b-41d4-a716-446655440000 ",
		ScanType: " manual ",
		Host: models.Host{
			ID:        " host-1 ",
			Hostname:  " app-01 ",
			IPAddress: " 10.0.0.5 ",
		},
	}
	if err := normalizeScanReport(&report); err != nil {
		t.Fatalf("normalize scan report: %v", err)
	}
	if report.ScanID != "550e8400-e29b-41d4-a716-446655440000" || report.ScanType != "manual" {
		t.Fatalf("scan identity was not normalized: %#v", report)
	}
	if report.Host.ID != "host-1" || report.Host.Hostname != "app-01" || report.Host.IPAddress != "10.0.0.5" {
		t.Fatalf("host identity was not normalized: %#v", report.Host)
	}
	if report.Timestamp.IsZero() {
		t.Fatal("missing report timestamp default")
	}
}

func TestNormalizeScanReportRejectsInvalidScannerFields(t *testing.T) {
	for _, report := range []models.ScanReport{
		{ScanID: "not-a-uuid", ScanType: "manual", Host: models.Host{Hostname: "app-01"}},
		{ScanType: "completed", Host: models.Host{Hostname: "app-01"}},
	} {
		if err := normalizeScanReport(&report); err == nil {
			t.Fatalf("invalid report should be rejected: %#v", report)
		}
	}
}

func TestNormalizeScanReportDerivesStableHostDefaults(t *testing.T) {
	report := models.ScanReport{Host: models.Host{Hostname: " App-01 "}}
	if err := normalizeScanReport(&report); err != nil {
		t.Fatalf("normalize scan report: %v", err)
	}
	if report.ScanID == "" || report.ScanType != "inventory" {
		t.Fatalf("scan defaults missing: %#v", report)
	}
	if report.Host.ID != "hostname:app-01" || report.Host.Hostname != "App-01" {
		t.Fatalf("stable host fallback missing: %#v", report.Host)
	}
}

func TestNormalizeScanReportCarriesBoundedCollectionErrors(t *testing.T) {
	longErr := strings.Repeat("x", maxReportErrorBytes+20)
	report := models.ScanReport{
		Host: models.Host{Hostname: "app-01"},
		Errors: []string{
			"  trivy_host: missing binary  ",
			"",
			longErr,
		},
	}
	for i := 0; i < maxReportErrors+5; i++ {
		report.Errors = append(report.Errors, fmt.Sprintf("container-%02d: failed", i))
	}

	if err := normalizeScanReport(&report); err != nil {
		t.Fatalf("normalize scan report: %v", err)
	}
	if len(report.Errors) != maxReportErrors {
		t.Fatalf("normalized errors = %d, want %d", len(report.Errors), maxReportErrors)
	}
	if report.Errors[0] != "trivy_host: missing binary" {
		t.Fatalf("error was not trimmed: %q", report.Errors[0])
	}
	if !strings.HasSuffix(report.Errors[1], "...(truncated)") {
		t.Fatalf("long error was not truncated: %q", report.Errors[1])
	}
	report.Errors = []string{"", "  "}
	if err := normalizeScanReport(&report); err != nil {
		t.Fatalf("normalize empty errors: %v", err)
	}
	if report.Errors != nil {
		t.Fatalf("empty errors should normalize to nil: %#v", report.Errors)
	}

	report.Errors = []string{strings.Repeat("한", maxReportErrorBytes)}
	if err := normalizeScanReport(&report); err != nil {
		t.Fatalf("normalize unicode errors: %v", err)
	}
	if !utf8.ValidString(report.Errors[0]) {
		t.Fatalf("truncated unicode error is not valid UTF-8: %q", report.Errors[0])
	}
}

func TestNormalizeScanReportBackfillsContainerAssetContext(t *testing.T) {
	report := models.ScanReport{
		Host: models.Host{ID: "host-1", Hostname: "app-01"},
		Containers: []models.ContainerAsset{{
			Name:        " api ",
			ContainerID: " container-1 ",
			ImageName:   " registry.example/api:1.0 ",
			ImageID:     " sha256:image ",
		}},
		Packages: []models.Package{
			{Name: "openssl", Version: "3.0.13"},
			{Name: "lodash", Version: "4.17.20", Container: " api "},
			{Name: "debug", Version: "4.3.0", ContainerID: " container-1 "},
		},
		Vulns: []models.Vulnerability{
			{VulnerabilityID: "CVE-2026-0001", PkgName: "lodash", Container: " api "},
			{VulnerabilityID: "CVE-2026-0002", PkgName: "debug", ContainerID: " container-1 "},
		},
	}

	if err := normalizeScanReport(&report); err != nil {
		t.Fatalf("normalize scan report: %v", err)
	}
	hostPkg := report.Packages[0]
	if hostPkg.AssetType != "host" || hostPkg.AssetID != "host-1" {
		t.Fatalf("host package context = (%q, %q), want host/host-1", hostPkg.AssetType, hostPkg.AssetID)
	}
	for _, pkg := range report.Packages[1:] {
		if pkg.AssetType != "container" || pkg.AssetID != "container-1" || pkg.Container != "api" ||
			pkg.ContainerID != "container-1" || pkg.ImageName != "registry.example/api:1.0" || pkg.ImageID != "sha256:image" {
			t.Fatalf("container package context was not backfilled: %#v", pkg)
		}
	}
	for _, vuln := range report.Vulns {
		if vuln.AssetType != "container" || vuln.Container != "api" || vuln.ContainerID != "container-1" ||
			vuln.ImageName != "registry.example/api:1.0" || vuln.ImageID != "sha256:image" {
			t.Fatalf("container vulnerability context was not backfilled: %#v", vuln)
		}
	}
}

func TestNormalizeScanReportRejectsInvalidAssetTypes(t *testing.T) {
	for _, report := range []models.ScanReport{
		{Host: models.Host{Hostname: "app-01"}, Packages: []models.Package{{AssetType: "service", Name: "openssl"}}},
		{Host: models.Host{Hostname: "app-01"}, Vulns: []models.Vulnerability{{AssetType: "service", VulnerabilityID: "CVE-2026-0001"}}},
	} {
		if err := normalizeScanReport(&report); err == nil {
			t.Fatalf("invalid asset type should be rejected: %#v", report)
		}
	}
}

func TestHandleReportNormalizesScannerInput(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleReport")
	if start < 0 {
		t.Fatal("handleReport not found")
	}
	end := strings.Index(body[start:], "func reportWebhookPayload")
	if end < 0 {
		t.Fatal("reportWebhookPayload not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"normalizeScanReport(&report)",
		"agentHostTokenHash(r, report.Host.ID)",
		"UpsertHostWithAgentToken",
		`writeError(w, http.StatusBadRequest, err.Error())`,
		`uuid.Parse(report.ScanID)`,
		`"invalid scan_type"`,
		`ingestErrors := append([]string{}, report.Errors...)`,
		"GetVulnRiskCountsByScan",
		"riskCounts",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("report normalization missing %q: %s", want, fn)
		}
	}
}

func TestHandleReportAppliesScanScopedCveRematch(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleReport")
	if start < 0 {
		t.Fatal("handleReport not found")
	}
	end := strings.Index(body[start:], "func normalizeScanReport")
	if end < 0 {
		t.Fatal("handleReport end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"opts.ScanID = report.ScanID",
		"s.db.RematchCVEs(ctx, opts)",
		`"cve_db_rematch: "`,
		"insertedVulns += result.NewVulns",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("scan-scoped rematch missing %q: %s", want, fn)
		}
	}
}

func TestVulnFilterFromRequestIncludesFindingSource(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/vulnerabilities?finding_source=%20CVE_DB%20&risk_level=%20HIGH%20", nil)
	req.Header.Set("X-API-Key", "admin")
	s := &Server{apiKey: "admin", webAuth: true}
	filter, forbidden, empty, err := s.vulnFilterFromRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if forbidden || empty {
		t.Fatalf("unexpected forbidden=%v empty=%v", forbidden, empty)
	}
	if filter.FindingSource != "cve-db" {
		t.Fatalf("finding source = %q, want cve-db", filter.FindingSource)
	}
	if filter.RiskLevel != "high" {
		t.Fatalf("risk level = %q, want high", filter.RiskLevel)
	}
}

func TestVulnFilterFromRequestRejectsInvalidFindingSource(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/vulnerabilities?finding_source=python", nil)
	req.Header.Set("X-API-Key", "admin")
	s := &Server{apiKey: "admin", webAuth: true}
	_, _, _, err := s.vulnFilterFromRequest(req)
	if err == nil || !strings.Contains(err.Error(), "invalid finding_source") {
		t.Fatalf("expected invalid finding_source error, got %v", err)
	}
}

func TestHandleListVulnerabilitiesRejectsInvalidFindingSource(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/vulnerabilities?finding_source=python", nil)
	req.Header.Set("X-API-Key", "admin")
	w := httptest.NewRecorder()
	s := &Server{apiKey: "admin", webAuth: true}

	s.handleListVulnerabilities(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	if !strings.Contains(w.Body.String(), "invalid finding_source") {
		t.Fatalf("body = %q, want invalid finding_source", w.Body.String())
	}
}

func TestHandleListVulnerabilitiesBoundsRuntime(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleListVulnerabilities")
	if start < 0 {
		t.Fatal("handleListVulnerabilities not found")
	}
	end := strings.Index(body[start:], "func (s *Server) vulnFilterFromRequest")
	if end < 0 {
		t.Fatal("vulnFilterFromRequest not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		`envInt("BONGSU_VULNERABILITY_LIST_TIMEOUT_SECONDS", 15)`,
		"context.WithTimeout(r.Context()",
		"s.db.ListVulnerabilities(ctx, filter, limit, offset)",
		`writeError(w, http.StatusGatewayTimeout, "vulnerability list timeout")`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("list vulnerabilities timeout handling missing %q: %s", want, fn)
		}
	}
}

func TestVulnFilterFromRequestRejectsInvalidRiskLevel(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/vulnerabilities?risk_level=urgent", nil)
	req.Header.Set("X-API-Key", "admin")
	s := &Server{apiKey: "admin", webAuth: true}
	_, _, _, err := s.vulnFilterFromRequest(req)
	if err == nil || !strings.Contains(err.Error(), "invalid risk_level") {
		t.Fatalf("expected invalid risk_level error, got %v", err)
	}
}

func TestSecurityDBUpdateQueuesRescanAfterRecalculation(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) SecurityDatabaseUpdated")
	if start < 0 {
		t.Fatal("SecurityDatabaseUpdated not found")
	}
	end := strings.Index(body[start:], "func (s *Server) recalculateSecurityFindings")
	if end < 0 {
		t.Fatal("SecurityDatabaseUpdated end not found")
	}
	fn := body[start : start+end]
	if strings.Contains(fn, "queueSecurityDBRescans") {
		t.Fatalf("SecurityDatabaseUpdated should not queue rescans before recalculation: %s", fn)
	}
	for _, want := range []string{
		"securityDBChangedMeta(reason)",
		`"security_db.updated"`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("security DB changed event missing %q: %s", want, fn)
		}
	}

	start = strings.Index(body, "func (s *Server) securityDBChangedMeta")
	if start < 0 {
		t.Fatal("securityDBChangedMeta not found")
	}
	end = strings.Index(body[start:], "func (s *Server) SecurityDatabaseSyncFailed")
	if end < 0 {
		t.Fatal("securityDBChangedMeta end not found")
	}
	fn = body[start : start+end]
	for _, want := range []string{"securityDBRevisionMeta"} {
		if !strings.Contains(fn, want) {
			t.Fatalf("security DB change revision metadata missing %q: %s", want, fn)
		}
	}

	start = strings.Index(body, "func (s *Server) runSecurityRecalculation")
	if start < 0 {
		t.Fatal("runSecurityRecalculation not found")
	}
	end = strings.Index(body[start:], "func coalesceSecurityRecalcReason")
	if end < 0 {
		t.Fatal("runSecurityRecalculation end not found")
	}
	fn = body[start : start+end]
	for _, want := range []string{
		`s.auditSystem("security_db.recalculation"`,
		"GetSecurityDBRevision(ctx)",
		`meta["security_db_revision"]`,
		"SyncEPSSPriorityColumns(ctx)",
		`"epss_merged"`,
		"RemoveStaleRematchedVulnerabilities",
		`"stale_rematch_removed"`,
		`"stale_rematch_scanned"`,
		`"stale_rematch_batches"`,
		`"stale_rematch_batch_size"`,
		`"rematch_scanned_candidates"`,
		"rematchSourcePolicySummary(stats, rematchOpts)",
		`"rematch_eligible_sources"`,
		`"rematch_excluded_sources"`,
		`"rematch_source_policy"`,
		"s.queueSecurityDBRescans(reason, status)",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("post-recalculation rescan queueing missing %q: %s", want, fn)
		}
	}
	if strings.LastIndex(fn, `s.auditSystem("security_db.recalculation"`) > strings.Index(fn, "s.queueSecurityDBRescans(reason, status)") {
		t.Fatalf("rescan queueing must happen after recalculation audit: %s", fn)
	}

	start = strings.Index(body, "func (s *Server) handleSecurityDbRecalculate")
	if start < 0 {
		t.Fatal("handleSecurityDbRecalculate not found")
	}
	end = strings.Index(body[start:], "func (s *Server) handleSecurityDbExport")
	if end < 0 {
		t.Fatal("handleSecurityDbRecalculate end not found")
	}
	fn = body[start : start+end]
	for _, want := range []string{
		"s.authenticateAdmin(r)",
		"s.recalculateSecurityFindings(reason)",
		`"security_db.recalculation.request"`,
		`"status": "queued"`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("manual security recalculation endpoint missing %q: %s", want, fn)
		}
	}
}

func TestSecurityDBUpdateSurfacesTriggerBackgroundRecalculation(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	tests := []struct {
		name string
		fn   string
		next string
		want string
	}{
		{"trivy upload", "func (s *Server) handleTrivyDBUpload", "func trivyDBLoadErrorStatus", `s.SecurityDatabaseUpdated("trivy-db upload")`},
		{"trivy update", "func (s *Server) handleTrivyDBUpdate", "func (s *Server) handleCveDbExport", `s.SecurityDatabaseUpdated("trivy-db update")`},
		{"bundle import", "func (s *Server) handleSecurityDbImport", "type securityDBBundleManifest", `s.SecurityDatabaseUpdated("security-db bundle import")`},
		{"cve jsonl import", "func (s *Server) handleCveDbImport", "func (s *Server) importCveJSONL", `s.SecurityDatabaseUpdated("cve-db import")`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := strings.Index(body, tt.fn)
			if start < 0 {
				t.Fatalf("%s not found", tt.fn)
			}
			end := strings.Index(body[start:], tt.next)
			if end < 0 {
				t.Fatalf("%s end not found", tt.fn)
			}
			fn := body[start : start+end]
			if !strings.Contains(fn, tt.want) {
				t.Fatalf("%s must trigger background recalculation/rescan with %q: %s", tt.fn, tt.want, fn)
			}
		})
	}
}

func TestAutoRescanAuditReportsQueueAccounting(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) queueSecurityDBRescans")
	if start < 0 {
		t.Fatal("queueSecurityDBRescans not found")
	}
	end := strings.Index(body[start:], "func (s *Server) handleCveDbImport")
	if end < 0 {
		t.Fatal("queueSecurityDBRescans end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		`"eligible":`,
		`"queued":`,
		`"already_pending":`,
		`"recalculation_status":`,
		`"security_db_revision":`,
		"GetSecurityDBRevision",
		"result.Eligible",
		"result.Queued",
		"result.AlreadyPending",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("auto-rescan audit accounting missing %q: %s", want, fn)
		}
	}
}

func TestSecurityDBStatusEndpointExposesOperationalState(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		`"GET /api/admin/security-db/status"`,
		"func (s *Server) handleSecurityDbStatus",
		"s.authenticateAdmin(r)",
		"s.secMgr.Status()",
		"securityDBFreshnessStatus(dbCtx, true)",
		"securityRecalculationStatus(true)",
		"securityRecalculationLastResult(dbCtx, true)",
		"securityDBRevisionMeta(dbCtx)",
		"securityDbStatusQuality",
		"enrichSecurityDBManagerStatus(out[\"security_db\"], freshness)",
		"securityDBOperationalGuidance",
		`out["warnings"]`,
		`out["recommended_actions"]`,
		`out["cve_db_quality"]`,
		`out["cve_affected_package_index"]`,
		`out["cve_reference_key_index"]`,
		`out["security_db_freshness"]`,
		`out["status"] = "degraded"`,
		"affectedIndexRebuildStatus",
		"referenceIndexRebuildStatus",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("security DB status endpoint missing %q", want)
		}
	}
}

func TestSecurityDBOperationalGuidanceSurfacesActionableProblems(t *testing.T) {
	warnings, actions := securityDBOperationalGuidance(
		map[string]any{
			"configured":          true,
			"status":              "never",
			"last_sync_persisted": "2026-06-04T05:31:32Z",
			"last_error":          "curl failed",
		},
		map[string]any{
			"status":          "stale",
			"missing_sources": []string{"trivy"},
			"stale_sources": []map[string]any{
				{"source": "trivy"},
			},
		},
		map[string]any{"status": "warning"},
		true,
	)
	for _, want := range []string{
		"security DB freshness check timed out",
		"last security DB sync attempt failed",
		"sync manager has not completed since this process started",
		"one or more security DB sources are stale",
		"missing security DB sources: trivy",
		"stale security DB sources: trivy",
		"CVE DB quality status is warning",
	} {
		if !containsString(warnings, want) {
			t.Fatalf("warnings missing %q: %#v", want, warnings)
		}
	}
	if len(actions) != len(warnings) {
		t.Fatalf("actions should track warnings, warnings=%#v actions=%#v", warnings, actions)
	}

	warnings, actions = securityDBOperationalGuidance(
		map[string]any{"configured": true, "status": "ok"},
		map[string]any{"status": "ok", "missing_sources": []string{}, "stale_sources": []map[string]any{}},
		map[string]any{"status": "ok"},
		false,
	)
	if len(warnings) != 0 || len(actions) != 0 {
		t.Fatalf("healthy guidance warnings=%#v actions=%#v", warnings, actions)
	}

	warnings, actions = securityDBOperationalGuidance(
		map[string]any{
			"configured":          true,
			"status":              "never",
			"last_sync_persisted": "2026-06-04T08:43:52Z",
		},
		map[string]any{"status": "ok", "missing_sources": []string{}, "stale_sources": []map[string]any{}},
		map[string]any{"status": "ok"},
		false,
	)
	if containsString(warnings, "sync manager has not completed since this process started") || len(actions) != 0 {
		t.Fatalf("healthy persisted freshness should not warn about restarted sync manager, warnings=%#v actions=%#v", warnings, actions)
	}
}

func TestWebhookAuditIncludesSecurityDBRevision(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) auditWebhookResult")
	if start < 0 {
		t.Fatal("auditWebhookResult not found")
	}
	end := strings.Index(body[start:], "func (s *Server) actorType")
	if end < 0 {
		t.Fatal("auditWebhookResult end not found")
	}
	fn := body[start : start+end]
	if !strings.Contains(fn, `"security_db_revision"`) {
		t.Fatalf("webhook audit should carry security_db_revision: %s", fn)
	}
}

func TestCveDbAdminActionsCarrySecurityDBRevision(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleCveDbRematch")
	if start < 0 {
		t.Fatal("handleCveDbRematch not found")
	}
	end := strings.Index(body[start:], "func rematchOptionsFromEnv")
	if end < 0 {
		t.Fatal("handleCveDbRematch end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"revisionMeta := s.securityDBRevisionMeta(r.Context())",
		"result.SecurityDBRevision",
		"rematchSourcePolicySummary(stats, opts)",
		"result.SourcePolicy",
		`"eligible_sources"`,
		`"excluded_sources"`,
		`"source_policy"`,
		"for k, v := range revisionMeta",
		`"cve_db.rematch"`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("cve db rematch revision metadata missing %q: %s", want, fn)
		}
	}

	start = strings.Index(body, "func (s *Server) handleCveDbRecalcCVSS")
	if start < 0 {
		t.Fatal("handleCveDbRecalcCVSS not found")
	}
	end = strings.Index(body[start:], "func (s *Server) handleCveDbExport")
	if end < 0 {
		t.Fatal("handleCveDbRecalcCVSS end not found")
	}
	fn = body[start : start+end]
	for _, want := range []string{
		"revisionMeta := s.securityDBRevisionMeta(r.Context())",
		"resp[k] = v",
		"for k, v := range revisionMeta",
		`"cve_db.recalc_cvss"`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("cve db cvss recalc revision metadata missing %q: %s", want, fn)
		}
	}
}

func TestHostSBOMAuditIncludesLatestScanID(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleHostSBOM")
	if start < 0 {
		t.Fatal("handleHostSBOM not found")
	}
	end := strings.Index(body[start:], "func latestPackageScanID")
	if end < 0 {
		t.Fatal("handleHostSBOM end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"authenticateExport",
		"exportScope",
		"scanID := latestPackageScanID(pkgs)",
		`"scan_id":`,
		"scanID",
		`s.audit(r, "sbom.export", "host", hostID, "started"`,
		`w.WriteHeader(http.StatusOK)`,
		`s.audit(r, "sbom.export", "host", hostID, "ok"`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("SBOM audit scan identity missing %q: %s", want, fn)
		}
	}
	if strings.Index(fn, `"started"`) > strings.Index(fn, `w.WriteHeader(http.StatusOK)`) {
		t.Fatalf("SBOM export must audit start before writing response: %s", fn)
	}
	pkgs := []models.Package{{ScanID: ""}, {ScanID: " scan-1 "}}
	if got := latestPackageScanID(pkgs); got != "scan-1" {
		t.Fatalf("latestPackageScanID = %q, want scan-1", got)
	}
}

func TestVulnerabilityExportRequiresExportScopeAndAuditsBeforeWrite(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleExportVulnerabilities")
	if start < 0 {
		t.Fatal("handleExportVulnerabilities not found")
	}
	end := strings.Index(body[start:], "func writeVulnerabilityCSV")
	if end < 0 {
		t.Fatal("handleExportVulnerabilities end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"authenticateExport",
		"exportScope := s.exportScope(r)",
		"exportScope.Empty()",
		"vulnFilterFromRequestWithScope(r, exportScope)",
		"revisionMeta := s.securityDBRevisionMeta(r.Context())",
		"vulnerabilityExportMetadata(format, filter",
		`"metadata": auditMeta`,
		`"X-Bongsu-Security-DB-Revision"`,
		`"X-Bongsu-Export-Truncated"`,
		`s.audit(r, "vulnerability.export", "vulnerability", "filtered", "forbidden"`,
		`s.audit(r, "vulnerability.export", "vulnerability", "filtered", "started"`,
		`w.WriteHeader(http.StatusOK)`,
		`s.audit(r, "vulnerability.export", "vulnerability", "filtered", "ok"`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("vulnerability export hardening missing %q: %s", want, fn)
		}
	}
	if strings.Index(fn, `"started"`) > strings.Index(fn, `w.WriteHeader(http.StatusOK)`) {
		t.Fatalf("vulnerability export must audit start before writing response: %s", fn)
	}
}

func TestVulnerabilityExportMetadataCapturesProvenance(t *testing.T) {
	generatedAt := time.Date(2026, 6, 1, 2, 3, 4, 0, time.UTC)
	meta := vulnerabilityExportMetadata("json", db.VulnFilter{
		HostID:        "host-1",
		HostIDs:       []string{"host-1", "host-2"},
		Severity:      "CRITICAL",
		TriageStatus:  "open",
		FindingSource: "cve-db",
		RiskLevel:     "critical",
		Overdue:       true,
		Exploited:     true,
		MinEPSS:       0.7,
		PkgName:       "openssl",
		Owner:         "platform",
		Team:          "infra",
		Environment:   "prod",
		Criticality:   "critical",
		MinCVSS:       7,
		SortBy:        "risk_score",
		SortDesc:      true,
		HideFixed:     true,
		HideNoFix:     true,
		HideMismatch:  true,
	}, 250, 100, 100, map[string]any{"security_db_revision": "rev-123"}, generatedAt)

	if meta["security_db_revision"] != "rev-123" || meta["generated_at"] != "2026-06-01T02:03:04Z" || meta["truncated"] != true {
		t.Fatalf("unexpected export metadata: %#v", meta)
	}
	filters, ok := meta["filters"].(map[string]any)
	if !ok {
		t.Fatalf("filters metadata has unexpected type: %#v", meta["filters"])
	}
	for _, want := range []string{"host_id", "scope_host_count", "severity", "triage_status", "finding_source", "risk_level", "overdue", "exploited", "min_epss", "pkg_name", "owner", "team", "environment", "criticality", "min_cvss", "sort_by", "sort_desc", "hide_fixed", "hide_no_fix", "hide_mismatch"} {
		if _, ok := filters[want]; !ok {
			t.Fatalf("export filter metadata missing %q: %#v", want, filters)
		}
	}
}

func TestRBACPolicyAPIAllowsExportPermission(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleUpsertAccessPolicy")
	if start < 0 {
		t.Fatal("handleUpsertAccessPolicy not found")
	}
	end := strings.Index(body[start:], "func (s *Server) handleCveDbStats")
	if end < 0 {
		t.Fatal("handleUpsertAccessPolicy end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		`case "read", "write", "admin", "export":`,
		`"permission":    body.Permission`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("RBAC policy API export support missing %q: %s", want, fn)
		}
	}
}

func TestRBACListHandlersUseStableArrayFields(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, tt := range []struct {
		fn   string
		want string
	}{
		{"handleListAccessSubjects", "items = []models.AccessSubject{}"},
		{"handleListAccessPolicies", "items = []models.AccessPolicy{}"},
	} {
		start := strings.Index(body, "func (s *Server) "+tt.fn)
		if start < 0 {
			t.Fatalf("%s not found", tt.fn)
		}
		end := strings.Index(body[start+1:], "\nfunc ")
		if end < 0 {
			t.Fatalf("%s end not found", tt.fn)
		}
		fn := body[start : start+1+end]
		if !strings.Contains(fn, tt.want) || !strings.Contains(fn, `map[string]any{"items": items}`) {
			t.Fatalf("%s must preserve stable items array using %q: %s", tt.fn, tt.want, fn)
		}
	}
}

func TestRBACStatusEndpointExposesOperationalCounters(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		`"GET /api/admin/rbac/status"`,
		"func (s *Server) handleAccessControlStatus",
		"s.authenticateAdmin(r)",
		"GetAccessControlStats",
		"OrphanPolicyCount",
		`"stats":        stats`,
		`"access policies reference missing subjects"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("RBAC status endpoint missing %q", want)
		}
	}

	script, err := os.ReadFile("../../../scripts/verify-operator-workflow.sh")
	if err != nil {
		t.Fatalf("read operator workflow verifier: %v", err)
	}
	for _, want := range []string{
		`/api/admin/rbac/status`,
		`.stats.subject_count`,
		`.stats.policy_count`,
		`.stats.orphan_policy_count`,
	} {
		if !strings.Contains(string(script), want) {
			t.Fatalf("operator workflow must verify RBAC status, missing %q", want)
		}
	}
}

func TestHealthOnlyShowsDetailedDBStatusToAdmins(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleHealth")
	if start < 0 {
		t.Fatal("handleHealth not found")
	}
	end := strings.Index(body[start+1:], "\nfunc ")
	if end < 0 {
		t.Fatal("handleHealth end not found")
	}
	fn := body[start : start+1+end]
	for _, want := range []string{
		"isAdmin := s.authenticateAdmin(r)",
		"includeOperationalDetails := isAdmin",
		"s.dbMgr.Status()",
		"s.dbMgr.PublicStatus()",
		"s.secMgr.Status()",
		"s.secMgr.PublicStatus()",
		`envInt("BONGSU_HEALTH_DB_TIMEOUT_SECONDS", 2)`,
		"context.WithTimeout(r.Context()",
		"recalcStatus := s.securityRecalculationStatus(isAdmin)",
		"if includeOperationalDetails",
		`s.securityRecalculationLastResult(dbCtx, isAdmin)`,
		`recalcStatus["last_result"] = last`,
		`s.cveDBRematchLastResult(dbCtx, isAdmin)`,
		`resp["cve_db_rematch"]`,
		`s.securityDBAutoRescanLastResult(dbCtx, isAdmin)`,
		`resp["security_db_auto_rescan"]`,
		`resp["cve_affected_package_index"]`,
		`resp["cve_affected_index_rebuild"]`,
		"affectedIndexRebuildStatus",
		"GetCveAffectedPackageIndexHealthStats",
		"detail_error",
		"cveAffectedPackageIndexStatsFromHealthMap",
		"AffectedIndexPartial",
		"AffectedIndexDetail",
		"fallback_error",
		`resp["cve_reference_key_index"]`,
		"GetCveReferenceKeyIndexHealthStats",
		"cveReferenceKeyIndexStatsFromHealthMap",
		"ReferenceIndexPartial",
		"ReferenceIndexDetail",
		`resp["cve_reference_index_rebuild"]`,
		`resp["cve_db_quality"]`,
		"cveDBQualitySummary",
		"GetCveReferenceKeyIndexStats",
		"referenceIndexRebuildStatus",
		`"security_recalculation": recalcStatus`,
		"for k, v := range s.securityDBRevisionMeta(dbCtx)",
		`k == "security_db_revision" || isAdmin`,
		`s.securityDBFreshnessStatus(dbCtx, isAdmin)`,
		`resp["security_db_freshness_timeout"] = true`,
		`resp["security_db_freshness"] = freshness`,
		`enrichSecurityDBManagerStatus(resp["security_db"], freshness)`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("health handler missing %q: %s", want, fn)
		}
	}
	if strings.Index(fn, "s.secMgr.PublicStatus()") < strings.Index(fn, "else") {
		t.Fatalf("public security DB status should be used only for non-admin health: %s", fn)
	}
	if strings.Index(fn, "s.dbMgr.PublicStatus()") < strings.Index(fn, "else") {
		t.Fatalf("public Trivy DB status should be used only for non-admin health: %s", fn)
	}
}

func TestEnrichSecurityDBManagerStatusAddsPersistedFreshness(t *testing.T) {
	status := map[string]any{"status": "never"}
	freshness := map[string]any{
		"latest_source":      "osv",
		"latest_last_update": "2026-06-04T05:31:32Z",
		"source_count":       5,
		"status":             "ok",
	}
	enrichSecurityDBManagerStatus(status, freshness)
	if status["persisted_latest_source"] != "osv" {
		t.Fatalf("persisted latest source = %#v", status["persisted_latest_source"])
	}
	if status["persisted_status"] != "ok" {
		t.Fatalf("persisted status = %#v", status["persisted_status"])
	}
	if status["last_sync_persisted"] != "2026-06-04T05:31:32Z" {
		t.Fatalf("persisted last sync = %#v", status["last_sync_persisted"])
	}
	if _, ok := status["status_detail"].(string); !ok {
		t.Fatalf("status detail missing: %#v", status)
	}
}

func TestCveDBQualitySummarySupportsPartialAffectedIndexHealth(t *testing.T) {
	quality := buildCveDBQualitySummary(cveDBQualityInput{
		Placeholders: &db.CvePlaceholderStats{},
		AffectedIndex: &db.CveAffectedPackageIndexStats{
			Count:       100,
			SourceCount: 1,
			IndexedCVEs: 25,
			Orphans:     0,
		},
		AffectedIndexPartial: true,
		AffectedIndexDetail:  errors.New("detail timed out"),
		ReferenceIndex:       &db.CveReferenceKeyIndexStats{},
	})
	if quality["status"] != "ok" {
		t.Fatalf("partial affected index status = %#v, want ok: %#v", quality["status"], quality)
	}
	if quality["affected_index_summary_mode"] != "indexed-only" {
		t.Fatalf("partial affected index summary mode = %#v", quality["affected_index_summary_mode"])
	}
	if quality["affected_index_detail_error"] != "detail timed out" {
		t.Fatalf("partial affected index detail error = %#v", quality["affected_index_detail_error"])
	}
	if _, ok := quality["affected_index_coverage_percent"]; ok {
		t.Fatalf("partial affected index must not expose unknown coverage: %#v", quality)
	}
	if _, ok := quality["affected_index_stale"]; ok {
		t.Fatalf("partial affected index must not expose unknown stale state: %#v", quality)
	}
	if quality["total_matchable"] != 25 {
		t.Fatalf("partial affected index total_matchable = %#v, want indexed CVE count", quality["total_matchable"])
	}
	if quality["eligible_sources"] != 1 {
		t.Fatalf("partial affected index eligible_sources = %#v, want affected index source count", quality["eligible_sources"])
	}

	quality = buildCveDBQualitySummary(cveDBQualityInput{
		Placeholders: &db.CvePlaceholderStats{},
		AffectedIndex: &db.CveAffectedPackageIndexStats{
			Orphans: 1,
		},
		AffectedIndexPartial: true,
		ReferenceIndex:       &db.CveReferenceKeyIndexStats{},
	})
	if quality["status"] != "degraded" {
		t.Fatalf("partial affected index orphan status = %#v, want degraded: %#v", quality["status"], quality)
	}
}

func TestCveDBQualitySummarySupportsPartialReferenceIndexHealth(t *testing.T) {
	quality := buildCveDBQualitySummary(cveDBQualityInput{
		Placeholders:  &db.CvePlaceholderStats{},
		AffectedIndex: &db.CveAffectedPackageIndexStats{},
		ReferenceIndex: &db.CveReferenceKeyIndexStats{
			Count:       100,
			IndexedCVEs: 25,
			Orphans:     0,
		},
		ReferenceIndexPartial: true,
		ReferenceIndexDetail:  errors.New("reference detail timed out"),
	})
	if quality["status"] != "ok" {
		t.Fatalf("partial reference index status = %#v, want ok: %#v", quality["status"], quality)
	}
	if quality["reference_index_summary_mode"] != "indexed-only" {
		t.Fatalf("partial reference index summary mode = %#v", quality["reference_index_summary_mode"])
	}
	if quality["reference_index_detail_error"] != "reference detail timed out" {
		t.Fatalf("partial reference index detail error = %#v", quality["reference_index_detail_error"])
	}
	if _, ok := quality["reference_index_coverage_percent"]; ok {
		t.Fatalf("partial reference index must not expose unknown coverage: %#v", quality)
	}
	if _, ok := quality["reference_index_stale"]; ok {
		t.Fatalf("partial reference index must not expose unknown stale state: %#v", quality)
	}
	if quality["total_records"] != 0 {
		t.Fatalf("partial reference index without total CVEs should not invent total_records: %#v", quality["total_records"])
	}

	quality = buildCveDBQualitySummary(cveDBQualityInput{
		Placeholders:          &db.CvePlaceholderStats{},
		AffectedIndex:         &db.CveAffectedPackageIndexStats{},
		ReferenceIndex:        &db.CveReferenceKeyIndexStats{Orphans: 1},
		ReferenceIndexPartial: true,
	})
	if quality["status"] != "degraded" {
		t.Fatalf("partial reference index orphan status = %#v, want degraded: %#v", quality["status"], quality)
	}
}

func TestVulnerabilityAPIExposesExploitedFilterAndExportColumn(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		`Exploited:     r.URL.Query().Get("exploited") == "true"`,
		`MinEPSS:       floatParam(r, "min_epss", 0)`,
		`MinEPSSPct:    floatParam(r, "min_epss_percentile", 0)`,
		`RiskLevel:     riskLevel`,
		"riskLevelFilterParam",
		`"exploited"`,
		`"epss_score"`,
		`"epss_percentile"`,
		`"risk_score"`,
		`"risk_level"`,
		`strconv.FormatBool(v.Exploited)`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("vulnerability API exploited support missing %q", want)
		}
	}
}

func TestSecurityRecalculationStatusIncludesAdminPendingReason(t *testing.T) {
	s := &Server{securityRecalcRunning: true, securityRecalcPending: true, securityRecalcReason: "osv import"}
	publicStatus := s.securityRecalculationStatus(false)
	if publicStatus["running"] != true || publicStatus["pending"] != true {
		t.Fatalf("public status = %#v, want running and pending", publicStatus)
	}
	if _, ok := publicStatus["pending_reason"]; ok {
		t.Fatalf("public status must not expose pending reason: %#v", publicStatus)
	}
	adminStatus := s.securityRecalculationStatus(true)
	if adminStatus["pending_reason"] != "osv import" {
		t.Fatalf("admin pending reason = %#v, want osv import", adminStatus["pending_reason"])
	}
}

func TestSecurityRecalculationLastResultUsesAuditLog(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) securityRecalculationLastResult")
	if start < 0 {
		t.Fatal("securityRecalculationLastResult not found")
	}
	end := strings.Index(body[start:], "func (s *Server) handleDeleteScan")
	if end < 0 {
		t.Fatal("securityRecalculationLastResult end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"GetLatestAuditLog(ctx, db.AuditLogFilter",
		`Action:       "security_db.recalculation"`,
		`Action:       "cve_db.rematch"`,
		`ResourceType: "security_db"`,
		`ResourceType: "cve_db"`,
		`ResourceID:   "aggregate"`,
		`ResourceID:   "all"`,
		`[]string{"started", "queued"}`,
		`"finished_at"`,
		`"finished_at_unix"`,
		`"cvss_updated"`,
		`"findings_enriched"`,
		`"stale_rematch_removed"`,
		`"stale_rematch_scanned"`,
		`"stale_rematch_batches"`,
		`"stale_rematch_batch_size"`,
		`"rematch_new_vulns"`,
		`"scanned_candidates"`,
		`"rematch_eligible_sources"`,
		`"rematch_excluded_sources"`,
		`"rematch_source_policy"`,
		`if includeDetails`,
		`out["errors"] = errors`,
		`out["rematch_source_policy"] = policy`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("security recalculation last result missing %q: %s", want, fn)
		}
	}
}

func TestCveDbRematchLastResultExposesSourcePolicy(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) cveDBRematchLastResult")
	if start < 0 {
		t.Fatal("cveDBRematchLastResult not found")
	}
	end := strings.Index(body[start:], "func (s *Server) handleDeleteScan")
	if end < 0 {
		t.Fatal("cveDBRematchLastResult end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		`"eligible_sources"`,
		`"excluded_sources"`,
		`"source_policy"`,
		`out["source_policy"] = policy`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("manual rematch last result missing %q: %s", want, fn)
		}
	}
}

func TestAdminMetricsExposeSecurityRecalculationLastResult(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) adminMetrics")
	if start < 0 {
		t.Fatal("adminMetrics not found")
	}
	end := strings.Index(body[start:], "func boolMetric")
	if end < 0 {
		t.Fatal("boolMetric not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"securityRecalculationLastResult(ctx, true)",
		"bongsu_security_recalculation_last_finished_timestamp_seconds",
		"bongsu_security_recalculation_last_error",
		"bongsu_security_recalculation_last_cvss_updated",
		"bongsu_security_recalculation_last_findings_enriched",
		"bongsu_security_recalculation_last_stale_rematch_removed",
		"bongsu_security_recalculation_last_stale_rematch_scanned",
		"bongsu_security_recalculation_last_stale_rematch_batches",
		"bongsu_security_recalculation_last_stale_rematch_batch_size",
		"bongsu_security_recalculation_last_rematch_new_vulns",
		"bongsu_security_recalculation_last_rematch_limited",
		"bongsu_security_recalculation_last_rematch_candidates",
		"bongsu_security_recalculation_last_rematch_scanned_candidates",
		"bongsu_security_recalculation_last_rematch_candidate_limit",
		"bongsu_security_recalculation_last_rematch_eligible_sources",
		"bongsu_security_recalculation_last_rematch_excluded_sources",
		"securityDBAutoRescanLastResult(ctx, true)",
		"bongsu_security_db_auto_rescan_last_finished_timestamp_seconds",
		"bongsu_security_db_auto_rescan_last_error",
		"bongsu_security_db_auto_rescan_last_disabled",
		"bongsu_security_db_auto_rescan_last_eligible",
		"bongsu_security_db_auto_rescan_last_queued",
		"bongsu_security_db_auto_rescan_last_already_pending",
		"bongsu_security_db_rescan_total",
		"bongsu_security_db_rescan_open",
		"bongsu_security_db_rescan_terminal",
		"bongsu_security_db_rescan_complete_percent",
		"bongsu_security_db_rescan_healthy_percent",
		"bongsu_security_db_scan_coverage_hosts_total",
		"bongsu_security_db_scan_coverage_current_hosts",
		"bongsu_security_db_scan_coverage_stale_hosts",
		"bongsu_security_db_scan_coverage_unknown_hosts",
		"bongsu_security_db_scan_coverage_no_scan_hosts",
		"bongsu_security_db_scan_coverage_percent",
		"cveDBRematchLastResult(ctx, true)",
		"bongsu_cve_db_last_manual_rematch_timestamp_seconds",
		"bongsu_cve_db_last_manual_rematch_limited",
		"bongsu_cve_db_last_manual_rematch_matches",
		"bongsu_cve_db_last_manual_rematch_scanned_candidates",
		"bongsu_cve_db_last_manual_rematch_eligible_sources",
		"bongsu_cve_db_last_manual_rematch_excluded_sources",
		"bongsu_security_db_sync_configured",
		"bongsu_security_db_sync_running",
		"bongsu_security_db_sync_last_error",
		"bongsu_security_db_sync_last_attempt_timestamp_seconds",
		"bongsu_security_db_sync_last_success_timestamp_seconds",
		"bongsu_security_db_sync_next_timestamp_seconds",
		"installerBinaryReadiness(\"bongsu-agent\", agentBinaryPath())",
		"installerBinaryReadiness(\"trivy\", trivyBinaryPath())",
		"bongsu_installer_ready",
		"bongsu_installer_install_token_configured",
		"writeInstallerBinaryMetrics(&b, agentInstaller)",
		"writeInstallerBinaryMetrics(&b, trivyInstaller)",
		"bongsu_installer_binary_ready",
		"bongsu_installer_binary_bytes",
		"bongsu_installer_binary_info",
		"bongsu_installer_binary_error",
		"bongsu_agent_fleet_degraded",
		"bongsu_agent_fleet_warnings",
		"bongsu_agent_fleet_total_hosts",
		"bongsu_agent_outdated_percent",
		"metricTimestamp",
		"metricNumber",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("admin metrics security recalculation last result missing %q: %s", want, fn)
		}
	}
}

func TestDashboardInstallSnippetIncludesInstallToken(t *testing.T) {
	out, err := os.ReadFile("../../../web/src/App.tsx")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	if !strings.Contains(body, `-H "X-Install-Token: $BONGSU_INSTALL_TOKEN"`) {
		t.Fatal("dashboard install snippet must include BONGSU_INSTALL_TOKEN header")
	}
	if !strings.Contains(body, `/api/install.sh" | sudo bash`) {
		t.Fatal("dashboard install snippet must point to install.sh")
	}
	if strings.Contains(body, `api/install.sh | sudo bash`) {
		t.Fatal("dashboard install snippet must not show unauthenticated installer URL")
	}
	if strings.Contains(body, `api/install.sh?token=$BONGSU_INSTALL_TOKEN`) {
		t.Fatal("dashboard install snippet must not put install token in URL query")
	}
}

func TestDashboardShowsDatabaseHealthErrors(t *testing.T) {
	out, err := os.ReadFile("../../../web/src/App.tsx")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"setHealth(h)",
		"health?.trivy_db?.status",
		"health?.trivy_db?.last_error",
		"health?.security_db?.last_error",
		"health?.security_recalculation",
		"health?.security_recalculation?.last_result",
		"Last Recalculation",
		"lastRecalcColor",
		"lastRecalcTitle",
		"lastRecalcLimited",
		"Manual Rematch",
		"lastManualRematch",
		"Auto Rescan Queue",
		"lastAutoRescan",
		"security_db_auto_rescan",
		"CVE rematch hit candidate limit",
		"rematch_candidates",
		"rematch_candidate_limit",
		"Full Recalc",
		"handleSecurityRecalc",
		"Security Sync",
		"securitySyncNext",
		"securitySyncLast",
		"health?.security_db_revision",
		"health?.security_db_revision_error",
		"health?.security_db_freshness",
		"DB rev:",
		"Recalc:",
		"DB fresh:",
		"Trivy DB:",
		"Security sources:",
		"Security DB revision:",
		"Security DB freshness:",
		"Oldest CVE source:",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard DB health display missing %q", want)
		}
	}
}

func TestDashboardShowsCisaKevPrioritization(t *testing.T) {
	appOut, err := os.ReadFile("../../../web/src/App.tsx")
	if err != nil {
		t.Fatal(err)
	}
	apiOut, err := os.ReadFile("../../../web/src/api.ts")
	if err != nil {
		t.Fatal(err)
	}
	appBody := string(appOut)
	apiBody := string(apiOut)
	for _, want := range []string{
		"exploitedOnly",
		"minEpss",
		"params.exploited = 'true'",
		"params.min_epss = minEpssParam",
		"risk_score",
		"riskLevel",
		"risk_level",
		"Risk Score",
		"All Risk",
		"['exploited', 'KEV']",
		"['risk_score', 'Risk']",
		"['epss_score', 'EPSS']",
		"CISA KEV",
		"Min EPSS %",
		"Known exploited",
		"v.epss_score",
		"v.exploited",
		"Advisory Sources",
		"Advisory Evidence",
		"advisory_evidence",
		"v.advisory_sources",
		"v.advisory_evidence",
		"Advisory:",
	} {
		if !strings.Contains(appBody, want) {
			t.Fatalf("dashboard KEV prioritization missing %q", want)
		}
	}
	if !strings.Contains(apiBody, "exploited: boolean") || !strings.Contains(apiBody, "exploited?: string") ||
		!strings.Contains(apiBody, "epss_score?: number") || !strings.Contains(apiBody, "risk_score?: number") ||
		!strings.Contains(apiBody, "risk_level?: string") || !strings.Contains(apiBody, "advisory_sources?: string[]") ||
		!strings.Contains(apiBody, "min_epss?: string") {
		t.Fatal("web API types must expose exploited and EPSS vulnerability fields and filters")
	}
}

func TestSecurityDBFreshnessHealthAndMetricsAreExposed(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		`BONGSU_SECURITY_DB_MAX_SOURCE_AGE_HOURS`,
		`BONGSU_SECURITY_DB_REQUIRED_SOURCES`,
		`defaultSecurityDBMaxSourceAgeHours`,
		`requiredSecurityDBSources()`,
		`GetCveSourceFreshnessStats(ctx)`,
		`resp["status"] = "stale"`,
		`resp["status"] = "missing_sources"`,
		`"oldest_source"`,
		`"latest_source"`,
		`"latest_last_update"`,
		`"latest_age_seconds"`,
		`"stale_sources"`,
		`"required_sources"`,
		`"missing_sources"`,
		`"missing_source_count"`,
		`bongsu_security_db_source_stale`,
		`bongsu_security_db_source_count`,
		`bongsu_security_db_required_source_missing_count`,
		`bongsu_security_db_required_source_missing`,
		`bongsu_security_db_source_oldest_age_seconds`,
		`bongsu_security_db_source_matchable_percent`,
		`bongsu_cve_affected_package_index_records`,
		`bongsu_security_db_source_quality_metrics_error`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("security DB freshness support missing %q", want)
		}
	}
}

func TestAdminMetricsExposeCveSourceQuality(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) adminMetrics")
	if start < 0 {
		t.Fatal("adminMetrics not found")
	}
	end := strings.Index(body[start:], "func boolMetric")
	if end < 0 {
		t.Fatal("boolMetric not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"GetCveSourceStats(ctx)",
		`labels := map[string]string{"source": stat.Source}`,
		"bongsu_security_db_source_records",
		"bongsu_security_db_source_matchable_records",
		"bongsu_security_db_source_matchable_percent",
		"bongsu_security_db_source_with_ecosystem_records",
		"bongsu_security_db_source_with_fixed_records",
		"bongsu_security_db_source_with_ranges_records",
		"bongsu_security_db_source_with_cvss_records",
		"rematchSourcePolicySummary(sourceStats, rematchOptionsFromEnv())",
		"bongsu_security_db_source_rematch_eligible",
		"GetCveOsvEcosystemStats(ctx, 100)",
		`labels := map[string]string{"ecosystem": stat.Ecosystem}`,
		"bongsu_cve_osv_ecosystem_indexed_rows",
		"bongsu_cve_osv_ecosystem_matchable_cves",
		"bongsu_cve_osv_ecosystem_last_update_timestamp_seconds",
		"bongsu_cve_osv_ecosystem_metrics_error",
		"GetCveAffectedPackageIndexStats(ctx)",
		"bongsu_cve_affected_package_index_records",
		"bongsu_cve_affected_package_index_coverage_percent",
		"bongsu_cve_affected_package_index_missing_matchable_sources",
		"bongsu_cve_affected_package_index_orphans",
		"bongsu_cve_affected_package_index_stale",
		"bongsu_cve_affected_package_index_latest_matchable_update_timestamp_seconds",
		"GetCveReferenceKeyIndexStats(ctx)",
		"bongsu_cve_reference_key_index_records",
		"bongsu_cve_reference_key_index_coverage_percent",
		"bongsu_cve_reference_key_index_orphans",
		"bongsu_cve_reference_key_index_stale",
		"GetCveEPSSMergeStats(ctx)",
		"bongsu_cve_epss_records",
		"bongsu_cve_epss_cves",
		"bongsu_cve_epss_matched_cves",
		"bongsu_cve_epss_unmatched_cves",
		"bongsu_cve_epss_non_epss_cves",
		"bongsu_cve_epss_non_epss_cves_with_epss",
		"bongsu_cve_epss_non_epss_coverage_percent",
		"bongsu_cve_epss_enriched_records",
		"bongsu_cve_epss_enriched_cves",
		"bongsu_cve_epss_enriched_sources",
		"bongsu_cve_epss_merge_coverage_percent",
		"bongsu_cve_epss_universe_match_percent",
		"bongsu_cve_epss_loaded_without_enrichment",
		"bongsu_cve_epss_merge_metrics_error",
		"bongsu_cve_db_quality_status",
		"bongsu_cve_db_quality_warning_count",
		"bongsu_cve_db_temporary_placeholders",
		"bongsu_cve_db_empty_vulnerability_ids",
		"bongsu_security_db_source_quality_metrics_error",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("admin metrics source quality missing %q: %s", want, fn)
		}
	}
}

func TestCveDbStatsExposeRematchPolicy(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleCveDbStats")
	if start < 0 {
		t.Fatal("handleCveDbStats not found")
	}
	end := strings.Index(body[start:], "func (s *Server) handleCveDbSearch")
	if end < 0 {
		t.Fatal("handleCveDbStats end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"rematchOptionsFromEnv()",
		"getCveStatsCache",
		"beginCveStatsBuild",
		"finishCveStatsBuild",
		"setCveStatsCache",
		"cveStatsCacheGen",
		"getCveStatsStaleCache",
		"startCveStatsBackgroundBuild",
		`X-Bongsu-Cache", "stale"`,
		`BONGSU_CVE_STATS_STALE_SECONDS`,
		`BONGSU_CVE_STATS_BACKGROUND_TIMEOUT_SECONDS`,
		"var wg sync.WaitGroup",
		"go measure(&sourceStatsMS",
		"go measure(&affectedIndexMS",
		"go measure(&referenceIndexMS",
		"go measure(&epssMS",
		"go measure(&placeholderMS",
		"go measure(&osvEcosystemMS",
		"go measure(&securityRevisionMS",
		"wg.Wait()",
		`X-Bongsu-Cache`,
		`"shared"`,
		`r.URL.Query().Get("refresh") != "true"`,
		"rematchSourcePolicySummary(stats, opts)",
		"totalRecords += stat.Count",
		"totalMatchable += stat.Matchable",
		`"generated_at"`,
		`"durations_ms"`,
		`durations["source_stats"]`,
		`durations["affected_package_index"]`,
		`durations["reference_key_index"]`,
		`durations["epss_merge"]`,
		`durations["placeholder_quality"]`,
		`durations["osv_ecosystems"]`,
		`durations["security_db_revision"]`,
		`durations["total"]`,
		`"source_count"`,
		`"total_records"`,
		`"total_matchable"`,
		`"total_matchable_percent"`,
		`"affected_package_index"`,
		"GetCveAffectedPackageIndexStats",
		`"reference_key_index"`,
		"GetCveReferenceKeyIndexStats",
		"GetCveEPSSMergeStats",
		`"epss_merge"`,
		`"epss_merge_error"`,
		"GetCveOsvEcosystemStats",
		`"osv_ecosystems"`,
		`"osv_ecosystems_error"`,
		`"cve_db_quality"`,
		"GetCvePlaceholderStats",
		"buildCveDBQualitySummary",
		"s.securityDBRevisionMeta(ctx)",
		`"rematch_eligible"`,
		`"rematch_exclusion"`,
		`"rematch_policy"`,
		`"min_source_matchable_percent"`,
		`"eligible_sources"`,
		`"excluded_sources"`,
		"source not in rematch allowlist",
		"source has no matchable affected packages",
		"below %.1f%% policy",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("CVE DB stats rematch policy missing %q: %s", want, fn)
		}
	}
}

func TestDashboardShowsCveSourceQualityGate(t *testing.T) {
	appOut, err := os.ReadFile("../../../web/src/App.tsx")
	if err != nil {
		t.Fatal(err)
	}
	apiOut, err := os.ReadFile("../../../web/src/api.ts")
	if err != nil {
		t.Fatal(err)
	}
	appBody := string(appOut)
	apiBody := string(apiOut)
	for _, want := range []string{
		"sourceBelowQuality",
		"Matchable %",
		"below gate",
		"minQualityForDisplay",
		"cveDbStatus",
		"CVE DB Status",
		"CVE DB Quality",
		"cveQualityStatus",
		"temporary_placeholders",
		"CVE DB quality:",
		"CVE Matchable",
		"OSV Ecosystems",
		"osvEcosystems",
		"osvEcosystemRows",
		"oldestOsvEcosystem",
		"OSV ecosystem stats:",
		"Affected Index",
		"cveAffectedIndexUnhealthy",
		"cveAffectedIndex?.stale",
		"older than matchable CVE rows",
		"EPSS Merge",
		"epssMergeCoverage",
		"epssUniverseCoverage",
		"cveEpssMerge?.non_epss_cves_with_epss",
		"EPSS source is loaded but no non-EPSS CVE rows are enriched",
		"handleAffectedIndexRebuild",
		"Rebuild Affected Index",
		"Affected Rebuild",
		"affectedRebuildRunning",
		"cve_affected_index_rebuild?.running",
		"Affected package index rebuild queued",
		"handleReferenceIndexRebuild",
		"Rebuild Reference Index",
		"Reference key index rebuilt",
		"Reference key index rebuild queued",
		"indexed-only health snapshot",
		"duration_ms",
		"missing_matchable_sources",
		"Reference Index",
		"cveReferenceIndex",
		"coverage_percent",
		"Reference Rebuild",
		"referenceRebuildRunning",
		"cve_reference_index_rebuild?.running",
		"setInterval",
		"Weakest CVE Source",
		"Rematch Eligible Sources",
		"cveRematchPolicy",
		"cveRematchEligibleCount",
		"policy excluded",
		"s.rematch_eligible === false",
		"CVE Source Alerts",
		"missingCveSources",
		"Missing CVE sources",
		"oldestCveAgeDays",
		"staleCveSourceByName",
		"staleSource?.age_seconds",
		"missing last update",
		">stale</span>",
	} {
		if !strings.Contains(appBody, want) {
			t.Fatalf("dashboard source quality gate missing %q", want)
		}
	}
	for _, want := range []string{"CveDbStatsResponse", "CveEpssMergeStats", "CveDbQuality", "CveOsvEcosystemStat", "generated_at?: string", "total_matchable_percent?: number", "affected_package_index", "reference_key_index", "latest_matchable_update", "latest_cve_update", "stale?: boolean", "summary_mode?: string", "detail_error?: string", "epss_merge", "cve_db_quality", "temporary_placeholders?: number", "empty_vulnerability_ids?: number", "non_epss_coverage_percent?: number", "epss_universe_match_percent?: number", "epss_non_epss_coverage_percent?: number", "durations_ms?: Record<string, number>", "merge_coverage_percent", "osv_ecosystems?: CveOsvEcosystemStat[]", "osv_ecosystems_error?: string", "rebuildCveAffectedIndex", "rebuildCveReferenceIndex", "recalculateSecurityDB", "security_db_revision?: string", "matchable_percent", "matchability_reason?: string", "rematch_eligible", "rematch_exclusion", "CveRematchPolicy", "rematch_policy", "last_sync?: string", "last_attempt?: string", "next_sync?: string", "required_sources?: string[]", "missing_sources?: string[]"} {
		if !strings.Contains(apiBody, want) {
			t.Fatalf("CVE source stat API type missing %q", want)
		}
	}
}

func TestDashboardExposesAirgapSecurityBundleActions(t *testing.T) {
	appOut, err := os.ReadFile("../../../web/src/App.tsx")
	if err != nil {
		t.Fatal(err)
	}
	apiOut, err := os.ReadFile("../../../web/src/api.ts")
	if err != nil {
		t.Fatal(err)
	}
	appBody := string(appOut)
	apiBody := string(apiOut)
	for _, want := range []string{
		"Airgap Security Bundle",
		"Include Trivy DB",
		"Export Bundle",
		"Import Bundle",
		"handleSecurityBundleExport",
		"handleSecurityBundleImport",
		"securityBundleIncludeTrivy",
		"recalculation started",
	} {
		if !strings.Contains(appBody, want) {
			t.Fatalf("dashboard airgap bundle action missing %q", want)
		}
	}
	for _, want := range []string{
		"exportSecurityDBBundle",
		"importSecurityDBBundle",
		"/admin/security-db/export",
		"/admin/security-db/import",
		"FormData",
		"uploadForm",
		"bongsu-security-db-bundle.tar.gz",
	} {
		if !strings.Contains(apiBody, want) {
			t.Fatalf("web API airgap bundle helper missing %q", want)
		}
	}
}

func TestContainersViewShowsImageRiskSummary(t *testing.T) {
	appOut, err := os.ReadFile("../../../web/src/App.tsx")
	if err != nil {
		t.Fatal(err)
	}
	apiOut, err := os.ReadFile("../../../web/src/api.ts")
	if err != nil {
		t.Fatal(err)
	}
	appBody := string(appOut)
	apiBody := string(apiOut)
	for _, want := range []string{
		"vulnerability_count",
		"critical_count",
		"high_count",
		"max_cvss",
		"package_count",
	} {
		if !strings.Contains(appBody, want) {
			t.Fatalf("containers view risk summary missing %q", want)
		}
		if !strings.Contains(apiBody, want) {
			t.Fatalf("container API type risk summary missing %q", want)
		}
	}
	for _, want := range []string{"Max CVSS", "Findings"} {
		if !strings.Contains(appBody, want) {
			t.Fatalf("containers view risk label missing %q", want)
		}
	}
}

func TestStaticInstallScriptUsesHeaderAuthenticatedDownloads(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/install-agent.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`printf 'header = "X-Install-Token: %s"\n' "$INSTALL_TOKEN" > "$curl_config"`,
		`curl -fsSL --config "$curl_config" -D "$headers" "$url" -o "$output"`,
		`verify_download_sha256 "$headers" "$output"`,
		`tolower($1)=="x-bongsu-sha256:"`,
		`missing X-Bongsu-SHA256 header for $output`,
		`checksum mismatch for $output`,
		`curl_download "${SERVER_URL}/api/downloads/bongsu-agent" "$WORK_DIR/bin/bongsu-agent"`,
		`curl_download "${SERVER_URL}/api/downloads/trivy" "$WORK_DIR/bin/trivy"`,
		"AGENT_TOKEN=",
		"generate_agent_token()",
		`agent_token: ${AGENT_TOKEN}`,
		`chmod 600 "$WORK_DIR/agent.token"`,
		"Optional persistent per-host token",
		"BONGSU_AGENT_SCAN_ROOT",
		"BONGSU_AGENT_TRIVY_TIMEOUT_SECONDS",
		"BONGSU_AGENT_CONTAINER_TIMEOUT_SECONDS",
		"BONGSU_AGENT_SKIP_CONTAINERS",
		"BONGSU_AGENT_MAX_CONTAINERS",
		`API_KEY="${2:-${BONGSU_AGENT_API_KEY:-}}"`,
		"BONGSU_AGENT_API_KEY",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("static installer header download missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"INSTALL_TOKEN_QUERY",
		`api/downloads/bongsu-agent${INSTALL_TOKEN_QUERY}`,
		`api/downloads/trivy${INSTALL_TOKEN_QUERY}`,
		`?token=${INSTALL_TOKEN}`,
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("static installer must not use token-bearing download URLs: found %q", forbidden)
		}
	}
}

func TestSecurityDBSyncScriptFailsOnImportErrors(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/sync-all-cvedb.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"import_cve_file()",
		`download-cisa-kev.sh`,
		`import_cve_file "${CISA_KEV_FILE}" "cisa-kev"`,
		`download-epss.sh`,
		`import_cve_file "${EPSS_FILE}" "epss"`,
		"curl -fsS -X POST",
		`data.get("status") != "ok"`,
		"invalid import response",
		"ERROR: ${source} import request failed",
		"STATS=$(curl -fsS",
		"FAILED_SOURCES=()",
		`exit 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("sync-all-cvedb must fail closed on import errors, missing %q", want)
		}
	}
	for _, forbidden := range []string{
		`|| echo "0"`,
		`|| echo "  SKIP:`,
		"curl -s -X POST",
		"IMPORT_CMD=",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("sync-all-cvedb must not hide import failures with %q", forbidden)
		}
	}
}

func TestSecurityDBSyncScriptAppendsOSVEcosystemChunks(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/sync-all-cvedb.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`local replace="${3:-true}"`,
		`local finalize="${4:-true}"`,
		`-F "file=@${file}" -F "source=${source}" -F "replace=${replace}" -F "finalize=${finalize}"`,
		`import_cve_file "${OSV_ECO_FILE}" "osv" "false" "false"`,
		`if [ "${OSV_TOTAL}" -gt 0 ]; then`,
		`finalize_deferred_cve_imports "osv chunk import"`,
		`"${AFFECTED_INDEX_REBUILD_URL}"`,
		`"${REFERENCE_INDEX_REBUILD_URL}"`,
		`"${RECALCULATE_URL}"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("sync-all-cvedb must append OSV ecosystem chunks and finalize once, missing %q", want)
		}
	}
}

func TestSecurityDBSyncScriptPrunesStaleOSVAfterSuccessfulChunks(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/sync-all-cvedb.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`OSV_PRUNE_BEFORE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"`,
		`if [ "${OSV_FAILED}" -eq 0 ]; then`,
		`/api/admin/cve-db/source/osv/prune-stale?before=${OSV_PRUNE_BEFORE}`,
		`finalize_deferred_cve_imports "osv chunk import"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("sync-all-cvedb must prune stale OSV rows only after successful chunks, missing %q", want)
		}
	}
}

func TestSecurityDBSyncScriptCoversCoreOSVEcosystems(t *testing.T) {
	for _, path := range []string{
		"../../../scripts/sync-all-cvedb.sh",
		"../../../scripts/download-osv.sh",
	} {
		out, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		body := string(out)
		for _, want := range []string{
			"BONGSU_OSV_ECOSYSTEMS",
			"Ubuntu",
			"Red Hat",
			"Rocky Linux",
			"Wolfi",
			"openSUSE",
			"Azure Linux",
		} {
			if !strings.Contains(body, want) {
				t.Fatalf("%s must include core OSV ecosystem %q in the default/update path", path, want)
			}
		}
	}
}

func TestOperatorWorkflowVerifiesHealthAndMetricsObservability(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/verify-operator-workflow.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"Checking health and admin metrics observability",
		`CURL_MAX_TIME="${BONGSU_VERIFY_CURL_MAX_TIME_SECONDS:-45}"`,
		"health_json=\"$(api_json GET /api/health)\"",
		"admin metrics reported one or more metrics_error gauges",
		`grep -Eq '^bongsu_.*_metrics_error ' "$TMP_DIR/admin-metrics.txt"`,
		".security_db_revision",
		".security_db_revision_error",
		".security_recalculation.running",
		`.cve_affected_package_index.summary_mode == "indexed-only"`,
		".cve_reference_key_index.stale == false",
		"/api/admin/metrics",
		"bongsu_security_db_revision_info",
		"bongsu_security_db_revision_metrics_error",
		"bongsu_security_recalculation_running",
		"bongsu_security_recalculation_pending",
		"bongsu_cve_affected_package_index_coverage_percent",
		"bongsu_cve_affected_package_index_metrics_error",
		"bongsu_cve_reference_key_index_coverage_percent",
		"bongsu_cve_reference_key_index_metrics_error",
		"bongsu_cve_epss_enriched_records",
		"bongsu_cve_epss_merge_metrics_error",
		"bongsu_cve_osv_ecosystem_indexed_rows",
		"bongsu_cve_osv_ecosystem_metrics_error",
		"bongsu_agent_fleet_degraded",
		"bongsu_agent_fleet_warnings",
		"bongsu_agent_outdated_percent",
		"bongsu_security_db_rescan_open",
		"bongsu_security_db_rescan_metrics_error",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("operator workflow must verify health/metrics observability, missing %q", want)
		}
	}
}

func TestOperatorWorkflowVerifiesHostRuntimeInventoryEndpoints(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/verify-operator-workflow.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`/api/hosts/{id}/users:`,
		`/api/hosts/{id}/processes:`,
		`/api/hosts/{id}/ports:`,
		"bongsu-operator-user",
		"bongsu-operator-process",
		"bongsu-operator-listener",
		`api_json GET "/api/hosts/${VERIFY_HOST_ID}/users?limit=20"`,
		`api_json GET "/api/hosts/${VERIFY_HOST_ID}/processes?limit=20"`,
		`api_json GET "/api/hosts/${VERIFY_HOST_ID}/ports?limit=20"`,
		"host user runtime inventory endpoint must expose latest reported user accounts",
		"host process runtime inventory endpoint must expose latest reported process snapshot",
		"host port runtime inventory endpoint must expose latest reported listening ports",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("operator workflow must verify host runtime inventory endpoints, missing %q", want)
		}
	}
}

func TestAgentBinaryWorkflowVerifiesCodeLibrarySBOMContext(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/verify-agent-binary-workflow.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"bongsu-host-npm-library",
		"bongsu-container-python-library",
		`"Type":"npm"`,
		`"Type":"python-pkg"`,
		`pkg:npm/bongsu-host-npm-library@4.5.6`,
		`pkg:pypi/bongsu-container-python-library@1.2.3`,
		"host Trivy code library must preserve npm ecosystem and purl",
		"container Trivy code library must preserve PyPI ecosystem, purl, and container/image context",
		"latest package, code-library, and container inventory",
		"OS package, code-library, and container counts",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("agent binary workflow verifier missing code-library assertion %q", want)
		}
	}
}

func TestDownloadCisaKevScriptIsFailClosedAndAtomic(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/download-cisa-kev.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`known_exploited_vulnerabilities.json`,
		`OUTPUT_TMP="${OUTPUT}.tmp.$$"`,
		`urllib.request.urlopen(req, timeout=180)`,
		`CISA KEV feed produced no vulnerabilities`,
		`CISA KEV conversion produced no CVE entries`,
		`"source": "cisa-kev"`,
		`"known_exploited": True`,
		`mv "${OUTPUT_TMP}" "${OUTPUT}"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("download-cisa-kev must fail closed and write atomically, missing %q", want)
		}
	}
	if strings.Contains(body, `> "${OUTPUT}"`) {
		t.Fatal("download-cisa-kev must not write partial data directly to the final output")
	}
}

func TestDownloadEPSSScriptIsFailClosedAndAtomic(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/download-epss.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`epss_scores-`,
		`OUTPUT_TMP="${OUTPUT}.tmp.$$"`,
		`gzip.decompress(resp.read())`,
		`EPSS CSV missing required columns`,
		`EPSS conversion produced no CVE entries`,
		`"source": "epss"`,
		`"epss_score": epss_score`,
		`"epss_percentile": percentile`,
		`mv "${OUTPUT_TMP}" "${OUTPUT}"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("download-epss must fail closed and write atomically, missing %q", want)
		}
	}
	if strings.Contains(body, `> "${OUTPUT}"`) {
		t.Fatal("download-epss must not write partial data directly to the final output")
	}
}

func TestSecurityDBSyncScriptImportsNvdPerYear(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/sync-all-cvedb.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`NVD_FAILED=0`,
		`import_cve_file "${NVD_FILE}" "nvd"`,
		`incomplete NVD download; preserving existing nvd source`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("sync-all-cvedb per-year NVD import missing %q", want)
		}
	}
}

func TestNvdDownloaderFailsClosedAndWritesAtomically(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/download-nvd.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`OUTPUT_TMP="${OUTPUT}.tmp.$$"`,
		`trap 'rm -f "${OUTPUT_TMP}"' EXIT`,
		`output = "${OUTPUT_TMP}"`,
		`FAILED after 3 attempts`,
		`sys.exit(1)`,
		`NVD download produced no CVE entries`,
		`mv "${OUTPUT_TMP}" "${OUTPUT}"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("download-nvd must fail closed and write atomically, missing %q", want)
		}
	}
	if strings.Contains(body, `> "${OUTPUT}"`) || strings.Contains(body, `output = "${OUTPUT}"`) {
		t.Fatal("download-nvd must not write partial data directly to the final output")
	}
}

func TestOsvDownloaderFailsClosedAndWritesAtomically(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/download-osv.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`OUTPUT_TMP="${OUTPUT}.tmp.$$"`,
		`FAILED_ECOSYSTEMS=()`,
		`curl -fsSL`,
		`FAILED_ECOSYSTEMS+=("${eco}:download")`,
		`FAILED_ECOSYSTEMS+=("${eco}:empty-zip")`,
		`FAILED_ECOSYSTEMS+=("${eco}:unzip")`,
		`FAILED_ECOSYSTEMS+=("${eco}:no-entries")`,
		`ERROR: incomplete OSV download`,
		`OSV download produced no CVE entries`,
		`mv "${OUTPUT_TMP}" "${OUTPUT}"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("download-osv must fail closed and write atomically, missing %q", want)
		}
	}
	if strings.Contains(body, `> "${OUTPUT}"`) || strings.Contains(body, `with open("${OUTPUT}", "a")`) {
		t.Fatal("download-osv must not write partial data directly to the final output")
	}
	if strings.Contains(body, "WARNING: ${eco} download failed, skipping") {
		t.Fatal("download-osv must not silently skip failed ecosystems")
	}
	for _, forbidden := range []string{
		"affected[:20]",
		"refs[:20]",
		"aliases[:5]",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("download-osv must preserve complete OSV evidence and not truncate %s", forbidden)
		}
	}
}

func TestRestoreScriptVerifiesBackupSidecarChecksum(t *testing.T) {
	restore, err := os.ReadFile("../../../scripts/restore.sh")
	if err != nil {
		t.Fatal(err)
	}
	restoreBody := string(restore)
	for _, want := range []string{
		"verify_sidecar_checksum()",
		`local sidecar="${archive}.sha256"`,
		"invalid backup sidecar checksum",
		"backup archive checksum mismatch",
		`verify_sidecar_checksum "$BACKUP_FILE"`,
	} {
		if !strings.Contains(restoreBody, want) {
			t.Fatalf("restore.sh must verify optional backup sidecar checksums, missing %q", want)
		}
	}

	verifier, err := os.ReadFile("../../../scripts/verify-backup-restore-archive.sh")
	if err != nil {
		t.Fatal(err)
	}
	verifierBody := string(verifier)
	for _, want := range []string{
		"Archive sidecar checksum mismatch is rejected",
		`sha256sum "$valid_archive" > "${valid_archive}.sha256"`,
		"0000000000000000000000000000000000000000000000000000000000000000",
		`expect_restore_fail "$sidecar_archive" "archive checksum"`,
	} {
		if !strings.Contains(verifierBody, want) {
			t.Fatalf("backup/restore verifier must cover sidecar checksums, missing %q", want)
		}
	}
}

func TestLiveCveDbQualityVerifierChecksMatchableSentinelAndFixedVersionQuality(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/verify-live-cvedb-quality.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`BONGSU_VERIFY_CVEDB_REQUIRE_FRESH_SOURCES="${BONGSU_VERIFY_CVEDB_REQUIRE_FRESH_SOURCES:-false}"`,
		`if [ "$BONGSU_VERIFY_CVEDB_REQUIRE_FRESH_SOURCES" = "true" ]; then`,
		`/api/admin/security-db/status`,
		`.security_db_freshness.status == "ok"`,
		"security DB required sources must not be stale",
		`BONGSU_VERIFY_CVEDB_REQUIRE_OSV_UPSTREAM_FRESHNESS="${BONGSU_VERIFY_CVEDB_REQUIRE_OSV_UPSTREAM_FRESHNESS:-false}"`,
		`https://osv-vulnerabilities.storage.googleapis.com/${encoded_eco}/all.zip`,
		`lower(split_part(ecosystem, ':', 1)) = lower(${eco_literal})`,
		"local OSV affected-package index has no matchable rows for upstream sentinel ecosystem",
		"local OSV ecosystem ${eco} is older than upstream beyond grace",
		"local OSV source is older than upstream sentinel",
		`/api/cve-db/search?q=phenx%2Fphp-svg-lib&limit=10&matchable=true`,
		`WHERE fixed_version ~* '^[0-9a-f]{40}$'`,
		"affected package index rows must not keep hash-like fixed versions",
		"OSV Packagist sentinel must preserve phenx/php-svg-lib package/ecosystem/fixed evidence",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("live CVE DB quality verifier missing %q", want)
		}
	}
	if strings.Contains(body, "matchable_only=true") {
		t.Fatal("live CVE DB quality verifier must use the API's matchable=true parameter")
	}
}

func TestReleaseReadinessLiveGateRequiresFreshCveSources(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/verify-release-readiness.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`BONGSU_RELEASE_READINESS_LIVE=true`,
		`BONGSU_RELEASE_READINESS_REQUIRE_DB`,
		`env -u BONGSU_DB_PASSWORD -u BONGSU_API_KEY -u BONGSU_AGENT_API_KEY -u BONGSU_INSTALL_TOKEN ./scripts/verify-deploy-config.sh`,
		`./scripts/verify-live-server-build.sh`,
		`./scripts/verify-live-installer-payload.sh`,
		`BONGSU_DB_DSN is required for live release readiness`,
		`BONGSU_VERIFY_CVEDB_REQUIRE_FRESH_SOURCES=true BONGSU_VERIFY_CVEDB_REQUIRE_OSV_UPSTREAM_FRESHNESS=true BONGSU_VERIFY_CVEDB_REQUIRE_DB=${REQUIRE_DB} ./scripts/verify-live-cvedb-quality.sh`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("release readiness live gate must require fresh CVE sources, missing %q", want)
		}
	}
}

func TestLiveServerBuildVerifierChecksSourceAlignedServerBuild(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/verify-live-server-build.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`/api/health`,
		`EXPECTED_SERVER_COMMIT="${BONGSU_VERIFY_SERVER_COMMIT:-}"`,
		`BONGSU_VERIFY_SERVER_ALLOW_DEV_VERSION`,
		`git ls-files`,
		`grep -Ev '(^|/)(testdata|fixtures)(/|$)|_test\.go$'`,
		`git log -1 --format=%H --`,
		`"${SERVER_BUILD_FILES[@]}"`,
		`cmd/server`,
		`internal/server`,
		`deploy/Dockerfile.server`,
		`.status == "ok" or .status == "degraded"`,
		`server_version`,
		`build_date`,
		`Live server build verification passed`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("live server build verifier missing %q", want)
		}
	}
}

func TestLiveInstallerPayloadVerifierChecksSourceAlignedAgentPayload(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/verify-live-installer-payload.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`/api/admin/installer/status`,
		`EXPECTED_AGENT_COMMIT="${BONGSU_VERIFY_INSTALLER_AGENT_COMMIT:-}"`,
		`git ls-files`,
		`grep -Ev '(^|/)(testdata|fixtures)(/|$)|_test\.go$'`,
		`git log -1 --format=%H --`,
		`"${AGENT_BUILD_FILES[@]}"`,
		`internal/server/api/installer.go`,
		`deploy/Dockerfile.agent`,
		`.install_token_configured == true`,
		`.agent.ready == true`,
		`.trivy.ready == true`,
		`test("^[0-9a-f]{64}$")`,
		`"+${EXPECTED_AGENT_COMMIT}+"`,
		`Live installer payload verification passed`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("live installer payload verifier missing %q", want)
		}
	}
}

func TestSecurityDBSyncScriptFailsOnMissingRequiredTrivySource(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/sync-all-cvedb.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`REQUIRE_TRIVY_SOURCE="${BONGSU_SYNC_REQUIRE_TRIVY_SOURCE:-true}"`,
		`TRIVY_BIN_FOR_SYNC="${TRIVY_BIN:-${BONGSU_TRIVY_PATH:-}}"`,
		`find_trivy_binary()`,
		`"${SCRIPT_DIR}/../bin/trivy"`,
		`TRIVY_BIN="${TRIVY_BIN_FOR_SYNC}" "${SCRIPT_DIR}/extract-trivy-cvedb.sh"`,
		`TRIVY_FAILED=0`,
		`FAILED_SOURCES+=("trivy:extract")`,
		`FAILED_SOURCES+=("trivy:no-data")`,
		`FAILED_SOURCES+=("trivy:not-installed")`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("sync-all-cvedb must fail closed for required trivy source, missing %q", want)
		}
	}
}

func TestTrivySourceSyncScriptRefreshesOnlyTrivySource(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/sync-trivy-cvedb.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`TRIVY_BIN_FOR_SYNC="${TRIVY_BIN:-${BONGSU_TRIVY_PATH:-}}"`,
		`find_trivy_binary()`,
		`"${SCRIPT_DIR}/../bin/trivy"`,
		`TRIVY_BIN="${TRIVY_BIN_FOR_SYNC}" "${SCRIPT_DIR}/extract-trivy-cvedb.sh"`,
		`-F "source=trivy"`,
		`-F "replace=true"`,
		`-F "finalize=true"`,
		`Trivy import returned zero imported rows`,
		`/api/cve-db/stats`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("sync-trivy-cvedb must provide targeted fail-closed Trivy refresh, missing %q", want)
		}
	}
}

func TestTrivyCveExtractionUsesConfiguredCacheDir(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/extract-trivy-cvedb.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`TRIVY_BIN="${TRIVY_BIN:-${BONGSU_TRIVY_PATH:-}}"`,
		`TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-${BONGSU_TRIVY_CACHE_DIR:-}}"`,
		`BONGSU_TMPDIR`,
		`WORKDIR=$(mktemp -d`,
		`DB_PATH="${TRIVY_CACHE_DIR}/db/trivy.db"`,
		`--download-db-only --cache-dir "${TRIVY_CACHE_DIR}"`,
		`"--cache-dir", "${TRIVY_CACHE_DIR}"`,
		`--cache-dir "${TRIVY_CACHE_DIR}" --format json`,
		`--skip-db-update`,
		`sys.exit(1)`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("trivy CVE extraction must use configured cache dir, missing %q", want)
		}
	}
	for _, forbidden := range []string{
		`CACHE_DIR=$(${TRIVY_BIN} --cache-dir`,
		`${HOME}/.cache/trivy/db/trivy.db`,
		`--skip-update`,
		`sys.exit(0)`,
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("trivy CVE extraction must not use stale cache/update behavior %q", forbidden)
		}
	}
}

func TestDeployComposeRequiresOperationalSecrets(t *testing.T) {
	for _, path := range []string{
		"../../../deploy/docker-compose.yml",
		"../../../deploy/docker-compose.airgap.yml",
	} {
		t.Run(path, func(t *testing.T) {
			out, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			body := string(out)
			for _, want := range []string{
				"${BONGSU_DB_PASSWORD:?Set BONGSU_DB_PASSWORD in .env}",
				"${BONGSU_AGENT_API_KEY:?Set BONGSU_AGENT_API_KEY in .env}",
				"${BONGSU_INSTALL_TOKEN:?Set BONGSU_INSTALL_TOKEN in .env}",
				"BONGSU_ALLOW_WEAK_SECRETS: ${BONGSU_ALLOW_WEAK_SECRETS:-false}",
				"BONGSU_AGENT_HOST_BINDING: ${BONGSU_AGENT_HOST_BINDING:-true}",
				"BONGSU_ACCESS_LOG: ${BONGSU_ACCESS_LOG:-true}",
				"BONGSU_ACCESS_LOG_HEALTH: ${BONGSU_ACCESS_LOG_HEALTH:-false}",
				"BONGSU_DB_MAX_OPEN_CONNS: ${BONGSU_DB_MAX_OPEN_CONNS:-25}",
				"BONGSU_DB_MAX_IDLE_CONNS: ${BONGSU_DB_MAX_IDLE_CONNS:-5}",
				"BONGSU_DB_CONN_MAX_LIFETIME_MINUTES: ${BONGSU_DB_CONN_MAX_LIFETIME_MINUTES:-5}",
				"BONGSU_HTTP_READ_HEADER_TIMEOUT_SECONDS: ${BONGSU_HTTP_READ_HEADER_TIMEOUT_SECONDS:-10}",
				"BONGSU_HTTP_READ_TIMEOUT_SECONDS: ${BONGSU_HTTP_READ_TIMEOUT_SECONDS:-30}",
				"BONGSU_HTTP_WRITE_TIMEOUT_SECONDS: ${BONGSU_HTTP_WRITE_TIMEOUT_SECONDS:-900}",
				"BONGSU_HTTP_IDLE_TIMEOUT_SECONDS: ${BONGSU_HTTP_IDLE_TIMEOUT_SECONDS:-120}",
				"BONGSU_HTTP_MAX_HEADER_BYTES: ${BONGSU_HTTP_MAX_HEADER_BYTES:-1048576}",
				`BONGSU_PORT: "5677"`,
				`${BONGSU_API_PORT:-5677}:5677`,
				`${BONGSU_WEB_PORT:-5678}:80`,
				"BONGSU_SECURITY_DB_SYNC_OUTPUT_MAX_BYTES: ${BONGSU_SECURITY_DB_SYNC_OUTPUT_MAX_BYTES:-8192}",
				"BONGSU_SECURITY_DB_REQUIRED_SOURCES: ${BONGSU_SECURITY_DB_REQUIRED_SOURCES:-cisa-kev,epss,osv,nvd,trivy}",
				"BONGSU_SECURITY_DB_MAX_SOURCE_AGE_HOURS: ${BONGSU_SECURITY_DB_MAX_SOURCE_AGE_HOURS:-30}",
				"BONGSU_SYNC_REQUIRE_TRIVY_SOURCE:",
				"BONGSU_TRIVY_DB_UPLOAD_MAX_BYTES: ${BONGSU_TRIVY_DB_UPLOAD_MAX_BYTES:-2147483648}",
				"BONGSU_CVE_DB_IMPORT_MAX_BYTES: ${BONGSU_CVE_DB_IMPORT_MAX_BYTES:-2147483648}",
				"BONGSU_SECURITY_DB_BUNDLE_MAX_BYTES: ${BONGSU_SECURITY_DB_BUNDLE_MAX_BYTES:-4294967296}",
				"BONGSU_MULTIPART_MEMORY_MAX_BYTES: ${BONGSU_MULTIPART_MEMORY_MAX_BYTES:-33554432}",
				`pg_isready -U \"$${POSTGRES_USER}\" -d \"$${POSTGRES_DB}\"`,
			} {
				if !strings.Contains(body, want) {
					t.Fatalf("compose hardening missing %q in %s", want, path)
				}
			}
			for _, forbidden := range []string{
				"${BONGSU_DB_PASSWORD:-bongsu}",
				"POSTGRES_PASSWORD: ${BONGSU_DB_PASSWORD:-bongsu}",
				"BONGSU_AGENT_API_KEY: ${BONGSU_AGENT_API_KEY:-${BONGSU_API_KEY}}",
				"BONGSU_INSTALL_TOKEN: ${BONGSU_INSTALL_TOKEN:-}",
				"pg_isready -U bongsu",
			} {
				if strings.Contains(body, forbidden) {
					t.Fatalf("compose must not keep weak default %q in %s", forbidden, path)
				}
			}
		})
	}
}

func TestConnectedComposeEnablesSecurityDbAutoUpdateDefaults(t *testing.T) {
	out, err := os.ReadFile("../../../deploy/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"BONGSU_TRIVY_DB_INTERVAL_HOURS: ${BONGSU_TRIVY_DB_INTERVAL_HOURS:-6}",
		"BONGSU_SECURITY_DB_SYNC_CMD: ${BONGSU_SECURITY_DB_SYNC_CMD:-/app/scripts/sync-all-cvedb.sh http://localhost:5677}",
		"BONGSU_SECURITY_DB_INTERVAL_HOURS: ${BONGSU_SECURITY_DB_INTERVAL_HOURS:-6}",
		"BONGSU_SECURITY_DB_SYNC_ON_START: ${BONGSU_SECURITY_DB_SYNC_ON_START:-true}",
		"BONGSU_SYNC_REQUIRE_TRIVY_SOURCE: ${BONGSU_SYNC_REQUIRE_TRIVY_SOURCE:-true}",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("connected compose auto-update default missing %q", want)
		}
	}
}

func TestAirgapComposeDisablesConnectedSecurityDbAutoUpdate(t *testing.T) {
	out, err := os.ReadFile("../../../deploy/docker-compose.airgap.yml")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`BONGSU_TRIVY_DB_INTERVAL_HOURS: "0"`,
		`BONGSU_PORT: "5677"`,
		`BONGSU_SECURITY_DB_SYNC_CMD: ""`,
		`BONGSU_SECURITY_DB_SYNC_ON_START: "false"`,
		`BONGSU_SYNC_REQUIRE_TRIVY_SOURCE: ${BONGSU_SYNC_REQUIRE_TRIVY_SOURCE:-false}`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("airgap compose must disable connected auto-update, missing %q", want)
		}
	}
}

func TestDeployEnvExampleKeepsWebAuthEnabled(t *testing.T) {
	out, err := os.ReadFile("../../../deploy/.env.example")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	if !strings.Contains(body, "BONGSU_WEB_AUTH=true") {
		t.Fatal("example deployment must default web auth to enabled")
	}
	if strings.Contains(body, "BONGSU_WEB_AUTH=false") {
		t.Fatal("example deployment must not default web auth to disabled")
	}
	for _, want := range []string{
		"BONGSU_API_PORT=5677",
		"BONGSU_WEB_PORT=5678",
		"BONGSU_TRIVY_DB_INTERVAL_HOURS=6",
		"BONGSU_SECURITY_DB_SYNC_CMD=/app/scripts/sync-all-cvedb.sh http://localhost:5677",
		"BONGSU_SECURITY_DB_SYNC_ON_START=true",
		"BONGSU_SYNC_REQUIRE_TRIVY_SOURCE=true",
		"BONGSU_SECURITY_DB_REQUIRED_SOURCES=cisa-kev,epss,osv,nvd,trivy",
		"BONGSU_SECURITY_DB_MAX_SOURCE_AGE_HOURS=30",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("example deployment auto-update default missing %q", want)
		}
	}
}

func TestInstallerAndBinaryDownloadsAreAudited(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		`"installer.generate"`,
		`"installer.download"`,
		`"bongsu-agent"`,
		`"trivy"`,
		`"install_token_set"`,
		`"bytes"`,
		`info.Mode().IsRegular()`,
		`"copy failed"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("installer audit missing %q", want)
		}
	}
}

func TestBinaryDownloadAuditsOnlyAfterCopySuccess(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, fnName := range []string{"handleAgentDownload", "handleTrivyDownload"} {
		start := strings.Index(body, "func (s *Server) "+fnName)
		if start < 0 {
			t.Fatalf("%s not found", fnName)
		}
		end := strings.Index(body[start+1:], "\nfunc ")
		if end < 0 {
			t.Fatalf("%s end not found", fnName)
		}
		fn := body[start : start+1+end]
		copyIdx := strings.Index(fn, "io.Copy(w, f)")
		okAuditIdx := strings.LastIndex(fn, `"ok"`)
		if copyIdx < 0 || okAuditIdx < 0 {
			t.Fatalf("%s missing copy or ok audit: %s", fnName, fn)
		}
		if okAuditIdx < copyIdx {
			t.Fatalf("%s must audit ok only after io.Copy succeeds", fnName)
		}
		for _, want := range []string{`info.Mode().IsRegular()`, `"copy failed"`, `"error"`} {
			if !strings.Contains(fn, want) {
				t.Fatalf("%s missing download guard %q: %s", fnName, want, fn)
			}
		}
	}
}

func TestHostMetadataUpdateAuditsOnlyAfterHostReload(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleUpdateHostMetadata")
	if start < 0 {
		t.Fatal("handleUpdateHostMetadata not found")
	}
	end := strings.Index(body[start+1:], "\nfunc ")
	if end < 0 {
		t.Fatal("handleUpdateHostMetadata end not found")
	}
	fn := body[start : start+1+end]
	for _, want := range []string{
		"errors.Is(err, sql.ErrNoRows)",
		`writeError(w, http.StatusNotFound, "host not found")`,
		`s.db.GetHost(r.Context(), hostID)`,
		`"host.metadata.update"`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("metadata update missing %q: %s", want, fn)
		}
	}
	reloadIdx := strings.Index(fn, "s.db.GetHost(r.Context(), hostID)")
	auditIdx := strings.Index(fn, `"host.metadata.update"`)
	if reloadIdx < 0 || auditIdx < 0 || auditIdx < reloadIdx {
		t.Fatalf("metadata update must audit success only after host reload succeeds: %s", fn)
	}
}

func TestResetHostAgentTokenRequiresAdminAndAudits(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		`"POST /api/hosts/{id}/agent-token/reset"`,
		"func (s *Server) handleResetHostAgentToken",
		"s.authenticateAdmin(r)",
		"s.db.ResetHostAgentToken",
		`"host.agent_token.reset"`,
		`"host_id": hostID`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("host agent token reset handling missing %q", want)
		}
	}
}

func TestHostRuntimeInventoryEndpointsAreDocumentedAndScoped(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		`"GET /api/hosts/{id}/users"`,
		`"GET /api/hosts/{id}/processes"`,
		`"GET /api/hosts/{id}/ports"`,
		"func (s *Server) handleHostUsers",
		"func (s *Server) handleHostProcesses",
		"func (s *Server) handleHostPorts",
		"s.canReadHost(r, hostID)",
		"s.db.GetLatestUserAccounts",
		"s.db.GetLatestProcessSnapshots",
		"s.db.GetLatestPorts",
		"[]models.UserAccount{}",
		"[]models.ProcessSnapshot{}",
		"[]models.PortInfo{}",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("host runtime inventory endpoint missing %q", want)
		}
	}

	spec, err := os.ReadFile("../../../internal/server/api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	specBody := string(spec)
	for _, want := range []string{
		"/api/hosts/{id}/users:",
		"/api/hosts/{id}/processes:",
		"/api/hosts/{id}/ports:",
		"PaginatedUserAccounts:",
		"PaginatedProcessSnapshots:",
		"PaginatedPorts:",
	} {
		if !strings.Contains(specBody, want) {
			t.Fatalf("OpenAPI missing host runtime inventory contract %q", want)
		}
	}
}

func TestHostDetailShowsRuntimeInventory(t *testing.T) {
	apiOut, err := os.ReadFile("../../../web/src/api.ts")
	if err != nil {
		t.Fatal(err)
	}
	apiBody := string(apiOut)
	for _, want := range []string{
		"export interface UserAccount",
		"export interface ProcessSnapshot",
		"export interface PortInfo",
		"hostUsers:",
		"hostProcesses:",
		"hostPorts:",
	} {
		if !strings.Contains(apiBody, want) {
			t.Fatalf("web API client missing host runtime inventory support %q", want)
		}
	}

	appOut, err := os.ReadFile("../../../web/src/App.tsx")
	if err != nil {
		t.Fatal(err)
	}
	appBody := string(appOut)
	for _, want := range []string{
		"Users ({totalUsers})",
		"Listening Ports ({totalPorts})",
		"Top Processes ({totalProcesses})",
		"api.hostUsers(hostId, 20, 0)",
		"api.hostProcesses(hostId, 20, 0)",
		"api.hostPorts(hostId, 20, 0)",
	} {
		if !strings.Contains(appBody, want) {
			t.Fatalf("host detail UI missing runtime inventory evidence %q", want)
		}
	}
}

func TestDashboardShowsAgentTokenBindingState(t *testing.T) {
	appOut, err := os.ReadFile("../../../web/src/App.tsx")
	if err != nil {
		t.Fatal(err)
	}
	apiOut, err := os.ReadFile("../../../web/src/api.ts")
	if err != nil {
		t.Fatal(err)
	}
	modelOut, err := os.ReadFile("../../shared/models/models.go")
	if err != nil {
		t.Fatal(err)
	}
	appBody := string(appOut)
	apiBody := string(apiOut)
	modelBody := string(modelOut)
	for _, want := range []string{
		"agent_token_set",
		"pending bind",
		"token hash is never exposed",
		"Current binding:",
		"setHost({ ...host, agent_token_set: false })",
	} {
		if !strings.Contains(appBody, want) {
			t.Fatalf("dashboard agent token state missing %q", want)
		}
	}
	if !strings.Contains(apiBody, "agent_token_set?: boolean") {
		t.Fatal("web Host type must expose agent_token_set boolean")
	}
	if !strings.Contains(modelBody, "AgentTokenSet bool") || !strings.Contains(modelBody, `json:"agent_token_set,omitempty"`) {
		t.Fatal("server Host model must expose agent_token_set boolean")
	}
}

func TestHostInventoryStatus(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-1 * time.Hour)
	old := now.Add(-72 * time.Hour)

	tests := []struct {
		name string
		inv  db.HostInventorySummary
		want string
	}{
		{"none", db.HostInventorySummary{}, "none"},
		{"empty", db.HostInventorySummary{ScanID: "scan-1", ScannedAt: &recent}, "empty"},
		{"degraded", db.HostInventorySummary{ScanID: "scan-1", ScanStatus: "degraded", ScannedAt: &recent, PackageCount: 10}, "degraded"},
		{"stale", db.HostInventorySummary{ScanID: "scan-1", ScannedAt: &old, PackageCount: 10}, "stale"},
		{"healthy", db.HostInventorySummary{ScanID: "scan-1", ScannedAt: &recent, PackageCount: 10}, "healthy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hostInventoryStatus(tt.inv, now, 48*time.Hour); got != tt.want {
				t.Fatalf("status = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReportAuditStatus(t *testing.T) {
	if got := reportAuditStatus(0, 0); got != "ok" {
		t.Fatalf("status = %q, want ok", got)
	}
	if got := reportAuditStatus(2, 0); got != "degraded" {
		t.Fatalf("status = %q, want degraded", got)
	}
	if got := reportAuditStatus(0, 1); got != "degraded" {
		t.Fatalf("status = %q, want degraded", got)
	}
	if got := reportScanStatus(0, 0); got != "completed" {
		t.Fatalf("scan status = %q, want completed", got)
	}
	if got := reportScanStatus(2, 0); got != "degraded" {
		t.Fatalf("scan status = %q, want degraded", got)
	}
	if got := reportScanStatus(0, 1); got != "degraded" {
		t.Fatalf("scan status = %q, want degraded", got)
	}
	if got := reportInventoryStatus(0, "degraded"); got != "empty" {
		t.Fatalf("inventory status = %q, want empty", got)
	}
	if got := reportInventoryStatus(10, "degraded"); got != "degraded" {
		t.Fatalf("inventory status = %q, want degraded", got)
	}
	if got := reportInventoryStatus(10, "completed"); got != "healthy" {
		t.Fatalf("inventory status = %q, want healthy", got)
	}
}

func TestNormalizeVulnerabilityTriage(t *testing.T) {
	triage := models.VulnerabilityTriage{
		VulnerabilityID: " CVE-2026-0001 ",
		HostID:          " host-1 ",
		PkgName:         " openssl ",
		Status:          " accepted_risk ",
		Reason:          " approved ",
		Comment:         " maintenance window ",
		UpdatedBy:       " admin ",
	}
	normalizeVulnerabilityTriage(&triage)
	if triage.VulnerabilityID != "CVE-2026-0001" ||
		triage.HostID != "host-1" ||
		triage.PkgName != "openssl" ||
		triage.Status != "accepted_risk" ||
		triage.Reason != "approved" ||
		triage.Comment != "maintenance window" ||
		triage.UpdatedBy != "admin" {
		t.Fatalf("triage was not normalized: %#v", triage)
	}
}

func TestTriageHandlerValidatesScopeBeforeUpsert(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleUpsertVulnerabilityTriage")
	if start < 0 {
		t.Fatal("handleUpsertVulnerabilityTriage not found")
	}
	end := strings.Index(body[start+1:], "\nfunc ")
	if end < 0 {
		t.Fatal("handleUpsertVulnerabilityTriage end not found")
	}
	fn := body[start : start+1+end]
	for _, want := range []string{
		"normalizeVulnerabilityTriage(&body)",
		`body.PkgName != "" && body.HostID == ""`,
		`writeError(w, http.StatusBadRequest, "host_id is required when pkg_name is set")`,
		`s.db.GetHost(r.Context(), body.HostID)`,
		`writeError(w, http.StatusNotFound, "host not found")`,
		`triageStatusRequiresReason(body.Status) && body.Reason == ""`,
		`writeError(w, http.StatusBadRequest, "reason is required for "+body.Status)`,
		`s.db.UpsertVulnerabilityTriage`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("triage handler missing %q: %s", want, fn)
		}
	}
	hostLookupIdx := strings.Index(fn, "s.db.GetHost(r.Context(), body.HostID)")
	upsertIdx := strings.Index(fn, "s.db.UpsertVulnerabilityTriage")
	if hostLookupIdx < 0 || upsertIdx < 0 || upsertIdx < hostLookupIdx {
		t.Fatalf("triage handler must validate host before upsert: %s", fn)
	}
}

func TestTriageSuppressingStatusesRequireReason(t *testing.T) {
	for _, status := range []string{"accepted_risk", "false_positive", "fixed", "ignored"} {
		if !triageStatusRequiresReason(status) {
			t.Fatalf("%s should require an audit reason", status)
		}
	}
	for _, status := range []string{"", "open", "in_progress"} {
		if triageStatusRequiresReason(status) {
			t.Fatalf("%s should not require an audit reason", status)
		}
	}
}

func TestReportWebhookPayloadIncludesQualitySignals(t *testing.T) {
	report := &models.ScanReport{
		ScanID:   "scan-1",
		ScanType: "manual",
		Host: models.Host{
			ID:        "host-1",
			Hostname:  "app-1",
			IPAddress: "10.0.0.1",
			OSName:    "Ubuntu",
			OSVersion: "24.04",
		},
		Packages:   []models.Package{{ID: "pkg-1"}},
		Containers: []models.ContainerAsset{{ID: "ctr-1"}},
	}
	payload := reportWebhookPayload(report, "degraded", "degraded", 3, 2, 5, map[string]int{"HIGH": 1}, map[string]int{"high": 1}, []string{"packages: failed"})
	tests := map[string]any{
		"scan_status":      "degraded",
		"inventory_status": "degraded",
		"vulns_inserted":   3,
		"vulns_skipped":    2,
		"vulnerabilities":  5,
		"packages":         1,
		"containers":       1,
	}
	for k, want := range tests {
		if got := payload[k]; got != want {
			t.Fatalf("payload[%s] = %#v, want %#v", k, got, want)
		}
	}
	if counts, ok := payload["severity_counts"].(map[string]int); !ok || counts["HIGH"] != 1 {
		t.Fatalf("severity_counts = %#v", payload["severity_counts"])
	}
	if counts, ok := payload["risk_level_counts"].(map[string]int); !ok || counts["high"] != 1 {
		t.Fatalf("risk_level_counts = %#v", payload["risk_level_counts"])
	}
	if errs, ok := payload["ingest_errors"].([]string); !ok || len(errs) != 1 {
		t.Fatalf("ingest_errors = %#v", payload["ingest_errors"])
	}
}

func TestScanRequestErrorHTTPMapping(t *testing.T) {
	tests := []struct {
		err     error
		status  int
		message string
	}{
		{db.ErrInvalidScanRequestStatus, 400, "invalid scan request status"},
		{db.ErrScanRequestNotFound, 404, "scan request not found"},
		{db.ErrScanRequestNotActive, 409, "scan request is not pending or claimed"},
		{db.ErrScanRequestClaimMismatch, 403, "scan request was not claimed by this host"},
		{db.ErrScanRequestNotRetryable, 409, "scan request is not failed, degraded, or cancelled"},
	}
	for _, tt := range tests {
		if got := scanRequestErrorStatus(tt.err); got != tt.status {
			t.Fatalf("scanRequestErrorStatus(%v) = %d, want %d", tt.err, got, tt.status)
		}
		if got := scanRequestErrorMessage(tt.err); got != tt.message {
			t.Fatalf("scanRequestErrorMessage(%v) = %q, want %q", tt.err, got, tt.message)
		}
	}
}

func TestRequeueScanRequestAPIRequiresAdminAndAudits(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		`"POST /api/scan-requests/{id}/requeue"`,
		"func (s *Server) handleRequeueScanRequest",
		"s.authenticateAdmin(r)",
		"s.db.RequeueScanRequest",
		`"scan_request.requeue"`,
		"scanRequestAuditMeta(req, body.Message, \"\")",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("scan request requeue API missing %q", want)
		}
	}
}

func TestRequeueFilteredScanRequestAPIRequiresSafeFilters(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		`"POST /api/scan-requests/requeue-filtered"`,
		"func (s *Server) handleRequeueFilteredScanRequests",
		"s.authenticateAdmin(r)",
		`"at least one filter is required"`,
		`"status must be failed, degraded, or cancelled"`,
		"s.db.RequeueScanRequestsByFilter",
		`"scan_request.requeue_filtered"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("filtered scan request requeue API missing %q", want)
		}
	}
}

func TestRequeueStaleScanRequestReportsDuplicateCleanup(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		"func (s *Server) handleRequeueStaleScanRequests",
		"result.CancelledDuplicates",
		`"cancelled_duplicates"`,
		"requeueResult.CancelledDuplicates",
		`"trigger":              "agent_claim"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("stale requeue duplicate cleanup reporting missing %q", want)
		}
	}
}

func TestNormalizeScanRequestCreateForcesPendingState(t *testing.T) {
	claimedAt := time.Now()
	completedAt := time.Now()
	req := models.ScanRequest{
		HostID:          " host-1 ",
		RequestedBy:     " operator ",
		ScanType:        " manual ",
		Reason:          " dashboard force scan ",
		Status:          "claimed",
		ErrorMessage:    "old error",
		ClaimedByHostID: "other-host",
		ClaimedAt:       &claimedAt,
		CompletedAt:     &completedAt,
	}
	if err := normalizeScanRequestCreate(&req); err != nil {
		t.Fatalf("normalize scan request: %v", err)
	}
	if req.HostID != "host-1" || req.RequestedBy != "operator" || req.ScanType != "manual" || req.Reason != "dashboard force scan" {
		t.Fatalf("scan request fields were not normalized: %#v", req)
	}
	if req.Status != "pending" || req.ErrorMessage != "" || req.ClaimedByHostID != "" || req.ClaimedAt != nil || req.CompletedAt != nil {
		t.Fatalf("new scan request must start unclaimed pending, got %#v", req)
	}
}

func TestNormalizeScanRequestCreateRejectsUnknownType(t *testing.T) {
	req := models.ScanRequest{ScanType: "completed"}
	if err := normalizeScanRequestCreate(&req); err == nil {
		t.Fatal("unknown scan_type should be rejected")
	}
}

func TestListScanRequestsSupportsOperationalFilters(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleListScanRequests")
	if start < 0 {
		t.Fatal("handleListScanRequests not found")
	}
	end := strings.Index(body[start:], "func (s *Server) handleCancelScanRequest")
	if end < 0 {
		t.Fatal("handleListScanRequests end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		`strings.TrimSpace(r.URL.Query().Get("status"))`,
		`!validScanRequestStatus(status)`,
		`writeError(w, http.StatusBadRequest, "invalid status")`,
		`strings.TrimSpace(r.URL.Query().Get("scan_type"))`,
		`writeError(w, http.StatusBadRequest, "invalid scan_type")`,
		`strings.TrimSpace(r.URL.Query().Get("security_db_revision"))`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("scan request API filter missing %q: %s", want, fn)
		}
	}
}

func TestCreateScanRequestValidatesTargetHost(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleCreateScanRequest")
	if start < 0 {
		t.Fatal("handleCreateScanRequest not found")
	}
	end := strings.Index(body[start:], "func normalizeScanRequestCreate")
	if end < 0 {
		t.Fatal("normalizeScanRequestCreate not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"normalizeScanRequestCreate(&req)",
		`s.db.GetHost(r.Context(), req.HostID)`,
		`writeError(w, http.StatusNotFound, "host not found")`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("create scan request host validation missing %q: %s", want, fn)
		}
	}
}

func TestScanHistoryExposesIngestErrorSummary(t *testing.T) {
	apiOut := readAllPackageGoFiles(t)
	appOut, err := os.ReadFile("../../../web/src/App.tsx")
	if err != nil {
		t.Fatal(err)
	}
	typeOut, err := os.ReadFile("../../../web/src/api.ts")
	if err != nil {
		t.Fatal(err)
	}
	apiBody := string(apiOut)
	appBody := string(appOut)
	typeBody := string(typeOut)
	for _, want := range []string{
		"scanErrorSummary(ingestErrors)",
		"CompleteScan(ctx, report.ScanID, scanStatus, errorSummary)",
		"report.SecurityDBRevision",
		"report.ScanRequestID",
		`"security_db_revision": report.SecurityDBRevision`,
		`"scan_request_id":      report.ScanRequestID`,
		`"error_summary":        errorSummary`,
		`"error_summary":        errorSummary`,
		"truncateValidUTF8(summary, maxSummaryBytes)",
	} {
		if !strings.Contains(apiBody, want) {
			t.Fatalf("scan ingest error summary API missing %q", want)
		}
	}
	for _, want := range []string{"error_summary?: string", "Issue", "s.error_summary", "colSpan={10}"} {
		if !strings.Contains(typeBody, want) && !strings.Contains(appBody, want) {
			t.Fatalf("scan ingest error summary UI/type missing %q", want)
		}
	}
}

func TestAgentScanRequestCompletionRequiresClaimedHost(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleCompleteScanRequest")
	if start < 0 {
		t.Fatal("handleCompleteScanRequest not found")
	}
	end := strings.Index(body[start:], "func scanRequestErrorStatus")
	if end < 0 {
		t.Fatal("scanRequestErrorStatus not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		`HostID  string ` + "`json:\"host_id\"`",
		"validAgentScanRequestCompletionStatus",
		`writeError(w, http.StatusBadRequest, "invalid scan request status")`,
		"verifyAgentHostBinding",
		"body.Message = normalizeScanRequestMessage(body.Message)",
		"CompleteClaimedScanRequest",
		"scanRequestAuditMeta(req, body.Message, body.HostID)",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("scan request completion ownership check missing %q: %s", want, fn)
		}
	}
}

func TestScanRequestMessageNormalization(t *testing.T) {
	msg := normalizeScanRequestMessage("  failed\n")
	if msg != "failed" {
		t.Fatalf("message = %q, want trimmed", msg)
	}
	msg = normalizeScanRequestMessage(strings.Repeat("x", maxScanRequestMessageBytes+20))
	if !strings.HasSuffix(msg, "...(truncated)") || len(msg) > maxScanRequestMessageBytes+len("...(truncated)") {
		t.Fatalf("message was not bounded: len=%d value=%q", len(msg), msg)
	}
	msg = normalizeScanRequestMessage(strings.Repeat("한", maxScanRequestMessageBytes))
	if !utf8.ValidString(msg) {
		t.Fatalf("message is not valid UTF-8: %q", msg)
	}
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		"maxScanRequestMessageBytes",
		"truncateValidUTF8(message, maxScanRequestMessageBytes)",
		"body.Message = normalizeScanRequestMessage(body.Message)",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("scan request message normalization missing %q", want)
		}
	}
}

func TestScanRequestAuditMetadataCarriesDBRevision(t *testing.T) {
	req := &models.ScanRequest{
		HostID:             "target-host",
		RequestedBy:        "system",
		ScanType:           "security-db-update",
		PackagesOnly:       true,
		Reason:             "security-db periodic sync",
		SecurityDBRevision: "rev-123",
		ClaimedByHostID:    "agent-host",
	}
	meta := scanRequestAuditMeta(req, "done", "agent-host")
	tests := map[string]any{
		"message":              "done",
		"host_id":              "agent-host",
		"target_host_id":       "target-host",
		"requested_by":         "system",
		"scan_type":            "security-db-update",
		"packages_only":        true,
		"reason":               "security-db periodic sync",
		"security_db_revision": "rev-123",
		"claimed_by_host_id":   "agent-host",
	}
	for k, want := range tests {
		if got := meta[k]; got != want {
			t.Fatalf("meta[%s] = %#v, want %#v", k, got, want)
		}
	}
}

func TestStatsExposeActiveFindingCounts(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		"GetCurrentActionableVulnCountsByHost",
		"GetHostInventorySummaries(ctx)",
		"applyAgentStatus(&h, now)",
		"hostInventoryStatus(summary, now, inventoryStaleAfter)",
		"active_vulnerabilities",
		"active_severity_counts",
		"agent_status_counts",
		"agent_version_counts",
		"latest_agent_version",
		"agent_version_drift_counts",
		"agentVersionDriftCounts(agentVersionCounts",
		"agent_version_state",
		"agentVersionState(h.AgentVersion, latestAgentVersion)",
		"inventory_status_counts",
		`if summary.ScanID != ""`,
		"inventory_coverage_percent",
		"inventory_fresh_hosts",
		"inventory_fresh_percent",
		"inventory_latest_packages",
		"inventory_latest_vulnerabilities",
		"inventory_latest_containers",
		"GetSecurityDBRevision(ctx)",
		"CountSecurityDBRescanRequestsByStatus",
		"securityDBRescanProgressSummary",
		"GetSecurityDBScanCoverage",
		"CountStaleScanRequestsByState",
		"security_db_revision",
		"security_db_rescan_request_counts",
		"security_db_rescan_progress",
		"security_db_scan_coverage",
		"scan_request_stale_counts",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("stats active finding signal missing %q", want)
		}
	}
}

func TestDashboardShowsCurrentSecurityDBRescanCounts(t *testing.T) {
	out, err := os.ReadFile("../../../web/src/App.tsx")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"onOpenScanRequests",
		"onOpenHosts",
		"type HostFilters",
		"agent_version_state?: string",
		"setHostFilters(filters)",
		"initialFilters={hostFilters}",
		"initialFilters.agent_status || ''",
		"initialFilters.inventory_status || ''",
		"initialFilters.agent_version_state || ''",
		"openCurrentDBRescans",
		"setScanRequestFilters(filters)",
		"initialRequestFilters={scanRequestFilters}",
		"initialRequestFilters.status || ''",
		"initialRequestFilters.scan_type || ''",
		"initialRequestFilters.security_db_revision || ''",
		"initialRequestFilters.stale || ''",
		"stats.security_db_rescan_request_counts?.pending",
		"stats.security_db_rescan_request_counts?.claimed",
		"stats.security_db_rescan_request_counts?.degraded",
		"stats.security_db_rescan_request_counts?.failed",
		"stats?.security_db_rescan_progress",
		"rescanProgress.complete_percent",
		"Current DB Rescan Done",
		"rescanProgress.terminal",
		"rescanProgress.open",
		"stats?.security_db_scan_coverage",
		"scanCoverage.coverage_percent",
		"Current DB Scan Coverage",
		"scanCoverage.current_hosts",
		"scanCoverage.stale_hosts",
		"scanCoverage.unknown_hosts",
		"stats.scan_request_stale_counts?.pending",
		"stats.scan_request_stale_counts?.claimed",
		"stats.scan_request_counts?.degraded",
		"effectiveAgentCounts",
		"effectiveInventoryCounts",
		"inventoryCoveragePercent",
		"inventoryFreshPercent",
		"inventoryCoverageColor",
		"SBOM Coverage",
		"stats.inventory_covered_hosts",
		"inventoryFreshPercent",
		"% fresh",
		"stats.inventory_latest_packages",
		"agent_status: 'offline'",
		"agent_status: 'stale'",
		"agent_version_state: 'outdated'",
		"All Agent Versions",
		"Outdated Agent",
		"inventory_status: 'healthy'",
		"inventory_status: 'degraded'",
		"inventory_status: 'stale'",
		"inventory_status: 'empty'",
		"inventory_status: 'none'",
		"params.stale = stale",
		`stale: 'true'`,
		"req.request_age_seconds",
		"req.claim_age_seconds",
		"req.request_stale",
		"req.claim_stale",
		"Claim Age",
		"scan_type: 'security-db-update'",
		"api.requeueScanRequest",
		"api.requeueFilteredScanRequests",
		"Requeue Filtered",
		"Bulk requeue requires Failed, Degraded, or Cancelled status",
		"Set a status, type, or DB revision filter before bulk requeue",
		"canBulkRequeue",
		"confirm(`Requeue ${totalLabel}",
		"disabled={!canBulkRequeue}",
		"Requeue</button>",
		"Current DB Rescan Pending",
		"Current DB Rescan Claimed",
		"Current DB Rescan Degraded",
		"Current DB Rescan Failed",
		"Current DB Rescan Done",
		"Current DB Scan Coverage",
		"Scan Requests Degraded",
		"Stale Pending Requests",
		"Stale Claimed Requests",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard DB rescan count missing %q", want)
		}
	}
}

func TestAuditLogDashboardCoversSecurityStatusesAndActions(t *testing.T) {
	out, err := os.ReadFile("../../../web/src/App.tsx")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`<option value="forbidden">Forbidden</option>`,
		`<option value="error">Error</option>`,
		`<option value="started">Started</option>`,
		`<option value="completed">Completed</option>`,
		`id="audit-actions"`,
		`list="audit-actions"`,
		`value="host.agent_token.reset"`,
		`value="agent.report"`,
		`value="sbom.export"`,
		`value="vulnerability.export"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("audit dashboard filter missing %q", want)
		}
	}
}

func TestRetentionPruneCutoffsAreExposed(t *testing.T) {
	apiOut := readAllPackageGoFiles(t)
	appOut, err := os.ReadFile("../../../web/src/App.tsx")
	if err != nil {
		t.Fatal(err)
	}
	typeOut, err := os.ReadFile("../../../web/src/api.ts")
	if err != nil {
		t.Fatal(err)
	}
	apiBody := string(apiOut)
	appBody := string(appOut)
	typeBody := string(typeOut)
	for _, want := range []string{`"scan_cutoff":`, `"request_cutoff":`, `"audit_cutoff":`} {
		if !strings.Contains(apiBody, want) {
			t.Fatalf("retention prune audit metadata missing %q", want)
		}
	}
	for _, want := range []string{"scan_cutoff: string", "request_cutoff: string", "audit_cutoff: string"} {
		if !strings.Contains(typeBody, want) {
			t.Fatalf("retention prune API type missing %q", want)
		}
	}
	for _, want := range []string{"r.scan_cutoff", "r.request_cutoff", "r.audit_cutoff", "before ${scanCutoff}", "before ${requestCutoff}", "before ${auditCutoff}"} {
		if !strings.Contains(appBody, want) {
			t.Fatalf("retention prune dashboard cutoff display missing %q", want)
		}
	}
}

func TestAuditLogTimeRangeFiltersAreExposed(t *testing.T) {
	apiOut := readAllPackageGoFiles(t)
	apiBody := string(apiOut)
	for _, want := range []string{
		`auditTimeParam(r, "created_from", false)`,
		`auditTimeParam(r, "created_to", true)`,
		`time.Parse(time.RFC3339, raw)`,
		`time.Parse("2006-01-02", raw)`,
		`createdFrom.After(*createdTo)`,
		`http.StatusBadRequest`,
	} {
		if !strings.Contains(apiBody, want) {
			t.Fatalf("audit log API time filtering missing %q", want)
		}
	}

	uiOut, err := os.ReadFile("../../../web/src/App.tsx")
	if err != nil {
		t.Fatal(err)
	}
	uiBody := string(uiOut)
	for _, want := range []string{
		`const [createdFrom, setCreatedFrom] = useState('')`,
		`const [createdTo, setCreatedTo] = useState('')`,
		`params.created_from = from`,
		`params.created_to = to`,
		`aria-label="Audit created from"`,
		`aria-label="Audit created to"`,
	} {
		if !strings.Contains(uiBody, want) {
			t.Fatalf("audit log UI time filtering missing %q", want)
		}
	}

	apiTSOut, err := os.ReadFile("../../../web/src/api.ts")
	if err != nil {
		t.Fatal(err)
	}
	apiTSBody := string(apiTSOut)
	for _, want := range []string{`created_from?: string`, `created_to?: string`} {
		if !strings.Contains(apiTSBody, want) {
			t.Fatalf("audit log API client time filtering missing %q", want)
		}
	}
}

func TestVulnerabilityViewsShowPackageContext(t *testing.T) {
	out, err := os.ReadFile("../../../web/src/App.tsx")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"v.pkg_type || v.ecosystem",
		"Package Type",
		"Asset Type",
		"vuln.pkg_type",
		"Ecosystem",
		"vuln.ecosystem",
		"vuln.image_name",
		"vuln.image_id",
		"vuln.container_id",
		"vuln.target",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("vulnerability UI package context missing %q", want)
		}
	}
}

func TestScanRequestStalenessUsesConfiguredTimeout(t *testing.T) {
	items := []models.ScanRequest{
		{Status: "pending", RequestAgeS: 3601},
		{Status: "claimed", ClaimAgeS: 3601},
		{Status: "failed", RequestAgeS: 7200, ClaimAgeS: 7200},
	}
	annotateScanRequestStaleness(items, 3600)
	if !items[0].RequestStale || items[0].ClaimStale {
		t.Fatalf("pending staleness = %#v", items[0])
	}
	if !items[1].ClaimStale || items[1].RequestStale {
		t.Fatalf("claimed staleness = %#v", items[1])
	}
	if items[2].RequestStale || items[2].ClaimStale {
		t.Fatalf("terminal requests should not be marked stale: %#v", items[2])
	}
}

func TestHostsExposeActiveFindingCounts(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		"ActiveVulnCounts",
		"GetCurrentActionableVulnRiskCountsByHost",
		"GetCurrentActionableOverdueRiskCountsByHost",
		`"active_risk_level_counts"`,
		`"overdue_sla_count"`,
		`"overdue_sla_risk_counts"`,
		`json:"active_vuln_counts"`,
		"GetCurrentActionableVulnCountsByHost",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("host active finding signal missing %q", want)
		}
	}
}

func TestVulnSummaryUsesActiveFindingCounts(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleVulnSummary")
	if start < 0 {
		t.Fatal("handleVulnSummary not found")
	}
	fn := extractFuncBody(body, start)
	if !strings.Contains(fn, "GetCurrentActionableVulnCountsByHost") {
		t.Fatalf("vuln summary host counts must use active findings: %s", fn)
	}
}

func TestDashboardShowsRiskLevelSummary(t *testing.T) {
	appOut, err := os.ReadFile("../../../web/src/App.tsx")
	if err != nil {
		t.Fatal(err)
	}
	apiOut, err := os.ReadFile("../../../web/src/api.ts")
	if err != nil {
		t.Fatal(err)
	}
	cssOut, err := os.ReadFile("../../../web/src/index.css")
	if err != nil {
		t.Fatal(err)
	}
	appBody := string(appOut)
	apiBody := string(apiOut)
	cssBody := string(cssOut)
	for _, want := range []string{
		"active_risk_level_counts",
		"overdue_sla_count",
		"overdue_sla_risk_counts",
		"Critical Risk",
		"High Risk",
		"SLA Overdue",
		"High Risk Overdue",
		"onOpenVulnerabilities({ overdueOnly: true",
		"row.risk?.critical",
		"row.risk?.high",
		"type VulnerabilityFilters",
		"owner?: string",
		"team?: string",
		"environment?: string",
		"criticality?: string",
		"SummaryTable title=\"Owner Remediation Queue\" groupBy=\"owner\"",
		"onOpenVulnerabilities({ [groupBy]: row.group",
		"openRow(row, { riskLevel: 'critical' })",
		"openRow(row, { riskLevel: 'high' })",
		"openRow(row, { overdueOnly: true })",
		"initialFilters?.owner || ''",
		"initialFilters?.team || ''",
		"initialFilters?.environment || ''",
		"initialFilters?.criticality || ''",
		"activeFilters",
		"filter-chip",
		"Clear Filters",
		"clearFilters",
		"Owner: ${owner}",
		"Team: ${team}",
		"Environment: ${environment}",
		"Criticality: ${criticality}",
		"group_by: 'owner'",
		"group_by: 'team'",
		"group_by: 'environment'",
		"group_by: 'criticality'",
		"Owner Remediation Queue",
		"Team Remediation Queue",
		"Environment Risk Queue",
		"Criticality Risk Queue",
	} {
		if !strings.Contains(appBody, want) && !strings.Contains(apiBody, want) {
			t.Fatalf("dashboard risk summary missing %q", want)
		}
	}
	if !strings.Contains(apiBody, "active_risk_level_counts?: Record<string, number>") ||
		!strings.Contains(apiBody, "overdue_sla_count?: number") ||
		!strings.Contains(apiBody, "overdue_sla_risk_counts?: Record<string, number>") ||
		!strings.Contains(apiBody, "risk?: Record<string, number>") {
		t.Fatal("web API types must expose risk-level summary fields")
	}
	for _, want := range []string{".active-filters", ".filter-chip", ".filter-clear", ".filter-clear:hover"} {
		if !strings.Contains(cssBody, want) {
			t.Fatalf("active vulnerability filter styling missing %q", want)
		}
	}
}

func TestStatsAndDashboardShowTriageExceptionLifecycle(t *testing.T) {
	apiOut := readAllPackageGoFiles(t)
	appOut, err := os.ReadFile("../../../web/src/App.tsx")
	if err != nil {
		t.Fatal(err)
	}
	typeOut, err := os.ReadFile("../../../web/src/api.ts")
	if err != nil {
		t.Fatal(err)
	}
	apiBody := string(apiOut)
	appBody := string(appOut)
	typeBody := string(typeOut)
	start := strings.Index(apiBody, "func (s *Server) handleStats")
	if start < 0 {
		t.Fatal("handleStats not found")
	}
	fn := extractFuncBody(apiBody, start)
	for _, want := range []string{
		"CountVulnerabilityTriageByStatus(ctx)",
		"CountVulnerabilityTriageExpiringSoonByStatus(ctx, triageExpiringSoonDays)",
		`resp["triage_active_counts"]`,
		`resp["triage_expired_counts"]`,
		`resp["triage_expiring_soon_counts"]`,
		`resp["triage_expiring_soon_days"]`,
		"s.authenticateAdmin(r) || !s.webAuth",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("stats triage lifecycle missing %q: %s", want, fn)
		}
	}
	for _, want := range []string{
		"Suppressed Findings",
		"Expiring Exceptions",
		"suppressedTriageCount",
		"triageExpiringSoonTotal",
		"triageStatus: 'accepted_risk'",
	} {
		if !strings.Contains(appBody, want) {
			t.Fatalf("dashboard triage lifecycle missing %q", want)
		}
	}
	for _, want := range []string{
		"triage_active_counts?: Record<string, number>",
		"triage_expired_counts?: Record<string, number>",
		"triage_expiring_soon_counts?: Record<string, number>",
		"triage_expiring_soon_days?: number",
	} {
		if !strings.Contains(typeBody, want) {
			t.Fatalf("web stats type missing %q", want)
		}
	}
}

func TestCveJSONLImportUsesSingleTransaction(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) importCveJSONL(")
	if start < 0 {
		t.Fatal("importCveJSONL not found")
	}
	end := strings.Index(body[start:], "func (s *Server) importCveJSONLTx")
	if end < 0 {
		t.Fatal("importCveJSONLTx not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"s.db.BeginTx",
		"replace && source != \"\"",
		"s.db.DeleteCveEntriesBySourceTx",
		"s.importCveJSONLTx",
		"if finalize {",
		"s.db.SyncEPSSPriorityColumnsTx",
		"s.db.RefreshCveAffectedPackagesForSourceTx",
		"s.db.RefreshCveReferenceKeysForSourceTx",
		"errNoValidCveEntries",
		"tx.Commit()",
		"return 0, err",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("cve jsonl import transaction handling missing %q", want)
		}
	}
	if strings.Contains(fn, "UpsertCveEntries(ctx, batch)") {
		t.Fatal("cve jsonl import must not commit each batch outside a single transaction")
	}
	if !strings.Contains(body, "UpsertCveEntriesWithoutAffectedIndexTx") {
		t.Fatal("bulk cve jsonl import must rebuild affected package index after import instead of per row")
	}
}

func TestCveDbPruneStaleSourceEndpointRefreshesDerivedState(t *testing.T) {
	body := readAllPackageGoFiles(t)
	for _, want := range []string{
		`POST /api/admin/cve-db/source/{source}/prune-stale`,
		"func (s *Server) handleCveDbPruneStaleSource",
		"s.db.DeleteCveEntriesBySourceUpdatedBeforeTx",
		`s.SecurityDatabaseUpdated("cve-db stale source prune")`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("stale CVE source prune endpoint missing %q", want)
		}
	}
	fnStart := strings.Index(body, "func (s *Server) handleCveDbPruneStaleSource")
	fnEnd := strings.Index(body[fnStart:], "func (s *Server) importCveJSONL(")
	if fnStart < 0 || fnEnd < 0 {
		t.Fatal("stale CVE source prune endpoint body not found")
	}
	fn := body[fnStart : fnStart+fnEnd]
	for _, forbidden := range []string{
		"RefreshCveAffectedPackagesForSourceTx",
		"RefreshCveReferenceKeysForSourceTx",
		"SyncEPSSPriorityColumnsTx",
	} {
		if strings.Contains(fn, forbidden) {
			t.Fatalf("stale CVE source prune must rely on FK cascade instead of full source rebuild, found %q", forbidden)
		}
	}
}

func TestCveJSONLImportOverridesDirectSource(t *testing.T) {
	seen := []models.CveEntry{}
	input := strings.NewReader(`{"vulnerability_id":"CVE-2026-0001","source":"wrong"}`)
	count, err := (&Server{}).importCveJSONLWithUpsert(context.Background(), input, "OSV", func(ctx context.Context, batch []models.CveEntry) (int, error) {
		seen = append(seen, batch...)
		return len(batch), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || len(seen) != 1 || seen[0].Source != "osv" {
		t.Fatalf("count=%d seen=%#v, want direct source override", count, seen)
	}
}

func TestCveJSONLImportNormalizesEntryIdentity(t *testing.T) {
	seen := []models.CveEntry{}
	input := strings.NewReader(strings.Join([]string{
		`{"id":" row-1 ","vulnerability_id":" CVE-2026-0001 ","source":" OSV ","category":" code-library ","ecosystem":" PyPI ","severity":" moderate ","cvss_vector":" CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H ","title":" title ","description":" desc ","published_date":"2026-01-02T03:04:05.123","modified_date":"2026-01-03"}`,
		`{"vulnerability_id":" cga-2026-0002 ","source":"osv","severity":"high"}`,
		`{"vulnerability_id":" TEMP-0000000-F7A20F ","source":"trivy","severity":"low"}`,
		`{"id":"TEMP-NOTHEX","vulnerability_id":"CVE-2026-0003","source":"osv","severity":"high"}`,
		`{"vulnerability_id":" CVD-0000000-F7A20F ","source":"trivy","severity":"low"}`,
		`{"id":"CVD-NOTHEX","vulnerability_id":"CVE-2026-0004","source":"osv","severity":"high"}`,
	}, "\n"))
	count, err := (&Server{}).importCveJSONLWithUpsert(context.Background(), input, "", func(ctx context.Context, batch []models.CveEntry) (int, error) {
		seen = append(seen, batch...)
		return len(batch), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || len(seen) != 1 {
		t.Fatalf("count=%d seen=%#v, want one non-placeholder entry", count, seen)
	}
	got := seen[0]
	if got.ID != "row-1" ||
		got.VulnerabilityID != "CVE-2026-0001" ||
		got.Source != "osv" ||
		got.Category != "code-library" ||
		got.Ecosystem != "PyPI" ||
		got.Severity != "MODERATE" ||
		got.CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" ||
		got.Title != "title" ||
		got.Description != "desc" ||
		got.PublishedDate == nil ||
		got.PublishedDate.Location() != time.UTC ||
		got.ModifiedDate == nil ||
		got.ModifiedDate.Location() != time.UTC {
		t.Fatalf("normalized entry = %#v", got)
	}
}

func TestTemporaryCvePlaceholder(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{id: "TEMP-0000000-F7A20F", want: true},
		{id: " temp-0841856-b18baf ", want: true},
		{id: "TEMP-", want: false},
		{id: "TEMP-NOTHEX", want: true},
		{id: "CVD-0000000-F7A20F", want: true},
		{id: " cvd-0841856-b18baf ", want: true},
		{id: "CVD-", want: false},
		{id: "CVD-NOTHEX", want: true},
		{id: "CVE-2026-0001", want: false},
	}
	for _, tt := range tests {
		if got := temporaryCvePlaceholder(tt.id); got != tt.want {
			t.Fatalf("temporaryCvePlaceholder(%q)=%v, want %v", tt.id, got, tt.want)
		}
	}
}

func TestFlexibleCveTimeAcceptsNvdTimestamps(t *testing.T) {
	tests := []string{
		`"2023-01-01T01:15:10.057"`,
		`"2023-11-09T05:15:09.047Z"`,
		`"2023-01-01"`,
		`""`,
		`null`,
	}
	for _, input := range tests {
		var ts flexibleCveTime
		if err := json.Unmarshal([]byte(input), &ts); err != nil {
			t.Fatalf("timestamp %s rejected: %v", input, err)
		}
	}
	var ts flexibleCveTime
	if err := json.Unmarshal([]byte(`"bad-time"`), &ts); err == nil {
		t.Fatal("expected invalid timestamp error")
	}
}

func TestNormalizeCveSource(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		fallback string
		want     string
		wantErr  bool
	}{
		{name: "lowercase", source: " OSV ", want: "osv"},
		{name: "slug", source: "nvd-2026.feed", want: "nvd-2026.feed"},
		{name: "fallback", fallback: "custom", want: "custom"},
		{name: "empty", want: ""},
		{name: "space", source: "nvd feed", wantErr: true},
		{name: "slash", source: "../nvd", wantErr: true},
		{name: "too long", source: strings.Repeat("a", 65), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeCveSource(tt.source, tt.fallback)
			if tt.wantErr {
				if !errors.Is(err, errInvalidCveSource) {
					t.Fatalf("err = %v, want invalid source", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tt.want {
				t.Fatalf("source = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCveDbImportAuditsFailures(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleCveDbImport")
	if start < 0 {
		t.Fatal("handleCveDbImport not found")
	}
	end := strings.Index(body[start:], "func (s *Server) importCveJSONL")
	if end < 0 {
		t.Fatal("importCveJSONL not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		`cveImportErrorStatus(err)`,
		`cveImportErrorMessage(err)`,
		`normalizeCveSource(r.FormValue("source"), "custom")`,
		`"cve_db.import", "cve_db", source, "error"`,
		`"reason": "no valid entries"`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("cve db import failure handling missing %q", want)
		}
	}
}

func TestCveDbImportAndExportAuditSecurityDBRevision(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleCveDbImport")
	if start < 0 {
		t.Fatal("handleCveDbImport not found")
	}
	end := strings.Index(body[start:], "func (s *Server) importCveJSONL")
	if end < 0 {
		t.Fatal("importCveJSONL not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"revisionMeta := s.securityDBRevisionMeta(ctx)",
		`"security_db_revision": revisionMeta["security_db_revision"]`,
		`"finalized":            finalize`,
		"if finalize {",
		`s.SecurityDatabaseUpdated("cve-db import")`,
		"for k, v := range revisionMeta",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("cve db import revision metadata missing %q: %s", want, fn)
		}
	}

	start = strings.Index(body, "func (s *Server) handleCveDbExport")
	if start < 0 {
		t.Fatal("handleCveDbExport not found")
	}
	end = strings.Index(body[start:], "func (s *Server) securityDBRevisionMeta")
	if end < 0 {
		t.Fatal("securityDBRevisionMeta not found")
	}
	fn = body[start : start+end]
	for _, want := range []string{
		"revisionMeta := s.securityDBRevisionMeta(r.Context())",
		"for k, v := range revisionMeta",
		`"cve_db.export"`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("cve db export revision metadata missing %q: %s", want, fn)
		}
	}
}

func TestSecurityDBBundleExportStagesCompleteArchiveBeforeResponse(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleSecurityDbExport")
	if start < 0 {
		t.Fatal("handleSecurityDbExport not found")
	}
	end := strings.Index(body[start:], "func (s *Server) handleSecurityDbImport")
	if end < 0 {
		t.Fatal("handleSecurityDbImport not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"s.buildSecurityDBBundleTemp",
		"os.Open(bundleFile)",
		`w.Header().Set("Content-Length"`,
		"io.Copy(w, f)",
		`"bytes":`,
		"gzip.NewWriter(tmp)",
		"tar.NewWriter(gz)",
		"tw.Close()",
		"gz.Close()",
		"os.Stat(path)",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("bundle export staging missing %q: %s", want, fn)
		}
	}
	if strings.Contains(fn, "gzip.NewWriter(w)") {
		t.Fatalf("bundle export must not stream gzip directly to response: %s", fn)
	}
}

func TestCveDbExportStagesCompleteJSONLBeforeResponse(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleCveDbExport")
	if start < 0 {
		t.Fatal("handleCveDbExport not found")
	}
	end := strings.Index(body[start:], "func (s *Server) writeCveJSONLTemp")
	if end < 0 {
		t.Fatal("writeCveJSONLTemp not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		`normalizeCveSource(r.URL.Query().Get("source"), "")`,
		`writeError(w, http.StatusBadRequest, "invalid source")`,
		"s.writeCveJSONLTemp(r.Context(), source)",
		"writeError(w, http.StatusInternalServerError, \"export failed\")",
		"os.Stat(cveFile)",
		"os.Open(cveFile)",
		`w.Header().Set("Content-Length"`,
		`w.Header().Set("X-Bongsu-CVE-Records"`,
		`w.Header().Set("X-Bongsu-SHA256"`,
		`w.Header().Set("X-Bongsu-Security-DB-Revision"`,
		"io.Copy(w, f)",
		`"records": count`,
		`"bytes": info.Size()`,
		`"sha256": cveSHA`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("cve db export staging missing %q: %s", want, fn)
		}
	}
	if strings.Contains(fn, "db.ScanCveEntry(rows, &e)") || strings.Contains(fn, "encoder.Encode(e)") {
		t.Fatal("handleCveDbExport must not stream rows directly before full export validation")
	}
}

func TestWriteCveJSONLTempSupportsSourceFilterAndRowErrors(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) writeCveJSONLTemp")
	if start < 0 {
		t.Fatal("writeCveJSONLTemp not found")
	}
	end := strings.Index(body[start:], "func writeTarBytes")
	if end < 0 {
		t.Fatal("writeTarBytes not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"source string",
		`normalizeCveSource(source, "")`,
		"WHERE source=$1",
		"db.ScanCveEntry(rows, &e)",
		"encoder.Encode(e)",
		"rows.Err()",
		"os.Remove(path)",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("writeCveJSONLTemp robustness missing %q: %s", want, fn)
		}
	}
}

func TestCveDbSearchNormalizesSourceFilter(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleCveDbSearch")
	if start < 0 {
		t.Fatal("handleCveDbSearch not found")
	}
	end := strings.Index(body[start:], "func writeJSON")
	if end < 0 {
		t.Fatal("writeJSON not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		`normalizeCveSource(r.URL.Query().Get("source"), "")`,
		`strings.TrimSpace(r.URL.Query().Get("reference_key"))`,
		`writeError(w, http.StatusBadRequest, "invalid source")`,
		`floatParam(r, "min_cvss", 0)`,
		`floatParam(r, "min_epss", 0)`,
		`floatParam(r, "min_epss_percentile", 0)`,
		`boolQuery(r, "matchable")`,
		`boolQuery(r, "include_priority_sources")`,
		`envInt("BONGSU_CVE_SEARCH_TIMEOUT_SECONDS", 15)`,
		"context.WithTimeout(r.Context()",
		"s.db.SearchCveDatabase(ctx, query, referenceKey, severity, source",
		"minCVSS, minEPSS, minEPSSPercentile, matchableOnly, includePrioritySources",
		`writeError(w, http.StatusGatewayTimeout, "search timeout")`,
		"entries = []models.CveEntry{}",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("CVE search source normalization missing %q: %s", want, fn)
		}
	}
}

func TestCveDbReferenceGroupEndpoint(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		`"GET /api/cve-db/reference-group"`,
		"func (s *Server) handleCveDbReferenceGroup",
		"s.authenticateWeb(r)",
		"s.canReadCveDB(r)",
		`r.URL.Query().Get("key")`,
		`envInt("BONGSU_CVE_REFERENCE_GROUP_TIMEOUT_SECONDS", 10)`,
		"context.WithTimeout(r.Context()",
		"s.db.GetCveReferenceGroupSummary",
		"errors.Is(err, db.ErrInvalidCveReferenceKey)",
		`writeError(w, http.StatusBadRequest, "invalid key")`,
		`writeError(w, http.StatusGatewayTimeout, "reference group timeout")`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("CVE reference group endpoint missing %q", want)
		}
	}
}

func TestCveDbAffectedPackageEvidenceEndpoint(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, want := range []string{
		`"GET /api/cve-db/{id}/affected-packages"`,
		"func (s *Server) handleCveDbAffectedPackages",
		"s.authenticateWeb(r)",
		`r.PathValue("id")`,
		"offsetParam(r)",
		`envInt("BONGSU_CVE_AFFECTED_PACKAGES_TIMEOUT_SECONDS", 10)`,
		"context.WithTimeout(r.Context()",
		"s.db.ListCveAffectedPackages",
		`writeError(w, http.StatusGatewayTimeout, "affected packages timeout")`,
		"items = []db.CveAffectedPackage{}",
		`"items": items`,
		`"offset": offset`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("CVE affected package evidence endpoint missing %q", want)
		}
	}
}

func TestDashboardCveSearchAutoLoadsAndShowsErrors(t *testing.T) {
	out, err := os.ReadFile("../../../web/src/App.tsx")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"useRef",
		"initialSearchStarted",
		"doSearch(0, 'published_date', true)",
		"reference_key",
		"Reference group",
		"setError(err?.message || 'CVE database search failed')",
		"setError(err?.message || 'CVE source list failed')",
		"disabled={loading}",
		"{loading ? 'Searching...' : 'Search'}",
		"isPriorityFeed",
		"includePrioritySources ? 'All Sources' : 'Advisory Sources'",
		"priorityFeed ? 'priority' : 'reference'",
		"matchable_affected_count",
		"matchability_reason",
		"affected",
		"cveDbAffectedPackages",
		"Indexed Match Evidence",
		"Load More",
		"Reference Groups",
		"reference_keys",
		"reference_group_total",
		"reference_group_matchable",
		"reference_group_sources",
		"reference_group_status",
		"reference_group_key",
		"group {entry.reference_group_total}",
		"entry.reference_group_key",
		"group summary unavailable",
		"searchReferenceGroup",
		"Group Context",
		"source_groups",
		"Group Match Evidence",
		"affected_package_total",
		"groupSummary.data.affected_packages",
		"Grouped Evidence",
		"groupSummary.data.items",
		"cveDbReferenceGroup",
		"CveReferenceGroupSummary",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard CVE search auto-load/error UI missing %q", want)
		}
	}
}

func TestCveImportErrorStatusMapsJsonErrors(t *testing.T) {
	if got := cveImportErrorStatus(&json.SyntaxError{}); got != http.StatusBadRequest {
		t.Fatalf("syntax error status = %d, want %d", got, http.StatusBadRequest)
	}
	if got := cveImportErrorStatus(&json.UnmarshalTypeError{}); got != http.StatusBadRequest {
		t.Fatalf("type error status = %d, want %d", got, http.StatusBadRequest)
	}
	if got := cveImportErrorStatus(errors.New("database unavailable")); got != http.StatusInternalServerError {
		t.Fatalf("generic error status = %d, want %d", got, http.StatusInternalServerError)
	}
}

func TestFilterEndpointsApplyRBACScope(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	for _, fnName := range []string{"handleVulnFilters", "handlePackageFilters"} {
		start := strings.Index(body, "func (s *Server) "+fnName)
		if start < 0 {
			t.Fatalf("%s not found", fnName)
		}
		next := strings.Index(body[start+1:], "\nfunc ")
		if next < 0 {
			t.Fatalf("%s body end not found", fnName)
		}
		fn := body[start : start+1+next]
		for _, want := range []string{
			"s.accessScope(r)",
			"scope.Empty()",
			"scopeHostFilter(scope, scope.HostIDs)",
		} {
			if !strings.Contains(fn, want) {
				t.Fatalf("%s must apply RBAC scope, missing %q: %s", fnName, want, fn)
			}
		}
	}
}

func TestInventoryAndScanEndpointsApplyRBACScope(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	tests := []struct {
		name   string
		fnName string
		wants  []string
	}{
		{
			name:   "packages",
			fnName: "handleSearchPackages",
			wants: []string{
				"scope := s.accessScope(r)",
				"scope.Empty()",
				`writeError(w, http.StatusForbidden, "forbidden")`,
				"HostIDs:    scope.HostIDs",
			},
		},
		{
			name:   "containers",
			fnName: "handleSearchContainers",
			wants: []string{
				"scope := s.accessScope(r)",
				"scope.Empty()",
				`writeError(w, http.StatusForbidden, "forbidden")`,
				"HostIDs:    scope.HostIDs",
			},
		},
		{
			name:   "scans",
			fnName: "handleListScans",
			wants: []string{
				"scope := s.accessScope(r)",
				"scope.Empty()",
				`writeError(w, http.StatusForbidden, "forbidden")`,
				"ListScans(ctx, hostID, scope.HostIDs",
			},
		},
		{
			name:   "scan requests",
			fnName: "handleListScanRequests",
			wants: []string{
				"scope := s.accessScope(r)",
				"scope.Empty()",
				`writeError(w, http.StatusForbidden, "forbidden")`,
				"scope.HostIDs",
				"ListScanRequests(",
			},
		},
	}
	for _, tt := range tests {
		start := strings.Index(body, "func (s *Server) "+tt.fnName)
		if start < 0 {
			t.Fatalf("%s handler not found", tt.fnName)
		}
		next := strings.Index(body[start+1:], "\nfunc ")
		if next < 0 {
			t.Fatalf("%s body end not found", tt.fnName)
		}
		fn := body[start : start+1+next]
		for _, want := range tt.wants {
			if !strings.Contains(fn, want) {
				t.Fatalf("%s endpoint must apply RBAC scope, missing %q: %s", tt.name, want, fn)
			}
		}
	}
}

func TestWriteVulnerabilityCSV(t *testing.T) {
	var b strings.Builder
	err := writeVulnerabilityCSV(&b, []models.Vulnerability{{
		HostID:          "host-1",
		HostOwner:       "platform",
		HostTeam:        "security",
		Container:       "api",
		AssetType:       "container",
		ContainerID:     "container-a",
		ImageName:       "registry/app:1.0",
		ImageID:         "sha256:abc",
		Target:          "package-lock.json",
		VulnerabilityID: "CVE-2026-0001",
		Severity:        "HIGH",
		CVSSScore:       8.1,
		TriageStatus:    "accepted_risk",
		TriageExpiresAt: ptrTime(time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)),
		PkgName:         "openssl",
		InstalledVer:    "1.0.0",
		FixedVersion:    "1.0.1",
		FindingSource:   "cve-db",
		AdvisorySources: []string{"osv", "nvd"},
		AdvisoryEvidence: []models.AdvisoryEvidence{{
			Source:       "osv",
			Ecosystem:    "Packagist",
			FixedVersion: "1.0.1",
			CVSSScore:    8.1,
			EPSSScore:    0.12345,
		}},
		RiskScore: 72.3,
		RiskLevel: "high",
		Title:     "csv title",
		CreatedAt: time.Date(2026, 5, 31, 0, 0, 0, 0, time.UTC),
	}})
	if err != nil {
		t.Fatalf("write csv: %v", err)
	}
	out := b.String()
	if !strings.Contains(out, "vulnerability_id") {
		t.Fatal("missing csv header")
	}
	if !strings.Contains(out, "triage_expires_at") || !strings.Contains(out, "2026-06-30T00:00:00Z") {
		t.Fatalf("missing triage expiry: %s", out)
	}
	if !strings.Contains(out, "finding_source") || !strings.Contains(out, "cve-db") {
		t.Fatalf("missing finding source: %s", out)
	}
	if !strings.Contains(out, "advisory_sources") || !strings.Contains(out, "osv;nvd") {
		t.Fatalf("missing advisory sources: %s", out)
	}
	if !strings.Contains(out, "advisory_evidence") || !strings.Contains(out, "osv|eco=Packagist|fixed=1.0.1|cvss=8.1|epss=0.12345") {
		t.Fatalf("missing advisory evidence: %s", out)
	}
	if !strings.Contains(out, "risk_level") || !strings.Contains(out, "high") || !strings.Contains(out, "72.3") {
		t.Fatalf("missing risk fields: %s", out)
	}
	for _, want := range []string{"asset_type", "container_id", "image_name", "image_id", "target", "registry/app:1.0", "package-lock.json"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing package placement %q: %s", want, out)
		}
	}
	if !strings.Contains(out, "CVE-2026-0001") || !strings.Contains(out, "accepted_risk") || !strings.Contains(out, "platform") {
		t.Fatalf("missing csv values: %s", out)
	}
}

func TestWriteVulnerabilityCSVEscapesFormulaCells(t *testing.T) {
	var b strings.Builder
	err := writeVulnerabilityCSV(&b, []models.Vulnerability{{
		HostID:          "host-1",
		HostOwner:       "=cmd|' /C calc'!A0",
		HostTeam:        " +SUM(1,1)",
		Container:       "@container",
		ContainerID:     "=container-id",
		ImageName:       "+image",
		ImageID:         "-image-id",
		Target:          "@target",
		VulnerabilityID: "CVE-2026-0001",
		Severity:        "HIGH",
		CVSSScore:       8.1,
		PkgName:         "-danger",
		InstalledVer:    "=1+1",
		FixedVersion:    "+2.0.0",
		Title:           "@title",
		CreatedAt:       time.Date(2026, 5, 31, 0, 0, 0, 0, time.UTC),
	}})
	if err != nil {
		t.Fatalf("write csv: %v", err)
	}
	rows, err := csv.NewReader(strings.NewReader(b.String())).ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	header := map[string]int{}
	for i, name := range rows[0] {
		header[name] = i
	}
	for _, col := range []string{"host_owner", "host_team", "container", "container_id", "image_name", "image_id", "target", "pkg_name", "installed_version", "fixed_version", "title"} {
		got := rows[1][header[col]]
		if !strings.HasPrefix(got, "'") {
			t.Fatalf("%s = %q, want formula-safe leading quote", col, got)
		}
	}
}

func ptrTime(t time.Time) *time.Time {
	return &t
}

func TestLoginHandlerUsesBcryptForPasswordVerification(t *testing.T) {
	out := readAllPackageGoFiles(t)
	body := out
	start := strings.Index(body, "func (s *Server) handleLogin")
	if start < 0 {
		t.Fatal("handleLogin not found")
	}
	end := strings.Index(body[start:], "func (s *Server) handleLogout")
	if end < 0 {
		t.Fatal("handleLogout not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		`bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))`,
		`"invalid credentials"`,
		`"username and password are required"`,
		`"auth.login"`,
		`"denied"`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("login handler missing %q: %s", want, fn)
		}
	}
}

func TestSessionTokenIs256BitRandom(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		`sessionTokenBytes = 32`,
		`rand.Read(raw)`,
		`hex.EncodeToString(raw)`,
		`sha256.Sum256([]byte(token))`,
		`hex.EncodeToString(h[:])`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("session token generation missing %q", want)
		}
	}
}

func TestExpiredSessionsAreCleanedUp(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		"DeleteExpiredSessions",
		`time.Sleep(time.Hour)`,
		"startSessionCleanup",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("session cleanup missing %q", want)
		}
	}
}

func TestInitialAdminUserCreatedFromEnvVars(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		`BONGSU_ADMIN_USERNAME`,
		`BONGSU_ADMIN_PASSWORD`,
		`CountLocalUsers(ctx)`,
		`CreateLocalUser(ctx, adminUser, string(hash), "admin")`,
		`bcrypt.GenerateFromPassword([]byte(adminPass), bcrypt.DefaultCost)`,
		`bootstrapAdmin()`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("admin bootstrap missing %q", want)
		}
	}
}

func TestSessionCookieIsHttpOnly(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		`HttpOnly: true`,
		`SameSite: http.SameSiteLaxMode`,
		`bongsu_session`,
		`MaxAge:   int(maxAge.Seconds())`,
		`Secure:   secureRequest(r)`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("session cookie security missing %q", want)
		}
	}
}

func TestAuthenticateWebIncludesSessionCheck(t *testing.T) {
	out := readAllPackageGoFiles(t)
	start := strings.Index(out, "func (s *Server) authenticateWeb")
	if start < 0 {
		t.Fatal("authenticateWeb not found")
	}
	end := strings.Index(out[start:], "\nfunc ")
	if end < 0 {
		t.Fatal("authenticateWeb end not found")
	}
	fn := out[start : start+end]
	if !strings.Contains(fn, "authenticateSession(r)") {
		t.Fatalf("authenticateWeb must check session: %s", fn)
	}
}

func TestSessionMaxAgeIsConfigurable(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		`BONGSU_SESSION_MAX_AGE_HOURS`,
		`sessionMaxAge`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("session max age config missing %q", want)
		}
	}
}

func TestAuthRoutesAreRegistered(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		`"POST /api/auth/login"`,
		`"POST /api/auth/logout"`,
		`"GET /api/auth/me"`,
		`"POST /api/auth/change-password"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("auth route missing %q", want)
		}
	}
}

func TestChangePasswordRequiresCurrentPassword(t *testing.T) {
	out := readAllPackageGoFiles(t)
	start := strings.Index(out, "func (s *Server) handleChangePassword")
	if start < 0 {
		t.Fatal("handleChangePassword not found")
	}
	end := strings.Index(out[start:], "func (s *Server) sessionFromRequest")
	if end < 0 {
		t.Fatal("handleChangePassword end not found")
	}
	fn := out[start : start+end]
	for _, want := range []string{
		`sessionFromRequest(r)`,
		`"not authenticated"`,
		`"current_password and new_password are required"`,
		`len(req.NewPassword) < changeMinLen`,
		`envBool("BONGSU_ALLOW_WEAK_SECRETS", false)`,
		`bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword))`,
		`bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)`,
		`UpdateLocalUserPassword(ctx, user.ID, string(newHash))`,
		`"auth.change_password"`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("change password handler missing %q: %s", want, fn)
		}
	}
}

func TestAuthenticatorInterfaceExists(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		"type Authenticator interface",
		"Authenticate(ctx context.Context, username, password string) (*AuthResult, error)",
		"type LocalAuthenticator struct",
		"type OIDCAuthenticator struct",
		"OIDC authentication not configured",
		"BONGSU_OIDC_ISSUER",
		"initAuthenticator()",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("authenticator interface missing %q", want)
		}
	}
}
