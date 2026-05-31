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

	req = httptest.NewRequest("GET", "/api/install.sh?token=install-token", nil)
	if !s.authenticateInstall(req) {
		t.Fatal("install token should authenticate installer")
	}

	req = httptest.NewRequest("GET", "/api/install.sh?api_key=admin-key", nil)
	if s.authenticateInstall(req) {
		t.Fatal("api_key query parameter must not authenticate installer")
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
	req = httptest.NewRequest("GET", "/api/install.sh?token=install-token", nil)
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

func TestAdminMetricsExposeActiveRiskLevelBacklog(t *testing.T) {
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
		`map[string]string{"risk_level": riskLevel}`,
		`[]string{"critical", "high", "medium", "low"}`,
		"bongsu_active_vulnerability_risk_metrics_error",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("admin metrics risk backlog missing %q: %s", want, fn)
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"maxTrivyDBUploadBytes()",
		"maxCveDBImportBytes()",
		"maxSecurityDBBundleBytes()",
		`envBytes("BONGSU_TRIVY_DB_UPLOAD_MAX_BYTES", 2<<30)`,
		`envBytes("BONGSU_CVE_DB_IMPORT_MAX_BYTES", 2<<30)`,
		`envBytes("BONGSU_SECURITY_DB_BUNDLE_MAX_BYTES", 4<<30)`,
		`envBytes("BONGSU_MULTIPART_MEMORY_MAX_BYTES", 32<<20)`,
		"ParseMultipartForm(maxMultipartMemoryBytes())",
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

	for _, tt := range []struct {
		key  string
		def  int64
		call func() int64
	}{
		{"BONGSU_TRIVY_DB_UPLOAD_MAX_BYTES", 2 << 30, maxTrivyDBUploadBytes},
		{"BONGSU_CVE_DB_IMPORT_MAX_BYTES", 2 << 30, maxCveDBImportBytes},
		{"BONGSU_SECURITY_DB_BUNDLE_MAX_BYTES", 4 << 30, maxSecurityDBBundleBytes},
		{"BONGSU_MULTIPART_MEMORY_MAX_BYTES", 32 << 20, maxMultipartMemoryBytes},
	} {
		for _, value := range []string{"0", "-1", "invalid"} {
			t.Setenv(tt.key, value)
			if got := tt.call(); got != tt.def {
				t.Fatalf("%s=%q got %d, want %d", tt.key, value, got, tt.def)
			}
		}
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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

func TestSecurityDBBundleManifestCarriesRevision(t *testing.T) {
	manifest := securityDBBundleManifest{SecurityDBRevision: "rev-123"}
	if manifest.SecurityDBRevision != "rev-123" {
		t.Fatalf("manifest revision = %q", manifest.SecurityDBRevision)
	}

	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"s.db.BeginTx",
		"s.db.DeleteAllCveEntriesTx",
		"s.importCveJSONLTx",
		"tx.Rollback()",
		"tx.Commit()",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("bundle import must use one CVE transaction, missing %q", want)
		}
	}
}

func TestSecurityDBBundleImportValidatesTrivyBeforeCommitAndLoadsAfter(t *testing.T) {
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"umask 077",
		"AGENT_TOKEN=",
		"generate_agent_token()",
		`agent_token: ${AGENT_TOKEN}`,
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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

func TestShellQuoteEscapesInstallerCredentials(t *testing.T) {
	got := shellQuote(`agent'key"$HOME`)
	want := `'agent'"'"'key"$HOME'`
	if got != want {
		t.Fatalf("shellQuote = %q, want %q", got, want)
	}
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"shellQuote(serverURL)",
		"shellQuote(apiKey)",
		"shellQuote(s.installToken)",
		`w.Header().Set("Cache-Control", "no-store")`,
		`printf 'header = "X-Install-Token: %%s"\n' "$INSTALL_TOKEN" > "$curl_config"`,
		`curl_download "$SERVER/api/downloads/bongsu-agent" "$WORK_DIR/bin/bongsu-agent"`,
		`curl_download "$SERVER/api/downloads/trivy" "$WORK_DIR/bin/trivy"`,
		`rm -f "$WORK_DIR/bin/bongsu-agent"`,
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

func TestHandleReportNormalizesScannerInput(t *testing.T) {
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
		`http.Error(w, err.Error(), http.StatusBadRequest)`,
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
		"RemoveStaleRematchedVulnerabilities",
		`"stale_rematch_removed"`,
		"s.queueSecurityDBRescans(reason, status)",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("post-recalculation rescan queueing missing %q: %s", want, fn)
		}
	}
	if strings.LastIndex(fn, `s.auditSystem("security_db.recalculation"`) > strings.Index(fn, "s.queueSecurityDBRescans(reason, status)") {
		t.Fatalf("rescan queueing must happen after recalculation audit: %s", fn)
	}
}

func TestSecurityDBUpdateSurfacesTriggerBackgroundRecalculation(t *testing.T) {
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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

func TestWebhookAuditIncludesSecurityDBRevision(t *testing.T) {
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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

func TestRBACPolicyAPIAllowsExportPermission(t *testing.T) {
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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

func TestHealthOnlyShowsDetailedDBStatusToAdmins(t *testing.T) {
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
		"s.dbMgr.Status()",
		"s.dbMgr.PublicStatus()",
		"s.secMgr.Status()",
		"s.secMgr.PublicStatus()",
		`"security_recalculation": s.securityRecalculationStatus(isAdmin)`,
		"for k, v := range s.securityDBRevisionMeta(r.Context())",
		`k == "security_db_revision" || isAdmin`,
		`s.securityDBFreshnessStatus(r.Context(), isAdmin)`,
		`resp["security_db_freshness"] = freshness`,
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

func TestVulnerabilityAPIExposesExploitedFilterAndExportColumn(t *testing.T) {
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
	} {
		if !strings.Contains(appBody, want) {
			t.Fatalf("dashboard KEV prioritization missing %q", want)
		}
	}
	if !strings.Contains(apiBody, "exploited: boolean") || !strings.Contains(apiBody, "exploited?: string") ||
		!strings.Contains(apiBody, "epss_score?: number") || !strings.Contains(apiBody, "risk_score?: number") ||
		!strings.Contains(apiBody, "risk_level?: string") || !strings.Contains(apiBody, "min_epss?: string") {
		t.Fatal("web API types must expose exploited and EPSS vulnerability fields and filters")
	}
}

func TestSecurityDBFreshnessHealthAndMetricsAreExposed(t *testing.T) {
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`BONGSU_SECURITY_DB_MAX_SOURCE_AGE_HOURS`,
		`defaultSecurityDBMaxSourceAgeHours`,
		`GetCveSourceStats(ctx)`,
		`resp["status"] = "stale"`,
		`"oldest_source"`,
		`"stale_sources"`,
		`bongsu_security_db_source_stale`,
		`bongsu_security_db_source_count`,
		`bongsu_security_db_source_oldest_age_seconds`,
		`bongsu_security_db_source_matchable_percent`,
		`bongsu_security_db_source_quality_metrics_error`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("security DB freshness support missing %q", want)
		}
	}
}

func TestAdminMetricsExposeCveSourceQuality(t *testing.T) {
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
		"bongsu_security_db_source_quality_metrics_error",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("admin metrics source quality missing %q: %s", want, fn)
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
	} {
		if !strings.Contains(appBody, want) {
			t.Fatalf("dashboard source quality gate missing %q", want)
		}
	}
	if !strings.Contains(apiBody, "matchable_percent") {
		t.Fatal("CVE source stat API type must include matchable_percent")
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

func TestSecurityDBSyncScriptImportsNvdOnceAfterCombiningYears(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/sync-all-cvedb.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`NVD_ALL_FILE="${TMPDIR}/nvd-all.jsonl"`,
		`NVD_FAILED=0`,
		`cat "${NVD_FILE}" >> "${NVD_ALL_FILE}"`,
		`import_cve_file "${NVD_ALL_FILE}" "nvd"`,
		`incomplete NVD download; preserving existing nvd source`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("sync-all-cvedb must combine NVD years before import, missing %q", want)
		}
	}
	if strings.Contains(body, `import_cve_file "${NVD_FILE}" "nvd"`) {
		t.Fatal("sync-all-cvedb must not replace the nvd source once per year")
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
}

func TestSecurityDBSyncScriptFailsOnMissingRequiredTrivySource(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/sync-all-cvedb.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`REQUIRE_TRIVY_SOURCE="${BONGSU_SYNC_REQUIRE_TRIVY_SOURCE:-true}"`,
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

func TestTrivyCveExtractionUsesConfiguredCacheDir(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/extract-trivy-cvedb.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-${BONGSU_TRIVY_CACHE_DIR:-}}"`,
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
				"BONGSU_HTTP_WRITE_TIMEOUT_SECONDS: ${BONGSU_HTTP_WRITE_TIMEOUT_SECONDS:-120}",
				"BONGSU_HTTP_IDLE_TIMEOUT_SECONDS: ${BONGSU_HTTP_IDLE_TIMEOUT_SECONDS:-120}",
				"BONGSU_HTTP_MAX_HEADER_BYTES: ${BONGSU_HTTP_MAX_HEADER_BYTES:-1048576}",
				"BONGSU_SECURITY_DB_SYNC_OUTPUT_MAX_BYTES: ${BONGSU_SECURITY_DB_SYNC_OUTPUT_MAX_BYTES:-8192}",
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
		"BONGSU_SECURITY_DB_SYNC_CMD: ${BONGSU_SECURITY_DB_SYNC_CMD:-/app/scripts/sync-all-cvedb.sh http://localhost:8080}",
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
		"BONGSU_TRIVY_DB_INTERVAL_HOURS=6",
		"BONGSU_SECURITY_DB_SYNC_CMD=/app/scripts/sync-all-cvedb.sh http://localhost:8080",
		"BONGSU_SECURITY_DB_SYNC_ON_START=true",
		"BONGSU_SYNC_REQUIRE_TRIVY_SOURCE=true",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("example deployment auto-update default missing %q", want)
		}
	}
}

func TestInstallerAndBinaryDownloadsAreAudited(t *testing.T) {
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
		`http.Error(w, "host not found", http.StatusNotFound)`,
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
		`http.Error(w, "host_id is required when pkg_name is set", http.StatusBadRequest)`,
		`s.db.GetHost(r.Context(), body.HostID)`,
		`http.Error(w, "host not found", http.StatusNotFound)`,
		`triageStatusRequiresReason(body.Status) && body.Reason == ""`,
		`http.Error(w, "reason is required for "+body.Status, http.StatusBadRequest)`,
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
		`strings.TrimSpace(r.URL.Query().Get("scan_type"))`,
		`http.Error(w, "invalid scan_type", http.StatusBadRequest)`,
		`strings.TrimSpace(r.URL.Query().Get("security_db_revision"))`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("scan request API filter missing %q: %s", want, fn)
		}
	}
}

func TestCreateScanRequestValidatesTargetHost(t *testing.T) {
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
		`http.Error(w, "host not found", http.StatusNotFound)`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("create scan request host validation missing %q: %s", want, fn)
		}
	}
}

func TestAgentScanRequestCompletionRequiresClaimedHost(t *testing.T) {
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
		"verifyAgentHostBinding",
		"CompleteClaimedScanRequest",
		"scanRequestAuditMeta(req, body.Message, body.HostID)",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("scan request completion ownership check missing %q: %s", want, fn)
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"GetCurrentActionableVulnCountsByHost",
		"active_vulnerabilities",
		"active_severity_counts",
		"GetSecurityDBRevision(ctx)",
		"CountSecurityDBRescanRequestsByStatus",
		"security_db_revision",
		"security_db_rescan_request_counts",
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
		"openCurrentDBRescans",
		"setScanRequestFilters(filters)",
		"initialRequestFilters={scanRequestFilters}",
		"initialRequestFilters.status || ''",
		"initialRequestFilters.scan_type || ''",
		"initialRequestFilters.security_db_revision || ''",
		"stats.security_db_rescan_request_counts?.pending",
		"stats.security_db_rescan_request_counts?.claimed",
		"stats.security_db_rescan_request_counts?.degraded",
		"stats.security_db_rescan_request_counts?.failed",
		"stats.scan_request_counts?.degraded",
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
		"Scan Requests Degraded",
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

func TestAuditLogTimeRangeFiltersAreExposed(t *testing.T) {
	apiOut, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
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
		"vuln.pkg_type",
		"Ecosystem",
		"vuln.ecosystem",
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"ActiveVulnCounts",
		"GetCurrentActionableVulnRiskCountsByHost",
		`"active_risk_level_counts"`,
		`json:"active_vuln_counts"`,
		"GetCurrentActionableVulnCountsByHost",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("host active finding signal missing %q", want)
		}
	}
}

func TestVulnSummaryUsesActiveFindingCounts(t *testing.T) {
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (s *Server) handleVulnSummary")
	if start < 0 {
		t.Fatal("handleVulnSummary not found")
	}
	end := strings.Index(body[start:], "func (s *Server) handleStats")
	if end < 0 {
		t.Fatal("handleStats not found")
	}
	fn := body[start : start+end]
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
	appBody := string(appOut)
	apiBody := string(apiOut)
	for _, want := range []string{
		"active_risk_level_counts",
		"Critical Risk",
		"High Risk",
		"row.risk?.critical",
		"row.risk?.high",
	} {
		if !strings.Contains(appBody, want) && !strings.Contains(apiBody, want) {
			t.Fatalf("dashboard risk summary missing %q", want)
		}
	}
	if !strings.Contains(apiBody, "active_risk_level_counts?: Record<string, number>") ||
		!strings.Contains(apiBody, "risk?: Record<string, number>") {
		t.Fatal("web API types must expose risk-level summary fields")
	}
}

func TestCveJSONLImportUsesSingleTransaction(t *testing.T) {
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
		"s.db.DeleteCveEntriesBySourceTx",
		"s.importCveJSONLTx",
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
		`http.Error(w, "invalid source", http.StatusBadRequest)`,
		"s.writeCveJSONLTemp(r.Context(), source)",
		"http.Error(w, \"export failed\", http.StatusInternalServerError)",
		"os.Open(cveFile)",
		"io.Copy(w, f)",
		`"records": count`,
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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
		`http.Error(w, "invalid source", http.StatusBadRequest)`,
		"s.db.SearchCveDatabase(ctx, query, severity, source",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("CVE search source normalization missing %q: %s", want, fn)
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
	out, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
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

func TestWriteVulnerabilityCSV(t *testing.T) {
	var b strings.Builder
	err := writeVulnerabilityCSV(&b, []models.Vulnerability{{
		HostID:          "host-1",
		HostOwner:       "platform",
		HostTeam:        "security",
		Container:       "api",
		VulnerabilityID: "CVE-2026-0001",
		Severity:        "HIGH",
		CVSSScore:       8.1,
		TriageStatus:    "accepted_risk",
		TriageExpiresAt: ptrTime(time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)),
		PkgName:         "openssl",
		InstalledVer:    "1.0.0",
		FixedVersion:    "1.0.1",
		FindingSource:   "cve-db",
		RiskScore:       72.3,
		RiskLevel:       "high",
		Title:           "csv title",
		CreatedAt:       time.Date(2026, 5, 31, 0, 0, 0, 0, time.UTC),
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
	if !strings.Contains(out, "risk_level") || !strings.Contains(out, "high") || !strings.Contains(out, "72.3") {
		t.Fatalf("missing risk fields: %s", out)
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
	for _, col := range []string{"host_owner", "host_team", "container", "pkg_name", "installed_version", "fixed_version", "title"} {
		got := rows[1][header[col]]
		if !strings.HasPrefix(got, "'") {
			t.Fatalf("%s = %q, want formula-safe leading quote", col, got)
		}
	}
}

func ptrTime(t time.Time) *time.Time {
	return &t
}
