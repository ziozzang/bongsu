package api

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

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
}

func TestViewerKeys(t *testing.T) {
	keys := parseViewerKeys("viewer-key:alice, team-key:devops, malformed")
	if keys["viewer-key"] != "alice" {
		t.Fatalf("viewer-key subject = %q", keys["viewer-key"])
	}
	if keys["team-key"] != "devops" {
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
	t.Setenv("BONGSU_CVE_MATCH_SOURCES", "osv, nvd,osv, ")
	t.Setenv("BONGSU_CVE_MATCH_MIN_SOURCE_MATCHABLE_PERCENT", "175.5")

	opts := rematchOptionsFromEnv()
	if len(opts.Sources) != 2 || opts.Sources[0] != "osv" || opts.Sources[1] != "nvd" {
		t.Fatalf("sources = %#v", opts.Sources)
	}
	if opts.MinSourceMatchablePercent != 100 {
		t.Fatalf("min quality = %.1f", opts.MinSourceMatchablePercent)
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
		`http.Error(w, err.Error(), http.StatusBadRequest)`,
		`uuid.Parse(report.ScanID)`,
		`"invalid scan_type"`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("report normalization missing %q: %s", want, fn)
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

func TestStaticInstallScriptUsesHeaderAuthenticatedDownloads(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/install-agent.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`printf 'header = "X-Install-Token: %s"\n' "$INSTALL_TOKEN" > "$curl_config"`,
		`curl -fsSL --config "$curl_config" "$url" -o "$output"`,
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
	payload := reportWebhookPayload(report, "degraded", "degraded", 3, 2, 5, map[string]int{"HIGH": 1}, []string{"packages: failed"})
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
		"CompleteClaimedScanRequest",
		`"host_id": body.HostID`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("scan request completion ownership check missing %q: %s", want, fn)
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
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("stats active finding signal missing %q", want)
		}
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
		"s.importCveJSONLTx",
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
		`"cve_db.import", "cve_db", source, "error"`,
		`"reason": "no valid entries"`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("cve db import failure handling missing %q", want)
		}
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
	if !strings.Contains(out, "CVE-2026-0001") || !strings.Contains(out, "accepted_risk") || !strings.Contains(out, "platform") {
		t.Fatalf("missing csv values: %s", out)
	}
}

func ptrTime(t time.Time) *time.Time {
	return &t
}
