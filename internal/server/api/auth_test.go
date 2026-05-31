package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/server/db"
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
		"shellQuote(tokenQuery)",
		"url.QueryEscape(s.installToken)",
		`w.Header().Set("Cache-Control", "no-store")`,
		`curl -fsSL "$SERVER/api/downloads/bongsu-agent$INSTALL_TOKEN_QUERY"`,
		`rm -f "$WORK_DIR/bin/bongsu-agent"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("installer credential rendering missing %q", want)
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

func TestDashboardInstallSnippetIncludesInstallToken(t *testing.T) {
	out, err := os.ReadFile("../../../web/src/App.tsx")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	if !strings.Contains(body, `api/install.sh?token=$BONGSU_INSTALL_TOKEN`) {
		t.Fatal("dashboard install snippet must include BONGSU_INSTALL_TOKEN placeholder")
	}
	if strings.Contains(body, `api/install.sh | sudo bash`) {
		t.Fatal("dashboard install snippet must not show unauthenticated installer URL")
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
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("installer audit missing %q", want)
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
