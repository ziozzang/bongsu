package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/ziozzang/bongsu/internal/server/cvematch"
	"github.com/ziozzang/bongsu/internal/server/db"
	"github.com/ziozzang/bongsu/internal/server/secdb"
	"github.com/ziozzang/bongsu/internal/server/trivydb"
	"github.com/ziozzang/bongsu/internal/shared/models"
)

type Server struct {
	db           *db.DB
	apiKey       string
	agentKey     string
	installToken string
	viewerKeys   map[string]string
	webAuth      bool
	corsOrigins  map[string]bool
	corsAllowAll bool
	mux          *http.ServeMux
	matcher      *cvematch.Matcher
	dbMgr        *trivydb.Manager
	secMgr       *secdb.Manager
	notifier     *webhookNotifier

	securityRecalcMu      sync.Mutex
	securityRecalcRunning bool
	securityRecalcPending bool
	securityRecalcReason  string
}

const (
	maxReportErrors                    = 32
	maxReportErrorBytes                = 2048
	defaultSecurityDBMaxSourceAgeHours = 30
)

func New(database *db.DB, matcher *cvematch.Matcher, dbMgr *trivydb.Manager, secMgr *secdb.Manager) *Server {
	apiKey := os.Getenv("BONGSU_API_KEY")
	if apiKey == "" {
		apiKey = uuid.New().String()
		log.Printf("WARNING: Generated random API key. Set BONGSU_API_KEY env var for persistence.")
	}
	agentKey := os.Getenv("BONGSU_AGENT_API_KEY")
	if agentKey == "" {
		agentKey = apiKey
		log.Printf("WARNING: BONGSU_AGENT_API_KEY is not set; agents will share the admin API key.")
	}

	s := &Server{
		db:           database,
		apiKey:       apiKey,
		agentKey:     agentKey,
		installToken: os.Getenv("BONGSU_INSTALL_TOKEN"),
		viewerKeys:   parseViewerKeys(os.Getenv("BONGSU_VIEWER_API_KEYS")),
		webAuth:      os.Getenv("BONGSU_WEB_AUTH") != "false",
		corsOrigins:  parseAllowedOrigins(os.Getenv("BONGSU_CORS_ALLOWED_ORIGINS")),
		corsAllowAll: allowsAllOrigins(os.Getenv("BONGSU_CORS_ALLOWED_ORIGINS")),
		mux:          http.NewServeMux(),
		matcher:      matcher,
		dbMgr:        dbMgr,
		secMgr:       secMgr,
		notifier:     newWebhookNotifierFromEnv(),
	}
	if s.notifier != nil {
		s.notifier.onResult = s.auditWebhookResult
	}
	s.routes()
	return s
}

func parseAllowedOrigins(raw string) map[string]bool {
	out := map[string]bool{}
	for _, origin := range cleanCSV(strings.Split(raw, ",")) {
		if origin == "*" {
			continue
		}
		out[origin] = true
	}
	return out
}

func allowsAllOrigins(raw string) bool {
	for _, origin := range cleanCSV(strings.Split(raw, ",")) {
		if origin == "*" {
			return true
		}
	}
	return false
}

func parseViewerKeys(raw string) map[string]string {
	out := map[string]string{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			continue
		}
		out[parts[0]] = parts[1]
	}
	return out
}

func (s *Server) Handler() http.Handler {
	var h http.Handler = s.mux
	h = s.recoverMiddleware(h)
	h = s.corsMiddleware(h)
	h = s.securityHeadersMiddleware(h)
	h = s.requestIDMiddleware(h)
	h = s.accessLogMiddleware(h)
	return h
}

func (s *Server) APIKey() string {
	return s.apiKey
}

func (s *Server) routes() {
	s.mux.HandleFunc("POST /api/report", s.handleReport)
	s.mux.HandleFunc("GET /api/hosts", s.handleListHosts)
	s.mux.HandleFunc("GET /api/hosts/{id}", s.handleGetHost)
	s.mux.HandleFunc("POST /api/hosts/{id}/metadata", s.handleUpdateHostMetadata)
	s.mux.HandleFunc("POST /api/hosts/{id}/agent-token/reset", s.handleResetHostAgentToken)
	s.mux.HandleFunc("GET /api/hosts/{id}/packages", s.handleHostPackages)
	s.mux.HandleFunc("GET /api/hosts/{id}/sbom", s.handleHostSBOM)
	s.mux.HandleFunc("GET /api/hosts/{id}/vuln-counts", s.handleHostVulnCounts)
	s.mux.HandleFunc("GET /api/vulnerabilities", s.handleListVulnerabilities)
	s.mux.HandleFunc("GET /api/vulnerabilities/export", s.handleExportVulnerabilities)
	s.mux.HandleFunc("GET /api/vulnerabilities/filters", s.handleVulnFilters)
	s.mux.HandleFunc("POST /api/vulnerabilities/triage", s.handleUpsertVulnerabilityTriage)
	s.mux.HandleFunc("GET /api/cve-search", s.handleCveSearch)
	s.mux.HandleFunc("GET /api/vuln-summary", s.handleVulnSummary)
	s.mux.HandleFunc("GET /api/packages", s.handleSearchPackages)
	s.mux.HandleFunc("GET /api/packages/filters", s.handlePackageFilters)
	s.mux.HandleFunc("GET /api/packages/{id}/vulnerabilities", s.handlePackageVulns)
	s.mux.HandleFunc("GET /api/containers", s.handleSearchContainers)
	s.mux.HandleFunc("GET /api/scans", s.handleListScans)
	s.mux.HandleFunc("GET /api/scan-requests", s.handleListScanRequests)
	s.mux.HandleFunc("POST /api/scan-requests", s.handleCreateScanRequest)
	s.mux.HandleFunc("POST /api/scan-requests/{id}/cancel", s.handleCancelScanRequest)
	s.mux.HandleFunc("POST /api/scan-requests/{id}/requeue", s.handleRequeueScanRequest)
	s.mux.HandleFunc("POST /api/scan-requests/requeue-stale", s.handleRequeueStaleScanRequests)
	s.mux.HandleFunc("POST /api/scan-requests/requeue-filtered", s.handleRequeueFilteredScanRequests)
	s.mux.HandleFunc("POST /api/agent/scan-requests/claim", s.handleClaimScanRequest)
	s.mux.HandleFunc("POST /api/agent/scan-requests/{id}/complete", s.handleCompleteScanRequest)
	s.mux.HandleFunc("GET /api/install.sh", s.handleInstallScript)
	s.mux.HandleFunc("GET /api/downloads/bongsu-agent", s.handleAgentDownload)
	s.mux.HandleFunc("GET /api/downloads/trivy", s.handleTrivyDownload)
	s.mux.HandleFunc("GET /api/stats", s.handleStats)
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("DELETE /api/scans/{id}", s.handleDeleteScan)
	s.mux.HandleFunc("POST /api/admin/trivy-db", s.handleTrivyDBUpload)
	s.mux.HandleFunc("POST /api/admin/trivy-db/update", s.handleTrivyDBUpdate)
	s.mux.HandleFunc("POST /api/admin/cve-db/import", s.handleCveDbImport)
	s.mux.HandleFunc("GET /api/admin/security-db/export", s.handleSecurityDbExport)
	s.mux.HandleFunc("POST /api/admin/security-db/import", s.handleSecurityDbImport)
	s.mux.HandleFunc("POST /api/admin/security-db/update", s.handleSecurityDbUpdate)
	s.mux.HandleFunc("POST /api/admin/cve-db/rematch", s.handleCveDbRematch)
	s.mux.HandleFunc("POST /api/admin/cve-db/recalc-cvss", s.handleCveDbRecalcCVSS)
	s.mux.HandleFunc("GET /api/admin/cve-db/export", s.handleCveDbExport)
	s.mux.HandleFunc("GET /api/admin/cve-db/sources", s.handleCveDbSources)
	s.mux.HandleFunc("GET /api/admin/metrics", s.handleAdminMetrics)
	s.mux.HandleFunc("POST /api/admin/retention/prune", s.handleRetentionPrune)
	s.mux.HandleFunc("GET /api/admin/rbac/subjects", s.handleListAccessSubjects)
	s.mux.HandleFunc("POST /api/admin/rbac/subjects", s.handleUpsertAccessSubject)
	s.mux.HandleFunc("DELETE /api/admin/rbac/subjects/{id}", s.handleDeleteAccessSubject)
	s.mux.HandleFunc("GET /api/admin/rbac/policies", s.handleListAccessPolicies)
	s.mux.HandleFunc("POST /api/admin/rbac/policies", s.handleUpsertAccessPolicy)
	s.mux.HandleFunc("DELETE /api/admin/rbac/policies/{id}", s.handleDeleteAccessPolicy)
	s.mux.HandleFunc("GET /api/admin/audit-logs", s.handleListAuditLogs)
	s.mux.HandleFunc("GET /api/cve-db/stats", s.handleCveDbStats)
	s.mux.HandleFunc("GET /api/cve-db/search", s.handleCveDbSearch)
	s.serveDashboard()
}

func (s *Server) serveDashboard() {
	distDir := os.Getenv("BONGSU_WEB_DIST")
	if distDir == "" {
		distDir = "web/dist"
	}
	if _, err := os.Stat(distDir); os.IsNotExist(err) {
		log.Printf("Web dist not found at %s, dashboard disabled", distDir)
		return
	}
	distFS, err := fs.Sub(os.DirFS(distDir), ".")
	if err != nil {
		log.Printf("Failed to load web dist: %v", err)
		return
	}
	fileServer := http.FileServer(http.FS(distFS))
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// No-cache for HTML entry point
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		path := r.URL.Path
		f, err := distFS.Open(strings.TrimPrefix(path, "/"))
		if err != nil {
			r.URL.Path = "/"
		}
		if f != nil {
			f.Close()
		}
		fileServer.ServeHTTP(w, r)
	})
	log.Printf("Serving dashboard from %s", distDir)
}

func (s *Server) authenticateWeb(r *http.Request) bool {
	if !s.webAuth {
		return true
	}
	return s.authenticateAdmin(r) || s.viewerSubject(r) != ""
}

func (s *Server) authenticateAdmin(r *http.Request) bool {
	return s.matchKey(r.Header.Get("X-API-Key"), s.apiKey)
}

func (s *Server) authenticateAgent(r *http.Request) bool {
	key := r.Header.Get("X-API-Key")
	return s.matchKey(key, s.agentKey) || s.matchKey(key, s.apiKey)
}

func (s *Server) authenticateInstall(r *http.Request) bool {
	token := r.Header.Get("X-Install-Token")
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	if s.installToken != "" && s.matchKey(token, s.installToken) {
		return true
	}
	return s.authenticateAdmin(r)
}

func (s *Server) viewerSubject(r *http.Request) string {
	key := r.Header.Get("X-API-Key")
	if key == "" {
		return ""
	}
	return s.viewerKeys[key]
}

func (s *Server) accessScope(r *http.Request) db.AccessScope {
	if s.authenticateAdmin(r) || !s.webAuth {
		return db.AccessScope{All: true}
	}
	subject := s.viewerSubject(r)
	if subject == "" {
		return db.AccessScope{}
	}
	scope, err := s.db.GetAccessScope(r.Context(), subject)
	if err != nil {
		log.Printf("rbac scope %s: %v", subject, err)
		return db.AccessScope{}
	}
	return scope
}

func (s *Server) authenticateExport(r *http.Request) bool {
	return s.authenticateAdmin(r) || s.viewerSubject(r) != ""
}

func (s *Server) exportScope(r *http.Request) db.AccessScope {
	if s.authenticateAdmin(r) {
		return db.AccessScope{All: true}
	}
	subject := s.viewerSubject(r)
	if subject == "" {
		return db.AccessScope{}
	}
	scope, err := s.db.GetExportScope(r.Context(), subject)
	if err != nil {
		log.Printf("rbac export scope %s: %v", subject, err)
		return db.AccessScope{}
	}
	return scope
}

func (s *Server) canReadHost(r *http.Request, hostID string) bool {
	scope := s.accessScope(r)
	return scope.CanReadHost(hostID)
}

func (s *Server) matchKey(got, want string) bool {
	if got == "" || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (s *Server) audit(r *http.Request, action, resourceType, resourceID, status string, metadata map[string]any) {
	if status == "" {
		status = "ok"
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	if rid := requestIDFromRequest(r); rid != "" {
		if _, exists := metadata["request_id"]; !exists {
			metadata["request_id"] = rid
		}
	}
	meta, err := json.Marshal(metadata)
	if err != nil {
		meta = []byte(`{}`)
	}
	entry := &models.AuditLog{
		ActorType:    s.actorType(r),
		ActorID:      s.actorID(r),
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Status:       status,
		IPAddress:    clientIP(r),
		UserAgent:    r.UserAgent(),
		Metadata:     meta,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.db.RecordAuditLog(ctx, entry); err != nil {
		log.Printf("audit log failed action=%s resource=%s/%s: %v", action, resourceType, resourceID, err)
	}
}

func cloneMetadata(in map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (s *Server) auditSystem(action, resourceType, resourceID, status string, metadata map[string]any) {
	if status == "" {
		status = "ok"
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	meta, err := json.Marshal(metadata)
	if err != nil {
		meta = []byte(`{}`)
	}
	entry := &models.AuditLog{
		ActorType:    "system",
		ActorID:      "bongsu",
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Status:       status,
		Metadata:     meta,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.db.RecordAuditLog(ctx, entry); err != nil {
		log.Printf("audit log failed action=%s resource=%s/%s: %v", action, resourceType, resourceID, err)
	}
}

func (s *Server) auditWebhookResult(event string, data map[string]any, status string, httpStatus int, errMsg string, attempts int) {
	resourceType := "webhook"
	resourceID := event
	if id, ok := data["scan_id"].(string); ok && id != "" {
		resourceType = "scan"
		resourceID = id
	} else if event == "security_db.updated" {
		resourceType = "security_db"
		resourceID = "aggregate"
	}
	meta := map[string]any{
		"event":       event,
		"http_status": httpStatus,
		"attempts":    attempts,
	}
	if errMsg != "" {
		meta["error"] = errMsg
	}
	for _, key := range []string{"host_id", "hostname", "inventory_status", "reason", "security_db_revision"} {
		if v, ok := data[key]; ok {
			meta[key] = v
		}
	}
	s.auditSystem("webhook.send", resourceType, resourceID, status, meta)
}

func (s *Server) actorType(r *http.Request) string {
	if s.authenticateAdmin(r) {
		return "admin"
	}
	if s.authenticateAgent(r) {
		return "agent"
	}
	if s.viewerSubject(r) != "" {
		return "viewer"
	}
	return "anonymous"
}

func (s *Server) actorID(r *http.Request) string {
	if subject := s.viewerSubject(r); subject != "" {
		return subject
	}
	if s.authenticateAdmin(r) {
		return "admin"
	}
	if s.authenticateAgent(r) {
		return "agent"
	}
	return ""
}

func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return strings.TrimSpace(realIP)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAgent(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAgentReportBytes())

	var report models.ScanReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "report too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := normalizeScanReport(&report); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	tokenHash, err := s.agentHostTokenHash(r, report.Host.ID)
	if err != nil {
		s.audit(r, "agent.report", "host", report.Host.ID, "forbidden", map[string]any{"reason": err.Error()})
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if err := s.db.UpsertHostWithAgentToken(ctx, &report.Host, tokenHash); err != nil {
		log.Printf("upsert host: %v", err)
		if errors.Is(err, db.ErrAgentHostTokenMismatch) {
			s.audit(r, "agent.report", "host", report.Host.ID, "forbidden", map[string]any{"reason": "agent token mismatch"})
			http.Error(w, "agent token does not match host binding", http.StatusForbidden)
			return
		}
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	scan := &models.Scan{
		ID:        report.ScanID,
		HostID:    report.Host.ID,
		ScanType:  report.ScanType,
		Status:    "running",
		StartedAt: report.Timestamp,
	}
	if err := s.db.CreateScan(ctx, scan); err != nil {
		log.Printf("create scan: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	ingestErrors := append([]string{}, report.Errors...)

	for i := range report.Containers {
		if report.Containers[i].ID == "" {
			report.Containers[i].ID = uuid.New().String()
		}
		report.Containers[i].ScanID = report.ScanID
		report.Containers[i].HostID = report.Host.ID
	}
	if err := s.db.InsertContainers(ctx, report.Containers); err != nil {
		log.Printf("insert containers: %v", err)
		ingestErrors = append(ingestErrors, "containers: "+err.Error())
	}

	for i := range report.Packages {
		if report.Packages[i].ID == "" {
			report.Packages[i].ID = uuid.New().String()
		}
		report.Packages[i].ScanID = report.ScanID
		report.Packages[i].HostID = report.Host.ID
		if report.Packages[i].AssetType == "" {
			report.Packages[i].AssetType = "host"
		}
		if report.Packages[i].AssetID == "" && report.Packages[i].AssetType == "host" {
			report.Packages[i].AssetID = report.Host.ID
		}
	}
	if err := s.db.InsertPackages(ctx, report.Packages); err != nil {
		log.Printf("insert packages: %v", err)
		ingestErrors = append(ingestErrors, "packages: "+err.Error())
	}

	insertedVulns := 0
	skippedVulns := 0
	if len(report.Vulns) > 0 {
		for i := range report.Vulns {
			if report.Vulns[i].ID == "" {
				report.Vulns[i].ID = uuid.New().String()
			}
			report.Vulns[i].ScanID = report.ScanID
			report.Vulns[i].HostID = report.Host.ID
		}
		if result, err := s.db.InsertVulnerabilities(ctx, report.Vulns); err != nil {
			log.Printf("insert vulns: %v", err)
			ingestErrors = append(ingestErrors, "vulnerabilities: "+err.Error())
		} else if result != nil {
			insertedVulns += result.Inserted
			skippedVulns += result.Skipped
		}
		if n, err := s.db.EnrichVulnerabilities(ctx); err == nil && n > 0 {
			log.Printf("Enriched %d vulnerabilities with CVE DB info", n)
		}
	} else if s.matcher != nil && s.dbMgr != nil && s.dbMgr.IsReady() && len(report.Packages) > 0 {
		log.Printf("Running server-side CVE matching for scan %s (%d packages)", report.ScanID, len(report.Packages))
		vulns, err := s.matcher.Match(ctx, report.Packages, report.Host)
		if err != nil {
			log.Printf("Server-side CVE matching failed: %v", err)
			ingestErrors = append(ingestErrors, "server_match: "+err.Error())
		} else {
			log.Printf("Matched %d vulnerabilities for scan %s", len(vulns), report.ScanID)
			for i := range vulns {
				if vulns[i].ID == "" {
					vulns[i].ID = uuid.New().String()
				}
				vulns[i].ScanID = report.ScanID
				vulns[i].HostID = report.Host.ID
			}
			if result, err := s.db.InsertVulnerabilities(ctx, vulns); err != nil {
				log.Printf("insert matched vulns: %v", err)
				ingestErrors = append(ingestErrors, "matched_vulnerabilities: "+err.Error())
			} else if result != nil {
				insertedVulns += result.Inserted
				skippedVulns += result.Skipped
			}
			if n, err := s.db.EnrichVulnerabilities(ctx); err == nil && n > 0 {
				log.Printf("Enriched %d vulnerabilities with CVE DB scores", n)
			}
		}
	}
	if len(report.Packages) > 0 {
		opts := rematchOptionsFromEnv()
		opts.ScanID = report.ScanID
		if result, err := s.db.RematchCVEs(ctx, opts); err != nil {
			log.Printf("scan CVE DB rematch failed: %v", err)
			ingestErrors = append(ingestErrors, "cve_db_rematch: "+err.Error())
		} else {
			if result.Limited {
				ingestErrors = append(ingestErrors, fmt.Sprintf("cve_db_rematch: candidate limit %d reached", result.CandidateLimit))
			}
			if result.NewVulns > 0 {
				log.Printf("CVE DB rematched %d vulnerabilities for scan %s", result.NewVulns, report.ScanID)
				insertedVulns += result.NewVulns
			}
		}
	}

	for i := range report.Users {
		if report.Users[i].ID == "" {
			report.Users[i].ID = uuid.New().String()
		}
		report.Users[i].ScanID = report.ScanID
		report.Users[i].HostID = report.Host.ID
	}
	if err := s.db.InsertUserAccounts(ctx, report.Users); err != nil {
		log.Printf("insert users: %v", err)
		ingestErrors = append(ingestErrors, "users: "+err.Error())
	}

	for i := range report.Processes {
		if report.Processes[i].ID == "" {
			report.Processes[i].ID = uuid.New().String()
		}
		report.Processes[i].ScanID = report.ScanID
		report.Processes[i].HostID = report.Host.ID
	}
	if err := s.db.InsertProcessSnapshots(ctx, report.Processes); err != nil {
		log.Printf("insert processes: %v", err)
		ingestErrors = append(ingestErrors, "processes: "+err.Error())
	}

	for i := range report.Ports {
		if report.Ports[i].ID == "" {
			report.Ports[i].ID = uuid.New().String()
		}
		report.Ports[i].ScanID = report.ScanID
		report.Ports[i].HostID = report.Host.ID
	}
	if err := s.db.InsertPorts(ctx, report.Ports); err != nil {
		log.Printf("insert ports: %v", err)
		ingestErrors = append(ingestErrors, "ports: "+err.Error())
	}

	scanStatus := reportScanStatus(skippedVulns, len(ingestErrors))
	if err := s.db.CompleteScan(ctx, report.ScanID, scanStatus); err != nil {
		log.Printf("complete scan: %v", err)
		ingestErrors = append(ingestErrors, "complete_scan: "+err.Error())
	}
	sevCounts, vulnTotal, err := s.db.GetVulnCountsByScan(ctx, report.ScanID)
	if err != nil {
		log.Printf("scan vuln counts: %v", err)
		sevCounts = map[string]int{}
	}
	riskCounts, err := s.db.GetVulnRiskCountsByScan(ctx, report.ScanID)
	if err != nil {
		log.Printf("scan vuln risk counts: %v", err)
		riskCounts = map[string]int{}
	}
	inventoryStatus := reportInventoryStatus(len(report.Packages), scanStatus)
	s.audit(r, "agent.report", "scan", report.ScanID, reportAuditStatus(skippedVulns, len(ingestErrors)), map[string]any{
		"host_id":          report.Host.ID,
		"hostname":         report.Host.Hostname,
		"packages":         len(report.Packages),
		"vulnerabilities":  vulnTotal,
		"vulns_inserted":   insertedVulns,
		"vulns_skipped":    skippedVulns,
		"containers":       len(report.Containers),
		"inventory_status": inventoryStatus,
		"users":            len(report.Users),
		"processes":        len(report.Processes),
		"ports":            len(report.Ports),
		"scan_status":      scanStatus,
		"ingest_errors":    ingestErrors,
	})
	if s.notifier.ShouldSendScan(sevCounts, riskCounts, inventoryStatus) {
		s.notifier.Send("scan.completed", reportWebhookPayload(&report, scanStatus, inventoryStatus, insertedVulns, skippedVulns, vulnTotal, sevCounts, riskCounts, ingestErrors))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":             "ok",
		"scan_id":            report.ScanID,
		"scan_status":        scanStatus,
		"inventory_status":   inventoryStatus,
		"ingest_error_count": len(ingestErrors),
		"skipped_vuln_count": skippedVulns,
	})
}

func (s *Server) agentHostTokenHash(r *http.Request, hostID string) (string, error) {
	if !envBool("BONGSU_AGENT_HOST_BINDING", true) {
		return "", nil
	}
	token := strings.TrimSpace(r.Header.Get("X-Bongsu-Agent-Token"))
	if token == "" {
		return "", fmt.Errorf("missing agent host token")
	}
	if len(token) < 32 {
		return "", fmt.Errorf("agent host token is too short")
	}
	if strings.TrimSpace(r.Header.Get("X-Bongsu-Host-ID")) != hostID {
		return "", fmt.Errorf("agent host id header mismatch")
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:]), nil
}

func (s *Server) verifyAgentHostBinding(r *http.Request, hostID string) error {
	tokenHash, err := s.agentHostTokenHash(r, hostID)
	if err != nil {
		return err
	}
	if tokenHash == "" {
		return nil
	}
	if err := s.db.VerifyOrBindHostAgentToken(r.Context(), hostID, tokenHash); err != nil {
		if errors.Is(err, db.ErrAgentHostTokenMismatch) {
			return fmt.Errorf("agent token does not match host binding")
		}
		return err
	}
	return nil
}

func normalizeScanReport(report *models.ScanReport) error {
	report.ScanID = strings.TrimSpace(report.ScanID)
	if report.ScanID == "" {
		report.ScanID = uuid.New().String()
	} else if _, err := uuid.Parse(report.ScanID); err != nil {
		return fmt.Errorf("invalid scan_id")
	}
	report.ScanType = strings.TrimSpace(report.ScanType)
	if report.ScanType == "" {
		report.ScanType = "inventory"
	}
	switch report.ScanType {
	case "inventory", "daily", "manual", "security-db-update":
	default:
		return fmt.Errorf("invalid scan_type")
	}
	if report.Timestamp.IsZero() {
		report.Timestamp = time.Now().UTC()
	}
	report.Host.ID = strings.TrimSpace(report.Host.ID)
	report.Host.Hostname = strings.TrimSpace(report.Host.Hostname)
	report.Host.IPAddress = strings.TrimSpace(report.Host.IPAddress)
	if report.Host.ID == "" {
		report.Host.ID = fallbackHostID(report.Host)
	}
	if report.Host.Hostname == "" {
		report.Host.Hostname = report.Host.ID
	}
	report.Errors = normalizeReportErrors(report.Errors)
	return nil
}

func normalizeReportErrors(errs []string) []string {
	if len(errs) == 0 {
		return nil
	}
	normalized := make([]string, 0, min(len(errs), maxReportErrors))
	for _, entry := range errs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if len(entry) > maxReportErrorBytes {
			entry = truncateValidUTF8(entry, maxReportErrorBytes) + "...(truncated)"
		}
		normalized = append(normalized, entry)
		if len(normalized) == maxReportErrors {
			break
		}
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func truncateValidUTF8(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	s = s[:limit]
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s
}

func reportAuditStatus(skippedVulns, ingestErrorCount int) string {
	if skippedVulns > 0 || ingestErrorCount > 0 {
		return "degraded"
	}
	return "ok"
}

func reportScanStatus(skippedVulns, ingestErrorCount int) string {
	if skippedVulns > 0 || ingestErrorCount > 0 {
		return "degraded"
	}
	return "completed"
}

func reportInventoryStatus(packageCount int, scanStatus string) string {
	if packageCount == 0 {
		return "empty"
	}
	if scanStatus == "degraded" {
		return "degraded"
	}
	return "healthy"
}

func reportWebhookPayload(report *models.ScanReport, scanStatus, inventoryStatus string, insertedVulns, skippedVulns, vulnTotal int, sevCounts, riskCounts map[string]int, ingestErrors []string) map[string]any {
	return map[string]any{
		"scan_id":           report.ScanID,
		"scan_status":       scanStatus,
		"host_id":           report.Host.ID,
		"hostname":          report.Host.Hostname,
		"ip_address":        report.Host.IPAddress,
		"os_name":           report.Host.OSName,
		"os_version":        report.Host.OSVersion,
		"scan_type":         report.ScanType,
		"inventory_status":  inventoryStatus,
		"packages":          len(report.Packages),
		"containers":        len(report.Containers),
		"vulnerabilities":   vulnTotal,
		"vulns_inserted":    insertedVulns,
		"vulns_skipped":     skippedVulns,
		"ingest_errors":     ingestErrors,
		"severity_counts":   sevCounts,
		"risk_level_counts": riskCounts,
	}
}

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	scope := s.accessScope(r)
	statusFilter := r.URL.Query().Get("agent_status")
	inventoryStatusFilter := r.URL.Query().Get("inventory_status")
	inventoryStaleAfter := time.Duration(envInt("BONGSU_INVENTORY_STALE_HOURS", 48)) * time.Hour
	hosts, err := s.db.ListHosts(ctx)
	if err != nil {
		log.Printf("list hosts: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	vulnCounts, err := s.db.GetVulnCountsByHost(ctx)
	if err != nil {
		log.Printf("vuln counts: %v", err)
		vulnCounts = map[string]map[string]int{}
	}
	activeVulnCounts, err := s.db.GetCurrentActionableVulnCountsByHost(ctx, scopeHostFilter(scope, scope.HostIDs))
	if err != nil {
		log.Printf("active vuln counts: %v", err)
		activeVulnCounts = map[string]map[string]int{}
	}
	inventory, err := s.db.GetHostInventorySummaries(ctx)
	if err != nil {
		log.Printf("host inventory summaries: %v", err)
		inventory = map[string]db.HostInventorySummary{}
	}

	type hostWithVulns struct {
		models.Host
		VulnCounts       map[string]int          `json:"vuln_counts"`
		ActiveVulnCounts map[string]int          `json:"active_vuln_counts"`
		LatestInventory  db.HostInventorySummary `json:"latest_inventory"`
	}

	now := time.Now()
	result := make([]hostWithVulns, 0, len(hosts))
	for _, h := range hosts {
		if !scope.CanReadHost(h.ID) {
			continue
		}
		applyAgentStatus(&h, now)
		if statusFilter != "" && h.AgentStatus != statusFilter {
			continue
		}
		item := hostWithVulns{Host: h, VulnCounts: vulnCounts[h.ID], ActiveVulnCounts: activeVulnCounts[h.ID], LatestInventory: inventory[h.ID]}
		if inventoryStatusFilter != "" && hostInventoryStatus(item.LatestInventory, now, inventoryStaleAfter) != inventoryStatusFilter {
			continue
		}
		if item.VulnCounts == nil {
			item.VulnCounts = map[string]int{}
		}
		if item.ActiveVulnCounts == nil {
			item.ActiveVulnCounts = map[string]int{}
		}
		result = append(result, item)
	}
	writeJSON(w, http.StatusOK, result)
}

func hostInventoryStatus(inv db.HostInventorySummary, now time.Time, staleAfter time.Duration) string {
	if inv.ScanID == "" {
		return "none"
	}
	if inv.PackageCount == 0 {
		return "empty"
	}
	if inv.ScanStatus == "degraded" {
		return "degraded"
	}
	if staleAfter > 0 && inv.ScannedAt != nil && now.Sub(*inv.ScannedAt) > staleAfter {
		return "stale"
	}
	return "healthy"
}

func (s *Server) handleGetHost(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	hostID := r.PathValue("id")
	if !s.canReadHost(r, hostID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ctx := r.Context()

	host, err := s.db.GetHost(ctx, hostID)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	applyAgentStatus(host, time.Now())
	writeJSON(w, http.StatusOK, host)
}

func (s *Server) handleUpdateHostMetadata(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	hostID := r.PathValue("id")
	if hostID == "" {
		http.Error(w, "host id is required", http.StatusBadRequest)
		return
	}
	var body struct {
		Owner       string `json:"owner"`
		Team        string `json:"team"`
		Environment string `json:"environment"`
		Criticality string `json:"criticality"`
		Tags        string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.Tags == "" {
		body.Tags = "{}"
	}
	var tags any
	if err := json.Unmarshal([]byte(body.Tags), &tags); err != nil {
		http.Error(w, "tags must be valid JSON", http.StatusBadRequest)
		return
	}
	if err := s.db.UpdateHostMetadata(r.Context(), hostID, body.Owner, body.Team, body.Environment, body.Criticality, body.Tags); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "host not found", http.StatusNotFound)
			return
		}
		log.Printf("update host metadata: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	host, err := s.db.GetHost(r.Context(), hostID)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.audit(r, "host.metadata.update", "host", hostID, "ok", map[string]any{
		"owner":       body.Owner,
		"team":        body.Team,
		"environment": body.Environment,
		"criticality": body.Criticality,
	})
	writeJSON(w, http.StatusOK, host)
}

func (s *Server) handleResetHostAgentToken(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	hostID := r.PathValue("id")
	if hostID == "" {
		http.Error(w, "host id is required", http.StatusBadRequest)
		return
	}
	if _, err := s.db.GetHost(r.Context(), hostID); err != nil {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}
	if err := s.db.ResetHostAgentToken(r.Context(), hostID); err != nil {
		log.Printf("reset host agent token: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	s.audit(r, "host.agent_token.reset", "host", hostID, "ok", map[string]any{
		"host_id": hostID,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleHostPackages(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	hostID := r.PathValue("id")
	if !s.canReadHost(r, hostID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ctx := r.Context()

	limit := limitParam(r, 100)
	offset := offsetParam(r)

	pkgs, total, err := s.db.GetLatestPackages(ctx, hostID, limit, offset)
	if err != nil {
		log.Printf("host packages: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items": pkgs,
		"total": total,
	})
}

func (s *Server) handleHostSBOM(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateExport(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	hostID := r.PathValue("id")
	if !s.exportScope(r).CanReadHost(hostID) {
		s.audit(r, "sbom.export", "host", hostID, "forbidden", map[string]any{"reason": "missing export permission"})
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ctx := r.Context()

	host, err := s.db.GetHost(ctx, hostID)
	if err != nil {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}
	pkgs, err := s.db.GetLatestPackagesForSBOM(ctx, hostID)
	if err != nil {
		log.Printf("host sbom packages: %v", err)
		s.audit(r, "sbom.export", "host", hostID, "error", map[string]any{"error": "package lookup failed"})
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if len(pkgs) == 0 {
		s.audit(r, "sbom.export", "host", hostID, "error", map[string]any{"error": "no packages available"})
		http.Error(w, "no packages available for host", http.StatusNotFound)
		return
	}
	scanID := latestPackageScanID(pkgs)
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "cyclonedx"
	}
	var data []byte
	var contentType, suffix, auditFormat string
	switch format {
	case "spdx":
		data, err = cvematch.GenerateSPDX(pkgs, *host)
		contentType = "application/spdx+json"
		suffix = "spdx.json"
		auditFormat = "SPDX 2.3"
	case "cyclonedx", "cdx":
		data, err = cvematch.GenerateCycloneDX(pkgs, *host)
		contentType = "application/vnd.cyclonedx+json"
		suffix = "cyclonedx.json"
		auditFormat = "CycloneDX 1.5"
	default:
		http.Error(w, "unsupported sbom format", http.StatusBadRequest)
		return
	}
	if err != nil {
		log.Printf("generate host sbom: %v", err)
		s.audit(r, "sbom.export", "host", hostID, "error", map[string]any{"format": auditFormat, "scan_id": scanID, "error": "generation failed"})
		http.Error(w, "sbom generation failed", http.StatusInternalServerError)
		return
	}
	filename := sanitizeFilename(host.Hostname)
	if filename == "" {
		filename = sanitizeFilename(host.ID)
	}
	auditMeta := map[string]any{
		"hostname": host.Hostname,
		"scan_id":  scanID,
		"packages": len(pkgs),
		"format":   auditFormat,
	}
	s.audit(r, "sbom.export", "host", hostID, "started", auditMeta)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s"`, filename, suffix))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(data); err != nil {
		log.Printf("write host sbom: %v", err)
		errMeta := cloneMetadata(auditMeta)
		errMeta["error"] = "response write failed"
		s.audit(r, "sbom.export", "host", hostID, "error", errMeta)
		return
	}
	s.audit(r, "sbom.export", "host", hostID, "ok", auditMeta)
}

func latestPackageScanID(pkgs []models.Package) string {
	for _, pkg := range pkgs {
		if strings.TrimSpace(pkg.ScanID) != "" {
			return strings.TrimSpace(pkg.ScanID)
		}
	}
	return ""
}

func (s *Server) handleHostVulnCounts(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	hostID := r.PathValue("id")
	if !s.canReadHost(r, hostID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ctx := r.Context()

	counts, err := s.db.GetHostVulnCounts(ctx, hostID)
	if err != nil {
		log.Printf("vuln counts: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, counts)
}

func (s *Server) handleListVulnerabilities(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()

	filter, forbidden, empty, err := s.vulnFilterFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if empty {
		writeJSON(w, http.StatusOK, map[string]any{"items": []models.Vulnerability{}, "total": 0})
		return
	}
	if forbidden {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	limit := limitParam(r, 100)
	offset := offsetParam(r)

	vulns, total, err := s.db.ListVulnerabilities(ctx, filter, limit, offset)
	if err != nil {
		log.Printf("list vulns: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items": vulns,
		"total": total,
	})
}

func (s *Server) vulnFilterFromRequest(r *http.Request) (db.VulnFilter, bool, bool, error) {
	return s.vulnFilterFromRequestWithScope(r, s.accessScope(r))
}

func (s *Server) vulnFilterFromRequestWithScope(r *http.Request, scope db.AccessScope) (db.VulnFilter, bool, bool, error) {
	hostID := strings.TrimSpace(r.URL.Query().Get("host_id"))
	findingSource, err := findingSourceFilterParam(r)
	if err != nil {
		return db.VulnFilter{}, false, false, err
	}
	riskLevel, err := riskLevelFilterParam(r)
	if err != nil {
		return db.VulnFilter{}, false, false, err
	}
	if scope.Empty() {
		return db.VulnFilter{}, false, true, nil
	}
	if hostID != "" && !scope.CanReadHost(hostID) {
		return db.VulnFilter{}, true, false, nil
	}
	return db.VulnFilter{
		HostID:        hostID,
		HostIDs:       scope.HostIDs,
		Severity:      r.URL.Query().Get("severity"),
		TriageStatus:  r.URL.Query().Get("triage_status"),
		FindingSource: findingSource,
		RiskLevel:     riskLevel,
		Overdue:       r.URL.Query().Get("overdue") == "true",
		Exploited:     r.URL.Query().Get("exploited") == "true",
		MinEPSS:       floatParam(r, "min_epss", 0),
		MinEPSSPct:    floatParam(r, "min_epss_percentile", 0),
		PkgName:       r.URL.Query().Get("pkg_name"),
		Container:     r.URL.Query().Get("container"),
		Owner:         r.URL.Query().Get("owner"),
		Team:          r.URL.Query().Get("team"),
		Environment:   r.URL.Query().Get("environment"),
		Criticality:   r.URL.Query().Get("criticality"),
		MinCVSS:       floatParam(r, "min_cvss", 0.1),
		SortBy:        r.URL.Query().Get("sort_by"),
		SortDesc:      r.URL.Query().Get("sort_order") == "desc",
		HideFixed:     true,
		HideNoFix:     r.URL.Query().Get("show_no_fix") != "true",
		HideMismatch:  r.URL.Query().Get("show_mismatch") != "true",
	}, false, false, nil
}

func riskLevelFilterParam(r *http.Request) (string, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("risk_level"))
	switch strings.ToLower(raw) {
	case "":
		return "", nil
	case "critical", "high", "medium", "low":
		return strings.ToLower(raw), nil
	default:
		return "", fmt.Errorf("invalid risk_level %q; allowed values are critical, high, medium, or low", raw)
	}
}

func findingSourceFilterParam(r *http.Request) (string, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("finding_source"))
	switch strings.ToLower(raw) {
	case "":
		return "", nil
	case "scanner":
		return "scanner", nil
	case "cve-db", "cve_db", "cvedb":
		return "cve-db", nil
	default:
		return "", fmt.Errorf("invalid finding_source %q; allowed values are scanner or cve-db", raw)
	}
}

func (s *Server) handleExportVulnerabilities(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateExport(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	exportScope := s.exportScope(r)
	if exportScope.Empty() {
		s.audit(r, "vulnerability.export", "vulnerability", "filtered", "forbidden", map[string]any{"reason": "missing export permission"})
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	filter, forbidden, empty, err := s.vulnFilterFromRequestWithScope(r, exportScope)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if forbidden {
		s.audit(r, "vulnerability.export", "vulnerability", "filtered", "forbidden", map[string]any{"reason": "missing export permission"})
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	maxRows := envInt("BONGSU_VULN_EXPORT_MAX_ROWS", 100000)
	if requested := intParam(r, "limit", 0); requested > 0 && requested < maxRows {
		maxRows = requested
	}
	if maxRows <= 0 {
		maxRows = 100000
	}
	var vulns []models.Vulnerability
	total := 0
	if !empty {
		vulns, total, err = s.db.ListVulnerabilities(r.Context(), filter, maxRows, 0)
		if err != nil {
			log.Printf("export vulnerabilities: %v", err)
			s.audit(r, "vulnerability.export", "vulnerability", "filtered", "error", map[string]any{"error": "db lookup failed", "max_rows": maxRows})
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
	}
	format := strings.ToLower(r.URL.Query().Get("format"))
	auditMeta := map[string]any{
		"format":   exportFormatLabel(format),
		"exported": len(vulns),
		"total":    total,
		"max_rows": maxRows,
	}
	var body bytes.Buffer
	if format == "json" {
		if err := json.NewEncoder(&body).Encode(map[string]any{"items": vulns, "total": total, "exported": len(vulns)}); err != nil {
			log.Printf("encode vulnerability export json: %v", err)
			errMeta := cloneMetadata(auditMeta)
			errMeta["error"] = "json encode failed"
			s.audit(r, "vulnerability.export", "vulnerability", "filtered", "error", errMeta)
			http.Error(w, "export failed", http.StatusInternalServerError)
			return
		}
	} else {
		if err := writeVulnerabilityCSV(&body, vulns); err != nil {
			log.Printf("write vulnerability export csv: %v", err)
			errMeta := cloneMetadata(auditMeta)
			errMeta["error"] = "csv encode failed"
			s.audit(r, "vulnerability.export", "vulnerability", "filtered", "error", errMeta)
			http.Error(w, "export failed", http.StatusInternalServerError)
			return
		}
	}
	s.audit(r, "vulnerability.export", "vulnerability", "filtered", "started", auditMeta)
	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="bongsu-vulnerabilities.json"`)
	} else {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="bongsu-vulnerabilities.csv"`)
	}
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body.Bytes()); err != nil {
		log.Printf("write vulnerability export response: %v", err)
		errMeta := cloneMetadata(auditMeta)
		errMeta["error"] = "response write failed"
		s.audit(r, "vulnerability.export", "vulnerability", "filtered", "error", errMeta)
		return
	}
	s.audit(r, "vulnerability.export", "vulnerability", "filtered", "ok", auditMeta)
}

func writeVulnerabilityCSV(w io.Writer, vulns []models.Vulnerability) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{
		"host_id", "host_owner", "host_team", "host_environment", "host_criticality", "container", "vulnerability_id", "risk_score", "risk_level", "exploited", "epss_score", "epss_percentile", "severity", "cvss_score", "triage_status",
		"sla_days", "due_at", "overdue", "pkg_name", "pkg_type", "ecosystem", "installed_version", "fixed_version", "finding_source", "pkg_path", "title", "primary_url",
		"triage_reason", "triage_comment", "triage_expires_at", "triage_updated_by", "created_at",
	}); err != nil {
		return err
	}
	for _, v := range vulns {
		if err := cw.Write([]string{
			csvSafeCell(v.HostID),
			csvSafeCell(v.HostOwner),
			csvSafeCell(v.HostTeam),
			csvSafeCell(v.HostEnvironment),
			csvSafeCell(v.HostCriticality),
			csvSafeCell(v.Container),
			csvSafeCell(v.VulnerabilityID),
			fmt.Sprintf("%.1f", v.RiskScore),
			csvSafeCell(v.RiskLevel),
			strconv.FormatBool(v.Exploited),
			fmt.Sprintf("%.5f", v.EPSSScore),
			fmt.Sprintf("%.5f", v.EPSSPercentile),
			csvSafeCell(v.Severity),
			fmt.Sprintf("%.1f", v.CVSSScore),
			csvSafeCell(exportStatusLabel(v.TriageStatus)),
			strconv.Itoa(v.SLADays),
			formatTimePtr(v.DueAt),
			strconv.FormatBool(v.Overdue),
			csvSafeCell(v.PkgName),
			csvSafeCell(v.PkgType),
			csvSafeCell(v.Ecosystem),
			csvSafeCell(v.InstalledVer),
			csvSafeCell(v.FixedVersion),
			csvSafeCell(v.FindingSource),
			csvSafeCell(v.PkgPath),
			csvSafeCell(v.Title),
			csvSafeCell(v.PrimaryURL),
			csvSafeCell(v.TriageReason),
			csvSafeCell(v.TriageComment),
			formatTimePtr(v.TriageExpiresAt),
			csvSafeCell(v.TriageUpdatedBy),
			v.CreatedAt.Format(time.RFC3339),
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func csvSafeCell(s string) string {
	if s == "" {
		return s
	}
	trimmed := strings.TrimLeft(s, " \t\r\n")
	if trimmed == "" {
		return s
	}
	switch trimmed[0] {
	case '=', '+', '-', '@':
		return "'" + s
	}
	return s
}

func formatTimePtr(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func exportFormatLabel(format string) string {
	if format == "" {
		return "csv"
	}
	return format
}

func exportStatusLabel(status string) string {
	if status == "" {
		return "open"
	}
	return status
}

func (s *Server) handleVulnFilters(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	scope := s.accessScope(r)
	if scope.Empty() {
		writeJSON(w, http.StatusOK, &db.FilterOptions{})
		return
	}

	opts, err := s.db.GetVulnFilterOptions(ctx, scopeHostFilter(scope, scope.HostIDs))
	if err != nil {
		log.Printf("vuln filter options: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, opts)
}

func (s *Server) handleUpsertVulnerabilityTriage(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body models.VulnerabilityTriage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	normalizeVulnerabilityTriage(&body)
	if body.VulnerabilityID == "" {
		http.Error(w, "vulnerability_id is required", http.StatusBadRequest)
		return
	}
	if body.PkgName != "" && body.HostID == "" {
		http.Error(w, "host_id is required when pkg_name is set", http.StatusBadRequest)
		return
	}
	if body.HostID != "" {
		if _, err := s.db.GetHost(r.Context(), body.HostID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.Error(w, "host not found", http.StatusNotFound)
				return
			}
			log.Printf("triage host lookup: %v", err)
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
	}
	switch body.Status {
	case "", "open", "in_progress", "accepted_risk", "false_positive", "fixed", "ignored":
	default:
		http.Error(w, "invalid status", http.StatusBadRequest)
		return
	}
	if body.Status == "" {
		body.Status = "open"
	}
	if triageStatusRequiresReason(body.Status) && body.Reason == "" {
		http.Error(w, "reason is required for "+body.Status, http.StatusBadRequest)
		return
	}
	if body.UpdatedBy == "" {
		body.UpdatedBy = s.actorID(r)
	}
	if err := s.db.UpsertVulnerabilityTriage(r.Context(), &body); err != nil {
		log.Printf("upsert vulnerability triage: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	s.audit(r, "vulnerability.triage", "vulnerability", body.VulnerabilityID, "ok", map[string]any{
		"host_id":    body.HostID,
		"pkg_name":   body.PkgName,
		"status":     body.Status,
		"reason":     body.Reason,
		"expires_at": formatTimePtr(body.ExpiresAt),
	})
	writeJSON(w, http.StatusOK, body)
}

func normalizeVulnerabilityTriage(t *models.VulnerabilityTriage) {
	t.VulnerabilityID = strings.TrimSpace(t.VulnerabilityID)
	t.HostID = strings.TrimSpace(t.HostID)
	t.PkgName = strings.TrimSpace(t.PkgName)
	t.Status = strings.TrimSpace(t.Status)
	t.Reason = strings.TrimSpace(t.Reason)
	t.Comment = strings.TrimSpace(t.Comment)
	t.UpdatedBy = strings.TrimSpace(t.UpdatedBy)
}

func triageStatusRequiresReason(status string) bool {
	switch status {
	case "accepted_risk", "false_positive", "fixed", "ignored":
		return true
	default:
		return false
	}
}

func (s *Server) handleCveSearch(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	scope := s.accessScope(r)
	if scope.Empty() {
		writeJSON(w, http.StatusOK, map[string]any{"items": []models.Vulnerability{}, "total": 0})
		return
	}

	query := r.URL.Query().Get("q")
	pkgName := r.URL.Query().Get("pkg_name")
	severity := r.URL.Query().Get("severity")
	minCVSS := floatParam(r, "min_cvss", 0.1)
	limit := limitParam(r, 50)
	offset := offsetParam(r)
	sortBy := r.URL.Query().Get("sort_by")
	sortOrder := r.URL.Query().Get("sort_order")

	vulns, total, err := s.db.SearchCVEs(ctx, db.CveSearchFilter{
		Query:    query,
		PkgName:  pkgName,
		Severity: severity,
		HostIDs:  scope.HostIDs,
		MinCVSS:  minCVSS,
		SortBy:   sortBy,
		SortDesc: sortOrder != "asc",
	}, limit, offset)
	if err != nil {
		log.Printf("cve search: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items": vulns,
		"total": total,
	})
}

func (s *Server) handleVulnSummary(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	scope := s.accessScope(r)
	if scope.Empty() {
		if r.URL.Query().Get("group_by") != "" {
			writeJSON(w, http.StatusOK, map[string]any{"group_by": r.URL.Query().Get("group_by"), "items": []db.VulnerabilitySummaryRow{}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]map[string]int{})
		return
	}

	groupBy := r.URL.Query().Get("group_by")
	if groupBy != "" {
		rows, err := s.db.GetVulnSummaryByMetadata(ctx, groupBy, scope.HostIDs)
		if err != nil {
			log.Printf("vuln summary metadata: %v", err)
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"group_by": groupBy,
			"items":    rows,
		})
		return
	}

	counts, err := s.db.GetCurrentActionableVulnCountsByHost(ctx, scopeHostFilter(scope, scope.HostIDs))
	if err != nil {
		log.Printf("vuln summary: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, counts)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	scope := s.accessScope(r)

	hosts, _ := s.db.ListHosts(ctx)
	vulnCounts, _ := s.db.GetVulnCountsByHost(ctx)

	totalVulns := 0
	sevCounts := map[string]int{}
	visibleHosts := 0
	visibleHostIDs := []string{}
	for _, h := range hosts {
		if !scope.CanReadHost(h.ID) {
			continue
		}
		visibleHosts++
		visibleHostIDs = append(visibleHostIDs, h.ID)
		vc := vulnCounts[h.ID]
		for sev, cnt := range vc {
			totalVulns += cnt
			sevCounts[sev] += cnt
		}
	}
	activeVulnCounts, err := s.db.GetCurrentActionableVulnCountsByHost(ctx, scopeHostFilter(scope, visibleHostIDs))
	if err != nil {
		log.Printf("active vuln status counts: %v", err)
		activeVulnCounts = map[string]map[string]int{}
	}
	activeRiskCountsByHost, err := s.db.GetCurrentActionableVulnRiskCountsByHost(ctx, scopeHostFilter(scope, visibleHostIDs))
	if err != nil {
		log.Printf("active vuln risk counts: %v", err)
		activeRiskCountsByHost = map[string]map[string]int{}
	}
	activeTotalVulns := 0
	activeSevCounts := map[string]int{}
	activeRiskCounts := map[string]int{}
	for hostID, vc := range activeVulnCounts {
		if !scope.CanReadHost(hostID) {
			continue
		}
		for sev, cnt := range vc {
			activeTotalVulns += cnt
			activeSevCounts[sev] += cnt
		}
	}
	for hostID, rc := range activeRiskCountsByHost {
		if !scope.CanReadHost(hostID) {
			continue
		}
		for riskLevel, cnt := range rc {
			activeRiskCounts[riskLevel] += cnt
		}
	}
	scanRequestCounts, err := s.db.CountScanRequestsByStatus(ctx, visibleHostIDs, scope.All)
	if err != nil {
		log.Printf("scan request status counts: %v", err)
		scanRequestCounts = map[string]int{}
	}
	securityDBRevision := ""
	securityDBRescanCounts := map[string]int{}
	if revision, err := s.db.GetSecurityDBRevision(ctx); err != nil {
		log.Printf("security db revision stats: %v", err)
	} else {
		securityDBRevision = revision
		if counts, err := s.db.CountSecurityDBRescanRequestsByStatus(ctx, visibleHostIDs, scope.All, revision); err != nil {
			log.Printf("security db rescan status counts: %v", err)
		} else {
			securityDBRescanCounts = counts
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total_hosts":                       visibleHosts,
		"total_vulnerabilities":             totalVulns,
		"severity_counts":                   sevCounts,
		"active_vulnerabilities":            activeTotalVulns,
		"active_severity_counts":            activeSevCounts,
		"active_risk_level_counts":          activeRiskCounts,
		"scan_request_counts":               scanRequestCounts,
		"security_db_revision":              securityDBRevision,
		"security_db_rescan_request_counts": securityDBRescanCounts,
	})
}

func scopeHostFilter(scope db.AccessScope, visibleHostIDs []string) []string {
	if scope.All {
		return nil
	}
	return visibleHostIDs
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func fallbackHostID(host models.Host) string {
	if host.Hostname != "" {
		return "hostname:" + strings.ToLower(strings.TrimSpace(host.Hostname))
	}
	if host.IPAddress != "" {
		return "ip:" + strings.TrimSpace(host.IPAddress)
	}
	return uuid.New().String()
}

func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateInstall(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.installToken == "" {
		s.audit(r, "installer.generate", "installer", "install.sh", "error", map[string]any{
			"reason": "install token is not configured",
		})
		http.Error(w, "install token is not configured", http.StatusServiceUnavailable)
		return
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Host
	apiKey := s.agentKey
	serverURL := fmt.Sprintf("%s://%s", scheme, host)

	script := fmt.Sprintf(`#!/bin/bash
set -euo pipefail

# Bongsu Agent Installer
# Usage: curl -fsSL -H "X-Install-Token: $BONGSU_INSTALL_TOKEN" %s://%s/api/install.sh | bash

SERVER=%s
API_KEY=%s
INSTALL_TOKEN=%s
WORK_DIR="${BONGSU_WORK_DIR:-/opt/bongsu}"
INSTALL_MODE="${BONGSU_INSTALL_MODE:-cron}"
CRON_SCHEDULE="${BONGSU_CRON:-0 3 * * *}"
FORCE_SCAN_DAEMON="${BONGSU_FORCE_SCAN_DAEMON:-true}"
AGENT_TOKEN="${BONGSU_AGENT_TOKEN:-}"

curl_download() {
    local url="$1"
    local output="$2"
    local headers
    headers="$(mktemp)"
    trap 'rm -f "$headers"' RETURN
    if [ -n "$INSTALL_TOKEN" ]; then
        local curl_config
        curl_config="$(mktemp)"
        chmod 600 "$curl_config"
        printf 'header = "X-Install-Token: %%s"\n' "$INSTALL_TOKEN" > "$curl_config"
        if curl -fsSL --config "$curl_config" -D "$headers" "$url" -o "$output"; then
            rm -f "$curl_config"
            if ! verify_download_sha256 "$headers" "$output"; then
                rm -f "$headers"
                trap - RETURN
                return 1
            fi
            rm -f "$headers"
            trap - RETURN
            return 0
        fi
        rm -f "$curl_config"
        rm -f "$headers"
        trap - RETURN
        return 1
    fi
    if curl -fsSL -D "$headers" "$url" -o "$output"; then
        if ! verify_download_sha256 "$headers" "$output"; then
            rm -f "$headers"
            trap - RETURN
            return 1
        fi
        rm -f "$headers"
        trap - RETURN
        return 0
    fi
    rm -f "$headers"
    trap - RETURN
    return 1
}

file_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "ERROR: sha256sum or shasum is required to verify downloaded binaries" >&2
        return 1
    fi
}

verify_download_sha256() {
    local headers="$1"
    local output="$2"
    local expected
    expected="$(awk 'tolower($1)=="x-bongsu-sha256:" {print $2}' "$headers" | tail -1 | tr -d '\r')"
    if [ -z "$expected" ]; then
        echo "ERROR: missing X-Bongsu-SHA256 header for $output" >&2
        rm -f "$output"
        return 1
    fi
    local actual
    actual="$(file_sha256 "$output")"
    if [ "$actual" != "$expected" ]; then
        echo "ERROR: checksum mismatch for $output" >&2
        rm -f "$output"
        return 1
    fi
}

generate_agent_token() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    elif command -v uuidgen >/dev/null 2>&1; then
        printf '%%s%%s\n' "$(uuidgen)" "$(uuidgen)" | tr -d '-'
    else
        date +%%s%%N | sha256sum | awk '{print $1}'
    fi
}

echo "=== Bongsu Agent Installer ==="
echo "Server:  $SERVER"
echo "WorkDir: $WORK_DIR"
echo "Mode:    $INSTALL_MODE"

mkdir -p "$WORK_DIR/bin"
if [ -z "$AGENT_TOKEN" ]; then
    if [ -s "$WORK_DIR/agent.token" ]; then
        AGENT_TOKEN="$(tr -d '\r\n' < "$WORK_DIR/agent.token")"
    else
        AGENT_TOKEN="$(generate_agent_token)"
        umask 077
        printf '%%s\n' "$AGENT_TOKEN" > "$WORK_DIR/agent.token"
    fi
fi

# Download agent binary from server
echo "Downloading bongsu-agent..."
if ! curl_download "$SERVER/api/downloads/bongsu-agent" "$WORK_DIR/bin/bongsu-agent"; then
    rm -f "$WORK_DIR/bin/bongsu-agent"
    echo "ERROR: Failed to download bongsu-agent"
    exit 1
fi
chmod +x "$WORK_DIR/bin/bongsu-agent"

if [ ! -x "$WORK_DIR/bin/bongsu-agent" ]; then
    echo "ERROR: Failed to download bongsu-agent"
    exit 1
fi

echo "Downloading trivy..."
if curl_download "$SERVER/api/downloads/trivy" "$WORK_DIR/bin/trivy"; then
    chmod +x "$WORK_DIR/bin/trivy"
else
    rm -f "$WORK_DIR/bin/trivy"
    echo "WARNING: trivy download failed; install trivy manually or provide it at $WORK_DIR/bin/trivy"
fi

# Write config. It contains the agent API key, so keep it owner-readable only.
umask 077
cat > "$WORK_DIR/config.yaml" <<EOF
server_url: ${SERVER}
api_key: ${API_KEY}
agent_token: ${AGENT_TOKEN}
work_dir: ${WORK_DIR}
EOF
chmod 600 "$WORK_DIR/config.yaml"
chmod 600 "$WORK_DIR/agent.token" 2>/dev/null || true

AGENT_CMD="$WORK_DIR/bin/bongsu-agent --config $WORK_DIR/config.yaml --type daily --packages-only"

if [ "$INSTALL_MODE" = "systemd" ] && command -v systemctl >/dev/null 2>&1 && [ "$(id -u)" = "0" ]; then
    cat > /etc/systemd/system/bongsu-agent.service <<SERVICE
[Unit]
Description=Bongsu package inventory agent
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$AGENT_CMD
Nice=10
IOSchedulingClass=best-effort
UMask=0077
ProtectSystem=strict
ReadWritePaths=$WORK_DIR
PrivateTmp=true
SERVICE
    cat > /etc/systemd/system/bongsu-agent.timer <<TIMER
[Unit]
Description=Run Bongsu package inventory agent

[Timer]
OnCalendar=*-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
TIMER
    systemctl daemon-reload
    systemctl enable --now bongsu-agent.timer
    echo "Systemd timer installed: bongsu-agent.timer"
    if [ "$FORCE_SCAN_DAEMON" = "true" ]; then
        cat > /etc/systemd/system/bongsu-agent-daemon.service <<SERVICE
[Unit]
Description=Bongsu force scan polling agent
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=$WORK_DIR/bin/bongsu-agent --config $WORK_DIR/config.yaml --daemon --poll-interval 60s
Restart=always
RestartSec=10
Nice=10
IOSchedulingClass=best-effort
UMask=0077
ProtectSystem=strict
ReadWritePaths=$WORK_DIR
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SERVICE
        systemctl daemon-reload
        systemctl enable --now bongsu-agent-daemon.service
        echo "Systemd daemon installed: bongsu-agent-daemon.service"
    fi
else
    CRON_CMD="$AGENT_CMD >> $WORK_DIR/agent.log 2>&1"
    (crontab -l 2>/dev/null | grep -v bongsu-agent; echo "$CRON_SCHEDULE $CRON_CMD") | crontab -
    echo "Cron installed: $CRON_SCHEDULE"
fi

# Run first scan
echo "Running first scan..."
$AGENT_CMD 2>&1 | tail -5 || true

echo ""
echo "=== Done ==="
echo "  Config:  $WORK_DIR/config.yaml"
echo "  Manual:  $WORK_DIR/bin/bongsu-agent --config $WORK_DIR/config.yaml --type daily --packages-only"
echo "  Log:     $WORK_DIR/agent.log"
`, scheme, host, shellQuote(serverURL), shellQuote(apiKey), shellQuote(s.installToken))

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/x-shellscript")
	s.audit(r, "installer.generate", "installer", "install.sh", "ok", map[string]any{
		"server":            serverURL,
		"install_token_set": s.installToken != "",
	})
	w.Write([]byte(script))
}

func (s *Server) handleAgentDownload(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateInstall(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	agentPath := os.Getenv("BONGSU_AGENT_BIN")
	if agentPath == "" {
		exe, _ := os.Executable()
		agentPath = filepath.Join(filepath.Dir(exe), "bongsu-agent")
		if _, err := os.Stat(agentPath); err != nil {
			agentPath = "/app/bin/bongsu-agent"
		}
	}

	f, err := os.Open(agentPath)
	if err != nil {
		s.audit(r, "installer.download", "binary", "bongsu-agent", "error", map[string]any{
			"reason": "agent binary not found",
			"path":   agentPath,
		})
		http.Error(w, "agent binary not found", http.StatusNotFound)
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		s.audit(r, "installer.download", "binary", "bongsu-agent", "error", map[string]any{
			"reason": "agent binary is not readable",
			"path":   agentPath,
		})
		http.Error(w, "agent binary not readable", http.StatusInternalServerError)
		return
	}
	digest, err := fileSHA256Hex(f)
	if err != nil {
		s.audit(r, "installer.download", "binary", "bongsu-agent", "error", map[string]any{
			"reason": "agent binary checksum failed",
			"path":   agentPath,
			"error":  err.Error(),
		})
		http.Error(w, "agent binary checksum failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	w.Header().Set("Content-Disposition", "attachment; filename=bongsu-agent")
	w.Header().Set("X-Bongsu-SHA256", digest)
	if _, err := io.Copy(w, f); err != nil {
		log.Printf("agent binary download failed: %v", err)
		s.audit(r, "installer.download", "binary", "bongsu-agent", "error", map[string]any{
			"reason": "copy failed",
			"path":   agentPath,
			"error":  err.Error(),
		})
		return
	}
	s.audit(r, "installer.download", "binary", "bongsu-agent", "ok", map[string]any{
		"bytes":  info.Size(),
		"sha256": digest,
	})
}

func (s *Server) handleTrivyDownload(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateInstall(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	trivyPath := os.Getenv("BONGSU_TRIVY_PATH")
	if trivyPath == "" {
		trivyPath = "/usr/local/bin/trivy"
	}
	f, err := os.Open(trivyPath)
	if err != nil {
		s.audit(r, "installer.download", "binary", "trivy", "error", map[string]any{
			"reason": "trivy binary not found",
			"path":   trivyPath,
		})
		http.Error(w, "trivy binary not found", http.StatusNotFound)
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		s.audit(r, "installer.download", "binary", "trivy", "error", map[string]any{
			"reason": "trivy binary is not readable",
			"path":   trivyPath,
		})
		http.Error(w, "trivy binary not readable", http.StatusInternalServerError)
		return
	}
	digest, err := fileSHA256Hex(f)
	if err != nil {
		s.audit(r, "installer.download", "binary", "trivy", "error", map[string]any{
			"reason": "trivy binary checksum failed",
			"path":   trivyPath,
			"error":  err.Error(),
		})
		http.Error(w, "trivy binary checksum failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	w.Header().Set("Content-Disposition", "attachment; filename=trivy")
	w.Header().Set("X-Bongsu-SHA256", digest)
	if _, err := io.Copy(w, f); err != nil {
		log.Printf("trivy binary download failed: %v", err)
		s.audit(r, "installer.download", "binary", "trivy", "error", map[string]any{
			"reason": "copy failed",
			"path":   trivyPath,
			"error":  err.Error(),
		})
		return
	}
	s.audit(r, "installer.download", "binary", "trivy", "ok", map[string]any{
		"bytes":  info.Size(),
		"sha256": digest,
	})
}

func fileSHA256Hex(f *os.File) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *Server) handlePackageVulns(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	pkgID := r.PathValue("id")
	ctx := r.Context()
	hostID, err := s.db.GetPackageHostID(ctx, pkgID)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !s.canReadHost(r, hostID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	vulns, err := s.db.GetVulnsByPackageID(ctx, pkgID)
	if err != nil {
		log.Printf("package vulns: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if vulns == nil {
		vulns = []models.Vulnerability{}
	}
	writeJSON(w, http.StatusOK, vulns)
}

func (s *Server) handleSearchPackages(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	scope := s.accessScope(r)
	if scope.Empty() {
		writeJSON(w, http.StatusOK, map[string]any{"items": []models.Package{}, "total": 0})
		return
	}
	hostID := r.URL.Query().Get("host_id")
	if hostID != "" && !scope.CanReadHost(hostID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	f := db.PackageFilter{
		HostID:     hostID,
		HostIDs:    scope.HostIDs,
		Container:  r.URL.Query().Get("container"),
		PkgType:    r.URL.Query().Get("pkg_type"),
		Source:     r.URL.Query().Get("source"),
		NameSearch: r.URL.Query().Get("q"),
		SortBy:     r.URL.Query().Get("sort_by"),
		SortDesc:   r.URL.Query().Get("sort_order") == "desc",
		Limit:      limitParam(r, 100),
		Offset:     offsetParam(r),
	}

	pkgs, total, err := s.db.SearchPackages(ctx, f)
	if err != nil {
		log.Printf("search packages: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items": pkgs,
		"total": total,
	})
}

func (s *Server) handleSearchContainers(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	scope := s.accessScope(r)
	if scope.Empty() {
		writeJSON(w, http.StatusOK, map[string]any{"items": []models.ContainerAsset{}, "total": 0})
		return
	}
	hostID := r.URL.Query().Get("host_id")
	if hostID != "" && !scope.CanReadHost(hostID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	f := db.ContainerFilter{
		HostID:     hostID,
		HostIDs:    scope.HostIDs,
		Runtime:    r.URL.Query().Get("runtime"),
		State:      r.URL.Query().Get("state"),
		ImageName:  r.URL.Query().Get("image"),
		NameSearch: r.URL.Query().Get("q"),
		SortBy:     r.URL.Query().Get("sort_by"),
		SortDesc:   r.URL.Query().Get("sort_order") == "desc",
		Limit:      limitParam(r, 100),
		Offset:     offsetParam(r),
	}

	containers, total, err := s.db.SearchContainers(ctx, f)
	if err != nil {
		log.Printf("search containers: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items": containers,
		"total": total,
	})
}

func (s *Server) handlePackageFilters(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	scope := s.accessScope(r)
	if scope.Empty() {
		writeJSON(w, http.StatusOK, &db.FilterOptions{})
		return
	}

	opts, err := s.db.GetFilterOptions(ctx, scopeHostFilter(scope, scope.HostIDs))
	if err != nil {
		log.Printf("filter options: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, opts)
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()

	hostID := r.URL.Query().Get("host_id")
	scope := s.accessScope(r)
	if scope.Empty() {
		writeJSON(w, http.StatusOK, map[string]any{"items": []models.Scan{}, "total": 0})
		return
	}
	if hostID != "" && !scope.CanReadHost(hostID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	limit := limitParam(r, 50)
	offset := offsetParam(r)

	scans, total, err := s.db.ListScans(ctx, hostID, scope.HostIDs, limit, offset)
	if err != nil {
		log.Printf("list scans: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items": scans,
		"total": total,
	})
}

func (s *Server) handleListScanRequests(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	scope := s.accessScope(r)
	if scope.Empty() {
		writeJSON(w, http.StatusOK, map[string]any{"items": []models.ScanRequest{}, "total": 0})
		return
	}
	hostID := r.URL.Query().Get("host_id")
	if hostID != "" && !scope.CanReadHost(hostID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	scanType := strings.TrimSpace(r.URL.Query().Get("scan_type"))
	if scanType != "" && !validScanRequestType(scanType) {
		http.Error(w, "invalid scan_type", http.StatusBadRequest)
		return
	}
	items, total, err := s.db.ListScanRequests(
		r.Context(),
		hostID,
		scope.HostIDs,
		status,
		scanType,
		strings.TrimSpace(r.URL.Query().Get("security_db_revision")),
		limitParam(r, 50),
		offsetParam(r),
	)
	if err != nil {
		log.Printf("list scan requests: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	annotateScanRequestStaleness(items, scanRequestClaimTimeoutSeconds())
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

func annotateScanRequestStaleness(items []models.ScanRequest, timeoutSeconds int64) {
	for i := range items {
		if items[i].Status == "pending" && items[i].RequestAgeS > timeoutSeconds {
			items[i].RequestStale = true
		}
		if items[i].Status == "claimed" && items[i].ClaimAgeS > timeoutSeconds {
			items[i].ClaimStale = true
		}
	}
}

func scanRequestClaimTimeoutSeconds() int64 {
	timeoutMinutes := envInt("BONGSU_SCAN_REQUEST_CLAIM_TIMEOUT_MINUTES", 60)
	if timeoutMinutes <= 0 {
		timeoutMinutes = 60
	}
	return int64(timeoutMinutes) * 60
}

func (s *Server) handleCancelScanRequest(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}
	if err := s.db.CompleteScanRequest(r.Context(), id, "cancelled", "cancelled by admin"); err != nil {
		log.Printf("cancel scan request: %v", err)
		http.Error(w, scanRequestErrorMessage(err), scanRequestErrorStatus(err))
		return
	}
	req, _ := s.db.GetScanRequest(r.Context(), id)
	s.audit(r, "scan_request.cancel", "scan_request", id, "cancelled", scanRequestAuditMeta(req, "cancelled by admin", ""))
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

func (s *Server) handleRequeueScanRequest(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}
	var body struct {
		Message string `json:"message"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
	}
	body.Message = strings.TrimSpace(body.Message)
	if body.Message == "" {
		body.Message = "requeued by admin"
	}
	if err := s.db.RequeueScanRequest(r.Context(), id, body.Message); err != nil {
		log.Printf("requeue scan request: %v", err)
		http.Error(w, scanRequestErrorMessage(err), scanRequestErrorStatus(err))
		return
	}
	req, _ := s.db.GetScanRequest(r.Context(), id)
	s.audit(r, "scan_request.requeue", "scan_request", id, "ok", scanRequestAuditMeta(req, body.Message, ""))
	writeJSON(w, http.StatusOK, map[string]string{"status": "pending"})
}

func (s *Server) handleRequeueStaleScanRequests(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body struct {
		TimeoutMinutes int `json:"timeout_minutes"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
	}
	if body.TimeoutMinutes <= 0 {
		body.TimeoutMinutes = envInt("BONGSU_SCAN_REQUEST_CLAIM_TIMEOUT_MINUTES", 60)
	}
	if body.TimeoutMinutes <= 0 {
		body.TimeoutMinutes = 60
	}
	count, err := s.db.RequeueStaleScanRequests(r.Context(), time.Duration(body.TimeoutMinutes)*time.Minute)
	if err != nil {
		log.Printf("requeue stale scan requests: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	s.audit(r, "scan_request.requeue_stale", "scan_request", "stale_claims", "ok", map[string]any{
		"timeout_minutes": body.TimeoutMinutes,
		"requeued":        count,
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "requeued": count, "timeout_minutes": body.TimeoutMinutes})
}

func (s *Server) handleRequeueFilteredScanRequests(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body struct {
		HostID             string `json:"host_id"`
		Status             string `json:"status"`
		ScanType           string `json:"scan_type"`
		SecurityDBRevision string `json:"security_db_revision"`
		Message            string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	body.HostID = strings.TrimSpace(body.HostID)
	body.Status = strings.TrimSpace(body.Status)
	body.ScanType = strings.TrimSpace(body.ScanType)
	body.SecurityDBRevision = strings.TrimSpace(body.SecurityDBRevision)
	body.Message = strings.TrimSpace(body.Message)
	if body.HostID == "" && body.Status == "" && body.ScanType == "" && body.SecurityDBRevision == "" {
		http.Error(w, "at least one filter is required", http.StatusBadRequest)
		return
	}
	if body.Status != "" && body.Status != "failed" && body.Status != "degraded" && body.Status != "cancelled" {
		http.Error(w, "status must be failed, degraded, or cancelled", http.StatusBadRequest)
		return
	}
	if body.ScanType != "" && !validScanRequestType(body.ScanType) {
		http.Error(w, "invalid scan_type", http.StatusBadRequest)
		return
	}
	if body.HostID != "" {
		if _, err := s.db.GetHost(r.Context(), body.HostID); err != nil {
			http.Error(w, "host not found", http.StatusNotFound)
			return
		}
	}
	if body.Message == "" {
		body.Message = "bulk requeued by admin"
	}
	count, err := s.db.RequeueScanRequestsByFilter(r.Context(), body.HostID, body.Status, body.ScanType, body.SecurityDBRevision, body.Message)
	if err != nil {
		log.Printf("requeue filtered scan requests: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	s.audit(r, "scan_request.requeue_filtered", "scan_request", "filtered", "ok", map[string]any{
		"host_id":              body.HostID,
		"status":               body.Status,
		"scan_type":            body.ScanType,
		"security_db_revision": body.SecurityDBRevision,
		"message":              body.Message,
		"requeued":             count,
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "requeued": count})
}

func (s *Server) handleCreateScanRequest(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req models.ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := normalizeScanRequestCreate(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.HostID != "" {
		if _, err := s.db.GetHost(r.Context(), req.HostID); err != nil {
			http.Error(w, "host not found", http.StatusNotFound)
			return
		}
	}
	if err := s.db.CreateScanRequest(r.Context(), &req); err != nil {
		log.Printf("create scan request: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	s.audit(r, "scan_request.create", "scan_request", req.ID, "ok", map[string]any{
		"host_id":       req.HostID,
		"scan_type":     req.ScanType,
		"packages_only": req.PackagesOnly,
		"reason":        req.Reason,
	})
	writeJSON(w, http.StatusAccepted, req)
}

func normalizeScanRequestCreate(req *models.ScanRequest) error {
	req.HostID = strings.TrimSpace(req.HostID)
	req.RequestedBy = strings.TrimSpace(req.RequestedBy)
	req.ScanType = strings.TrimSpace(req.ScanType)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.RequestedBy == "" {
		req.RequestedBy = "api"
	}
	if req.ScanType == "" {
		req.ScanType = "manual"
	}
	if !validScanRequestType(req.ScanType) {
		return fmt.Errorf("invalid scan_type")
	}
	req.Status = "pending"
	req.ErrorMessage = ""
	req.SecurityDBRevision = strings.TrimSpace(req.SecurityDBRevision)
	req.ClaimedByHostID = ""
	req.ClaimedAt = nil
	req.CompletedAt = nil
	return nil
}

func validScanRequestType(scanType string) bool {
	switch scanType {
	case "manual", "daily", "security-db-update":
		return true
	default:
		return false
	}
}

func (s *Server) handleClaimScanRequest(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAgent(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	hostID := r.URL.Query().Get("host_id")
	if hostID == "" {
		http.Error(w, "host_id is required", http.StatusBadRequest)
		return
	}
	if err := s.verifyAgentHostBinding(r, hostID); err != nil {
		s.audit(r, "scan_request.claim", "host", hostID, "forbidden", map[string]any{"reason": err.Error()})
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	timeoutMinutes := int(scanRequestClaimTimeoutSeconds() / 60)
	req, requeued, err := s.db.ClaimScanRequest(r.Context(), hostID, time.Duration(timeoutMinutes)*time.Minute)
	if err != nil {
		log.Printf("claim scan request: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if requeued > 0 {
		s.audit(r, "scan_request.requeue_stale", "scan_request", "stale_claims", "ok", map[string]any{
			"timeout_minutes": timeoutMinutes,
			"requeued":        requeued,
			"trigger":         "agent_claim",
		})
	}
	if req == nil {
		writeJSON(w, http.StatusOK, map[string]any{"request": nil})
		return
	}
	s.audit(r, "scan_request.claim", "scan_request", req.ID, "ok", map[string]any{
		"host_id":              hostID,
		"target_host_id":       req.HostID,
		"scan_type":            req.ScanType,
		"packages_only":        req.PackagesOnly,
		"security_db_revision": req.SecurityDBRevision,
	})
	writeJSON(w, http.StatusOK, map[string]any{"request": req})
}

func (s *Server) handleCompleteScanRequest(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAgent(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := r.PathValue("id")
	var body struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		HostID  string `json:"host_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	body.HostID = strings.TrimSpace(body.HostID)
	body.Status = strings.TrimSpace(body.Status)
	if body.Status == "" {
		body.Status = "completed"
	}
	if err := s.verifyAgentHostBinding(r, body.HostID); err != nil {
		s.audit(r, "scan_request.complete", "host", body.HostID, "forbidden", map[string]any{"reason": err.Error()})
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := s.db.CompleteClaimedScanRequest(r.Context(), id, body.HostID, body.Status, body.Message); err != nil {
		log.Printf("complete scan request: %v", err)
		http.Error(w, scanRequestErrorMessage(err), scanRequestErrorStatus(err))
		return
	}
	req, _ := s.db.GetScanRequest(r.Context(), id)
	s.audit(r, "scan_request.complete", "scan_request", id, body.Status, scanRequestAuditMeta(req, body.Message, body.HostID))
	writeJSON(w, http.StatusOK, map[string]string{"status": body.Status})
}

func scanRequestAuditMeta(req *models.ScanRequest, message, completedByHostID string) map[string]any {
	meta := map[string]any{}
	if message != "" {
		meta["message"] = message
	}
	if completedByHostID != "" {
		meta["host_id"] = completedByHostID
	}
	if req == nil {
		return meta
	}
	meta["target_host_id"] = req.HostID
	meta["requested_by"] = req.RequestedBy
	meta["scan_type"] = req.ScanType
	meta["packages_only"] = req.PackagesOnly
	meta["reason"] = req.Reason
	meta["security_db_revision"] = req.SecurityDBRevision
	meta["claimed_by_host_id"] = req.ClaimedByHostID
	return meta
}

func scanRequestErrorStatus(err error) int {
	switch {
	case errors.Is(err, db.ErrInvalidScanRequestStatus):
		return http.StatusBadRequest
	case errors.Is(err, db.ErrScanRequestNotFound):
		return http.StatusNotFound
	case errors.Is(err, db.ErrScanRequestNotActive):
		return http.StatusConflict
	case errors.Is(err, db.ErrScanRequestClaimMismatch):
		return http.StatusForbidden
	case errors.Is(err, db.ErrScanRequestNotRetryable):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func scanRequestErrorMessage(err error) string {
	switch {
	case errors.Is(err, db.ErrInvalidScanRequestStatus):
		return "invalid scan request status"
	case errors.Is(err, db.ErrScanRequestNotFound):
		return "scan request not found"
	case errors.Is(err, db.ErrScanRequestNotActive):
		return "scan request is not pending or claimed"
	case errors.Is(err, db.ErrScanRequestClaimMismatch):
		return "scan request was not claimed by this host"
	case errors.Is(err, db.ErrScanRequestNotRetryable):
		return "scan request is not failed, degraded, or cancelled"
	default:
		return "db error"
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	isAdmin := s.authenticateAdmin(r)
	resp := map[string]any{
		"status":                 "ok",
		"trivy_db_ready":         false,
		"web_auth":               s.webAuth,
		"security_recalculation": s.securityRecalculationStatus(isAdmin),
	}
	if err := s.db.PingContext(r.Context()); err != nil {
		resp["status"] = "degraded"
		resp["db_error"] = "connection failed"
	}
	for k, v := range s.securityDBRevisionMeta(r.Context()) {
		if k == "security_db_revision" || isAdmin {
			resp[k] = v
		}
	}
	if s.db != nil {
		freshness := s.securityDBFreshnessStatus(r.Context(), isAdmin)
		resp["security_db_freshness"] = freshness
		if status, _ := freshness["status"].(string); status != "" && status != "ok" {
			resp["status"] = "degraded"
		}
	}
	if s.dbMgr != nil {
		resp["trivy_db_ready"] = s.dbMgr.IsReady()
		if lu := s.dbMgr.LastUpdate(); !lu.IsZero() {
			resp["trivy_db_last_update"] = lu.Format("2006-01-02T15:04:05Z07:00")
		}
		if isAdmin {
			resp["trivy_db"] = s.dbMgr.Status()
		} else {
			resp["trivy_db"] = s.dbMgr.PublicStatus()
		}
	}
	if s.secMgr != nil {
		if isAdmin {
			resp["security_db"] = s.secMgr.Status()
		} else {
			resp["security_db"] = s.secMgr.PublicStatus()
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) securityDBFreshnessStatus(ctx context.Context, includeDetails bool) map[string]any {
	maxAgeHours := envFloat("BONGSU_SECURITY_DB_MAX_SOURCE_AGE_HOURS", defaultSecurityDBMaxSourceAgeHours)
	if maxAgeHours < 0 {
		maxAgeHours = defaultSecurityDBMaxSourceAgeHours
	}
	maxAge := time.Duration(maxAgeHours * float64(time.Hour))
	resp := map[string]any{
		"max_age_hours": maxAgeHours,
	}
	if s.db == nil {
		resp["status"] = "unavailable"
		resp["stale"] = true
		return resp
	}
	stats, err := s.db.GetCveSourceStats(ctx)
	if err != nil {
		resp["status"] = "error"
		resp["stale"] = true
		resp["source_count"] = 0
		if includeDetails {
			resp["error"] = err.Error()
		}
		return resp
	}
	resp["source_count"] = len(stats)
	if len(stats) == 0 {
		resp["status"] = "empty"
		resp["stale"] = true
		if includeDetails {
			resp["stale_sources"] = []map[string]any{}
		}
		return resp
	}

	now := time.Now()
	var oldestSource string
	var oldestLastUpdate *time.Time
	var oldestAge time.Duration
	staleSources := make([]map[string]any, 0)
	for _, stat := range stats {
		source := stat.Source
		sourceStatus := map[string]any{"source": source}
		isStale := false
		if stat.LastUpdate == nil {
			isStale = true
		} else {
			age := now.Sub(*stat.LastUpdate)
			if age < 0 {
				age = 0
			}
			if oldestLastUpdate == nil || age > oldestAge {
				oldestSource = source
				oldestLastUpdate = stat.LastUpdate
				oldestAge = age
			}
			sourceStatus["last_update"] = stat.LastUpdate.Format(time.RFC3339)
			sourceStatus["age_seconds"] = age.Seconds()
			if maxAge > 0 && age > maxAge {
				isStale = true
			}
		}
		if isStale {
			staleSources = append(staleSources, sourceStatus)
		}
	}
	if oldestLastUpdate != nil {
		resp["oldest_source"] = oldestSource
		resp["oldest_last_update"] = oldestLastUpdate.Format(time.RFC3339)
		resp["oldest_age_seconds"] = oldestAge.Seconds()
	} else if len(stats) > 0 {
		resp["oldest_source"] = stats[0].Source
	}
	if len(staleSources) > 0 {
		resp["status"] = "stale"
		resp["stale"] = true
	} else {
		resp["status"] = "ok"
		resp["stale"] = false
	}
	if includeDetails {
		resp["stale_sources"] = staleSources
	}
	return resp
}

func (s *Server) handleAdminMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	io.WriteString(w, s.adminMetrics(r.Context()))
}

func (s *Server) adminMetrics(ctx context.Context) string {
	var b strings.Builder
	writePromGauge(&b, "bongsu_build_info", map[string]string{"service": "bongsu"}, 1)
	if s.db != nil {
		stats := s.db.Stats()
		writePromGauge(&b, "bongsu_database_max_open_connections", nil, float64(stats.MaxOpenConnections))
		writePromGauge(&b, "bongsu_database_open_connections", nil, float64(stats.OpenConnections))
		writePromGauge(&b, "bongsu_database_in_use_connections", nil, float64(stats.InUse))
		writePromGauge(&b, "bongsu_database_idle_connections", nil, float64(stats.Idle))
		writePromCounter(&b, "bongsu_database_wait_total", nil, float64(stats.WaitCount))
		writePromCounter(&b, "bongsu_database_wait_duration_seconds_total", nil, stats.WaitDuration.Seconds())
		writePromCounter(&b, "bongsu_database_max_idle_closed_total", nil, float64(stats.MaxIdleClosed))
		writePromCounter(&b, "bongsu_database_max_idle_time_closed_total", nil, float64(stats.MaxIdleTimeClosed))
		writePromCounter(&b, "bongsu_database_max_lifetime_closed_total", nil, float64(stats.MaxLifetimeClosed))
	}
	recalc := s.securityRecalculationStatus(true)
	writePromGauge(&b, "bongsu_security_recalculation_running", nil, boolMetric(recalc["running"]))
	writePromGauge(&b, "bongsu_security_recalculation_pending", nil, boolMetric(recalc["pending"]))
	if s.dbMgr != nil && s.dbMgr.IsReady() {
		writePromGauge(&b, "bongsu_trivy_db_ready", nil, 1)
	} else {
		writePromGauge(&b, "bongsu_trivy_db_ready", nil, 0)
	}
	if s.db != nil {
		if hosts, err := s.db.ListHosts(ctx); err == nil {
			agentStatusCounts := map[string]int{}
			agentVersionCounts := map[string]int{}
			now := time.Now()
			for _, host := range hosts {
				applyAgentStatus(&host, now)
				status := host.AgentStatus
				if status == "" {
					status = "unknown"
				}
				version := strings.TrimSpace(host.AgentVersion)
				if version == "" {
					version = "unknown"
				}
				agentStatusCounts[status]++
				agentVersionCounts[version]++
			}
			for _, status := range []string{"online", "stale", "offline", "unknown"} {
				writePromGauge(&b, "bongsu_agent_hosts", map[string]string{"status": status}, float64(agentStatusCounts[status]))
			}
			for version, count := range agentVersionCounts {
				writePromGauge(&b, "bongsu_agent_version_hosts", map[string]string{"version": version}, float64(count))
			}
		} else {
			writePromGauge(&b, "bongsu_agent_metrics_error", nil, 1)
		}
		if hosts, err := s.db.ListHosts(ctx); err == nil {
			inventoryStaleAfter := time.Duration(envInt("BONGSU_INVENTORY_STALE_HOURS", 48)) * time.Hour
			inventory, err := s.db.GetHostInventorySummaries(ctx)
			if err == nil {
				inventoryStatusCounts := map[string]int{}
				totalPackages := 0
				totalVulns := 0
				totalContainers := 0
				now := time.Now()
				for _, host := range hosts {
					summary := inventory[host.ID]
					status := hostInventoryStatus(summary, now, inventoryStaleAfter)
					inventoryStatusCounts[status]++
					totalPackages += summary.PackageCount
					totalVulns += summary.VulnCount
					totalContainers += summary.ContainerCount
				}
				for _, status := range []string{"healthy", "degraded", "stale", "empty", "none"} {
					writePromGauge(&b, "bongsu_inventory_hosts", map[string]string{"status": status}, float64(inventoryStatusCounts[status]))
				}
				writePromGauge(&b, "bongsu_inventory_latest_packages", nil, float64(totalPackages))
				writePromGauge(&b, "bongsu_inventory_latest_vulnerabilities", nil, float64(totalVulns))
				writePromGauge(&b, "bongsu_inventory_latest_containers", nil, float64(totalContainers))
			} else {
				writePromGauge(&b, "bongsu_inventory_metrics_error", nil, 1)
			}
		} else {
			writePromGauge(&b, "bongsu_inventory_metrics_error", nil, 1)
		}
		triageExpiringSoonDays := envInt("BONGSU_TRIAGE_EXPIRING_SOON_DAYS", 14)
		if triageExpiringSoonDays <= 0 {
			triageExpiringSoonDays = 14
		}
		writePromGauge(&b, "bongsu_vulnerability_triage_expiring_soon_days", nil, float64(triageExpiringSoonDays))
		if triageCounts, err := s.db.CountVulnerabilityTriageByStatus(ctx); err == nil {
			for _, count := range triageCounts {
				writePromGauge(&b, "bongsu_vulnerability_triage_decisions", map[string]string{"status": count.Status, "state": count.State}, float64(count.Count))
			}
		} else {
			writePromGauge(&b, "bongsu_vulnerability_triage_metrics_error", nil, 1)
		}
		if expiringCounts, err := s.db.CountVulnerabilityTriageExpiringSoonByStatus(ctx, triageExpiringSoonDays); err == nil {
			for _, status := range []string{"open", "in_progress", "accepted_risk", "false_positive", "fixed", "ignored"} {
				writePromGauge(&b, "bongsu_vulnerability_triage_expiring_soon", map[string]string{"status": status}, float64(expiringCounts[status]))
			}
		} else {
			writePromGauge(&b, "bongsu_vulnerability_triage_expiring_soon_metrics_error", nil, 1)
		}
		if riskCountsByHost, err := s.db.GetCurrentActionableVulnRiskCountsByHost(ctx, nil); err == nil {
			activeRiskCounts := map[string]int{}
			for _, counts := range riskCountsByHost {
				for riskLevel, count := range counts {
					activeRiskCounts[riskLevel] += count
				}
			}
			for _, riskLevel := range []string{"critical", "high", "medium", "low"} {
				writePromGauge(&b, "bongsu_active_vulnerabilities_by_risk_level", map[string]string{"risk_level": riskLevel}, float64(activeRiskCounts[riskLevel]))
			}
		} else {
			writePromGauge(&b, "bongsu_active_vulnerability_risk_metrics_error", nil, 1)
		}
		freshness := s.securityDBFreshnessStatus(ctx, true)
		writePromGauge(&b, "bongsu_security_db_source_stale", nil, boolMetric(freshness["stale"]))
		if count, ok := freshness["source_count"].(int); ok {
			writePromGauge(&b, "bongsu_security_db_source_count", nil, float64(count))
		}
		if oldestAge, ok := freshness["oldest_age_seconds"].(float64); ok {
			writePromGauge(&b, "bongsu_security_db_source_oldest_age_seconds", nil, oldestAge)
		}
		if status, _ := freshness["status"].(string); status == "error" {
			writePromGauge(&b, "bongsu_security_db_freshness_metrics_error", nil, 1)
		}
		if sourceStats, err := s.db.GetCveSourceStats(ctx); err == nil {
			for _, stat := range sourceStats {
				labels := map[string]string{"source": stat.Source}
				writePromGauge(&b, "bongsu_security_db_source_records", labels, float64(stat.Count))
				writePromGauge(&b, "bongsu_security_db_source_matchable_records", labels, float64(stat.Matchable))
				writePromGauge(&b, "bongsu_security_db_source_matchable_percent", labels, stat.MatchablePercent)
				writePromGauge(&b, "bongsu_security_db_source_with_ecosystem_records", labels, float64(stat.WithEcosystem))
				writePromGauge(&b, "bongsu_security_db_source_with_fixed_records", labels, float64(stat.WithFixed))
				writePromGauge(&b, "bongsu_security_db_source_with_ranges_records", labels, float64(stat.WithRanges))
				writePromGauge(&b, "bongsu_security_db_source_with_cvss_records", labels, float64(stat.WithCVSS))
			}
		} else {
			writePromGauge(&b, "bongsu_security_db_source_quality_metrics_error", nil, 1)
		}
		if revision, err := s.db.GetSecurityDBRevision(ctx); err == nil {
			writePromGauge(&b, "bongsu_security_db_revision_info", map[string]string{"revision": revision}, 1)
			if counts, err := s.db.CountSecurityDBRescanRequestsByStatus(ctx, nil, true, revision); err == nil {
				for _, status := range []string{"pending", "claimed", "completed", "degraded", "failed", "cancelled"} {
					writePromGauge(&b, "bongsu_security_db_rescan_requests", map[string]string{"status": status}, float64(counts[status]))
				}
			} else {
				writePromGauge(&b, "bongsu_security_db_rescan_metrics_error", nil, 1)
			}
		} else {
			writePromGauge(&b, "bongsu_security_db_revision_metrics_error", nil, 1)
		}
	}
	return b.String()
}

func boolMetric(v any) float64 {
	if b, ok := v.(bool); ok && b {
		return 1
	}
	return 0
}

func writePromGauge(b *strings.Builder, name string, labels map[string]string, value float64) {
	writePromMetric(b, "gauge", name, labels, value)
}

func writePromCounter(b *strings.Builder, name string, labels map[string]string, value float64) {
	writePromMetric(b, "counter", name, labels, value)
}

func writePromMetric(b *strings.Builder, metricType, name string, labels map[string]string, value float64) {
	fmt.Fprintf(b, "# TYPE %s %s\n", name, metricType)
	fmt.Fprint(b, name)
	if len(labels) > 0 {
		keys := make([]string, 0, len(labels))
		for k := range labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(b, "%s=\"%s\"", k, prometheusLabelValue(labels[k]))
		}
		b.WriteByte('}')
	}
	fmt.Fprintf(b, " %g\n", value)
}

func prometheusLabelValue(v string) string {
	v = strings.ReplaceAll(v, "\\", "\\\\")
	v = strings.ReplaceAll(v, "\n", "\\n")
	return strings.ReplaceAll(v, "\"", "\\\"")
}

func (s *Server) securityRecalculationStatus(includeReason bool) map[string]any {
	s.securityRecalcMu.Lock()
	defer s.securityRecalcMu.Unlock()
	status := map[string]any{
		"running": s.securityRecalcRunning,
		"pending": s.securityRecalcPending,
	}
	if includeReason && s.securityRecalcReason != "" {
		status["pending_reason"] = s.securityRecalcReason
	}
	return status
}

func (s *Server) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	scanID := r.PathValue("id")
	force := r.URL.Query().Get("force") == "true"
	if err := s.db.DeleteScan(r.Context(), scanID, force); err != nil {
		if errors.Is(err, db.ErrLatestInventoryScan) {
			http.Error(w, "latest inventory scan requires force=true", http.StatusConflict)
			return
		}
		if errors.Is(err, db.ErrScanNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		log.Printf("delete scan %s: %v", scanID, err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	s.audit(r, "scan.delete", "scan", scanID, "ok", map[string]any{"force": force})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleTrivyDBUpload(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.dbMgr == nil {
		http.Error(w, "trivy db manager not available", http.StatusServiceUnavailable)
		return
	}

	uploadLimit := maxTrivyDBUploadBytes()
	r.Body = http.MaxBytesReader(w, r.Body, uploadLimit)
	if err := r.ParseMultipartForm(maxMultipartMemoryBytes()); err != nil {
		http.Error(w, "file too large or invalid form", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("db")
	if err != nil {
		http.Error(w, "missing 'db' file field", http.StatusBadRequest)
		return
	}
	defer file.Close()

	tmpFile, err := os.CreateTemp("", "trivy-db-*.tar.gz")
	if err != nil {
		http.Error(w, "temp file error", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := io.Copy(tmpFile, file); err != nil {
		http.Error(w, "file write error", http.StatusInternalServerError)
		return
	}
	tmpFile.Close()

	if err := s.dbMgr.LoadFromFile(tmpFile.Name()); err != nil {
		log.Printf("load trivy-db: %v", err)
		status := trivyDBLoadErrorStatus(err)
		s.audit(r, "trivy_db.upload", "security_db", "trivy", "error", map[string]any{
			"status": status,
			"error":  err.Error(),
		})
		http.Error(w, trivyDBLoadErrorMessage(err), status)
		return
	}

	s.audit(r, "trivy_db.upload", "security_db", "trivy", "ok", nil)
	s.SecurityDatabaseUpdated("trivy-db upload")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "trivy-db loaded"})
}

func trivyDBLoadErrorStatus(err error) int {
	if errors.Is(err, trivydb.ErrInvalidArchive) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func trivyDBLoadErrorMessage(err error) string {
	if trivyDBLoadErrorStatus(err) == http.StatusBadRequest {
		return "invalid trivy db archive"
	}
	return "failed to load db"
}

func (s *Server) handleTrivyDBUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.dbMgr == nil {
		http.Error(w, "trivy db manager not available", http.StatusServiceUnavailable)
		return
	}

	if err := s.dbMgr.UpdateNow(r.Context()); err != nil {
		log.Printf("trivy-db update failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"status": "error", "message": "download failed"})
		return
	}

	s.audit(r, "trivy_db.update", "security_db", "trivy", "ok", nil)
	s.SecurityDatabaseUpdated("trivy-db update")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"message":        "trivy-db updated",
		"trivy_db_ready": s.dbMgr.IsReady(),
		"last_update":    s.dbMgr.LastUpdate().Format("2006-01-02T15:04:05Z07:00"),
	})
}

func (s *Server) handleSecurityDbUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.secMgr == nil {
		http.Error(w, "security db manager not available", http.StatusServiceUnavailable)
		return
	}
	if err := s.secMgr.UpdateNowWithReason(r.Context(), "security-db update"); err != nil {
		log.Printf("security-db update failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"status": "error", "message": err.Error(), "security_db": s.secMgr.Status()})
		return
	}
	s.audit(r, "security_db.update", "security_db", "aggregate", "ok", nil)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "security_db": s.secMgr.Status()})
}

func (s *Server) handleSecurityDbExport(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	includeTrivy := r.URL.Query().Get("include_trivy") != "false"
	bundleFile, cveCount, trivyIncluded, bundleSize, revision, err := s.buildSecurityDBBundleTemp(r.Context(), includeTrivy)
	if err != nil {
		log.Printf("security-db bundle export: %v", err)
		http.Error(w, "export failed", http.StatusInternalServerError)
		return
	}
	defer os.Remove(bundleFile)

	f, err := os.Open(bundleFile)
	if err != nil {
		log.Printf("security-db bundle open: %v", err)
		http.Error(w, "export failed", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=bongsu-security-db-bundle.tar.gz")
	w.Header().Set("Content-Length", strconv.FormatInt(bundleSize, 10))
	if _, err := io.Copy(w, f); err != nil {
		log.Printf("security-db bundle copy: %v", err)
		return
	}
	s.audit(r, "security_db.export", "security_db", "bundle", "ok", map[string]any{
		"cve_records":          cveCount,
		"trivy_db_included":    trivyIncluded,
		"bytes":                bundleSize,
		"security_db_revision": revision,
	})
}

func (s *Server) buildSecurityDBBundleTemp(ctx context.Context, includeTrivy bool) (string, int, bool, int64, string, error) {
	cveFile, cveCount, cveSHA, err := s.writeCveJSONLTemp(ctx, "")
	if err != nil {
		return "", 0, false, 0, "", err
	}
	defer os.Remove(cveFile)

	var trivyBytes []byte
	trivySHA := ""
	if includeTrivy && s.dbMgr != nil && s.dbMgr.IsReady() {
		if b, err := s.dbMgr.ArchiveBytes(); err == nil {
			trivyBytes = b
			sum := sha256.Sum256(b)
			trivySHA = hex.EncodeToString(sum[:])
		} else {
			log.Printf("security-db bundle trivy export skipped: %v", err)
		}
	}

	sourceStats, _ := s.db.GetCveSourceStats(ctx)
	revision, err := s.db.GetSecurityDBRevision(ctx)
	if err != nil {
		return "", 0, false, 0, "", err
	}
	manifest := securityDBBundleManifest{
		Format:             "bongsu-security-db-bundle",
		Version:            1,
		CreatedAt:          time.Now().UTC().Format(time.RFC3339),
		SecurityDBRevision: revision,
		CveRecords:         cveCount,
		CveDatabaseSHA256:  cveSHA,
		TrivyDBIncluded:    len(trivyBytes) > 0,
		TrivyDBSHA256:      trivySHA,
		Sources:            sourceStats,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", 0, false, 0, "", err
	}

	tmp, err := os.CreateTemp("", "bongsu-security-db-bundle-*.tar.gz")
	if err != nil {
		return "", 0, false, 0, "", err
	}
	path := tmp.Name()
	cleanup := func(err error) (string, int, bool, int64, string, error) {
		tmp.Close()
		os.Remove(path)
		return "", 0, false, 0, "", err
	}

	gz := gzip.NewWriter(tmp)
	tw := tar.NewWriter(gz)
	if err := writeTarBytes(tw, "manifest.json", manifestBytes); err != nil {
		return cleanup(err)
	}
	if err := writeTarFile(tw, "cve-database.jsonl", cveFile); err != nil {
		return cleanup(err)
	}
	if len(trivyBytes) > 0 {
		if err := writeTarBytes(tw, "trivy-db.tar.gz", trivyBytes); err != nil {
			return cleanup(err)
		}
	}
	if err := tw.Close(); err != nil {
		return cleanup(err)
	}
	if err := gz.Close(); err != nil {
		return cleanup(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(path)
		return "", 0, false, 0, "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		os.Remove(path)
		return "", 0, false, 0, "", err
	}
	return path, cveCount, len(trivyBytes) > 0, info.Size(), revision, nil
}

func (s *Server) handleSecurityDbImport(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	fail := func(status int, msg, stage string, err error) {
		meta := map[string]any{"stage": stage, "message": msg}
		if err != nil {
			meta["error"] = err.Error()
		}
		s.audit(r, "security_db.import", "security_db", "bundle", "error", meta)
		http.Error(w, msg, status)
	}
	uploadLimit := maxSecurityDBBundleBytes()
	r.Body = http.MaxBytesReader(w, r.Body, uploadLimit)
	if err := r.ParseMultipartForm(maxMultipartMemoryBytes()); err != nil {
		fail(http.StatusBadRequest, "file too large or invalid form", "parse_form", err)
		return
	}
	file, _, err := r.FormFile("bundle")
	if err != nil {
		fail(http.StatusBadRequest, "missing 'bundle' file field", "form_file", err)
		return
	}
	defer file.Close()

	gz, err := gzip.NewReader(file)
	if err != nil {
		fail(http.StatusBadRequest, "invalid gzip bundle", "gzip", err)
		return
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	imported := 0
	var manifest *securityDBBundleManifest
	var cveFile string
	var cveSHA string
	var trivyArchive string
	var trivySHA string
	defer func() {
		if cveFile != "" {
			os.Remove(cveFile)
		}
		if trivyArchive != "" {
			os.Remove(trivyArchive)
		}
	}()
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			fail(http.StatusBadRequest, "invalid tar bundle", "tar", err)
			return
		}
		if err := validateSecurityDBBundleEntry(hdr); err != nil {
			fail(http.StatusBadRequest, err.Error(), "tar_entry", err)
			return
		}
		switch hdr.Name {
		case "manifest.json":
			if manifest != nil {
				fail(http.StatusBadRequest, "duplicate manifest.json", "manifest", nil)
				return
			}
			var m securityDBBundleManifest
			if err := json.NewDecoder(tr).Decode(&m); err != nil {
				fail(http.StatusBadRequest, "invalid bundle manifest", "manifest", err)
				return
			}
			if m.Format != "bongsu-security-db-bundle" {
				fail(http.StatusBadRequest, "unsupported bundle format", "manifest", nil)
				return
			}
			manifest = &m
		case "cve-database.jsonl":
			if cveFile != "" {
				fail(http.StatusBadRequest, "duplicate cve-database.jsonl", "cve", nil)
				return
			}
			cveFile, cveSHA, err = writeBundleEntryTemp(tr, "bongsu-bundle-cve-*.jsonl")
			if err != nil {
				fail(http.StatusInternalServerError, "cve archive write failed", "stage_cve", err)
				return
			}
		case "trivy-db.tar.gz":
			if trivyArchive != "" {
				fail(http.StatusBadRequest, "duplicate trivy-db.tar.gz", "trivy", nil)
				return
			}
			trivyArchive, trivySHA, err = writeBundleEntryTemp(tr, "bongsu-bundle-trivy-db-*.tar.gz")
			if err != nil {
				fail(http.StatusInternalServerError, "trivy archive write failed", "stage_trivy", err)
				return
			}
		}
	}
	if err := validateSecurityDBBundle(manifest, cveFile, cveSHA, trivyArchive, trivySHA); err != nil {
		fail(http.StatusBadRequest, err.Error(), "validate", err)
		return
	}
	if trivyArchive != "" && s.dbMgr == nil {
		fail(http.StatusServiceUnavailable, "bundle contains trivy db but manager is unavailable", "precondition", nil)
		return
	}
	if trivyArchive != "" {
		if err := s.dbMgr.ValidateArchive(trivyArchive); err != nil {
			log.Printf("security-db bundle trivy validation: %v", err)
			fail(http.StatusBadRequest, "trivy db archive validation failed", "validate_trivy", err)
			return
		}
	}
	cveReader, err := os.Open(cveFile)
	if err != nil {
		fail(http.StatusInternalServerError, "cve archive read failed", "read_cve", err)
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		cveReader.Close()
		fail(http.StatusInternalServerError, "cve import transaction failed", "begin_tx", err)
		return
	}
	if _, err := s.db.DeleteAllCveEntriesTx(r.Context(), tx); err != nil {
		cveReader.Close()
		tx.Rollback()
		fail(http.StatusInternalServerError, "cve import reset failed", "reset_cve", err)
		return
	}
	imported, err = s.importCveJSONLTx(r.Context(), cveReader, "", tx)
	cveReader.Close()
	if err != nil {
		tx.Rollback()
		log.Printf("security-db bundle cve import: %v", err)
		fail(cveImportErrorStatus(err), cveImportErrorMessage(err), "import_cve", err)
		return
	}
	if imported == 0 {
		tx.Rollback()
		fail(http.StatusBadRequest, "no valid cve entries found", "import_cve", errNoValidCveEntries)
		return
	}
	if err := tx.Commit(); err != nil {
		fail(http.StatusInternalServerError, "cve import commit failed", "commit_cve", err)
		return
	}
	trivyLoaded := false
	if trivyArchive != "" {
		if err := s.dbMgr.LoadFromFile(trivyArchive); err != nil {
			log.Printf("security-db bundle trivy import: %v", err)
			fail(http.StatusInternalServerError, "trivy db import failed after cve commit", "import_trivy", err)
			return
		}
		trivyLoaded = true
	}
	s.audit(r, "security_db.import", "security_db", "bundle", "ok", map[string]any{
		"imported":             imported,
		"trivy_db_loaded":      trivyLoaded,
		"security_db_revision": manifest.SecurityDBRevision,
	})
	s.SecurityDatabaseUpdated("security-db bundle import")
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "imported": imported, "trivy_db_loaded": trivyLoaded})
}

type securityDBBundleManifest struct {
	Format             string              `json:"format"`
	Version            int                 `json:"version"`
	CreatedAt          string              `json:"created_at"`
	SecurityDBRevision string              `json:"security_db_revision,omitempty"`
	CveRecords         int                 `json:"cve_records"`
	CveDatabaseSHA256  string              `json:"cve_database_sha256"`
	TrivyDBIncluded    bool                `json:"trivy_db_included"`
	TrivyDBSHA256      string              `json:"trivy_db_sha256"`
	Sources            []db.CveSourceStats `json:"sources,omitempty"`
}

var errNoValidCveEntries = errors.New("no valid cve entries")
var errInvalidCveSource = errors.New("invalid cve source")

func writeBundleEntryTemp(r io.Reader, pattern string) (string, string, error) {
	tmp, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", "", err
	}
	path := tmp.Name()
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, hash), r); err != nil {
		tmp.Close()
		os.Remove(path)
		return "", "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(path)
		return "", "", err
	}
	return path, hex.EncodeToString(hash.Sum(nil)), nil
}

func validateSecurityDBBundle(manifest *securityDBBundleManifest, cveFile, cveSHA, trivyArchive, trivySHA string) error {
	if manifest == nil {
		return fmt.Errorf("missing bundle manifest")
	}
	if manifest.Version != 1 {
		return fmt.Errorf("unsupported bundle version")
	}
	if cveFile == "" {
		return fmt.Errorf("missing cve-database.jsonl")
	}
	if manifest.CveDatabaseSHA256 == "" {
		return fmt.Errorf("missing cve database checksum")
	}
	if !strings.EqualFold(manifest.CveDatabaseSHA256, cveSHA) {
		return fmt.Errorf("cve database checksum mismatch")
	}
	if manifest.TrivyDBIncluded && trivyArchive == "" {
		return fmt.Errorf("manifest requires trivy db but archive is missing")
	}
	if trivyArchive != "" {
		if manifest.TrivyDBSHA256 == "" {
			return fmt.Errorf("missing trivy db checksum")
		}
		if !strings.EqualFold(manifest.TrivyDBSHA256, trivySHA) {
			return fmt.Errorf("trivy db checksum mismatch")
		}
	}
	return nil
}

func validateSecurityDBBundleEntry(hdr *tar.Header) error {
	if hdr == nil {
		return fmt.Errorf("invalid tar entry")
	}
	if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
		return fmt.Errorf("unsupported bundle entry type: %s", hdr.Name)
	}
	switch hdr.Name {
	case "manifest.json", "cve-database.jsonl", "trivy-db.tar.gz":
		return nil
	default:
		return fmt.Errorf("unexpected bundle entry: %s", hdr.Name)
	}
}

func (s *Server) SecurityDatabaseUpdated(reason string) {
	meta := s.securityDBChangedMeta(reason)
	s.auditSystem("security_db.changed", "security_db", "aggregate", "ok", meta)
	if s.notifier.Enabled() {
		s.notifier.Send("security_db.updated", meta)
	}
	s.recalculateSecurityFindings(reason)
}

func (s *Server) securityDBChangedMeta(reason string) map[string]any {
	meta := map[string]any{"reason": reason}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for k, v := range s.securityDBRevisionMeta(ctx) {
		meta[k] = v
	}
	return meta
}

func (s *Server) SecurityDatabaseSyncFailed(reason string, err error) {
	meta := map[string]any{"reason": reason}
	if err != nil {
		meta["error"] = err.Error()
	}
	s.auditSystem("security_db.update", "security_db", "aggregate", "error", meta)
}

func (s *Server) recalculateSecurityFindings(reason string) {
	s.securityRecalcMu.Lock()
	if s.securityRecalcRunning {
		s.securityRecalcPending = true
		s.securityRecalcReason = coalesceSecurityRecalcReason(s.securityRecalcReason, reason)
		s.securityRecalcMu.Unlock()
		log.Printf("security recalculation already running; queued another pass (%s)", reason)
		s.auditSystem("security_db.recalculation", "security_db", "aggregate", "queued", map[string]any{"reason": reason})
		return
	}
	s.securityRecalcRunning = true
	s.securityRecalcMu.Unlock()

	go func() {
		for currentReason := reason; ; {
			s.runSecurityRecalculation(currentReason)

			s.securityRecalcMu.Lock()
			if !s.securityRecalcPending {
				s.securityRecalcRunning = false
				s.securityRecalcMu.Unlock()
				return
			}
			currentReason = s.securityRecalcReason
			s.securityRecalcPending = false
			s.securityRecalcReason = ""
			s.securityRecalcMu.Unlock()
		}
	}()
}

func (s *Server) runSecurityRecalculation(reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	log.Printf("security recalculation started (%s)", reason)
	s.auditSystem("security_db.recalculation", "security_db", "aggregate", "started", map[string]any{"reason": reason})
	meta := map[string]any{"reason": reason}
	failures := []string{}
	if n, err := s.db.CalcCvssScores(ctx); err != nil {
		log.Printf("security recalculation cvss failed: %v", err)
		failures = append(failures, "cvss: "+err.Error())
	} else if n > 0 {
		log.Printf("security recalculation updated CVSS for %d CVE records", n)
		meta["cvss_updated"] = n
	} else {
		meta["cvss_updated"] = n
	}
	if n, err := s.db.EnrichVulnerabilities(ctx); err != nil {
		log.Printf("security recalculation enrich failed: %v", err)
		failures = append(failures, "enrich: "+err.Error())
	} else if n > 0 {
		log.Printf("security recalculation enriched %d findings", n)
		meta["findings_enriched"] = n
	} else {
		meta["findings_enriched"] = n
	}
	if n, err := s.db.RemoveStaleRematchedVulnerabilities(ctx); err != nil {
		log.Printf("security recalculation stale rematch cleanup failed: %v", err)
		failures = append(failures, "stale_rematch_cleanup: "+err.Error())
	} else if n > 0 {
		log.Printf("security recalculation removed %d stale CVE DB rematch findings", n)
		meta["stale_rematch_removed"] = n
	} else {
		meta["stale_rematch_removed"] = n
	}
	if r, err := s.db.RematchCVEs(ctx, rematchOptionsFromEnv()); err != nil {
		log.Printf("security recalculation rematch failed: %v", err)
		failures = append(failures, "rematch: "+err.Error())
	} else {
		log.Printf("security recalculation rematched candidates=%d new=%d skipped=%d limited=%v limit=%d", r.Matched, r.NewVulns, r.Skipped, r.Limited, r.CandidateLimit)
		meta["rematch_candidates"] = r.Matched
		meta["rematch_new_vulns"] = r.NewVulns
		meta["rematch_skipped"] = r.Skipped
		meta["rematch_limited"] = r.Limited
		meta["rematch_candidate_limit"] = r.CandidateLimit
	}
	if n, err := s.db.NormalizeVulnSeverity(ctx); err != nil {
		log.Printf("security recalculation severity normalization failed: %v", err)
		failures = append(failures, "severity: "+err.Error())
	} else if n > 0 {
		log.Printf("security recalculation normalized %d findings", n)
		meta["severity_normalized"] = n
	} else {
		meta["severity_normalized"] = n
	}
	log.Printf("security recalculation finished (%s)", reason)
	status := "ok"
	if len(failures) > 0 {
		status = "error"
		meta["errors"] = failures
	}
	s.auditSystem("security_db.recalculation", "security_db", "aggregate", status, meta)
	s.queueSecurityDBRescans(reason, status)
}

func coalesceSecurityRecalcReason(previous, next string) string {
	if previous == "" {
		return next
	}
	if previous == next {
		return previous
	}
	for _, existing := range strings.Split(previous, "; ") {
		if existing == next {
			return previous
		}
	}
	return previous + "; " + next
}

func (s *Server) queueSecurityDBRescans(reason, recalculationStatus string) {
	if !envBool("BONGSU_AUTO_RESCAN_ON_DB_UPDATE", true) {
		log.Printf("security-db auto rescan disabled (%s)", reason)
		s.auditSystem("security_db.auto_rescan", "scan_request", "security-db-update", "disabled", map[string]any{
			"reason":               reason,
			"recalculation_status": recalculationStatus,
		})
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		lookbackHours := envInt("BONGSU_AUTO_RESCAN_LAST_SEEN_HOURS", 720)
		var lastSeenAfter time.Time
		if lookbackHours > 0 {
			lastSeenAfter = time.Now().Add(-time.Duration(lookbackHours) * time.Hour)
		}
		revision, err := s.db.GetSecurityDBRevision(ctx)
		if err != nil {
			log.Printf("security-db auto rescan revision failed (%s): %v", reason, err)
			s.auditSystem("security_db.auto_rescan", "scan_request", "security-db-update", "error", map[string]any{
				"reason":               reason,
				"recalculation_status": recalculationStatus,
				"last_seen_after":      lastSeenAfter,
				"last_seen_hours":      lookbackHours,
				"error":                err.Error(),
				"stage":                "security_db_revision",
			})
			return
		}
		result, err := s.db.QueueSecurityDBRescans(ctx, "system", reason, revision, lastSeenAfter)
		if err != nil {
			log.Printf("security-db auto rescan queue failed (%s): %v", reason, err)
			s.auditSystem("security_db.auto_rescan", "scan_request", "security-db-update", "error", map[string]any{
				"reason":               reason,
				"recalculation_status": recalculationStatus,
				"last_seen_after":      lastSeenAfter,
				"last_seen_hours":      lookbackHours,
				"security_db_revision": revision,
				"error":                err.Error(),
			})
			return
		}
		log.Printf("security-db auto rescan eligible=%d queued=%d already_pending=%d revision=%s (%s)", result.Eligible, result.Queued, result.AlreadyPending, revision, reason)
		s.auditSystem("security_db.auto_rescan", "scan_request", "security-db-update", "ok", map[string]any{
			"reason":               reason,
			"recalculation_status": recalculationStatus,
			"eligible":             result.Eligible,
			"queued":               result.Queued,
			"already_pending":      result.AlreadyPending,
			"last_seen_after":      lastSeenAfter,
			"last_seen_hours":      lookbackHours,
			"security_db_revision": revision,
		})
	}()
}

func (s *Server) handleCveDbImport(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()

	uploadLimit := maxCveDBImportBytes()
	r.Body = http.MaxBytesReader(w, r.Body, uploadLimit)
	if err := r.ParseMultipartForm(maxMultipartMemoryBytes()); err != nil {
		http.Error(w, "file too large", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "no file provided", http.StatusBadRequest)
		return
	}
	defer file.Close()

	source, err := normalizeCveSource(r.FormValue("source"), "custom")
	if err != nil {
		s.audit(r, "cve_db.import", "cve_db", "invalid", "error", map[string]any{
			"source": r.FormValue("source"),
			"error":  err.Error(),
		})
		http.Error(w, "invalid source", http.StatusBadRequest)
		return
	}

	count, err := s.importCveJSONL(ctx, file, source)
	if err != nil {
		log.Printf("cve-db import: %v", err)
		if errors.Is(err, errNoValidCveEntries) {
			s.audit(r, "cve_db.import", "cve_db", source, "error", map[string]any{
				"source": source,
				"reason": "no valid entries",
			})
			http.Error(w, "no valid entries found", http.StatusBadRequest)
			return
		}
		status := cveImportErrorStatus(err)
		s.audit(r, "cve_db.import", "cve_db", source, "error", map[string]any{
			"source": source,
			"status": status,
			"error":  err.Error(),
		})
		http.Error(w, cveImportErrorMessage(err), status)
		return
	}
	if count == 0 {
		s.audit(r, "cve_db.import", "cve_db", source, "error", map[string]any{
			"source": source,
			"reason": "no valid entries",
		})
		http.Error(w, "no valid entries found", http.StatusBadRequest)
		return
	}

	revisionMeta := s.securityDBRevisionMeta(ctx)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":               "ok",
		"imported":             count,
		"total":                count,
		"security_db_revision": revisionMeta["security_db_revision"],
	})
	auditMeta := map[string]any{
		"imported": count,
		"source":   source,
	}
	for k, v := range revisionMeta {
		auditMeta[k] = v
	}
	s.audit(r, "cve_db.import", "cve_db", source, "ok", auditMeta)
	s.SecurityDatabaseUpdated("cve-db import")
}

func (s *Server) importCveJSONL(ctx context.Context, reader io.Reader, source string) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	source, err = normalizeCveSource(source, "")
	if err != nil {
		return 0, err
	}
	if source != "" {
		if _, err := s.db.DeleteCveEntriesBySourceTx(ctx, tx, source); err != nil {
			return 0, err
		}
	}
	count, err := s.importCveJSONLTx(ctx, reader, source, tx)
	if err != nil {
		return 0, err
	}
	if count == 0 {
		return 0, errNoValidCveEntries
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Server) importCveJSONLTx(ctx context.Context, reader io.Reader, source string, tx *sql.Tx) (int, error) {
	return s.importCveJSONLWithUpsert(ctx, reader, source, func(ctx context.Context, batch []models.CveEntry) (int, error) {
		return s.db.UpsertCveEntriesTx(ctx, tx, batch)
	})
}

func (s *Server) importCveJSONLWithUpsert(ctx context.Context, reader io.Reader, source string, upsert func(context.Context, []models.CveEntry) (int, error)) (int, error) {
	source, err := normalizeCveSource(source, "")
	if err != nil {
		return 0, err
	}
	decoder := json.NewDecoder(reader)
	batch := make([]models.CveEntry, 0, 1000)
	total := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		n, err := upsert(ctx, batch)
		if err != nil {
			return err
		}
		total += n
		batch = batch[:0]
		return nil
	}
	for {
		var e models.CveEntry
		if err := decoder.Decode(&e); err != nil {
			if err == io.EOF {
				break
			}
			return total, err
		}
		if e.VulnerabilityID == "" || strings.HasPrefix(e.VulnerabilityID, "CGA-") {
			continue
		}
		if source != "" {
			e.Source = source
		} else {
			normalized, err := normalizeCveSource(e.Source, "bundle")
			if err != nil {
				return total, err
			}
			e.Source = normalized
		}
		batch = append(batch, e)
		if len(batch) >= 1000 {
			if err := flush(); err != nil {
				return total, err
			}
		}
	}
	return total, flush()
}

func normalizeCveSource(source, fallback string) (string, error) {
	source = strings.ToLower(strings.TrimSpace(source))
	if source == "" {
		source = strings.ToLower(strings.TrimSpace(fallback))
	}
	if source == "" {
		return "", nil
	}
	if len(source) > 64 {
		return "", fmt.Errorf("%w: source is too long", errInvalidCveSource)
	}
	for _, r := range source {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return "", fmt.Errorf("%w: source must contain only lowercase letters, digits, dot, underscore, or hyphen", errInvalidCveSource)
	}
	return source, nil
}

func cveImportErrorStatus(err error) int {
	if errors.Is(err, errInvalidCveSource) {
		return http.StatusBadRequest
	}
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &syntaxErr) || errors.As(err, &typeErr) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func cveImportErrorMessage(err error) string {
	if errors.Is(err, errInvalidCveSource) {
		return "invalid cve source"
	}
	if cveImportErrorStatus(err) == http.StatusBadRequest {
		return "invalid cve jsonl"
	}
	return "import failed"
}

func (s *Server) handleCveDbRematch(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var err error
	opts := rematchOptionsFromEnv()
	if r.Body != nil {
		var body struct {
			Sources                   []string `json:"sources"`
			MinSourceMatchablePercent float64  `json:"min_source_matchable_percent"`
			ScanID                    string   `json:"scan_id"`
			CandidateLimit            int      `json:"candidate_limit"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if len(body.Sources) > 0 {
			opts.Sources = cleanCSV(body.Sources)
		}
		if body.MinSourceMatchablePercent > 0 {
			opts.MinSourceMatchablePercent = body.MinSourceMatchablePercent
		}
		opts.ScanID = strings.TrimSpace(body.ScanID)
		if body.CandidateLimit > 0 {
			opts.CandidateLimit = body.CandidateLimit
		}
	}
	opts, err = normalizeRematchOptions(opts)
	if err != nil {
		http.Error(w, "invalid source", http.StatusBadRequest)
		return
	}
	result, err := s.db.RematchCVEs(r.Context(), opts)
	if err != nil {
		log.Printf("cve-db rematch: %v", err)
		http.Error(w, "rematch failed", http.StatusInternalServerError)
		return
	}
	revisionMeta := s.securityDBRevisionMeta(r.Context())
	if v, ok := revisionMeta["security_db_revision"].(string); ok {
		result.SecurityDBRevision = v
	}
	if v, ok := revisionMeta["security_db_revision_error"].(string); ok {
		result.SecurityDBRevisionError = v
	}
	writeJSON(w, http.StatusOK, result)
	auditMeta := map[string]any{
		"matched":                      result.Matched,
		"new_vulns":                    result.NewVulns,
		"skipped":                      result.Skipped,
		"candidate_limit":              result.CandidateLimit,
		"limited":                      result.Limited,
		"sources":                      opts.Sources,
		"min_source_matchable_percent": opts.MinSourceMatchablePercent,
		"scan_id":                      opts.ScanID,
	}
	for k, v := range revisionMeta {
		auditMeta[k] = v
	}
	s.audit(r, "cve_db.rematch", "cve_db", "all", "ok", auditMeta)
	enriched, _ := s.db.EnrichVulnerabilities(r.Context())
	log.Printf("Enriched %d vulnerabilities with CVE DB data", enriched)
}

func rematchOptionsFromEnv() db.RematchOptions {
	opts, err := normalizeRematchOptions(db.RematchOptions{
		Sources:                   splitCSV(os.Getenv("BONGSU_CVE_MATCH_SOURCES")),
		MinSourceMatchablePercent: envFloat("BONGSU_CVE_MATCH_MIN_SOURCE_MATCHABLE_PERCENT", 0),
		CandidateLimit:            envInt("BONGSU_CVE_MATCH_CANDIDATE_LIMIT", db.DefaultRematchCandidateLimit),
	})
	if err != nil {
		log.Printf("invalid BONGSU_CVE_MATCH_SOURCES ignored: %v", err)
		opts.Sources = nil
	}
	return opts
}

func normalizeRematchOptions(opts db.RematchOptions) (db.RematchOptions, error) {
	var err error
	opts.Sources, err = normalizeCveSources(opts.Sources)
	if err != nil {
		return opts, err
	}
	opts.ScanID = strings.TrimSpace(opts.ScanID)
	if opts.MinSourceMatchablePercent < 0 {
		opts.MinSourceMatchablePercent = 0
	}
	if opts.MinSourceMatchablePercent > 100 {
		opts.MinSourceMatchablePercent = 100
	}
	if opts.CandidateLimit <= 0 {
		opts.CandidateLimit = db.DefaultRematchCandidateLimit
	}
	if opts.CandidateLimit > db.MaxRematchCandidateLimit {
		opts.CandidateLimit = db.MaxRematchCandidateLimit
	}
	return opts, nil
}

func normalizeCveSources(sources []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range sources {
		source, err := normalizeCveSource(raw, "")
		if err != nil {
			return nil, err
		}
		if source == "" || seen[source] {
			continue
		}
		seen[source] = true
		out = append(out, source)
	}
	return out, nil
}

func (s *Server) handleCveDbRecalcCVSS(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	count, err := s.db.RecalcCVSSFromVectors(r.Context())
	if err != nil {
		log.Printf("cvss recalc: %v", err)
		http.Error(w, "recalc failed", http.StatusInternalServerError)
		return
	}
	revisionMeta := s.securityDBRevisionMeta(r.Context())
	auditMeta := map[string]any{"updated": count}
	resp := map[string]any{"status": "ok", "updated": count}
	for k, v := range revisionMeta {
		auditMeta[k] = v
		resp[k] = v
	}
	s.audit(r, "cve_db.recalc_cvss", "cve_db", "all", "ok", auditMeta)
	writeJSON(w, http.StatusOK, resp)
}
func (s *Server) handleCveDbExport(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	source, err := normalizeCveSource(r.URL.Query().Get("source"), "")
	if err != nil {
		http.Error(w, "invalid source", http.StatusBadRequest)
		return
	}
	revisionMeta := s.securityDBRevisionMeta(r.Context())

	cveFile, count, _, err := s.writeCveJSONLTemp(r.Context(), source)
	if err != nil {
		log.Printf("cve-db export: %v", err)
		http.Error(w, "export failed", http.StatusInternalServerError)
		return
	}
	defer os.Remove(cveFile)
	f, err := os.Open(cveFile)
	if err != nil {
		log.Printf("cve-db export open: %v", err)
		http.Error(w, "export failed", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", "attachment; filename=cve-database.jsonl")
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, f); err != nil {
		log.Printf("cve-db export write: %v", err)
		return
	}
	auditMeta := map[string]any{"source": source, "records": count}
	for k, v := range revisionMeta {
		auditMeta[k] = v
	}
	s.audit(r, "cve_db.export", "cve_db", source, "ok", auditMeta)
}

func (s *Server) securityDBRevisionMeta(ctx context.Context) map[string]any {
	meta := map[string]any{}
	revision, err := s.db.GetSecurityDBRevision(ctx)
	if err != nil {
		meta["security_db_revision_error"] = err.Error()
		return meta
	}
	meta["security_db_revision"] = revision
	return meta
}

func (s *Server) writeCveJSONLTemp(ctx context.Context, source string) (string, int, string, error) {
	source, err := normalizeCveSource(source, "")
	if err != nil {
		return "", 0, "", err
	}
	tmp, err := os.CreateTemp("", "bongsu-cve-database-*.jsonl")
	if err != nil {
		return "", 0, "", err
	}
	path := tmp.Name()
	defer tmp.Close()

	q := "SELECT " + db.CveCols + " FROM cve_database"
	args := []any{}
	if source != "" {
		q += " WHERE source=$1"
		args = append(args, source)
	}
	q += " ORDER BY vulnerability_id, source"

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		os.Remove(path)
		return "", 0, "", err
	}
	defer rows.Close()

	hash := sha256.New()
	writer := io.MultiWriter(tmp, hash)
	encoder := json.NewEncoder(writer)
	count := 0
	for rows.Next() {
		var e models.CveEntry
		if err := db.ScanCveEntry(rows, &e); err != nil {
			os.Remove(path)
			return "", 0, "", err
		}
		if err := encoder.Encode(e); err != nil {
			os.Remove(path)
			return "", 0, "", err
		}
		count++
	}
	if err := rows.Err(); err != nil {
		os.Remove(path)
		return "", 0, "", err
	}
	return path, count, hex.EncodeToString(hash.Sum(nil)), nil
}

func writeTarBytes(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0644,
		Size:    int64(len(data)),
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func writeTarFile(tw *tar.Writer, name, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	hdr := &tar.Header{
		Name:    name,
		Mode:    0644,
		Size:    info.Size(),
		ModTime: info.ModTime(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}

func (s *Server) handleCveDbSources(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	sources, err := s.db.GetCveSources(r.Context())
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": sources})
}

func (s *Server) handleRetentionPrune(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body struct {
		DryRun      *bool `json:"dry_run"`
		ScanDays    int   `json:"scan_days"`
		RequestDays int   `json:"request_days"`
		AuditDays   int   `json:"audit_days"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
	}
	if body.ScanDays <= 0 {
		body.ScanDays = envInt("BONGSU_RETENTION_SCAN_DAYS", 180)
	}
	if body.ScanDays <= 0 {
		body.ScanDays = 180
	}
	if body.RequestDays <= 0 {
		body.RequestDays = envInt("BONGSU_RETENTION_SCAN_REQUEST_DAYS", 90)
	}
	if body.RequestDays <= 0 {
		body.RequestDays = 90
	}
	if body.AuditDays <= 0 {
		body.AuditDays = envInt("BONGSU_RETENTION_AUDIT_DAYS", 365)
	}
	if body.AuditDays <= 0 {
		body.AuditDays = 365
	}
	dryRun := true
	if body.DryRun != nil {
		dryRun = *body.DryRun
	}
	result, err := s.db.PruneOperationalData(r.Context(), body.ScanDays, body.RequestDays, body.AuditDays, dryRun)
	if err != nil {
		log.Printf("retention prune: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	status := "dry_run"
	if !dryRun {
		status = "pruned"
	}
	s.audit(r, "retention.prune", "retention", "operational_data", status, map[string]any{
		"dry_run":         result.DryRun,
		"scan_days":       result.ScanDays,
		"request_days":    result.RequestDays,
		"audit_days":      result.AuditDays,
		"scans":           result.Scans,
		"packages":        result.Packages,
		"vulnerabilities": result.Vulns,
		"containers":      result.Containers,
		"users":           result.Users,
		"processes":       result.Processes,
		"ports":           result.Ports,
		"scan_requests":   result.Requests,
		"audit_logs":      result.AuditLogs,
	})
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleUpsertAccessSubject(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body struct {
		ID          string `json:"id"`
		SubjectType string `json:"subject_type"`
		ExternalID  string `json:"external_id"`
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.SubjectType == "" {
		body.SubjectType = "user"
	}
	switch body.SubjectType {
	case "user", "group":
	default:
		http.Error(w, "invalid subject_type", http.StatusBadRequest)
		return
	}
	if body.ExternalID == "" {
		http.Error(w, "external_id is required", http.StatusBadRequest)
		return
	}
	if err := s.db.UpsertAccessSubject(r.Context(), body.ID, body.SubjectType, body.ExternalID, body.DisplayName); err != nil {
		log.Printf("upsert access subject: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	s.audit(r, "rbac.subject.upsert", "access_subject", body.ExternalID, "ok", map[string]any{
		"subject_type": body.SubjectType,
		"display_name": body.DisplayName,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListAccessSubjects(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	items, err := s.db.ListAccessSubjects(r.Context())
	if err != nil {
		log.Printf("list access subjects: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleListAccessPolicies(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	items, err := s.db.ListAccessPolicies(r.Context(), r.URL.Query().Get("subject_external_id"))
	if err != nil {
		log.Printf("list access policies: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleDeleteAccessSubject(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}
	subject, policyCount, err := s.db.DeleteAccessSubject(r.Context(), id)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		log.Printf("delete access subject: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	s.audit(r, "rbac.subject.delete", "access_subject", id, "ok", map[string]any{
		"subject_type":       subject.SubjectType,
		"external_id":        subject.ExternalID,
		"display_name":       subject.DisplayName,
		"revoked_policies":   policyCount,
		"cascade_policy_del": true,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleDeleteAccessPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}
	policy, err := s.db.DeleteAccessPolicy(r.Context(), id)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		log.Printf("delete access policy: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	s.audit(r, "rbac.policy.delete", "access_policy", id, "ok", map[string]any{
		"subject_id":          policy.SubjectID,
		"subject_type":        policy.SubjectType,
		"subject_external_id": policy.SubjectExternalID,
		"resource_type":       policy.ResourceType,
		"resource_id":         policy.ResourceID,
		"permission":          policy.Permission,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleUpsertAccessPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body struct {
		ID                string `json:"id"`
		SubjectID         string `json:"subject_id"`
		SubjectExternalID string `json:"subject_external_id"`
		ResourceType      string `json:"resource_type"`
		ResourceID        string `json:"resource_id"`
		Permission        string `json:"permission"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.SubjectID == "" && body.SubjectExternalID == "" {
		http.Error(w, "subject_id or subject_external_id is required", http.StatusBadRequest)
		return
	}
	if body.ResourceType == "" {
		http.Error(w, "resource_type is required", http.StatusBadRequest)
		return
	}
	switch body.ResourceType {
	case "host", "container", "image", "asset_group", "all":
	default:
		http.Error(w, "invalid resource_type", http.StatusBadRequest)
		return
	}
	if body.Permission == "" {
		body.Permission = "read"
	}
	switch body.Permission {
	case "read", "write", "admin", "export":
	default:
		http.Error(w, "invalid permission", http.StatusBadRequest)
		return
	}
	if err := s.db.UpsertAccessPolicy(r.Context(), body.ID, body.SubjectID, body.SubjectExternalID, body.ResourceType, body.ResourceID, body.Permission); err != nil {
		log.Printf("upsert access policy: %v", err)
		if strings.Contains(err.Error(), "not found") {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	subjectAuditID := body.SubjectExternalID
	if subjectAuditID == "" {
		subjectAuditID = body.SubjectID
	}
	s.audit(r, "rbac.policy.upsert", "access_policy", subjectAuditID, "ok", map[string]any{
		"subject_id":    body.SubjectID,
		"resource_type": body.ResourceType,
		"resource_id":   body.ResourceID,
		"permission":    body.Permission,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	createdFrom, err := auditTimeParam(r, "created_from", false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	createdTo, err := auditTimeParam(r, "created_to", true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if createdFrom != nil && createdTo != nil && createdFrom.After(*createdTo) {
		http.Error(w, "created_from must be before created_to", http.StatusBadRequest)
		return
	}
	filter := db.AuditLogFilter{
		ActorType:    r.URL.Query().Get("actor_type"),
		ActorID:      r.URL.Query().Get("actor_id"),
		Action:       r.URL.Query().Get("action"),
		ResourceType: r.URL.Query().Get("resource_type"),
		ResourceID:   r.URL.Query().Get("resource_id"),
		Status:       r.URL.Query().Get("status"),
		CreatedFrom:  createdFrom,
		CreatedTo:    createdTo,
	}
	items, total, err := s.db.ListAuditLogs(r.Context(), filter, limitParam(r, 100), offsetParam(r))
	if err != nil {
		log.Printf("list audit logs: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

func (s *Server) handleCveDbStats(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	stats, err := s.db.GetCveSourceStats(r.Context())
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": stats})
}

func (s *Server) handleCveDbSearch(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()

	query := r.URL.Query().Get("q")
	severity := r.URL.Query().Get("severity")
	source, err := normalizeCveSource(r.URL.Query().Get("source"), "")
	if err != nil {
		http.Error(w, "invalid source", http.StatusBadRequest)
		return
	}
	minCVSS := floatParam(r, "min_cvss", 0.1)
	sortBy := r.URL.Query().Get("sort_by")
	sortOrder := r.URL.Query().Get("sort_order")
	limit := limitParam(r, 50)
	offset := offsetParam(r)

	entries, total, err := s.db.SearchCveDatabase(ctx, query, severity, source, minCVSS, sortBy, sortOrder, limit, offset)
	if err != nil {
		log.Printf("cve-db search: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items": entries,
		"total": total,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func intParam(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	if n < 0 {
		return def
	}
	return n
}

func limitParam(r *http.Request, def int) int {
	n := intParam(r, "limit", def)
	if n <= 0 {
		n = def
	}
	maxLimit := envInt("BONGSU_API_MAX_PAGE_LIMIT", 1000)
	if maxLimit <= 0 {
		maxLimit = 1000
	}
	if n > maxLimit {
		return maxLimit
	}
	return n
}

func offsetParam(r *http.Request) int {
	n := intParam(r, "offset", 0)
	maxOffset := envInt("BONGSU_API_MAX_PAGE_OFFSET", 1000000)
	if maxOffset <= 0 {
		maxOffset = 1000000
	}
	if n > maxOffset {
		return maxOffset
	}
	return n
}

func auditTimeParam(r *http.Request, key string, endOfDay bool) (*time.Time, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return nil, nil
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return &t, nil
	}
	t, err := time.Parse("2006-01-02", raw)
	if err != nil {
		return nil, fmt.Errorf("invalid %s; use RFC3339 or YYYY-MM-DD", key)
	}
	if endOfDay {
		t = t.Add(24*time.Hour - time.Nanosecond)
	}
	return &t, nil
}

func floatParam(r *http.Request, key string, def float64) float64 {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	if n < 0 {
		return def
	}
	return n
}

func applyAgentStatus(h *models.Host, now time.Time) {
	if h.LastSeen.IsZero() {
		h.AgentStatus = "unknown"
		h.LastSeenAgeS = 0
		return
	}
	age := now.Sub(h.LastSeen)
	if age < 0 {
		age = 0
	}
	h.LastSeenAgeS = int64(age.Seconds())
	online := time.Duration(envInt("BONGSU_AGENT_ONLINE_MINUTES", 26*60)) * time.Minute
	offline := time.Duration(envInt("BONGSU_AGENT_OFFLINE_MINUTES", 72*60)) * time.Minute
	if offline < online {
		offline = online
	}
	switch {
	case age <= online:
		h.AgentStatus = "online"
	case age <= offline:
		h.AgentStatus = "stale"
	default:
		h.AgentStatus = "offline"
	}
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func maxAgentReportBytes() int64 {
	n := envInt("BONGSU_AGENT_REPORT_MAX_BYTES", 512<<20)
	if n <= 0 {
		n = 512 << 20
	}
	return int64(n)
}

func maxTrivyDBUploadBytes() int64 {
	return envBytes("BONGSU_TRIVY_DB_UPLOAD_MAX_BYTES", 2<<30)
}

func maxCveDBImportBytes() int64 {
	return envBytes("BONGSU_CVE_DB_IMPORT_MAX_BYTES", 2<<30)
}

func maxSecurityDBBundleBytes() int64 {
	return envBytes("BONGSU_SECURITY_DB_BUNDLE_MAX_BYTES", 4<<30)
}

func maxMultipartMemoryBytes() int64 {
	return envBytes("BONGSU_MULTIPART_MEMORY_MAX_BYTES", 32<<20)
}

func envBytes(key string, def int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envFloat(key string, def float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return n
}

func splitCSV(v string) []string {
	if v == "" {
		return nil
	}
	return cleanCSV(strings.Split(v, ","))
}

func cleanCSV(items []string) []string {
	out := make([]string, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func sanitizeFilename(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('-')
	}
	return strings.Trim(b.String(), "-.")
}

type requestIDContextKey struct{}

func (s *Server) requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := cleanRequestID(r.Header.Get("X-Request-ID"))
		if rid == "" {
			rid = uuid.NewString()
		}
		w.Header().Set("X-Request-ID", rid)
		ctx := context.WithValue(r.Context(), requestIDContextKey{}, rid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func requestIDFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if rid, ok := r.Context().Value(requestIDContextKey{}).(string); ok {
		return rid
	}
	return cleanRequestID(r.Header.Get("X-Request-ID"))
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.status != 0 {
		return
	}
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(p)
	r.bytes += n
	return n, err
}

func (s *Server) accessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !envBool("BONGSU_ACCESS_LOG", true) {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		if r.URL.Path == "/api/health" && !envBool("BONGSU_ACCESS_LOG_HEALTH", false) {
			return
		}
		log.Printf("access request_id=%s method=%s path=%s status=%d bytes=%d duration_ms=%d ip=%s",
			rec.Header().Get("X-Request-ID"), r.Method, r.URL.Path, status, rec.bytes, time.Since(start).Milliseconds(), clientIP(r))
	})
}

func cleanRequestID(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 128 {
		return ""
	}
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '-', '_', '.', ':', '/':
			continue
		default:
			return ""
		}
	}
	return raw
}

func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic recovered request_id=%s: %v %s %s", requestIDFromRequest(r), err, r.Method, r.URL.Path)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin != "" {
			if s.corsAllowAll || s.corsOrigins[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key, X-Install-Token")
				w.Header().Set("Access-Control-Max-Age", "86400")
			} else if r.Method == "OPTIONS" {
				http.Error(w, "cors origin not allowed", http.StatusForbidden)
				return
			}
		}
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", securityContentPolicy())
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		if strings.HasPrefix(r.URL.Path, "/api/") && w.Header().Get("Cache-Control") == "" {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		}
		if secureRequest(r) && envBool("BONGSU_HSTS_ENABLED", true) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func securityContentPolicy() string {
	return strings.Join([]string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data:",
		"font-src 'self' data:",
		"connect-src 'self'",
		"object-src 'none'",
		"base-uri 'self'",
		"frame-ancestors 'none'",
		"form-action 'self'",
	}, "; ")
}

func secureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}
