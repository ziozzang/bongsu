package api

import (
	"archive/tar"
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
	"strconv"
	"strings"
	"sync"
	"time"

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
	s.mux.HandleFunc("POST /api/scan-requests/requeue-stale", s.handleRequeueStaleScanRequests)
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
	if s.installToken == "" {
		return true
	}
	token := r.Header.Get("X-Install-Token")
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	return s.matchKey(token, s.installToken) || s.authenticateAdmin(r)
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

func (s *Server) auditWebhookResult(event string, data map[string]any, status string, httpStatus int, errMsg string) {
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
	}
	if errMsg != "" {
		meta["error"] = errMsg
	}
	for _, key := range []string{"host_id", "hostname", "inventory_status", "reason"} {
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

	var report models.ScanReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	if report.ScanID == "" {
		report.ScanID = uuid.New().String()
	}

	if report.Host.ID == "" {
		report.Host.ID = uuid.New().String()
	}

	if err := s.db.UpsertHost(ctx, &report.Host); err != nil {
		log.Printf("upsert host: %v", err)
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

	for i := range report.Containers {
		if report.Containers[i].ID == "" {
			report.Containers[i].ID = uuid.New().String()
		}
		report.Containers[i].ScanID = report.ScanID
		report.Containers[i].HostID = report.Host.ID
	}
	if err := s.db.InsertContainers(ctx, report.Containers); err != nil {
		log.Printf("insert containers: %v", err)
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
			} else if result != nil {
				insertedVulns += result.Inserted
				skippedVulns += result.Skipped
			}
			if n, err := s.db.EnrichVulnerabilities(ctx); err == nil && n > 0 {
				log.Printf("Enriched %d vulnerabilities with CVE DB scores", n)
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
	}

	scanStatus := reportScanStatus(skippedVulns)
	if err := s.db.CompleteScan(ctx, report.ScanID, scanStatus); err != nil {
		log.Printf("complete scan: %v", err)
	}
	sevCounts, vulnTotal, err := s.db.GetVulnCountsByScan(ctx, report.ScanID)
	if err != nil {
		log.Printf("scan vuln counts: %v", err)
		sevCounts = map[string]int{}
	}
	inventoryStatus := reportInventoryStatus(len(report.Packages), scanStatus)
	s.audit(r, "agent.report", "scan", report.ScanID, reportAuditStatus(skippedVulns), map[string]any{
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
	})
	if s.notifier.ShouldSendScan(sevCounts, inventoryStatus) {
		s.notifier.Send("scan.completed", reportWebhookPayload(&report, scanStatus, inventoryStatus, insertedVulns, skippedVulns, vulnTotal, sevCounts))
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"scan_id": report.ScanID,
	})
}

func reportAuditStatus(skippedVulns int) string {
	if skippedVulns > 0 {
		return "degraded"
	}
	return "ok"
}

func reportScanStatus(skippedVulns int) string {
	if skippedVulns > 0 {
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

func reportWebhookPayload(report *models.ScanReport, scanStatus, inventoryStatus string, insertedVulns, skippedVulns, vulnTotal int, sevCounts map[string]int) map[string]any {
	return map[string]any{
		"scan_id":          report.ScanID,
		"scan_status":      scanStatus,
		"host_id":          report.Host.ID,
		"hostname":         report.Host.Hostname,
		"ip_address":       report.Host.IPAddress,
		"os_name":          report.Host.OSName,
		"os_version":       report.Host.OSVersion,
		"scan_type":        report.ScanType,
		"inventory_status": inventoryStatus,
		"packages":         len(report.Packages),
		"containers":       len(report.Containers),
		"vulnerabilities":  vulnTotal,
		"vulns_inserted":   insertedVulns,
		"vulns_skipped":    skippedVulns,
		"severity_counts":  sevCounts,
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
	inventory, err := s.db.GetHostInventorySummaries(ctx)
	if err != nil {
		log.Printf("host inventory summaries: %v", err)
		inventory = map[string]db.HostInventorySummary{}
	}

	type hostWithVulns struct {
		models.Host
		VulnCounts      map[string]int          `json:"vuln_counts"`
		LatestInventory db.HostInventorySummary `json:"latest_inventory"`
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
		item := hostWithVulns{Host: h, VulnCounts: vulnCounts[h.ID], LatestInventory: inventory[h.ID]}
		if inventoryStatusFilter != "" && hostInventoryStatus(item.LatestInventory, now, inventoryStaleAfter) != inventoryStatusFilter {
			continue
		}
		if item.VulnCounts == nil {
			item.VulnCounts = map[string]int{}
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
		log.Printf("update host metadata: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	s.audit(r, "host.metadata.update", "host", hostID, "ok", map[string]any{
		"owner":       body.Owner,
		"team":        body.Team,
		"environment": body.Environment,
		"criticality": body.Criticality,
	})
	host, err := s.db.GetHost(r.Context(), hostID)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, host)
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

	limit := intParam(r, "limit", 100)
	offset := intParam(r, "offset", 0)

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
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}
	pkgs, err := s.db.GetLatestPackagesForSBOM(ctx, hostID)
	if err != nil {
		log.Printf("host sbom packages: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if len(pkgs) == 0 {
		http.Error(w, "no packages available for host", http.StatusNotFound)
		return
	}
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
		http.Error(w, "sbom generation failed", http.StatusInternalServerError)
		return
	}
	filename := sanitizeFilename(host.Hostname)
	if filename == "" {
		filename = sanitizeFilename(host.ID)
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s"`, filename, suffix))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(data); err != nil {
		log.Printf("write host sbom: %v", err)
		return
	}
	s.audit(r, "sbom.export", "host", hostID, "ok", map[string]any{
		"hostname": host.Hostname,
		"packages": len(pkgs),
		"format":   auditFormat,
	})
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

	filter, forbidden, empty := s.vulnFilterFromRequest(r)
	if empty {
		writeJSON(w, http.StatusOK, map[string]any{"items": []models.Vulnerability{}, "total": 0})
		return
	}
	if forbidden {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	limit := intParam(r, "limit", 100)
	offset := intParam(r, "offset", 0)

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

func (s *Server) vulnFilterFromRequest(r *http.Request) (db.VulnFilter, bool, bool) {
	hostID := r.URL.Query().Get("host_id")
	scope := s.accessScope(r)
	if scope.Empty() {
		return db.VulnFilter{}, false, true
	}
	if hostID != "" && !scope.CanReadHost(hostID) {
		return db.VulnFilter{}, true, false
	}
	return db.VulnFilter{
		HostID:       hostID,
		HostIDs:      scope.HostIDs,
		Severity:     r.URL.Query().Get("severity"),
		TriageStatus: r.URL.Query().Get("triage_status"),
		Overdue:      r.URL.Query().Get("overdue") == "true",
		PkgName:      r.URL.Query().Get("pkg_name"),
		Container:    r.URL.Query().Get("container"),
		Owner:        r.URL.Query().Get("owner"),
		Team:         r.URL.Query().Get("team"),
		Environment:  r.URL.Query().Get("environment"),
		Criticality:  r.URL.Query().Get("criticality"),
		MinCVSS:      floatParam(r, "min_cvss", 0.1),
		SortBy:       r.URL.Query().Get("sort_by"),
		SortDesc:     r.URL.Query().Get("sort_order") == "desc",
		HideFixed:    true,
		HideNoFix:    r.URL.Query().Get("show_no_fix") != "true",
		HideMismatch: r.URL.Query().Get("show_mismatch") != "true",
	}, false, false
}

func (s *Server) handleExportVulnerabilities(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	filter, forbidden, empty := s.vulnFilterFromRequest(r)
	if forbidden {
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
	var err error
	if !empty {
		vulns, total, err = s.db.ListVulnerabilities(r.Context(), filter, maxRows, 0)
		if err != nil {
			log.Printf("export vulnerabilities: %v", err)
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
	}
	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="bongsu-vulnerabilities.json"`)
		writeJSON(w, http.StatusOK, map[string]any{"items": vulns, "total": total, "exported": len(vulns)})
	} else {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="bongsu-vulnerabilities.csv"`)
		if err := writeVulnerabilityCSV(w, vulns); err != nil {
			log.Printf("write vulnerability export csv: %v", err)
			return
		}
	}
	s.audit(r, "vulnerability.export", "vulnerability", "filtered", "ok", map[string]any{
		"format":   exportFormatLabel(format),
		"exported": len(vulns),
		"total":    total,
		"max_rows": maxRows,
	})
}

func writeVulnerabilityCSV(w io.Writer, vulns []models.Vulnerability) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{
		"host_id", "host_owner", "host_team", "host_environment", "host_criticality", "container", "vulnerability_id", "severity", "cvss_score", "triage_status",
		"sla_days", "due_at", "overdue", "pkg_name", "installed_version", "fixed_version", "pkg_path", "title", "primary_url",
		"triage_reason", "triage_comment", "triage_expires_at", "triage_updated_by", "created_at",
	}); err != nil {
		return err
	}
	for _, v := range vulns {
		if err := cw.Write([]string{
			v.HostID,
			v.HostOwner,
			v.HostTeam,
			v.HostEnvironment,
			v.HostCriticality,
			v.Container,
			v.VulnerabilityID,
			v.Severity,
			fmt.Sprintf("%.1f", v.CVSSScore),
			exportStatusLabel(v.TriageStatus),
			strconv.Itoa(v.SLADays),
			formatTimePtr(v.DueAt),
			strconv.FormatBool(v.Overdue),
			v.PkgName,
			v.InstalledVer,
			v.FixedVersion,
			v.PkgPath,
			v.Title,
			v.PrimaryURL,
			v.TriageReason,
			v.TriageComment,
			formatTimePtr(v.TriageExpiresAt),
			v.TriageUpdatedBy,
			v.CreatedAt.Format(time.RFC3339),
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
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

	opts, err := s.db.GetVulnFilterOptions(ctx)
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
	if body.VulnerabilityID == "" {
		http.Error(w, "vulnerability_id is required", http.StatusBadRequest)
		return
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
	limit := intParam(r, "limit", 50)
	offset := intParam(r, "offset", 0)
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

	counts, err := s.db.GetVulnCountsByHost(ctx)
	if err != nil {
		log.Printf("vuln summary: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if !scope.All {
		filtered := map[string]map[string]int{}
		for hostID, row := range counts {
			if scope.CanReadHost(hostID) {
				filtered[hostID] = row
			}
		}
		counts = filtered
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
	for _, h := range hosts {
		if !scope.CanReadHost(h.ID) {
			continue
		}
		visibleHosts++
		vc := vulnCounts[h.ID]
		for sev, cnt := range vc {
			totalVulns += cnt
			sevCounts[sev] += cnt
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total_hosts":           visibleHosts,
		"total_vulnerabilities": totalVulns,
		"severity_counts":       sevCounts,
	})
}

func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateInstall(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Host
	apiKey := s.agentKey
	tokenQuery := ""
	if s.installToken != "" {
		tokenQuery = "?token=" + s.installToken
	}

	script := fmt.Sprintf(`#!/bin/bash
set -euo pipefail

# Bongsu Agent Installer
# Usage: curl -sL %s://%s/api/install.sh%s | bash

SERVER="%s://%s"
API_KEY="%s"
INSTALL_TOKEN_QUERY="%s"
WORK_DIR="${BONGSU_WORK_DIR:-/opt/bongsu}"
INSTALL_MODE="${BONGSU_INSTALL_MODE:-cron}"
CRON_SCHEDULE="${BONGSU_CRON:-0 3 * * *}"
FORCE_SCAN_DAEMON="${BONGSU_FORCE_SCAN_DAEMON:-true}"

echo "=== Bongsu Agent Installer ==="
echo "Server:  $SERVER"
echo "WorkDir: $WORK_DIR"
echo "Mode:    $INSTALL_MODE"

mkdir -p "$WORK_DIR/bin"

# Download agent binary from server
echo "Downloading bongsu-agent..."
curl -sL "$SERVER/api/downloads/bongsu-agent$INSTALL_TOKEN_QUERY" -o "$WORK_DIR/bin/bongsu-agent"
chmod +x "$WORK_DIR/bin/bongsu-agent"

if [ ! -x "$WORK_DIR/bin/bongsu-agent" ]; then
    echo "ERROR: Failed to download bongsu-agent"
    exit 1
fi

echo "Downloading trivy..."
if curl -fsSL "$SERVER/api/downloads/trivy$INSTALL_TOKEN_QUERY" -o "$WORK_DIR/bin/trivy"; then
    chmod +x "$WORK_DIR/bin/trivy"
else
    rm -f "$WORK_DIR/bin/trivy"
    echo "WARNING: trivy download failed; install trivy manually or provide it at $WORK_DIR/bin/trivy"
fi

# Write config
cat > "$WORK_DIR/config.yaml" <<EOF
server_url: ${SERVER}
api_key: ${API_KEY}
work_dir: ${WORK_DIR}
EOF

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
`, scheme, host, tokenQuery, scheme, host, apiKey, tokenQuery)

	w.Header().Set("Content-Type", "text/x-shellscript")
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
		http.Error(w, "agent binary not found", http.StatusNotFound)
		return
	}
	defer f.Close()

	info, _ := f.Stat()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	w.Header().Set("Content-Disposition", "attachment; filename=bongsu-agent")
	io.Copy(w, f)
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
		http.Error(w, "trivy binary not found", http.StatusNotFound)
		return
	}
	defer f.Close()

	info, _ := f.Stat()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	w.Header().Set("Content-Disposition", "attachment; filename=trivy")
	io.Copy(w, f)
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
		Limit:      intParam(r, "limit", 100),
		Offset:     intParam(r, "offset", 0),
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
		Limit:      intParam(r, "limit", 100),
		Offset:     intParam(r, "offset", 0),
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

	opts, err := s.db.GetFilterOptions(ctx)
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
	limit := intParam(r, "limit", 50)
	offset := intParam(r, "offset", 0)

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
	items, total, err := s.db.ListScanRequests(
		r.Context(),
		hostID,
		scope.HostIDs,
		r.URL.Query().Get("status"),
		intParam(r, "limit", 50),
		intParam(r, "offset", 0),
	)
	if err != nil {
		log.Printf("list scan requests: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
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
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	s.audit(r, "scan_request.cancel", "scan_request", id, "cancelled", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
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
	if req.RequestedBy == "" {
		req.RequestedBy = "api"
	}
	if req.ScanType == "" {
		req.ScanType = "manual"
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
	timeoutMinutes := envInt("BONGSU_SCAN_REQUEST_CLAIM_TIMEOUT_MINUTES", 60)
	if timeoutMinutes <= 0 {
		timeoutMinutes = 60
	}
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
		"host_id": hostID,
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
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.Status == "" {
		body.Status = "completed"
	}
	if err := s.db.CompleteScanRequest(r.Context(), id, body.Status, body.Message); err != nil {
		log.Printf("complete scan request: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	s.audit(r, "scan_request.complete", "scan_request", id, body.Status, map[string]any{
		"message": body.Message,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": body.Status})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"status":         "ok",
		"trivy_db_ready": false,
		"web_auth":       s.webAuth,
	}
	if err := s.db.PingContext(r.Context()); err != nil {
		resp["status"] = "degraded"
		resp["db_error"] = "connection failed"
	}
	if s.dbMgr != nil {
		resp["trivy_db_ready"] = s.dbMgr.IsReady()
		if lu := s.dbMgr.LastUpdate(); !lu.IsZero() {
			resp["trivy_db_last_update"] = lu.Format("2006-01-02T15:04:05Z07:00")
		}
	}
	if s.secMgr != nil {
		resp["security_db"] = s.secMgr.Status()
	}
	writeJSON(w, http.StatusOK, resp)
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

	r.Body = http.MaxBytesReader(w, r.Body, 2<<30)
	if err := r.ParseMultipartForm(2 << 30); err != nil {
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
		http.Error(w, "failed to load db", http.StatusInternalServerError)
		return
	}

	s.audit(r, "trivy_db.upload", "security_db", "trivy", "ok", nil)
	s.SecurityDatabaseUpdated("trivy-db upload")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "trivy-db loaded"})
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
	ctx := r.Context()

	cveFile, cveCount, cveSHA, err := s.writeCveJSONLTemp(ctx)
	if err != nil {
		log.Printf("security-db bundle cve export: %v", err)
		http.Error(w, "export failed", http.StatusInternalServerError)
		return
	}
	defer os.Remove(cveFile)

	var trivyBytes []byte
	trivySHA := ""
	includeTrivy := r.URL.Query().Get("include_trivy") != "false"
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
	manifest := securityDBBundleManifest{
		Format:            "bongsu-security-db-bundle",
		Version:           1,
		CreatedAt:         time.Now().UTC().Format(time.RFC3339),
		CveRecords:        cveCount,
		CveDatabaseSHA256: cveSHA,
		TrivyDBIncluded:   len(trivyBytes) > 0,
		TrivyDBSHA256:     trivySHA,
		Sources:           sourceStats,
	}
	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=bongsu-security-db-bundle.tar.gz")
	gz := gzip.NewWriter(w)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	if err := writeTarBytes(tw, "manifest.json", manifestBytes); err != nil {
		log.Printf("security-db bundle manifest: %v", err)
		return
	}
	if err := writeTarFile(tw, "cve-database.jsonl", cveFile); err != nil {
		log.Printf("security-db bundle cve: %v", err)
		return
	}
	if len(trivyBytes) > 0 {
		if err := writeTarBytes(tw, "trivy-db.tar.gz", trivyBytes); err != nil {
			log.Printf("security-db bundle trivy: %v", err)
			return
		}
	}
	s.audit(r, "security_db.export", "security_db", "bundle", "ok", map[string]any{
		"cve_records":       cveCount,
		"trivy_db_included": len(trivyBytes) > 0,
	})
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
	r.Body = http.MaxBytesReader(w, r.Body, 4<<30)
	if err := r.ParseMultipartForm(4 << 30); err != nil {
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
		switch hdr.Name {
		case "manifest.json":
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
				os.Remove(cveFile)
			}
			cveFile, cveSHA, err = writeBundleEntryTemp(tr, "bongsu-bundle-cve-*.jsonl")
			if err != nil {
				fail(http.StatusInternalServerError, "cve archive write failed", "stage_cve", err)
				return
			}
		case "trivy-db.tar.gz":
			if trivyArchive != "" {
				os.Remove(trivyArchive)
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
	imported, err = s.importCveJSONLTx(r.Context(), cveReader, "", tx)
	cveReader.Close()
	if err != nil {
		tx.Rollback()
		log.Printf("security-db bundle cve import: %v", err)
		fail(http.StatusInternalServerError, "cve import failed", "import_cve", err)
		return
	}
	trivyLoaded := false
	if trivyArchive != "" {
		if err := s.dbMgr.LoadFromFile(trivyArchive); err != nil {
			log.Printf("security-db bundle trivy import: %v", err)
			tx.Rollback()
			fail(http.StatusInternalServerError, "trivy db import failed", "import_trivy", err)
			return
		}
		trivyLoaded = true
	}
	if err := tx.Commit(); err != nil {
		fail(http.StatusInternalServerError, "cve import commit failed", "commit_cve", err)
		return
	}
	s.audit(r, "security_db.import", "security_db", "bundle", "ok", map[string]any{
		"imported":        imported,
		"trivy_db_loaded": trivyLoaded,
	})
	s.SecurityDatabaseUpdated("security-db bundle import")
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "imported": imported, "trivy_db_loaded": trivyLoaded})
}

type securityDBBundleManifest struct {
	Format            string              `json:"format"`
	Version           int                 `json:"version"`
	CreatedAt         string              `json:"created_at"`
	CveRecords        int                 `json:"cve_records"`
	CveDatabaseSHA256 string              `json:"cve_database_sha256"`
	TrivyDBIncluded   bool                `json:"trivy_db_included"`
	TrivyDBSHA256     string              `json:"trivy_db_sha256"`
	Sources           []db.CveSourceStats `json:"sources,omitempty"`
}

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

func (s *Server) SecurityDatabaseUpdated(reason string) {
	s.auditSystem("security_db.changed", "security_db", "aggregate", "ok", map[string]any{"reason": reason})
	if s.notifier.Enabled() {
		s.notifier.Send("security_db.updated", map[string]any{"reason": reason})
	}
	s.recalculateSecurityFindings(reason)
	s.queueSecurityDBRescans(reason)
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
	if r, err := s.db.RematchCVEs(ctx, rematchOptionsFromEnv()); err != nil {
		log.Printf("security recalculation rematch failed: %v", err)
		failures = append(failures, "rematch: "+err.Error())
	} else {
		log.Printf("security recalculation rematched candidates=%d new=%d skipped=%d", r.Matched, r.NewVulns, r.Skipped)
		meta["rematch_candidates"] = r.Matched
		meta["rematch_new_vulns"] = r.NewVulns
		meta["rematch_skipped"] = r.Skipped
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

func (s *Server) queueSecurityDBRescans(reason string) {
	if !envBool("BONGSU_AUTO_RESCAN_ON_DB_UPDATE", true) {
		log.Printf("security-db auto rescan disabled (%s)", reason)
		s.auditSystem("security_db.auto_rescan", "scan_request", "security-db-update", "disabled", map[string]any{"reason": reason})
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
		queued, err := s.db.QueueSecurityDBRescans(ctx, "system", reason, lastSeenAfter)
		if err != nil {
			log.Printf("security-db auto rescan queue failed (%s): %v", reason, err)
			s.auditSystem("security_db.auto_rescan", "scan_request", "security-db-update", "error", map[string]any{
				"reason":          reason,
				"last_seen_after": lastSeenAfter,
				"last_seen_hours": lookbackHours,
				"error":           err.Error(),
			})
			return
		}
		log.Printf("security-db auto rescan queued %d host scans (%s)", queued, reason)
		s.auditSystem("security_db.auto_rescan", "scan_request", "security-db-update", "ok", map[string]any{
			"reason":          reason,
			"queued":          queued,
			"last_seen_after": lastSeenAfter,
			"last_seen_hours": lookbackHours,
		})
	}()
}

func (s *Server) handleCveDbImport(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()

	r.Body = http.MaxBytesReader(w, r.Body, 2<<30)
	if err := r.ParseMultipartForm(2 << 30); err != nil {
		http.Error(w, "file too large", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "no file provided", http.StatusBadRequest)
		return
	}
	defer file.Close()

	source := r.FormValue("source")
	if source == "" {
		source = "custom"
	}

	count, err := s.importCveJSONL(ctx, file, source)
	if err != nil {
		log.Printf("cve-db import: %v", err)
		http.Error(w, "import failed", http.StatusInternalServerError)
		return
	}
	if count == 0 {
		http.Error(w, "no valid entries found", http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"imported": count,
		"total":    count,
	})
	s.audit(r, "cve_db.import", "cve_db", source, "ok", map[string]any{
		"imported": count,
		"source":   source,
	})
	s.SecurityDatabaseUpdated("cve-db import")
}

func (s *Server) importCveJSONL(ctx context.Context, reader io.Reader, source string) (int, error) {
	return s.importCveJSONLWithUpsert(ctx, reader, source, func(ctx context.Context, batch []models.CveEntry) (int, error) {
		return s.db.UpsertCveEntries(ctx, batch)
	})
}

func (s *Server) importCveJSONLTx(ctx context.Context, reader io.Reader, source string, tx *sql.Tx) (int, error) {
	return s.importCveJSONLWithUpsert(ctx, reader, source, func(ctx context.Context, batch []models.CveEntry) (int, error) {
		return s.db.UpsertCveEntriesTx(ctx, tx, batch)
	})
}

func (s *Server) importCveJSONLWithUpsert(ctx context.Context, reader io.Reader, source string, upsert func(context.Context, []models.CveEntry) (int, error)) (int, error) {
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
		if e.Source == "" {
			if source != "" {
				e.Source = source
			} else {
				e.Source = "bundle"
			}
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

func (s *Server) handleCveDbRematch(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	opts := rematchOptionsFromEnv()
	if r.Body != nil {
		var body struct {
			Sources                   []string `json:"sources"`
			MinSourceMatchablePercent float64  `json:"min_source_matchable_percent"`
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
	}
	opts = normalizeRematchOptions(opts)
	result, err := s.db.RematchCVEs(r.Context(), opts)
	if err != nil {
		log.Printf("cve-db rematch: %v", err)
		http.Error(w, "rematch failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, result)
	s.audit(r, "cve_db.rematch", "cve_db", "all", "ok", map[string]any{
		"matched":                      result.Matched,
		"new_vulns":                    result.NewVulns,
		"skipped":                      result.Skipped,
		"sources":                      opts.Sources,
		"min_source_matchable_percent": opts.MinSourceMatchablePercent,
	})
	enriched, _ := s.db.EnrichVulnerabilities(r.Context())
	log.Printf("Enriched %d vulnerabilities with CVE DB data", enriched)
}

func rematchOptionsFromEnv() db.RematchOptions {
	return normalizeRematchOptions(db.RematchOptions{
		Sources:                   splitCSV(os.Getenv("BONGSU_CVE_MATCH_SOURCES")),
		MinSourceMatchablePercent: envFloat("BONGSU_CVE_MATCH_MIN_SOURCE_MATCHABLE_PERCENT", 0),
	})
}

func normalizeRematchOptions(opts db.RematchOptions) db.RematchOptions {
	opts.Sources = cleanCSV(opts.Sources)
	if opts.MinSourceMatchablePercent < 0 {
		opts.MinSourceMatchablePercent = 0
	}
	if opts.MinSourceMatchablePercent > 100 {
		opts.MinSourceMatchablePercent = 100
	}
	return opts
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
	s.audit(r, "cve_db.recalc_cvss", "cve_db", "all", "ok", map[string]any{"updated": count})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "updated": count})
}
func (s *Server) handleCveDbExport(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	source := r.URL.Query().Get("source")

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", "attachment; filename=cve-database.jsonl")

	q := "SELECT " + db.CveCols + " FROM cve_database"
	args := []any{}
	if source != "" {
		q += " WHERE source=$1"
		args = append(args, source)
	}
	q += " ORDER BY vulnerability_id"

	rows, err := s.db.QueryContext(r.Context(), q, args...)
	if err != nil {
		log.Printf("cve-db export: %v", err)
		return
	}
	defer rows.Close()

	encoder := json.NewEncoder(w)
	for rows.Next() {
		var e models.CveEntry
		if err := db.ScanCveEntry(rows, &e); err != nil {
			continue
		}
		encoder.Encode(e)
	}
	s.audit(r, "cve_db.export", "cve_db", source, "ok", map[string]any{"source": source})
}

func (s *Server) writeCveJSONLTemp(ctx context.Context) (string, int, string, error) {
	tmp, err := os.CreateTemp("", "bongsu-cve-database-*.jsonl")
	if err != nil {
		return "", 0, "", err
	}
	path := tmp.Name()
	defer tmp.Close()

	rows, err := s.db.QueryContext(ctx, "SELECT "+db.CveCols+" FROM cve_database ORDER BY vulnerability_id, source")
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
	case "read", "write", "admin":
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
	filter := db.AuditLogFilter{
		ActorType:    r.URL.Query().Get("actor_type"),
		ActorID:      r.URL.Query().Get("actor_id"),
		Action:       r.URL.Query().Get("action"),
		ResourceType: r.URL.Query().Get("resource_type"),
		ResourceID:   r.URL.Query().Get("resource_id"),
		Status:       r.URL.Query().Get("status"),
	}
	items, total, err := s.db.ListAuditLogs(r.Context(), filter, intParam(r, "limit", 100), intParam(r, "offset", 0))
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
	source := r.URL.Query().Get("source")
	minCVSS := floatParam(r, "min_cvss", 0.1)
	sortBy := r.URL.Query().Get("sort_by")
	sortOrder := r.URL.Query().Get("sort_order")
	limit := intParam(r, "limit", 50)
	offset := intParam(r, "offset", 0)

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
	return n
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

func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic recovered: %v %s %s", err, r.Method, r.URL.Path)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key, X-Install-Token")
		w.Header().Set("Access-Control-Max-Age", "86400")
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
		next.ServeHTTP(w, r)
	})
}
