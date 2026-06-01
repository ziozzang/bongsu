package api

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
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

//go:embed openapi.yaml
var openAPISpecYAML []byte

type BuildInfo struct {
	Version   string
	Commit    string
	BuildDate string
	StartTime time.Time
}

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

	affectedIndexMu        sync.Mutex
	affectedIndexRunning   bool
	affectedIndexStartedAt time.Time
	affectedIndexLast      map[string]any

	referenceIndexMu        sync.Mutex
	referenceIndexRunning   bool
	referenceIndexStartedAt time.Time
	referenceIndexLast      map[string]any

	cveStatsCacheMu    sync.Mutex
	cveStatsCacheUntil time.Time
	cveStatsCacheJSON  []byte
	cveStatsCacheGen   int64
	cveStatsInflight   bool
	cveStatsWaiters    []chan cveStatsBuildResult

	generalRateLimiter *ipRateLimiter
	agentRateLimiter   *ipRateLimiter

	buildInfo BuildInfo
}

type cveStatsBuildResult struct {
	body   []byte
	status int
	msg    string
}

const (
	maxReportErrors                    = 32
	maxReportErrorBytes                = 2048
	maxScanRequestMessageBytes         = 1024
	defaultSecurityDBMaxSourceAgeHours = 30
)

func New(database *db.DB, matcher *cvematch.Matcher, dbMgr *trivydb.Manager, secMgr *secdb.Manager, info BuildInfo) *Server {
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
		buildInfo:    info,
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

	generalRPS := envFloat("BONGSU_RATE_LIMIT_RPS", 30)
	generalBurst := envInt("BONGSU_RATE_LIMIT_BURST", 60)
	agentRPS := envFloat("BONGSU_RATE_LIMIT_AGENT_RPS", 100)
	s.generalRateLimiter = newIPRateLimiter(generalRPS, generalBurst)
	s.agentRateLimiter = newIPRateLimiter(agentRPS, int(agentRPS)*2)

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
	h = s.rateLimitMiddleware(h)
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
	s.mux.HandleFunc("GET /api/admin/installer/status", s.handleInstallerStatus)
	s.mux.HandleFunc("GET /api/stats", s.handleStats)
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/ready", s.handleReady)
	s.mux.HandleFunc("GET /api/live", s.handleLiveness)
	s.mux.HandleFunc("GET /api/docs/openapi.yaml", s.handleOpenAPISpec)
	s.mux.HandleFunc("DELETE /api/scans/{id}", s.handleDeleteScan)
	s.mux.HandleFunc("POST /api/admin/trivy-db", s.handleTrivyDBUpload)
	s.mux.HandleFunc("POST /api/admin/trivy-db/update", s.handleTrivyDBUpdate)
	s.mux.HandleFunc("POST /api/admin/cve-db/import", s.handleCveDbImport)
	s.mux.HandleFunc("GET /api/admin/security-db/export", s.handleSecurityDbExport)
	s.mux.HandleFunc("POST /api/admin/security-db/import", s.handleSecurityDbImport)
	s.mux.HandleFunc("POST /api/admin/security-db/update", s.handleSecurityDbUpdate)
	s.mux.HandleFunc("POST /api/admin/security-db/recalculate", s.handleSecurityDbRecalculate)
	s.mux.HandleFunc("POST /api/admin/cve-db/rematch", s.handleCveDbRematch)
	s.mux.HandleFunc("POST /api/admin/cve-db/affected-index/rebuild", s.handleCveDbAffectedIndexRebuild)
	s.mux.HandleFunc("POST /api/admin/cve-db/reference-index/rebuild", s.handleCveDbReferenceIndexRebuild)
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
	s.mux.HandleFunc("GET /api/cve-db/sources", s.handleCveDbSources)
	s.mux.HandleFunc("GET /api/cve-db/stats", s.handleCveDbStats)
	s.mux.HandleFunc("GET /api/cve-db/search", s.handleCveDbSearch)
	s.mux.HandleFunc("GET /api/cve-db/reference-group", s.handleCveDbReferenceGroup)
	s.mux.HandleFunc("GET /api/cve-db/{id}/affected-packages", s.handleCveDbAffectedPackages)
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

func (s *Server) canReadCveDB(r *http.Request) bool {
	if s.authenticateAdmin(r) || !s.webAuth {
		return true
	}
	subject := s.viewerSubject(r)
	if subject == "" {
		return false
	}
	ok, err := s.db.HasResourcePermission(r.Context(), subject, "cve_db", []string{"read", "admin"})
	if err != nil {
		log.Printf("rbac cve_db scope %s: %v", subject, err)
		return false
	}
	return ok
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

func (s *Server) handleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/openapi+yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write(openAPISpecYAML)
}
