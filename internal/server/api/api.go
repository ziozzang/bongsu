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
	"github.com/ziozzang/bongsu/internal/server/intel"
	"github.com/ziozzang/bongsu/internal/server/live"
	"github.com/ziozzang/bongsu/internal/server/llm"
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
	trustedAuth  trustedIdentityConfig
	oidcAuth     *oidcTokenVerifier
	webAuth      bool
	// authEnrichSameIdentity unions RBAC subjects from additional credential
	// sources that prove the SAME identity (e.g. session + OIDC for user:alice)
	// onto the first-wins principal. authRejectMismatch rejects (401) a request
	// that presents two DIFFERENT identities. Both default ON (Phase A v2); the
	// env escape hatches (=false) exist for one-release migration safety.
	authEnrichSameIdentity bool
	authRejectMismatch     bool
	corsOrigins            map[string]bool
	corsAllowAll           bool
	mux                    *http.ServeMux
	loginLimit             *loginLimiter
	matcher                *cvematch.Matcher
	dbMgr                  *trivydb.Manager
	secMgr                 *secdb.Manager
	notifier               *webhookNotifier
	bundleCache            *secdbBundleCache
	statsCache             *responseCache
	healthCache            *responseCache
	graphCache             *responseCache
	apiTokens              *apiTokenStore
	llm                    *llm.Client
	live                   *live.Hub

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

	securityDBRevisionMu         sync.Mutex
	securityDBRevisionCacheUntil time.Time
	securityDBRevisionCacheMeta  map[string]any
	securityDBRevisionCacheGen   int64
	securityDBRevisionInflight   bool
	securityDBRevisionWaiters    []chan map[string]any

	adminMetricsCacheMu    sync.Mutex
	adminMetricsCacheUntil time.Time
	adminMetricsCacheBody  []byte
	adminMetricsCacheGen   int64

	generalRateLimiter *ipRateLimiter
	agentRateLimiter   *ipRateLimiter

	sessionMaxAge time.Duration
	authenticator Authenticator
	ruleNotifier  *ruleNotifier
	intel         *intel.Service

	buildInfo BuildInfo
}

type trustedIdentityConfig struct {
	userHeader   string
	groupsHeader string
	adminUsers   map[string]bool
	adminGroups  map[string]bool
	proxyNets    []*net.IPNet
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
	// Route all transient large work files (export bundle JSONL, multipart
	// upload spillover, trivy archives) to BONGSU_TMPDIR when set, so they do
	// not fill a size-limited /tmp tmpfs. Setting TMPDIR makes os.TempDir(),
	// the multipart parser, and any os.CreateTemp("") respect it process-wide.
	if d := strings.TrimSpace(os.Getenv("BONGSU_TMPDIR")); d != "" {
		if err := os.MkdirAll(d, 0o700); err == nil {
			os.Setenv("TMPDIR", d)
		}
	}
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
		trustedAuth:  trustedIdentityConfigFromEnv(),
		oidcAuth:     newOIDCTokenVerifierFromEnv(),
		webAuth:      os.Getenv("BONGSU_WEB_AUTH") != "false",

		authEnrichSameIdentity: os.Getenv("BONGSU_AUTH_ENRICH_SAME_IDENTITY") != "false",
		authRejectMismatch:     os.Getenv("BONGSU_AUTH_REJECT_IDENTITY_MISMATCH") != "false",

		corsOrigins:  parseAllowedOrigins(os.Getenv("BONGSU_CORS_ALLOWED_ORIGINS")),
		corsAllowAll: allowsAllOrigins(os.Getenv("BONGSU_CORS_ALLOWED_ORIGINS")),
		mux:          http.NewServeMux(),
		loginLimit:   newLoginLimiter(),
		matcher:      matcher,
		dbMgr:        dbMgr,
		secMgr:       secMgr,
		notifier:     newWebhookNotifierFromEnv(),
		bundleCache:  newSecdbBundleCache(),
		statsCache:   newResponseCache("BONGSU_STATS_CACHE_SECONDS", 10),
		healthCache:  newResponseCache("BONGSU_HEALTH_CACHE_SECONDS", 8),
		graphCache:   newResponseCache("BONGSU_GRAPH_CACHE_SECONDS", 15),
	}
	if s.notifier != nil {
		s.notifier.onResult = s.auditWebhookResult
	}

	generalRPS := envFloat("BONGSU_RATE_LIMIT_RPS", 30)
	generalBurst := envInt("BONGSU_RATE_LIMIT_BURST", 60)
	agentRPS := envFloat("BONGSU_RATE_LIMIT_AGENT_RPS", 100)
	s.generalRateLimiter = newIPRateLimiter(generalRPS, generalBurst)
	s.agentRateLimiter = newIPRateLimiter(agentRPS, int(agentRPS)*2)

	sessionMaxAgeHours := envInt("BONGSU_SESSION_MAX_AGE_HOURS", 24)
	if sessionMaxAgeHours < 1 {
		sessionMaxAgeHours = 24
	}
	s.sessionMaxAge = time.Duration(sessionMaxAgeHours) * time.Hour
	s.authenticator = s.initAuthenticator()
	s.ruleNotifier = newRuleNotifier(s)

	s.llm = llm.New(llmConfigFromEnv())
	s.intel = intel.NewServiceFromEnv(database)
	s.live = live.NewHub(envInt("BONGSU_LIVE_RING", 1000), envInt("BONGSU_LIVE_MAX_CONNS", 256))
	s.routes()
	s.bootstrapAdmin()
	s.startSessionCleanup()
	s.startAPITokenStore()
	s.startVulnAnalyzer()
	s.startScheduler()
	s.startVulnTrendSnapshotter()
	// Optionally pre-build the airgap export bundle so the first download
	// streams an existing file. Off by default: the bundle is large and most
	// deployments export rarely, so on-demand build (cached after the first
	// download) is the better default. Enable with BONGSU_SECDB_BUNDLE_PREBUILD=true.
	if os.Getenv("BONGSU_SECDB_BUNDLE_PREBUILD") == "true" {
		go s.rebuildSecdbBundleCache("startup")
	}
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

func trustedIdentityConfigFromEnv() trustedIdentityConfig {
	userHeader := strings.TrimSpace(os.Getenv("BONGSU_TRUSTED_IDENTITY_HEADER"))
	groupsHeader := strings.TrimSpace(os.Getenv("BONGSU_TRUSTED_GROUPS_HEADER"))
	cfg := trustedIdentityConfig{
		userHeader:   userHeader,
		groupsHeader: groupsHeader,
		adminUsers:   mapFromList(splitCSV(os.Getenv("BONGSU_TRUSTED_ADMIN_USERS"))),
		adminGroups:  mapFromList(splitCSV(os.Getenv("BONGSU_TRUSTED_ADMIN_GROUPS"))),
	}
	if userHeader == "" && groupsHeader == "" {
		return cfg
	}
	cidrs := splitCSV(os.Getenv("BONGSU_TRUSTED_IDENTITY_PROXY_CIDRS"))
	if len(cidrs) == 0 {
		cidrs = []string{"127.0.0.1/32", "::1/128"}
	}
	for _, raw := range cidrs {
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			log.Printf("WARNING: ignoring invalid BONGSU_TRUSTED_IDENTITY_PROXY_CIDRS entry %q: %v", raw, err)
			continue
		}
		cfg.proxyNets = append(cfg.proxyNets, network)
	}
	if len(cfg.proxyNets) == 0 {
		log.Printf("WARNING: trusted identity headers configured but no valid trusted proxy CIDRs are available")
	}
	return cfg
}

func mapFromList(items []string) map[string]bool {
	out := map[string]bool{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			out[item] = true
		}
	}
	return out
}

func (s *Server) Handler() http.Handler {
	var h http.Handler = s.mux
	h = s.recoverMiddleware(h)
	h = s.corsMiddleware(h)
	h = s.securityHeadersMiddleware(h)
	h = s.rateLimitMiddleware(h)
	h = s.oidcIdentityCacheMiddleware(h)
	h = s.principalCacheMiddleware(h)
	h = s.requestIDMiddleware(h)
	h = s.accessLogMiddleware(h)
	return h
}

func (s *Server) APIKey() string {
	return s.apiKey
}

func (s *Server) routes() {
	s.mux.HandleFunc("POST /api/report", s.handleReport)
	s.mux.HandleFunc("POST /api/sbom", s.handleSBOMIngest)
	s.mux.HandleFunc("GET /api/intel/scenarios", s.handleIntelScenarios)
	s.mux.HandleFunc("POST /api/intel/runs", s.handleIntelRun)
	s.mux.HandleFunc("POST /api/intel/pipelines", s.handleIntelPipeline)
	s.mux.HandleFunc("POST /api/intel/verify", s.handleIntelVerify)
	s.mux.HandleFunc("GET /api/intel/runs/{id}", s.handleIntelGetRun)
	s.mux.HandleFunc("POST /api/exposure-catalog", s.handleUploadExposureCatalog)
	s.mux.HandleFunc("GET /api/exposure-catalog", s.handleListExposureCatalogs)
	s.mux.HandleFunc("DELETE /api/exposure-catalog/{id}", s.handleDeleteExposureCatalog)
	s.mux.HandleFunc("GET /api/scans/{id}/sbom", s.handleGetScanSBOM)
	s.mux.HandleFunc("GET /api/scans/{id}/dependents", s.handleScanDependents)
	s.mux.HandleFunc("GET /api/hosts/{id}/vex", s.handleExportHostVEX)
	s.mux.HandleFunc("POST /api/vex", s.handleImportVEX)
	s.mux.HandleFunc("GET /api/hosts", s.handleListHosts)
	s.mux.HandleFunc("GET /api/hosts/{id}", s.handleGetHost)
	s.mux.HandleFunc("DELETE /api/hosts/{id}", s.handleDeleteHost)
	s.mux.HandleFunc("POST /api/hosts/{id}/metadata", s.handleUpdateHostMetadata)
	s.mux.HandleFunc("POST /api/hosts/{id}/agent-token/reset", s.handleResetHostAgentToken)
	s.mux.HandleFunc("GET /api/hosts/{id}/packages", s.handleHostPackages)
	s.mux.HandleFunc("GET /api/hosts/{id}/users", s.handleHostUsers)
	s.mux.HandleFunc("GET /api/hosts/{id}/processes", s.handleHostProcesses)
	s.mux.HandleFunc("GET /api/hosts/{id}/ports", s.handleHostPorts)
	s.mux.HandleFunc("GET /api/hosts/{id}/sbom", s.handleHostSBOM)
	s.mux.HandleFunc("GET /api/hosts/{id}/vuln-counts", s.handleHostVulnCounts)
	s.mux.HandleFunc("GET /api/vulnerabilities", s.handleListVulnerabilities)
	s.mux.HandleFunc("GET /api/vulnerabilities/export", s.handleExportVulnerabilities)
	s.mux.HandleFunc("GET /api/vulnerabilities/filters", s.handleVulnFilters)
	s.mux.HandleFunc("GET /api/vulnerabilities/affected-assets", s.handleAffectedAssets)
	s.mux.HandleFunc("GET /api/graph/schema", s.handleGraphSchema)
	s.mux.HandleFunc("GET /api/graph/overview", s.handleGraphOverview)
	s.mux.HandleFunc("GET /api/graph/blast-radius", s.handleGraphBlastRadius)
	s.mux.HandleFunc("GET /api/graph/host/{id}", s.handleGraphHost)
	s.mux.HandleFunc("GET /api/graph/group/{id}", s.handleGraphGroup)
	s.mux.HandleFunc("GET /api/graph/cve/{id}", s.handleGraphCVE)
	s.mux.HandleFunc("GET /api/graph/exposure", s.handleGraphExposure)
	s.mux.HandleFunc("GET /api/graph/images", s.handleGraphImages)
	s.mux.HandleFunc("GET /api/graph/org", s.handleGraphOrg)
	s.mux.HandleFunc("GET /api/graph/remediation", s.handleGraphRemediation)
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
	s.mux.HandleFunc("GET /api/admin/agent-fleet/status", s.handleAgentFleetStatus)
	s.mux.HandleFunc("GET /api/stats", s.handleStats)
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/events/stream", s.handleEventStream)
	s.mux.HandleFunc("GET /api/ready", s.handleReady)
	s.mux.HandleFunc("GET /api/live", s.handleLiveness)
	s.mux.HandleFunc("GET /api/docs/openapi.yaml", s.handleOpenAPISpec)
	s.mux.HandleFunc("DELETE /api/scans/{id}", s.handleDeleteScan)
	s.mux.HandleFunc("POST /api/admin/trivy-db", s.handleTrivyDBUpload)
	s.mux.HandleFunc("POST /api/admin/trivy-db/update", s.handleTrivyDBUpdate)
	s.mux.HandleFunc("POST /api/admin/cve-db/import", s.handleCveDbImport)
	s.mux.HandleFunc("GET /api/admin/security-db/export", s.handleSecurityDbExport)
	s.mux.HandleFunc("POST /api/admin/security-db/import", s.handleSecurityDbImport)
	s.mux.HandleFunc("GET /api/admin/security-db/status", s.handleSecurityDbStatus)
	s.mux.HandleFunc("POST /api/admin/security-db/update", s.handleSecurityDbUpdate)
	s.mux.HandleFunc("POST /api/admin/security-db/recalculate", s.handleSecurityDbRecalculate)
	s.mux.HandleFunc("POST /api/admin/cve-db/rematch", s.handleCveDbRematch)
	s.mux.HandleFunc("POST /api/admin/cve-db/source/{source}/prune-stale", s.handleCveDbPruneStaleSource)
	s.mux.HandleFunc("POST /api/admin/cve-db/source/{source}/refresh-status", s.handleCveDbRefreshSourceStatus)
	s.mux.HandleFunc("GET /api/admin/cve-db/source/{source}/watermark", s.handleCveDbSourceWatermark)
	s.mux.HandleFunc("POST /api/admin/cve-db/affected-index/rebuild", s.handleCveDbAffectedIndexRebuild)
	s.mux.HandleFunc("POST /api/admin/cve-db/reference-index/rebuild", s.handleCveDbReferenceIndexRebuild)
	s.mux.HandleFunc("POST /api/admin/cve-db/recalc-cvss", s.handleCveDbRecalcCVSS)
	s.mux.HandleFunc("GET /api/admin/cve-db/export", s.handleCveDbExport)
	s.mux.HandleFunc("GET /api/admin/cve-db/sources", s.handleCveDbSources)
	s.mux.HandleFunc("GET /api/admin/metrics", s.handleAdminMetrics)
	s.mux.HandleFunc("GET /metrics", s.handleMetrics)
	s.mux.HandleFunc("GET /api/admin/users", s.handleListUsers)
	s.mux.HandleFunc("POST /api/admin/users", s.handleCreateUser)
	s.mux.HandleFunc("PATCH /api/admin/users/{id}", s.handleUpdateUserRole)
	s.mux.HandleFunc("POST /api/admin/users/{id}/password", s.handleResetUserPassword)
	s.mux.HandleFunc("DELETE /api/admin/users/{id}", s.handleDeleteUser)
	s.mux.HandleFunc("GET /api/admin/api-tokens", s.handleListAPITokens)
	s.mux.HandleFunc("POST /api/admin/api-tokens", s.handleCreateAPIToken)
	s.mux.HandleFunc("DELETE /api/admin/api-tokens/{id}", s.handleRevokeAPIToken)
	s.mux.HandleFunc("GET /api/admin/llm/status", s.handleLLMStatus)
	s.mux.HandleFunc("POST /api/admin/vuln-analysis/run", s.handleRunVulnAnalysis)
	s.mux.HandleFunc("GET /api/admin/vuln-analysis", s.handleListVulnAnalyses)
	s.mux.HandleFunc("POST /api/admin/vuln-analysis/{id}/apply", s.handleApplyVulnAnalysis)
	s.mux.HandleFunc("GET /api/vulnerabilities/analysis", s.handleGetVulnAnalysis)
	s.mux.HandleFunc("GET /api/admin/ai-policy", s.handleAIPolicyStatus)
	s.mux.HandleFunc("GET /api/admin/ai-approvals", s.handleListAIApprovals)
	s.mux.HandleFunc("POST /api/admin/ai-approvals/{id}/approve", s.handleApproveAIApproval)
	s.mux.HandleFunc("POST /api/admin/ai-approvals/{id}/reject", s.handleRejectAIApproval)
	s.mux.HandleFunc("POST /api/admin/retention/prune", s.handleRetentionPrune)
	s.mux.HandleFunc("GET /api/admin/rbac/status", s.handleAccessControlStatus)
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
	s.mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	s.mux.HandleFunc("GET /api/auth/me", s.handleAuthMe)
	s.mux.HandleFunc("POST /api/auth/change-password", s.handleChangePassword)
	s.mux.HandleFunc("GET /api/admin/schedules", s.handleListScheduledScans)
	s.mux.HandleFunc("POST /api/admin/schedules", s.handleCreateScheduledScan)
	s.mux.HandleFunc("GET /api/admin/schedules/{id}", s.handleGetScheduledScan)
	s.mux.HandleFunc("PUT /api/admin/schedules/{id}", s.handleUpdateScheduledScan)
	s.mux.HandleFunc("DELETE /api/admin/schedules/{id}", s.handleDeleteScheduledScan)
	s.mux.HandleFunc("GET /api/asset-groups", s.handleListAssetGroups)
	s.mux.HandleFunc("POST /api/asset-groups", s.handleCreateAssetGroup)
	s.mux.HandleFunc("GET /api/asset-groups/{id}", s.handleGetAssetGroup)
	s.mux.HandleFunc("DELETE /api/asset-groups/{id}", s.handleDeleteAssetGroup)
	s.mux.HandleFunc("POST /api/asset-groups/{id}/hosts", s.handleAddHostToAssetGroup)
	s.mux.HandleFunc("DELETE /api/asset-groups/{id}/hosts/{hostId}", s.handleRemoveHostFromAssetGroup)
	s.mux.HandleFunc("POST /api/asset-groups/{id}/scan", s.handleTriggerAssetGroupScan)
	s.mux.HandleFunc("GET /api/vuln-trends", s.handleGetVulnTrends)
	s.mux.HandleFunc("GET /api/scan-activity", s.handleGetScanActivity)
	s.mux.HandleFunc("GET /api/vuln-trends/summary", s.handleGetVulnTrendSummary)
	s.mux.HandleFunc("GET /api/intelligence/top-risk", s.handleGetTopAtRiskHosts)
	s.mux.HandleFunc("GET /api/intelligence/recommendations", s.handleGetRecommendations)
	s.mux.HandleFunc("GET /api/intelligence/posture", s.handleGetVulnPosture)
	s.mux.HandleFunc("GET /api/admin/notification-rules", s.handleListNotificationRules)
	s.mux.HandleFunc("POST /api/admin/notification-rules", s.handleCreateNotificationRule)
	s.mux.HandleFunc("GET /api/admin/notification-rules/{id}", s.handleGetNotificationRule)
	s.mux.HandleFunc("PUT /api/admin/notification-rules/{id}", s.handleUpdateNotificationRule)
	s.mux.HandleFunc("DELETE /api/admin/notification-rules/{id}", s.handleDeleteNotificationRule)
	s.mux.HandleFunc("POST /api/admin/notification-rules/{id}/test", s.handleTestNotificationRule)
	s.mux.HandleFunc("GET /api/admin/notification-log", s.handleListNotificationLog)
	s.mux.HandleFunc("GET /api/reports/executive-summary", s.handleGetExecutiveSummary)
	s.mux.HandleFunc("GET /api/reports/risk-breakdown", s.handleGetRiskBreakdown)
	s.mux.HandleFunc("GET /api/reports/sla-compliance", s.handleGetSLACompliance)
	s.mux.HandleFunc("GET /api/reports/export", s.handleExportReport)
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

// The authenticate* helpers below are thin capability checks over the unified
// Principal (see principal.go) — the single resolution point for all credential
// sources.

func (s *Server) authenticateWeb(r *http.Request) bool {
	if !s.webAuth {
		return true
	}
	p := s.principal(r)
	return p.Admin || p.has(ScopeViewer) || len(p.Subjects) > 0
}

func (s *Server) authenticateAdmin(r *http.Request) bool {
	return s.principal(r).has(ScopeAdmin)
}

func (s *Server) authenticateAgent(r *http.Request) bool {
	return s.principal(r).has(ScopeAgent)
}

func (s *Server) authenticateInstall(r *http.Request) bool {
	p := s.principal(r)
	return p.has(ScopeInstall) || p.Admin
}

func (s *Server) viewerSubject(r *http.Request) string {
	subjects := s.viewerSubjects(r)
	if len(subjects) == 0 {
		return ""
	}
	return subjects[0]
}

func (s *Server) viewerSubjects(r *http.Request) []string {
	subjects := s.principal(r).Subjects
	if subjects == nil {
		return []string{}
	}
	return subjects
}

func (s *Server) oidcIdentity(r *http.Request) oidcIdentity {
	if s.oidcAuth == nil {
		return oidcIdentity{}
	}
	if cache, ok := r.Context().Value(oidcIdentityCacheContextKey{}).(*oidcIdentityRequestCache); ok {
		cache.mu.Lock()
		defer cache.mu.Unlock()
		if cache.checked {
			return cache.identity
		}
		cache.checked = true
		cache.identity, cache.err = s.oidcAuth.identityFromRequest(r.Context(), r)
		if cache.err != nil {
			log.Printf("oidc token rejected request_id=%s: %v", requestIDFromRequest(r), cache.err)
			return oidcIdentity{}
		}
		return cache.identity
	}
	identity, err := s.oidcAuth.identityFromRequest(r.Context(), r)
	if err != nil {
		log.Printf("oidc token rejected request_id=%s: %v", requestIDFromRequest(r), err)
		return oidcIdentity{}
	}
	return identity
}

type oidcIdentityCacheContextKey struct{}

type oidcIdentityRequestCache struct {
	mu       sync.Mutex
	checked  bool
	identity oidcIdentity
	err      error
}

func (s *Server) oidcIdentityCacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), oidcIdentityCacheContextKey{}, &oidcIdentityRequestCache{})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type trustedIdentity struct {
	User     string
	Groups   []string
	Subjects []string
	Admin    bool
}

func (s *Server) trustedIdentity(r *http.Request) trustedIdentity {
	cfg := s.trustedAuth
	if cfg.userHeader == "" && cfg.groupsHeader == "" {
		return trustedIdentity{}
	}
	if !cfg.trustsRemoteAddr(r.RemoteAddr) {
		return trustedIdentity{}
	}
	user := ""
	if cfg.userHeader != "" {
		user = strings.TrimSpace(r.Header.Get(cfg.userHeader))
	}
	groups := []string{}
	if cfg.groupsHeader != "" {
		groups = splitIdentityHeaderValues(r.Header.Get(cfg.groupsHeader))
	}
	if user == "" && len(groups) == 0 {
		return trustedIdentity{}
	}
	subjects := []string{}
	admin := false
	if user != "" {
		subjects = appendUniqueString(subjects, "user:"+user)
		admin = cfg.adminUsers[user]
	}
	for _, group := range groups {
		subjects = appendUniqueString(subjects, "group:"+group)
		if cfg.adminGroups[group] {
			admin = true
		}
	}
	return trustedIdentity{User: user, Groups: groups, Subjects: subjects, Admin: admin}
}

func (c trustedIdentityConfig) trustsRemoteAddr(remoteAddr string) bool {
	if len(c.proxyNets) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	for _, network := range c.proxyNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func splitIdentityHeaderValues(raw string) []string {
	raw = strings.ReplaceAll(raw, ";", ",")
	return cleanCSV(strings.Split(raw, ","))
}

func appendUniqueString(items []string, item string) []string {
	item = strings.TrimSpace(item)
	if item == "" {
		return items
	}
	for _, existing := range items {
		if existing == item {
			return items
		}
	}
	return append(items, item)
}

func (s *Server) accessScope(r *http.Request) db.AccessScope {
	if !s.webAuth || s.principal(r).Admin {
		return db.AccessScope{All: true}
	}
	subjects := s.viewerSubjects(r)
	if len(subjects) == 0 {
		return db.AccessScope{}
	}
	scopes := make([]db.AccessScope, 0, len(subjects))
	for _, subject := range subjects {
		scope, err := s.db.GetAccessScope(r.Context(), subject)
		if err != nil {
			log.Printf("rbac scope %s: %v", subject, err)
			continue
		}
		scopes = append(scopes, scope)
	}
	return db.MergeAccessScopes(scopes...)
}

func (s *Server) authenticateExport(r *http.Request) bool {
	p := s.principal(r)
	return p.Admin || p.has(ScopeExport) || len(p.Subjects) > 0
}

func (s *Server) exportScope(r *http.Request) db.AccessScope {
	if s.principal(r).Admin {
		return db.AccessScope{All: true}
	}
	subjects := s.viewerSubjects(r)
	if len(subjects) == 0 {
		return db.AccessScope{}
	}
	scopes := make([]db.AccessScope, 0, len(subjects))
	for _, subject := range subjects {
		scope, err := s.db.GetExportScope(r.Context(), subject)
		if err != nil {
			log.Printf("rbac export scope %s: %v", subject, err)
			continue
		}
		scopes = append(scopes, scope)
	}
	return db.MergeAccessScopes(scopes...)
}

func (s *Server) canReadHost(r *http.Request, hostID string) bool {
	scope := s.accessScope(r)
	return scope.CanReadHost(hostID)
}

func (s *Server) canReadCveDB(r *http.Request) bool {
	if s.authenticateAdmin(r) || !s.webAuth {
		return true
	}
	subjects := s.viewerSubjects(r)
	if len(subjects) == 0 {
		return false
	}
	for _, subject := range subjects {
		ok, err := s.db.HasResourcePermission(r.Context(), subject, "cve_db", []string{"read", "admin"})
		if err != nil {
			log.Printf("rbac cve_db scope %s: %v", subject, err)
			continue
		}
		if ok {
			return true
		}
	}
	return false
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
	if u := s.sessionUser(r); u != nil {
		return u.Role
	}
	if s.trustedIdentity(r).User != "" {
		return "trusted_user"
	}
	if s.oidcIdentity(r).User != "" {
		return "oidc_user"
	}
	if len(s.viewerSubjects(r)) > 0 {
		return "viewer"
	}
	return "anonymous"
}

func (s *Server) actorID(r *http.Request) string {
	if u := s.sessionUser(r); u != nil {
		return u.Username
	}
	if identity := s.trustedIdentity(r); identity.User != "" {
		return "user:" + identity.User
	}
	if identity := s.oidcIdentity(r); identity.User != "" {
		return "user:" + identity.User
	}
	if subjects := s.viewerSubjects(r); len(subjects) > 0 {
		return subjects[0]
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
