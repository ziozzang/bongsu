package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ziozzang/bongsu/internal/server/api"
	"github.com/ziozzang/bongsu/internal/server/cvematch"
	"github.com/ziozzang/bongsu/internal/server/db"
	"github.com/ziozzang/bongsu/internal/server/secdb"
	"github.com/ziozzang/bongsu/internal/server/trivydb"
)

var (
	version   = "dev"
	commit    = ""
	buildDate = ""
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println(serverVersionString())
		return
	}
	// intel-mcp subcommand: serve the read-only intelligence tools over MCP stdio
	// for a single run (loaded by the jikji agent via --tools-from). It must not
	// start the HTTP server.
	if len(os.Args) > 1 && os.Args[1] == "intel-mcp" {
		os.Exit(runIntelMCP(os.Args[2:]))
	}

	startTime := time.Now()
	port := envInt("BONGSU_PORT", 5677)
	dbDSN := envOr("BONGSU_DB_DSN", "postgres://bongsu:bongsu@localhost:5432/bongsu?sslmode=disable")
	autoMigrate := envBool("BONGSU_AUTO_MIGRATE", true)
	if err := validateServerSecrets(); err != nil {
		log.Fatalf("invalid server secret configuration: %v", err)
	}

	connectCtx, connectCancel := context.WithTimeout(context.Background(), time.Duration(envPositiveInt("BONGSU_DB_CONNECT_TIMEOUT_SECONDS", 30))*time.Second)
	defer connectCancel()

	database, err := db.New(connectCtx, dbDSN)
	if err != nil {
		log.Fatalf("connect to database: %v", err)
	}
	defer database.Close()
	log.Println("Connected to database")

	queueStartupAffectedIndexRebuild := false
	if autoMigrate {
		migrationCtx, migrationCancel := context.WithTimeout(context.Background(), time.Duration(envPositiveInt("BONGSU_DB_MIGRATION_TIMEOUT_SECONDS", 600))*time.Second)
		if err := database.RunMigrations(migrationCtx); err != nil {
			migrationCancel()
			log.Fatalf("run migrations: %v", err)
		}
		migrationCancel()
		log.Println("Database migrations applied")
		indexCtx, indexCancel := context.WithTimeout(context.Background(), time.Duration(envInt("BONGSU_CVE_AFFECTED_INDEX_REBUILD_TIMEOUT_SECONDS", 180))*time.Second)
		if n, err := database.EnsureCveAffectedPackages(indexCtx); err != nil {
			indexCancel()
			queueStartupAffectedIndexRebuild = true
			log.Printf("WARNING: prepare CVE affected package index skipped; API will start and queue async rebuild: %v", err)
		} else if n > 0 {
			indexCancel()
			log.Printf("Indexed %d CVE affected packages", n)
		} else {
			indexCancel()
		}
		go func() {
			refCtx, refCancel := context.WithTimeout(context.Background(), time.Duration(envInt("BONGSU_CVE_REFERENCE_INDEX_REBUILD_TIMEOUT_SECONDS", 180))*time.Second)
			defer refCancel()
			if n, err := database.EnsureCveReferenceKeys(refCtx); err != nil {
				log.Printf("WARNING: prepare CVE reference key index: %v", err)
			} else if n > 0 {
				log.Printf("Indexed %d CVE reference keys", n)
			}
		}()
		sourceCtx, sourceCancel := context.WithTimeout(context.Background(), time.Duration(envInt("BONGSU_SECURITY_SOURCE_STATUS_TIMEOUT_SECONDS", 30))*time.Second)
		if err := database.EnsureSecuritySourceStatus(sourceCtx, ""); err != nil {
			log.Printf("WARNING: refresh security source registry status: %v", err)
		}
		sourceCancel()
	}

	// Trivy DB manager and CVE matcher (optional)
	var matcher *cvematch.Matcher
	var dbMgr *trivydb.Manager

	trivyPath := envOr("BONGSU_TRIVY_PATH", "trivy")
	if resolved, err := exec.LookPath(trivyPath); err == nil {
		trivyPath = resolved
		cacheDir := envOr("BONGSU_TRIVY_CACHE_DIR", "/app/trivy-cache")
		dbRepo := envOr("BONGSU_TRIVY_DB_REPO", "ghcr.io/aquasecurity/trivy-db")
		interval := time.Duration(envInt("BONGSU_TRIVY_DB_INTERVAL_HOURS", 6)) * time.Hour

		dbMgr = trivydb.NewManager(trivyPath, cacheDir, dbRepo, interval)
		matcher = cvematch.NewMatcher(trivyPath, cacheDir, dbRepo)
		log.Printf("Trivy DB manager configured (repo: %s, interval: %s)", dbRepo, interval)
	} else {
		log.Printf("Trivy not found at %s, server-side CVE matching disabled", trivyPath)
	}

	secSyncCmd := os.Getenv("BONGSU_SECURITY_DB_SYNC_CMD")
	secInterval := time.Duration(envInt("BONGSU_SECURITY_DB_INTERVAL_HOURS", 6)) * time.Hour
	secMgr := secdb.NewManager(secSyncCmd, secInterval)
	secMgr.SetSyncOnStart(envBool("BONGSU_SECURITY_DB_SYNC_ON_START", true))
	secFreshCtx, secFreshCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if stats, err := database.GetCveSourceFreshnessStats(secFreshCtx); err == nil {
		var latest time.Time
		for _, stat := range stats {
			if stat.LastUpdate != nil && stat.LastUpdate.After(latest) {
				latest = *stat.LastUpdate
			}
		}
		if !latest.IsZero() {
			secMgr.SetLastSyncHint(latest)
		}
	} else {
		log.Printf("security-db persisted freshness seed skipped: %v", err)
	}
	secFreshCancel()

	server := api.New(database, matcher, dbMgr, secMgr, api.BuildInfo{
		Version:   version,
		Commit:    commit,
		BuildDate: buildDate,
		StartTime: startTime,
	})
	secMgr.SetFailureHook(server.SecurityDatabaseSyncFailed)
	// Run the startup recalc in the BACKGROUND: on a large, mostly-enriched
	// dataset (100k+ rows) these full-table passes take a while, and blocking the
	// listener on them delayed availability by up to the whole budget. Each task
	// gets its OWN timeout so a slow one (enrichment) can't starve the next
	// (severity normalization) — the previous shared budget caused exactly that.
	// The passes only fill empty fields, so serving un-enriched rows briefly on a
	// cold boot is acceptable and self-heals.
	go func() {
		recalcTimeout := time.Duration(envInt("BONGSU_STARTUP_RECALC_TIMEOUT_SECONDS", 600)) * time.Second
		runStartupRecalc("CVSS score calculation", recalcTimeout, database.CalcCvssScores, "Calculated CVSS scores for %d entries")
		runStartupRecalc("CVE enrichment", recalcTimeout, database.EnrichVulnerabilities, "Enriched %d vulnerabilities with CVE DB info")
		runStartupRecalc("Severity normalization", recalcTimeout, database.NormalizeVulnSeverity, "Normalized severity for %d vulnerabilities")
	}()

	summaryCtx, summaryCancel := context.WithTimeout(context.Background(), time.Duration(envInt("BONGSU_PACKAGE_SUMMARY_REBUILD_TIMEOUT_SECONDS", 120))*time.Second)
	if n, err := database.RebuildLatestPackageVulnerabilitySummaries(summaryCtx); err == nil && n > 0 {
		log.Printf("Rebuilt %d package vulnerability summaries", n)
	} else if err != nil {
		log.Printf("Package vulnerability summary rebuild: %v", err)
	}
	summaryCancel()
	key := server.APIKey()
	if len(key) > 8 {
		log.Printf("API Key: %s...%s", key[:4], key[len(key)-4:])
	} else {
		log.Printf("API Key: %s", key)
	}

	httpServer := newHTTPServer(port, server.Handler())
	listener, err := net.Listen("tcp", httpServer.Addr)
	if err != nil {
		log.Fatalf("listen on %s: %v", httpServer.Addr, err)
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- httpServer.Serve(listener)
	}()

	log.Printf("Bongsu server listening on :%d", port)
	if queueStartupAffectedIndexRebuild {
		if started, status := server.QueueCveAffectedIndexRebuild(); started {
			log.Printf("Queued async CVE affected package index rebuild after startup prepare failure")
		} else {
			log.Printf("Async CVE affected package index rebuild not queued after startup prepare failure: %s", status)
		}
	}
	if dbMgr != nil {
		dbMgr.SetUpdateHook(server.SecurityDatabaseUpdated)
		bgCtx, bgCancel := context.WithCancel(context.Background())
		defer bgCancel()
		go dbMgr.Start(bgCtx)
		log.Println("Trivy DB manager started")
	}
	if secSyncCmd != "" {
		secMgr.SetUpdateHook(server.SecurityDatabaseUpdated)
		bgCtx, bgCancel := context.WithCancel(context.Background())
		defer bgCancel()
		go secMgr.Start(bgCtx)
		log.Println("Security DB sync manager started")
	}

	// Event-outbox dispatcher: delivers durable pipeline events (notifications,
	// rematch) at-least-once with retry and dead-lettering.
	{
		bgCtx, bgCancel := context.WithCancel(context.Background())
		defer bgCancel()
		go server.StartOutboxDispatcher(bgCtx)
		log.Println("Event outbox dispatcher started")
	}

	// Agent liveness monitor: emits agent.online/offline live events on status
	// transitions for the real-time dashboard.
	{
		bgCtx, bgCancel := context.WithCancel(context.Background())
		defer bgCancel()
		go server.StartLivenessMonitor(bgCtx)
		log.Println("Agent liveness monitor started")
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case <-sigCh:
		log.Println("Shutting down...")

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		httpServer.Shutdown(shutdownCtx)
		if err := <-serveErr; err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}
	log.Println("Server stopped")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// runStartupRecalc runs one background recalc pass under its own timeout and
// logs the outcome. Isolating each task's budget prevents a slow pass from
// starving the ones after it.
func runStartupRecalc(name string, timeout time.Duration, fn func(context.Context) (int, error), okFmt string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if n, err := fn(ctx); err != nil {
		log.Printf("%s: %v", name, err)
	} else if n > 0 {
		log.Printf(okFmt, n)
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

func envPositiveInt(key string, def int) int {
	n := envInt(key, def)
	if n <= 0 {
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

func newHTTPServer(port int, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           handler,
		ReadHeaderTimeout: time.Duration(envPositiveInt("BONGSU_HTTP_READ_HEADER_TIMEOUT_SECONDS", 10)) * time.Second,
		ReadTimeout:       time.Duration(envPositiveInt("BONGSU_HTTP_READ_TIMEOUT_SECONDS", 30)) * time.Second,
		WriteTimeout:      time.Duration(envPositiveInt("BONGSU_HTTP_WRITE_TIMEOUT_SECONDS", 900)) * time.Second,
		IdleTimeout:       time.Duration(envPositiveInt("BONGSU_HTTP_IDLE_TIMEOUT_SECONDS", 120)) * time.Second,
		MaxHeaderBytes:    envPositiveInt("BONGSU_HTTP_MAX_HEADER_BYTES", 1<<20),
	}
}

func validateServerSecrets() error {
	if envBool("BONGSU_ALLOW_WEAK_SECRETS", false) {
		return nil
	}
	type secret struct {
		name  string
		value string
	}
	secrets := []secret{
		{name: "BONGSU_API_KEY", value: os.Getenv("BONGSU_API_KEY")},
		{name: "BONGSU_AGENT_API_KEY", value: os.Getenv("BONGSU_AGENT_API_KEY")},
		{name: "BONGSU_INSTALL_TOKEN", value: os.Getenv("BONGSU_INSTALL_TOKEN")},
	}
	for _, s := range secrets {
		if weakSecretValue(s.value) {
			return fmt.Errorf("%s is missing, too short, or still uses a placeholder value", s.name)
		}
	}
	apiKey := strings.TrimSpace(os.Getenv("BONGSU_API_KEY"))
	agentKey := strings.TrimSpace(os.Getenv("BONGSU_AGENT_API_KEY"))
	if apiKey != "" && agentKey != "" && subtleSecretEqual(apiKey, agentKey) {
		return fmt.Errorf("BONGSU_AGENT_API_KEY must be distinct from BONGSU_API_KEY")
	}
	return nil
}

func weakSecretValue(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) < 16 {
		return true
	}
	lower := strings.ToLower(v)
	weakParts := []string{
		"change-me",
		"changeme",
		"your-",
		"example",
		"password",
		"secret-key",
		"secret-token",
		"admin-key",
		"agent-key",
		"install-token",
	}
	for _, part := range weakParts {
		if strings.Contains(lower, part) {
			return true
		}
	}
	return false
}

func subtleSecretEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func serverVersionString() string {
	parts := []string{strings.TrimSpace(version)}
	if parts[0] == "" {
		parts[0] = "dev"
	}
	if c := strings.TrimSpace(commit); c != "" {
		if len(c) > 12 {
			c = c[:12]
		}
		parts = append(parts, c)
	}
	if d := strings.TrimSpace(buildDate); d != "" {
		parts = append(parts, d)
	}
	return strings.Join(parts, "+")
}
