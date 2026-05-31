package main

import (
	"context"
	"fmt"
	"log"
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

func main() {
	port := envInt("BONGSU_PORT", 8080)
	dbDSN := envOr("BONGSU_DB_DSN", "postgres://bongsu:bongsu@localhost:5432/bongsu?sslmode=disable")
	autoMigrate := envBool("BONGSU_AUTO_MIGRATE", true)
	if err := validateServerSecrets(); err != nil {
		log.Fatalf("invalid server secret configuration: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	database, err := db.New(ctx, dbDSN)
	if err != nil {
		log.Fatalf("connect to database: %v", err)
	}
	defer database.Close()
	log.Println("Connected to database")

	if autoMigrate {
		if err := database.RunMigrations(ctx); err != nil {
			log.Fatalf("run migrations: %v", err)
		}
		log.Println("Database migrations applied")
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

	server := api.New(database, matcher, dbMgr, secMgr)
	secMgr.SetFailureHook(server.SecurityDatabaseSyncFailed)
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
	if n, err := database.CalcCvssScores(ctx); err == nil && n > 0 {
		log.Printf("Calculated CVSS scores for %d entries", n)
	} else if err != nil {
		log.Printf("CVSS score calculation: %v", err)
	}
	if n, err := database.EnrichVulnerabilities(ctx); err == nil && n > 0 {
		log.Printf("Enriched %d vulnerabilities with CVE DB info", n)
	} else if err != nil {
		log.Printf("CVE enrichment: %v", err)
	}
	if n, err := database.NormalizeVulnSeverity(ctx); err == nil && n > 0 {
		log.Printf("Normalized severity for %d vulnerabilities", n)
	} else if err != nil {
		log.Printf("Severity normalization: %v", err)
	}
	key := server.APIKey()
	if len(key) > 8 {
		log.Printf("API Key: %s...%s", key[:4], key[len(key)-4:])
	} else {
		log.Printf("API Key: %s", key)
	}

	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      server.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down...")

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		httpServer.Shutdown(shutdownCtx)
	}()

	log.Printf("Bongsu server listening on :%d", port)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
	log.Println("Server stopped")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
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
		if s.value == "" {
			continue
		}
		if weakSecretValue(s.value) {
			return fmt.Errorf("%s is empty, too short, or still uses a placeholder value", s.name)
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
