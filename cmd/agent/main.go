package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/ziozzang/bongsu/internal/agent/collector"
	"github.com/ziozzang/bongsu/internal/agent/reporter"
	"github.com/ziozzang/bongsu/internal/agent/system"
	"github.com/ziozzang/bongsu/internal/shared/models"
)

const (
	maxCollectionErrors     = 32
	maxCollectionErrorBytes = 2048
)

func main() {
	serverURL := flag.String("server", "", "Bongsu server URL (e.g. http://bongsu:8080)")
	apiKey := flag.String("api-key", "", "API key for authentication")
	workDir := flag.String("work-dir", "/opt/bongsu", "Working directory")
	scanType := flag.String("type", "daily", "Scan type: daily or manual")
	packagesOnly := flag.Bool("packages-only", false, "Collect packages only (server-side CVE matching)")
	daemon := flag.Bool("daemon", false, "Poll server for force scan requests")
	pollInterval := flag.Duration("poll-interval", 60*time.Second, "Force scan polling interval")
	configFile := flag.String("config", "", "Config file path (YAML)")
	flag.Parse()
	agentToken := ""

	if *configFile != "" {
		cfg, err := loadConfig(*configFile)
		if err != nil {
			log.Fatalf("load config: %v", err)
		}
		if *serverURL == "" {
			*serverURL = cfg.ServerURL
		}
		if *apiKey == "" {
			*apiKey = cfg.APIKey
		}
		agentToken = cfg.AgentToken
		if *workDir == "/opt/bongsu" && cfg.WorkDir != "" {
			*workDir = cfg.WorkDir
		}
	}

	if *serverURL == "" {
		*serverURL = os.Getenv("BONGSU_SERVER_URL")
	}
	if *apiKey == "" {
		*apiKey = os.Getenv("BONGSU_AGENT_API_KEY")
	}
	if *apiKey == "" {
		*apiKey = os.Getenv("BONGSU_API_KEY")
	}
	if *serverURL == "" || *apiKey == "" {
		log.Fatal("server URL and API key are required (use -server, -api-key, or config file)")
	}
	if agentToken == "" {
		agentToken = os.Getenv("BONGSU_AGENT_TOKEN")
	}
	if agentToken == "" {
		var err error
		agentToken, err = ensureAgentToken(*workDir)
		if err != nil {
			log.Fatalf("agent token: %v", err)
		}
	}

	if *daemon {
		if err := runDaemon(*serverURL, *apiKey, agentToken, *workDir, *pollInterval); err != nil {
			log.Fatalf("daemon failed: %v", err)
		}
		return
	}

	if _, err := run(*serverURL, *apiKey, agentToken, *workDir, *scanType, *packagesOnly); err != nil {
		log.Fatalf("scan failed: %v", err)
	}
}

type config struct {
	ServerURL  string `yaml:"server_url"`
	APIKey     string `yaml:"api_key"`
	AgentToken string `yaml:"agent_token"`
	WorkDir    string `yaml:"work_dir"`
}

func loadConfig(path string) (*config, error) {
	// Simple YAML-like key: value parsing
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &config{}
	for _, line := range splitLines(string(data)) {
		k, v, ok := parseKV(line)
		if !ok {
			continue
		}
		switch k {
		case "server_url":
			cfg.ServerURL = trimQuotes(v)
		case "api_key":
			cfg.APIKey = trimQuotes(v)
		case "agent_token":
			cfg.AgentToken = trimQuotes(v)
		case "work_dir":
			cfg.WorkDir = trimQuotes(v)
		}
	}
	return cfg, nil
}

func splitLines(s string) []string {
	var lines []string
	for _, l := range split(s, "\n") {
		l = trimSpace(l)
		if l != "" && !hasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	return lines
}

func parseKV(line string) (string, string, bool) {
	for i, c := range line {
		if c == ':' {
			return trimSpace(line[:i]), trimSpace(line[i+1:]), true
		}
	}
	return "", "", false
}

func ensureAgentToken(workDir string) (string, error) {
	if err := os.MkdirAll(workDir, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(workDir, "agent.token")
	if data, err := os.ReadFile(path); err == nil {
		token := trimSpace(string(data))
		if token != "" {
			return token, nil
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	token := uuid.NewString() + uuid.NewString()
	if err := os.WriteFile(path, []byte(token+"\n"), 0600); err != nil {
		return "", err
	}
	return token, nil
}

func runDaemon(serverURL, apiKey, agentToken, workDir string, pollInterval time.Duration) error {
	log.Println("=== Bongsu Agent Daemon Starting ===")
	host, err := system.CollectHostInfo()
	if err != nil {
		return fmt.Errorf("system info: %w", err)
	}
	rep := reporter.New(serverURL, apiKey, agentToken)
	for {
		req, err := rep.ClaimScanRequest(host.ID)
		if err != nil {
			log.Printf("claim scan request failed: %v", err)
			time.Sleep(pollInterval)
			continue
		}
		if req == nil {
			time.Sleep(pollInterval)
			continue
		}
		log.Printf("claimed scan request %s type=%s packages_only=%v", req.ID, req.ScanType, req.PackagesOnly)
		result, err := run(serverURL, apiKey, agentToken, workDir, req.ScanType, req.PackagesOnly)
		if err != nil {
			log.Printf("scan request %s failed: %v", req.ID, err)
			_ = rep.CompleteScanRequest(req.ID, host.ID, "failed", err.Error())
			continue
		}
		status, message := scanRequestCompletionFromReport(result)
		if err := rep.CompleteScanRequest(req.ID, host.ID, status, message); err != nil {
			log.Printf("complete scan request %s failed: %v", req.ID, err)
		}
	}
}

func run(serverURL, apiKey, agentToken, workDir, scanType string, packagesOnly bool) (*reporter.ReportResult, error) {
	log.Println("=== Bongsu Agent Starting ===")
	log.Printf("Server: %s", serverURL)
	log.Printf("Work dir: %s", workDir)

	os.MkdirAll(filepath.Join(workDir, "bin"), 0755)

	scanID := uuid.New().String()
	now := time.Now()

	// 1. System info
	log.Println("Collecting system info...")
	host, err := system.CollectHostInfo()
	if err != nil {
		return nil, fmt.Errorf("system info: %w", err)
	}
	host.AgentVersion = "0.1.0"
	log.Printf("Host: %s (%s %s)", host.Hostname, host.OSName, host.OSVersion)
	collectionErrors := []string{}

	// 2. Users
	log.Println("Collecting user accounts...")
	users, err := system.CollectUsers()
	if err != nil {
		log.Printf("Warning: users collection failed: %v", err)
		collectionErrors = appendCollectionError(collectionErrors, "users", err)
	}
	log.Printf("Found %d users", len(users))

	// 3. Processes
	log.Println("Collecting process snapshot...")
	procs, err := system.CollectProcesses()
	if err != nil {
		log.Printf("Warning: process collection failed: %v", err)
		collectionErrors = appendCollectionError(collectionErrors, "processes", err)
	}
	log.Printf("Found %d processes", len(procs))

	// 4. Trivy - host scan
	coll := collector.New(workDir)
	coll.PackagesOnly = packagesOnly
	if packagesOnly {
		log.Println("Packages-only mode: server will handle CVE matching")
	}
	var allPkgs []models.Package
	var allVulns []models.Vulnerability

	log.Println("Running Trivy host scan...")
	pkgs, vulns, err := coll.CollectHostPackages()
	if err != nil {
		log.Printf("Warning: Trivy host scan failed: %v", err)
		collectionErrors = appendCollectionError(collectionErrors, "trivy_host", err)
	} else {
		for i := range pkgs {
			pkgs[i].AssetType = "host"
			pkgs[i].AssetID = host.ID
		}
		allPkgs = append(allPkgs, pkgs...)
		allVulns = append(allVulns, vulns...)
		log.Printf("Host: %d packages, %d vulnerabilities", len(pkgs), len(vulns))
	}

	// 5. Trivy - container scans
	log.Println("Detecting running containers...")
	containers, err := system.GetRunningContainers()
	if err != nil {
		log.Printf("Warning: container detection failed: %v", err)
		collectionErrors = appendCollectionError(collectionErrors, "containers", err)
	}
	for _, c := range containers {
		log.Printf("Running Trivy scan for container: %s (%s)", c.Name, c.ImageName)
		pkgs, vulns, err := coll.CollectContainerPackages(c.Name)
		if err != nil {
			log.Printf("Warning: container %s scan failed: %v", c.Name, err)
			collectionErrors = appendCollectionError(collectionErrors, "container "+c.Name, err)
			continue
		}
		assetID := c.ContainerID
		for i := range pkgs {
			pkgs[i].AssetType = "container"
			pkgs[i].AssetID = assetID
			pkgs[i].ContainerID = c.ContainerID
			pkgs[i].ImageName = c.ImageName
			pkgs[i].ImageID = c.ImageID
		}
		for i := range vulns {
			vulns[i].Container = c.Name
		}
		allPkgs = append(allPkgs, pkgs...)
		allVulns = append(allVulns, vulns...)
		log.Printf("Container %s: %d packages, %d vulnerabilities", c.Name, len(pkgs), len(vulns))
	}

	// 6. OSQuery packages
	log.Println("Running OSQuery package scan...")
	osqPkgs, err := coll.CollectOSQueryPackages()
	if err != nil {
		log.Printf("Warning: OSQuery scan failed: %v", err)
		collectionErrors = appendCollectionError(collectionErrors, "osquery_packages", err)
	} else {
		for i := range osqPkgs {
			osqPkgs[i].AssetType = "host"
			osqPkgs[i].AssetID = host.ID
		}
		allPkgs = append(allPkgs, osqPkgs...)
		log.Printf("OSQuery: %d packages", len(osqPkgs))
	}

	// 7. OSQuery listening ports
	var ports []models.PortInfo
	log.Println("Collecting listening ports...")
	ports, err = coll.CollectOSQueryListeningPorts()
	if err != nil {
		log.Printf("Warning: port collection failed: %v", err)
		collectionErrors = appendCollectionError(collectionErrors, "osquery_ports", err)
	} else {
		log.Printf("Found %d listening ports", len(ports))
	}

	// 8. Build and send report
	report := &models.ScanReport{
		Host:       *host,
		ScanType:   scanType,
		ScanID:     scanID,
		Errors:     collectionErrors,
		Containers: containers,
		Packages:   allPkgs,
		Users:      users,
		Processes:  procs,
		Ports:      ports,
		Timestamp:  now,
	}
	if !packagesOnly {
		report.Vulns = allVulns
	}

	log.Printf("Total: %d packages, %d vulnerabilities", len(allPkgs), len(allVulns))

	log.Println("Sending report to server...")
	rep := reporter.New(serverURL, apiKey, agentToken)
	result, err := rep.Send(report)
	if err != nil {
		return nil, fmt.Errorf("send report: %w", err)
	}

	if result.ScanStatus == "degraded" {
		log.Printf("=== Scan degraded: inventory=%s ingest_errors=%d skipped_vulns=%d ===", result.InventoryStatus, result.IngestErrorCount, result.SkippedVulnCount)
	} else {
		log.Println("=== Scan complete ===")
	}
	return result, nil
}

func scanRequestCompletionFromReport(result *reporter.ReportResult) (string, string) {
	if result == nil || result.ScanStatus != "degraded" {
		return "completed", ""
	}
	return "degraded", fmt.Sprintf("scan degraded: inventory_status=%s ingest_errors=%d skipped_vulns=%d", result.InventoryStatus, result.IngestErrorCount, result.SkippedVulnCount)
}

func appendCollectionError(errs []string, area string, err error) []string {
	if err == nil {
		return errs
	}
	entry := trimSpace(area + ": " + err.Error())
	if len(entry) > maxCollectionErrorBytes {
		entry = truncateValidUTF8(entry, maxCollectionErrorBytes) + "...(truncated)"
	}
	if len(errs) >= maxCollectionErrors {
		errs[maxCollectionErrors-1] = "additional collection errors omitted"
		return errs
	}
	return append(errs, entry)
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

// Minimal string helpers (avoid importing full strings package for edge cases)
func split(s, sep string) []string {
	var result []string
	for {
		i := indexOf(s, sep)
		if i < 0 {
			result = append(result, s)
			break
		}
		result = append(result, s[:i])
		s = s[i+len(sep):]
	}
	return result
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\n' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func trimQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
