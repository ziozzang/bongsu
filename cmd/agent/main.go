package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/ziozzang/bongsu/internal/agent/collector"
	"github.com/ziozzang/bongsu/internal/agent/reporter"
	"github.com/ziozzang/bongsu/internal/agent/scanner"
	"github.com/ziozzang/bongsu/internal/agent/system"
	"github.com/ziozzang/bongsu/internal/shared/models"
)

const (
	maxCollectionErrors     = 32
	maxCollectionErrorBytes = 2048
	// defaultLangScanRoots enables language dependency scanning out of the box
	// in the locations where apps/runtimes are typically installed outside the
	// OS package manager (pyenv/nvm under home, service trees under /opt,/srv).
	// Operators can set 'none' to disable or 'all' to walk the whole scan-root.
	defaultLangScanRoots = "/opt,/srv,/usr/local,/var/www,/app,/home,/root"
)

var (
	version   = "dev"
	commit    = ""
	buildDate = ""
)

func main() {
	defaultScanRoot := envString("BONGSU_AGENT_SCAN_ROOT", "/")
	defaultTrivyTimeout := envDurationSeconds("BONGSU_AGENT_TRIVY_TIMEOUT_SECONDS", 30*time.Minute)
	defaultContainerTimeout := envDurationSeconds("BONGSU_AGENT_CONTAINER_TIMEOUT_SECONDS", 10*time.Minute)
	defaultCommandTimeout := envDurationSeconds("BONGSU_AGENT_COMMAND_TIMEOUT_SECONDS", 30*time.Second)
	serverURL := flag.String("server", "", "Bongsu API URL (e.g. http://bongsu:5677)")
	apiKey := flag.String("api-key", "", "API key for authentication")
	workDir := flag.String("work-dir", "/opt/bongsu", "Working directory")
	scanType := flag.String("type", "daily", "Scan type: daily or manual")
	packagesOnly := flag.Bool("packages-only", false, "Collect packages only (server-side CVE matching)")
	daemon := flag.Bool("daemon", false, "Poll server for force scan requests")
	pollInterval := flag.Duration("poll-interval", 60*time.Second, "Force scan polling interval")
	hostID := flag.String("host-id", "", "Override host identity for cloned/containerized environments")
	scanRoot := flag.String("scan-root", defaultScanRoot, "Host filesystem root/path for Trivy fs scans")
	trivyTimeout := flag.Duration("trivy-timeout", defaultTrivyTimeout, "Timeout for host Trivy filesystem scans")
	containerTimeout := flag.Duration("container-timeout", defaultContainerTimeout, "Timeout for each container image Trivy scan")
	commandTimeout := flag.Duration("command-timeout", defaultCommandTimeout, "Timeout for agent helper commands such as docker inspect, osquery, ps, and uname")
	skipContainers := flag.Bool("skip-containers", envBool("BONGSU_AGENT_SKIP_CONTAINERS", false), "Skip container detection and image scans")
	maxContainers := flag.Int("max-containers", envInt("BONGSU_AGENT_MAX_CONTAINERS", 0), "Maximum running containers to scan per run; 0 means unlimited")
	scannerMode := flag.String("scanner", envString("BONGSU_AGENT_SCANNER", "native"), "Package scanner engine: native (built-in, no external dependency) or trivy")
	langScanRoots := flag.String("lang-scan-roots", envString("BONGSU_AGENT_LANG_SCAN_ROOTS", defaultLangScanRoots), "Comma-separated roots to walk for language deps installed outside the OS package manager; 'none' disables, 'all' scans the host scan-root")
	langScanDepth := flag.Int("lang-scan-depth", envInt("BONGSU_AGENT_LANG_SCAN_DEPTH", 12), "Max directory depth for the language dependency walk")
	configFile := flag.String("config", "", "Config file path (YAML)")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()
	visitedFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { visitedFlags[f.Name] = true })
	agentToken := ""

	if *showVersion {
		fmt.Println(agentVersionString())
		return
	}

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
		if *hostID == "" {
			*hostID = cfg.HostID
		}
		if !visitedFlags["scan-root"] && cfg.ScanRoot != "" {
			*scanRoot = cfg.ScanRoot
		}
		if !visitedFlags["trivy-timeout"] && cfg.TrivyTimeoutSeconds > 0 {
			*trivyTimeout = time.Duration(cfg.TrivyTimeoutSeconds) * time.Second
		}
		if !visitedFlags["container-timeout"] && cfg.ContainerTimeoutSeconds > 0 {
			*containerTimeout = time.Duration(cfg.ContainerTimeoutSeconds) * time.Second
		}
		if !visitedFlags["command-timeout"] && cfg.CommandTimeoutSeconds > 0 {
			*commandTimeout = time.Duration(cfg.CommandTimeoutSeconds) * time.Second
		}
		if !visitedFlags["skip-containers"] && cfg.SkipContainers != nil {
			*skipContainers = *cfg.SkipContainers
		}
		if !visitedFlags["max-containers"] && cfg.MaxContainers > 0 {
			*maxContainers = cfg.MaxContainers
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
	if *hostID == "" {
		*hostID = os.Getenv("BONGSU_HOST_ID")
	}
	if *hostID == "" {
		*hostID = os.Getenv("BONGSU_AGENT_HOST_ID")
	}
	if agentToken == "" {
		var err error
		agentToken, err = ensureAgentToken(*workDir)
		if err != nil {
			log.Fatalf("agent token: %v", err)
		}
	}

	scanOpts := agentScanOptions{
		PackagesOnly:     *packagesOnly,
		ScanRoot:         *scanRoot,
		TrivyTimeout:     *trivyTimeout,
		ContainerTimeout: *containerTimeout,
		CommandTimeout:   *commandTimeout,
		SkipContainers:   *skipContainers,
		MaxContainers:    *maxContainers,
		Scanner:          *scannerMode,
		LangScanRoots:    resolveLangScanRoots(*langScanRoots, *scanRoot),
		LangScanDepth:    *langScanDepth,
	}
	applyAgentCommandTimeout(scanOpts.CommandTimeout)
	if *daemon {
		if err := runDaemon(*serverURL, *apiKey, agentToken, *workDir, *hostID, *pollInterval, scanOpts); err != nil {
			log.Fatalf("daemon failed: %v", err)
		}
		return
	}

	if _, err := run(*serverURL, *apiKey, agentToken, *workDir, *hostID, *scanType, scanOpts, "", ""); err != nil {
		log.Fatalf("scan failed: %v", err)
	}
}

type agentScanOptions struct {
	PackagesOnly     bool
	ScanRoot         string
	TrivyTimeout     time.Duration
	ContainerTimeout time.Duration
	CommandTimeout   time.Duration
	SkipContainers   bool
	MaxContainers    int
	Scanner          string
	LangScanRoots    []string
	LangScanDepth    int
}

func splitCSVRoots(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// resolveLangScanRoots maps the lang-scan-roots flag to concrete paths,
// honoring the 'none' (disable) and 'all' (whole scan-root) sentinels, and
// dropping configured roots that don't exist so a host without /var/www
// doesn't log spurious walk failures.
func resolveLangScanRoots(spec, scanRoot string) []string {
	switch strings.ToLower(strings.TrimSpace(spec)) {
	case "", "none", "off", "disabled":
		return nil
	case "all":
		if scanRoot == "" {
			scanRoot = "/"
		}
		return []string{scanRoot}
	}
	var out []string
	for _, p := range splitCSVRoots(spec) {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			out = append(out, p)
		}
	}
	return out
}

func (o agentScanOptions) nativeScanner() bool {
	return strings.ToLower(strings.TrimSpace(o.Scanner)) != "trivy"
}

type config struct {
	ServerURL               string `yaml:"server_url"`
	APIKey                  string `yaml:"api_key"`
	AgentToken              string `yaml:"agent_token"`
	WorkDir                 string `yaml:"work_dir"`
	HostID                  string `yaml:"host_id"`
	ScanRoot                string `yaml:"scan_root"`
	TrivyTimeoutSeconds     int    `yaml:"trivy_timeout_seconds"`
	ContainerTimeoutSeconds int    `yaml:"container_timeout_seconds"`
	CommandTimeoutSeconds   int    `yaml:"command_timeout_seconds"`
	SkipContainers          *bool  `yaml:"skip_containers"`
	MaxContainers           int    `yaml:"max_containers"`
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
		case "host_id":
			cfg.HostID = trimQuotes(v)
		case "scan_root":
			cfg.ScanRoot = trimQuotes(v)
		case "trivy_timeout_seconds":
			cfg.TrivyTimeoutSeconds = parsePositiveInt(v)
		case "container_timeout_seconds":
			cfg.ContainerTimeoutSeconds = parsePositiveInt(v)
		case "command_timeout_seconds":
			cfg.CommandTimeoutSeconds = parsePositiveInt(v)
		case "skip_containers":
			if b, ok := parseBool(v); ok {
				cfg.SkipContainers = &b
			}
		case "max_containers":
			cfg.MaxContainers = parsePositiveInt(v)
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

func applyHostIDOverride(host *models.Host, override string) {
	if host == nil {
		return
	}
	override = strings.TrimSpace(override)
	if override != "" {
		host.ID = override
	}
}

func runDaemon(serverURL, apiKey, agentToken, workDir, hostIDOverride string, pollInterval time.Duration, scanOpts agentScanOptions) error {
	log.Println("=== Bongsu Agent Daemon Starting ===")
	applyAgentCommandTimeout(scanOpts.CommandTimeout)
	host, err := system.CollectHostInfo()
	if err != nil {
		return fmt.Errorf("system info: %w", err)
	}
	applyHostIDOverride(host, hostIDOverride)
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
		reqOpts := scanOpts
		reqOpts.PackagesOnly = req.PackagesOnly
		result, err := run(serverURL, apiKey, agentToken, workDir, hostIDOverride, req.ScanType, reqOpts, req.ID, req.SecurityDBRevision)
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

func run(serverURL, apiKey, agentToken, workDir, hostIDOverride, scanType string, scanOpts agentScanOptions, scanRequestID, securityDBRevision string) (*reporter.ReportResult, error) {
	log.Println("=== Bongsu Agent Starting ===")
	log.Printf("Server: %s", serverURL)
	log.Printf("Work dir: %s", workDir)
	applyAgentCommandTimeout(scanOpts.CommandTimeout)

	os.MkdirAll(filepath.Join(workDir, "bin"), 0755)

	scanID := uuid.New().String()
	now := time.Now()

	// 1. System info
	log.Println("Collecting system info...")
	host, err := system.CollectHostInfo()
	if err != nil {
		return nil, fmt.Errorf("system info: %w", err)
	}
	applyHostIDOverride(host, hostIDOverride)
	host.AgentVersion = agentVersionString()
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
	coll.PackagesOnly = scanOpts.PackagesOnly
	coll.HostScanRoot = scanOpts.ScanRoot
	coll.HostTimeout = scanOpts.TrivyTimeout
	coll.ImageTimeout = scanOpts.ContainerTimeout
	coll.CommandTimeout = scanOpts.CommandTimeout
	coll.Scanner = scanOpts.Scanner
	if scanOpts.PackagesOnly {
		log.Println("Packages-only mode: server will handle CVE matching")
	}
	var allPkgs []models.Package
	var allVulns []models.Vulnerability

	hostScanLabel := "Trivy"
	if scanOpts.nativeScanner() {
		hostScanLabel = "native"
	}
	log.Printf("Running %s host scan...", hostScanLabel)
	nativeHostPackages := 0
	pkgs, vulns, err := coll.CollectHostPackages()
	if err != nil {
		log.Printf("Warning: %s host scan failed: %v", hostScanLabel, err)
		collectionErrors = appendCollectionError(collectionErrors, "host_packages", err)
	} else {
		for i := range pkgs {
			pkgs[i].AssetType = "host"
			pkgs[i].AssetID = host.ID
		}
		allPkgs = append(allPkgs, pkgs...)
		allVulns = append(allVulns, vulns...)
		nativeHostPackages = len(pkgs)
		log.Printf("Host: %d packages, %d vulnerabilities", len(pkgs), len(vulns))
	}

	// 4b. Language dependency + runtime scan — finds libraries (lockfiles,
	// installed metadata) AND language runtimes themselves (pyenv-built
	// pythons, node tarballs, hand-unpacked JDKs) installed outside the OS
	// package manager, across the configured language scan roots.
	if scanOpts.nativeScanner() && len(scanOpts.LangScanRoots) > 0 {
		langSeen := 0
		runtimeSeen := 0
		for _, lr := range scanOpts.LangScanRoots {
			langPkgs := scanner.ScanLanguagePackages(lr, scanOpts.LangScanDepth)
			for i := range langPkgs {
				langPkgs[i].AssetType = "host"
				langPkgs[i].AssetID = host.ID
			}
			allPkgs = append(allPkgs, langPkgs...)
			langSeen += len(langPkgs)

			rtPkgs := scanner.ScanRuntimes(lr, scanOpts.LangScanDepth)
			for i := range rtPkgs {
				rtPkgs[i].AssetType = "host"
				rtPkgs[i].AssetID = host.ID
			}
			allPkgs = append(allPkgs, rtPkgs...)
			runtimeSeen += len(rtPkgs)
		}
		if langSeen > 0 || runtimeSeen > 0 {
			log.Printf("Language scan: %d packages, %d runtimes across %d root(s)", langSeen, runtimeSeen, len(scanOpts.LangScanRoots))
		}
	}

	// 5. Trivy - container scans
	var containers []models.ContainerAsset
	if scanOpts.SkipContainers {
		log.Println("Container detection and scans skipped by configuration")
		collectionErrors = appendCollectionError(collectionErrors, "containers", fmt.Errorf("skipped by agent configuration"))
	} else {
		log.Println("Detecting running containers...")
		containers, err = system.GetRunningContainers()
		if err != nil {
			log.Printf("Warning: container detection failed: %v", err)
			collectionErrors = appendCollectionError(collectionErrors, "containers", err)
		}
		if scanOpts.MaxContainers > 0 && len(containers) > scanOpts.MaxContainers {
			msg := fmt.Errorf("container scan limit reached: scanning %d of %d containers", scanOpts.MaxContainers, len(containers))
			log.Printf("Warning: %v", msg)
			collectionErrors = appendCollectionError(collectionErrors, "containers", msg)
			containers = containers[:scanOpts.MaxContainers]
		}
		for idx := range containers {
			c := &containers[idx]
			var pkgs []models.Package
			var vulns []models.Vulnerability
			var err error
			if scanOpts.nativeScanner() {
				var scan *collector.ContainerScan
				scan, err = coll.ScanContainerNative(c.ContainerID, c.Runtime)
				if err == nil {
					pkgs = scan.Packages
					c.Facts = scan.Facts
				} else {
					// Native rootfs unreadable (e.g. CRI runtime, permissions):
					// fall back to trivy if it is available.
					log.Printf("Native container scan for %s failed (%v); trying trivy fallback", c.Name, err)
					pkgs, vulns, err = coll.CollectContainerPackages(c.Name, c.ImageName, c.Runtime)
				}
			} else {
				log.Printf("Running Trivy scan for container: %s (%s)", c.Name, c.ImageName)
				pkgs, vulns, err = coll.CollectContainerPackages(c.Name, c.ImageName, c.Runtime)
			}
			if err != nil {
				log.Printf("Warning: container %s scan failed: %v", c.Name, err)
				collectionErrors = appendCollectionError(collectionErrors, "container "+c.Name, err)
				continue
			}
			assetID := c.ContainerID
			for i := range pkgs {
				pkgs[i].AssetType = "container"
				pkgs[i].AssetID = assetID
				pkgs[i].Container = c.Name
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
	}

	// 6. OSQuery packages — only as a supplementary OS-package source when the
	// native scanner found nothing (it already reads the same dpkg/apk/rpm DBs,
	// so running both would double-count host packages).
	if !scanOpts.nativeScanner() || nativeHostPackages == 0 {
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
		Host:               *host,
		ScanType:           scanType,
		ScanID:             scanID,
		ScanRequestID:      scanRequestID,
		SecurityDBRevision: securityDBRevision,
		Errors:             collectionErrors,
		Containers:         containers,
		Packages:           allPkgs,
		Users:              users,
		Processes:          procs,
		Ports:              ports,
		Timestamp:          now,
	}
	if !scanOpts.PackagesOnly {
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

func applyAgentCommandTimeout(timeout time.Duration) {
	if timeout > 0 {
		os.Setenv("BONGSU_AGENT_COMMAND_TIMEOUT_SECONDS", strconv.Itoa(int(timeout.Seconds())))
	}
}

func agentVersionString() string {
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

func parsePositiveInt(s string) int {
	n, err := strconv.Atoi(trimQuotes(trimSpace(s)))
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

func parseBool(s string) (bool, bool) {
	b, err := strconv.ParseBool(trimQuotes(trimSpace(s)))
	return b, err == nil
}

func envString(key, def string) string {
	if v := os.Getenv(key); strings.TrimSpace(v) != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return n
}

func envBool(key string, def bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		return def
	}
	return b
}

func envDurationSeconds(key string, def time.Duration) time.Duration {
	seconds := envInt(key, 0)
	if seconds <= 0 {
		return def
	}
	return time.Duration(seconds) * time.Second
}
