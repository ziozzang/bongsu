package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ziozzang/bongsu/internal/shared/models"
	"github.com/ziozzang/bongsu/internal/shared/trivyparse"
)

const defaultDBRepository = "ghcr.io/aquasecurity/trivy-db"

type Collector struct {
	workDir        string
	trivy          string
	osquery        string
	dbRepository   string
	PackagesOnly   bool
	HostScanRoot   string
	HostTimeout    time.Duration
	ImageTimeout   time.Duration
	CommandTimeout time.Duration
}

func New(workDir string) *Collector {
	dbRepo := os.Getenv("TRIVY_DB_REPOSITORY")
	if dbRepo == "" {
		dbRepo = defaultDBRepository
	}
	binDir := filepath.Join(workDir, "bin")
	cacheDir := filepath.Join(workDir, "trivy-cache")
	os.RemoveAll(filepath.Join(cacheDir, "fanal"))
	return &Collector{
		workDir:        workDir,
		trivy:          filepath.Join(binDir, "trivy"),
		osquery:        filepath.Join(binDir, "osqueryi"),
		dbRepository:   dbRepo,
		HostScanRoot:   "/",
		CommandTimeout: 30 * time.Second,
	}
}

func (c *Collector) ensureTrivy() error {
	if _, err := os.Stat(c.trivy); err == nil {
		return nil
	}
	if p, err := exec.LookPath("trivy"); err == nil {
		c.trivy = p
		return nil
	}
	return fmt.Errorf("trivy not found at %s — download from https://github.com/aquasecurity/trivy/releases", c.trivy)
}

func (c *Collector) ensureOSQuery() error {
	if _, err := os.Stat(c.osquery); err == nil {
		return nil
	}
	if _, err := exec.LookPath("osqueryi"); err == nil {
		c.osquery = "osqueryi"
		return nil
	}
	return fmt.Errorf("osqueryi not found — install osquery or place binary at %s", c.osquery)
}

func (c *Collector) trivyCommandContext(ctx context.Context, args ...string) *exec.Cmd {
	allArgs := append([]string{}, args...)
	if !c.PackagesOnly {
		hasDBFlag := false
		for _, a := range allArgs {
			if a == "--db-repository" {
				hasDBFlag = true
				break
			}
		}
		if !hasDBFlag {
			allArgs = append([]string{"--db-repository", c.dbRepository}, allArgs...)
		}
	} else {
		allArgs = append([]string{"--skip-db-update", "--skip-java-db-update"}, allArgs...)
	}
	cmd := exec.CommandContext(ctx, c.trivy, allArgs...)
	cmd.Env = append(os.Environ(), "TRIVY_CACHE_DIR="+filepath.Join(c.workDir, "trivy-cache"))
	return cmd
}

func (c *Collector) CollectHostPackages() ([]models.Package, []models.Vulnerability, error) {
	if err := c.ensureTrivy(); err != nil {
		return nil, nil, err
	}

	var cmd *exec.Cmd
	scanRoot := strings.TrimSpace(c.HostScanRoot)
	if scanRoot == "" {
		scanRoot = "/"
	}
	ctx := context.Background()
	cancel := func() {}
	if c.HostTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, c.HostTimeout)
	}
	defer cancel()
	if c.PackagesOnly {
		cmd = c.trivyCommandContext(ctx, "fs", "--format", "json", "--list-all-pkgs", scanRoot)
	} else {
		cmd = c.trivyCommandContext(ctx, "fs", "--format", "json", "--list-all-pkgs", "--scanners", "vuln", scanRoot)
	}
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, fmt.Errorf("trivy fs timed out after %s scanning %s", c.HostTimeout, scanRoot)
		}
		return nil, nil, fmt.Errorf("trivy fs: %w", err)
	}

	return trivyparse.ExtractPackagesAndVulns(out, "trivy-host", "")
}

func (c *Collector) CollectContainerPackages(containerName string) ([]models.Package, []models.Vulnerability, error) {
	if err := c.ensureTrivy(); err != nil {
		return nil, nil, err
	}

	imageRef, err := c.getContainerImage(containerName)
	if err != nil {
		return nil, nil, err
	}

	var cmd *exec.Cmd
	ctx := context.Background()
	cancel := func() {}
	if c.ImageTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, c.ImageTimeout)
	}
	defer cancel()
	if c.PackagesOnly {
		cmd = c.trivyCommandContext(ctx, "image", "--format", "json", "--list-all-pkgs", imageRef)
	} else {
		cmd = c.trivyCommandContext(ctx, "image", "--format", "json", "--list-all-pkgs", "--scanners", "vuln", imageRef)
	}
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, fmt.Errorf("trivy image %s timed out after %s", imageRef, c.ImageTimeout)
		}
		return nil, nil, fmt.Errorf("trivy image %s: %w", imageRef, err)
	}

	return trivyparse.ExtractPackagesAndVulns(out, "trivy-container", containerName)
}

func (c *Collector) getContainerImage(containerName string) (string, error) {
	out, err := c.commandOutput("docker", "inspect", "--format", "{{.Config.Image}}", containerName)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (c *Collector) CollectOSQueryPackages() ([]models.Package, error) {
	osqueryErr := c.ensureOSQuery()
	if osqueryErr != nil {
		return c.CollectNativePackages()
	}

	queries := []string{
		"SELECT name, version, arch, source_name FROM deb_packages",
		"SELECT name, version, arch, '' as source_name FROM rpm_packages",
	}

	var allPkgs []models.Package
	for _, q := range queries {
		out, err := c.commandOutput(c.osquery, "--json", q)
		if err != nil {
			continue
		}
		var results []map[string]any
		if err := json.Unmarshal(out, &results); err != nil {
			continue
		}
		for _, r := range results {
			allPkgs = append(allPkgs, models.Package{
				ID:      uuid.New().String(),
				Name:    strVal(r, "name"),
				Version: strVal(r, "version"),
				Arch:    strVal(r, "arch"),
				SrcName: strVal(r, "source_name"),
				PkgType: "os",
				Source:  "osquery",
			})
		}
	}
	if len(allPkgs) == 0 {
		if pkgs, err := c.CollectNativePackages(); err == nil && len(pkgs) > 0 {
			return pkgs, nil
		}
	}
	return allPkgs, nil
}

func (c *Collector) CollectNativePackages() ([]models.Package, error) {
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		out, err := c.commandOutput("dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\n")
		if err == nil {
			return parseDelimitedPackages(out, "dpkg"), nil
		}
	}
	if _, err := exec.LookPath("rpm"); err == nil {
		out, err := c.commandOutput("rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n")
		if err == nil {
			return parseDelimitedPackages(out, "rpm"), nil
		}
	}
	if _, err := exec.LookPath("apk"); err == nil {
		out, err := c.commandOutput("apk", "info", "-v")
		if err == nil {
			return parseApkPackages(out), nil
		}
	}
	return nil, fmt.Errorf("no supported package manager found for native package fallback")
}

func parseDelimitedPackages(out []byte, source string) []models.Package {
	var pkgs []models.Package
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		version := strings.TrimSpace(parts[1])
		if name == "" || version == "" {
			continue
		}
		pkg := models.Package{
			ID:      uuid.New().String(),
			Name:    name,
			Version: version,
			PkgType: "os",
			Source:  source,
		}
		if len(parts) > 2 {
			pkg.Arch = strings.TrimSpace(parts[2])
		}
		if len(parts) > 3 {
			pkg.SrcName = normalizeSourcePackageName(strings.TrimSpace(parts[3]), source)
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs
}

func parseApkPackages(out []byte) []models.Package {
	var pkgs []models.Package
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		idx := strings.LastIndex(line, "-")
		if idx <= 0 || idx == len(line)-1 {
			continue
		}
		pkgs = append(pkgs, models.Package{
			ID:      uuid.New().String(),
			Name:    line[:idx],
			Version: line[idx+1:],
			PkgType: "os",
			Source:  "apk",
		})
	}
	return pkgs
}

func normalizeSourcePackageName(src, source string) string {
	if source != "rpm" {
		return src
	}
	src = strings.TrimSuffix(src, ".src.rpm")
	if idx := strings.LastIndex(src, "-"); idx > 0 {
		src = src[:idx]
		if idx := strings.LastIndex(src, "-"); idx > 0 {
			src = src[:idx]
		}
	}
	return src
}

func (c *Collector) CollectOSQueryListeningPorts() ([]models.PortInfo, error) {
	if err := c.ensureOSQuery(); err != nil {
		return nil, err
	}
	out, err := c.commandOutput(c.osquery, "--json",
		"SELECT DISTINCT name, port, protocol, address, pid FROM listening_ports l LEFT JOIN processes p ON l.pid = p.pid WHERE port > 0 ORDER BY port")
	if err != nil {
		return nil, fmt.Errorf("osquery listening_ports: %w", err)
	}
	var results []map[string]any
	if err := json.Unmarshal(out, &results); err != nil {
		return nil, err
	}
	var ports []models.PortInfo
	for _, r := range results {
		ports = append(ports, models.PortInfo{
			Name:     strVal(r, "name"),
			Port:     intVal(r, "port"),
			Protocol: strVal(r, "protocol"),
			Address:  strVal(r, "address"),
			PID:      intVal(r, "pid"),
		})
	}
	return ports, nil
}

func (c *Collector) commandOutput(name string, args ...string) ([]byte, error) {
	ctx := context.Background()
	cancel := func() {}
	if c.CommandTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, c.CommandTimeout)
	}
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%s timed out after %s", name, c.CommandTimeout)
	}
	return out, err
}

func strVal(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func intVal(m map[string]any, key string) int {
	if v, ok := m[key]; ok {
		var n int
		fmt.Sscanf(fmt.Sprintf("%v", v), "%d", &n)
		return n
	}
	return 0
}
