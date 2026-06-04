package cvematch

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
	"github.com/ziozzang/bongsu/internal/shared/trivyparse"
)

type Matcher struct {
	trivyPath string
	cacheDir  string
	dbRepo    string
	sem       chan struct{}
}

func NewMatcher(trivyPath, cacheDir, dbRepo string) *Matcher {
	return &Matcher{
		trivyPath: trivyPath,
		cacheDir:  cacheDir,
		dbRepo:    dbRepo,
		sem:       make(chan struct{}, 3),
	}
}

func (m *Matcher) Match(ctx context.Context, pkgs []models.Package, host models.Host) ([]models.Vulnerability, error) {
	groups := packageMatchGroups(pkgs, host)
	if len(groups) == 0 {
		return nil, fmt.Errorf("no valid packages for SBOM generation")
	}
	var all []models.Vulnerability
	var failures []error
	for _, group := range groups {
		vulns, err := m.matchGroup(ctx, group.pkgs, host)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", group.key, err))
			log.Printf("server-side CVE matching group failed: key=%s packages=%d error=%v", group.key, len(group.pkgs), err)
			continue
		}
		all = append(all, vulns...)
	}
	if len(all) > 0 {
		if len(failures) > 0 {
			log.Printf("server-side CVE matching partially succeeded: matched_vulns=%d failed_groups=%d", len(all), len(failures))
		}
		return all, nil
	}
	if len(failures) > 0 {
		return nil, errors.Join(failures...)
	}
	return all, nil
}

func (m *Matcher) matchGroup(ctx context.Context, pkgs []models.Package, host models.Host) ([]models.Vulnerability, error) {
	sbomData, err := GenerateCycloneDX(pkgs, host)
	if err != nil {
		return nil, fmt.Errorf("generate SBOM: %w", err)
	}

	sbomFile, err := writeTempSBOM(sbomData)
	if err != nil {
		return nil, fmt.Errorf("write SBOM: %w", err)
	}
	defer os.Remove(sbomFile)

	if err := m.acquire(ctx); err != nil {
		return nil, err
	}
	defer m.release()

	matchCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	args := []string{
		"sbom",
		"--skip-db-update",
		"--skip-java-db-update",
		"--format", "json",
		"--scanners", "vuln",
		"--cache-dir", m.cacheDir,
		sbomFile,
	}
	cmd := exec.CommandContext(matchCtx, m.trivyPath, args...)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			log.Printf("trivy sbom stderr: %s", string(ee.Stderr))
		}
		return nil, fmt.Errorf("trivy sbom: %w", err)
	}

	result, err := trivyparse.Parse(out)
	if err != nil {
		return nil, fmt.Errorf("parse trivy output: %w", err)
	}

	type pkgInfo struct {
		id        string
		container string
		filePath  string
	}
	pkgMap := map[string]pkgInfo{}
	nameCounts := map[string]int{}
	nameInfo := map[string]pkgInfo{}
	for _, p := range pkgs {
		info := pkgInfo{id: p.ID, container: p.Container, filePath: p.FilePath}
		pkgMap[matchPackageKey(p.Target, p.Name)] = info
		nameCounts[p.Name]++
		nameInfo[p.Name] = info
	}

	var vulns []models.Vulnerability
	for _, r := range result.Results {
		for _, v := range r.Vulnerabilities {
			var cvssScore float64
			var cvssVector string
			for _, c := range v.CVSS {
				if c.V3Score > cvssScore {
					cvssScore = c.V3Score
					cvssVector = c.V3Vector
				}
			}
			pi := pkgMap[matchPackageKey(r.Target, v.PkgName)]
			if pi.id == "" && nameCounts[v.PkgName] == 1 {
				pi = nameInfo[v.PkgName]
			}
			vulns = append(vulns, models.Vulnerability{
				PackageID:       pi.id,
				VulnerabilityID: v.VulnerabilityID,
				Severity:        v.Severity,
				Title:           v.Title,
				Description:     v.Description,
				PkgName:         v.PkgName,
				PkgPath:         coalesce(v.PkgPath, pi.filePath),
				Container:       pi.container,
				InstalledVer:    v.InstalledVersion,
				FixedVersion:    v.FixedVersion,
				CVSSScore:       cvssScore,
				CVSSVector:      cvssVector,
				PrimaryURL:      v.PrimaryURL,
				LayerID:         v.Layer.DiffID,
			})
		}
	}
	return vulns, nil
}

type packageMatchGroup struct {
	key  string
	pkgs []models.Package
}

func packageMatchGroups(pkgs []models.Package, host models.Host) []packageMatchGroup {
	grouped := map[string][]models.Package{}
	for _, pkg := range pkgs {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		key := packageMatchGroupKey(pkg, host)
		grouped[key] = append(grouped[key], pkg)
	}
	keys := make([]string, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	groups := make([]packageMatchGroup, 0, len(keys))
	for _, key := range keys {
		groups = append(groups, packageMatchGroup{key: key, pkgs: grouped[key]})
	}
	return groups
}

func packageMatchGroupKey(pkg models.Package, host models.Host) string {
	assetType := strings.TrimSpace(pkg.AssetType)
	if assetType == "" {
		assetType = "host"
	}
	assetID := firstNonEmpty(pkg.AssetID, pkg.ContainerID, pkg.ImageID, pkg.ImageName, pkg.Container, host.ID)
	if assetType == "host" {
		assetID = host.ID
	}
	pkgBucket := normalizedOSPackageType(pkg, host)
	if pkgBucket == "" {
		pkgBucket = "code"
	}
	return strings.Join([]string{assetType, assetID, pkgBucket}, "\x00")
}

func normalizedOSPackageType(pkg models.Package, host models.Host) string {
	pkgType := strings.ToLower(strings.TrimSpace(pkg.PkgType))
	switch pkgType {
	case "deb", "rpm", "apk":
		return pkgType
	case "os":
		inferred := inferOSPkgType(firstNonEmpty(pkg.Ecosystem, host.OSName))
		if inferred != "" {
			return inferred
		}
	}
	purl := strings.ToLower(strings.TrimSpace(pkg.PURL))
	for _, prefix := range []string{"pkg:deb/", "pkg:rpm/", "pkg:apk/"} {
		if strings.HasPrefix(purl, prefix) {
			return strings.TrimSuffix(strings.TrimPrefix(prefix, "pkg:"), "/")
		}
	}
	eco := strings.ToLower(strings.TrimSpace(pkg.Ecosystem))
	switch {
	case strings.Contains(eco, "alpine"):
		return "apk"
	case strings.Contains(eco, "ubuntu") || strings.Contains(eco, "debian"):
		return "deb"
	case strings.Contains(eco, "red hat") || strings.Contains(eco, "rhel") ||
		strings.Contains(eco, "rocky") || strings.Contains(eco, "almalinux") ||
		strings.Contains(eco, "fedora") || strings.Contains(eco, "centos") ||
		strings.Contains(eco, "amazon"):
		return "rpm"
	default:
		return ""
	}
}

func matchPackageKey(target, name string) string {
	return target + "\x00" + name
}

func writeTempSBOM(data []byte) (string, error) {
	f, err := os.CreateTemp("", "bongsu-sbom-*.cdx.json")
	if err != nil {
		return "", err
	}
	path := f.Name()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func (m *Matcher) acquire(ctx context.Context) error {
	select {
	case m.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Matcher) release() {
	<-m.sem
}

func coalesce(s ...string) string {
	return firstNonEmpty(s...)
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
