package cvematch

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
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
	sbomData, err := GenerateCycloneDX(pkgs, host)
	if err != nil {
		return nil, fmt.Errorf("generate SBOM: %w", err)
	}

	tmpDir := os.TempDir()
	sbomFile := filepath.Join(tmpDir, fmt.Sprintf("bongsu-sbom-%d.cdx.json", time.Now().UnixNano()))
	if err := os.WriteFile(sbomFile, sbomData, 0644); err != nil {
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

func matchPackageKey(target, name string) string {
	return target + "\x00" + name
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
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
