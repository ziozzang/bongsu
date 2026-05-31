package trivyparse

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

type Layer struct {
	DiffID string `json:"DiffID"`
}

type Pkg struct {
	Name     string `json:"Name"`
	Version  string `json:"Version"`
	Arch     string `json:"Arch"`
	SrcName  string `json:"SrcName"`
	FilePath string `json:"FilePath"`
	Layer    Layer  `json:"Layer"`
}

type Vuln struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
	Description      string `json:"Description"`
	PkgName          string `json:"PkgName"`
	PkgPath          string `json:"PkgPath"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	PrimaryURL       string `json:"PrimaryURL"`
	Layer            Layer  `json:"Layer"`
	CVSS             map[string]struct {
		V3Vector string  `json:"V3Vector"`
		V3Score  float64 `json:"V3Score"`
	} `json:"CVSS"`
}

type Result struct {
	Results []struct {
		Target          string `json:"Target"`
		Type            string `json:"Type"`
		Packages        []Pkg  `json:"Packages"`
		Vulnerabilities []Vuln `json:"Vulnerabilities"`
	} `json:"Results"`
}

func Parse(data []byte) (*Result, error) {
	var r Result
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func ExtractPackagesAndVulns(data []byte, source, container string) ([]models.Package, []models.Vulnerability, error) {
	result, err := Parse(data)
	if err != nil {
		return nil, nil, err
	}

	var pkgs []models.Package
	var vulns []models.Vulnerability
	pkgMap := map[string]string{}
	nameCounts := map[string]int{}
	nameIDs := map[string]string{}

	for _, r := range result.Results {
		for _, p := range r.Packages {
			pkgID := uuid.New().String()
			pkgs = append(pkgs, models.Package{
				ID:        pkgID,
				Source:    source,
				Container: container,
				Name:      p.Name,
				Version:   p.Version,
				Arch:      p.Arch,
				SrcName:   p.SrcName,
				PkgType:   r.Type,
				Ecosystem: ecosystemForType(r.Type),
				PURL:      purlForPackage(r.Type, p.Name, p.Version, p.Arch),
				FilePath:  p.FilePath,
				LayerID:   p.Layer.DiffID,
				Target:    r.Target,
			})
			pkgMap[trivyPackageKey(r.Target, p.Name)] = pkgID
			nameCounts[p.Name]++
			nameIDs[p.Name] = pkgID
		}

		for _, v := range r.Vulnerabilities {
			var cvssScore float64
			var cvssVector string
			for _, c := range v.CVSS {
				if c.V3Score > cvssScore {
					cvssScore = c.V3Score
					cvssVector = c.V3Vector
				}
			}
			sev := v.Severity
			if cvssScore >= 9.0 {
				sev = "CRITICAL"
			} else if cvssScore >= 7.0 {
				sev = "HIGH"
			} else if cvssScore >= 4.0 {
				sev = "MEDIUM"
			} else if cvssScore > 0 {
				sev = "LOW"
			}
			packageID := pkgMap[trivyPackageKey(r.Target, v.PkgName)]
			if packageID == "" && nameCounts[v.PkgName] == 1 {
				packageID = nameIDs[v.PkgName]
			}
			vulns = append(vulns, models.Vulnerability{
				PackageID:       packageID,
				VulnerabilityID: v.VulnerabilityID,
				Severity:        sev,
				Title:           v.Title,
				Description:     v.Description,
				PkgName:         v.PkgName,
				PkgPath:         v.PkgPath,
				InstalledVer:    v.InstalledVersion,
				FixedVersion:    v.FixedVersion,
				CVSSScore:       cvssScore,
				CVSSVector:      cvssVector,
				PrimaryURL:      v.PrimaryURL,
				Container:       container,
				LayerID:         v.Layer.DiffID,
			})
		}
	}
	return pkgs, vulns, nil
}

func trivyPackageKey(target, name string) string {
	return target + "\x00" + name
}

func ecosystemForType(pkgType string) string {
	switch strings.ToLower(pkgType) {
	case "ubuntu":
		return "Ubuntu"
	case "debian", "deb":
		return "Debian"
	case "alpine", "apk":
		return "Alpine"
	case "redhat", "centos", "rocky", "alma", "amazon", "rpm":
		return "RHEL"
	case "python-pkg", "pip", "poetry":
		return "PyPI"
	case "node-pkg", "npm", "yarn", "pnpm":
		return "npm"
	case "gomod", "go", "gobinary", "golang":
		return "Go"
	case "jar", "maven":
		return "Maven"
	case "cargo", "rustbinary":
		return "crates.io"
	case "composer":
		return "Packagist"
	case "gem":
		return "RubyGems"
	case "nuget":
		return "NuGet"
	default:
		return ""
	}
}

func purlForPackage(pkgType, name, version, arch string) string {
	if name == "" || version == "" {
		return ""
	}
	purlType := "generic"
	switch ecosystemForType(pkgType) {
	case "Debian", "Ubuntu":
		purlType = "deb"
	case "Alpine":
		purlType = "apk"
	case "RHEL":
		purlType = "rpm"
	case "PyPI":
		purlType = "pypi"
	case "npm":
		purlType = "npm"
	case "Go":
		purlType = "golang"
	case "Maven":
		purlType = "maven"
	case "crates.io":
		purlType = "cargo"
	case "Packagist":
		purlType = "composer"
	case "RubyGems":
		purlType = "gem"
	case "NuGet":
		purlType = "nuget"
	}
	p := fmt.Sprintf("pkg:%s/%s@%s", purlType, name, version)
	if arch != "" && (purlType == "deb" || purlType == "rpm" || purlType == "apk") {
		p += "?arch=" + arch
	}
	return p
}
