package cvematch

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

var pkgTypeToPURL = map[string]string{
	"deb":        "deb",
	"rpm":        "rpm",
	"apk":        "apk",
	"python-pkg": "pypi",
	"pip":        "pypi",
	"poetry":     "pypi",
	"node-pkg":   "npm",
	"npm":        "npm",
	"yarn":       "npm",
	"pnpm":       "npm",
	"golang":     "golang",
	"gobinary":   "golang",
	"jar":        "maven",
	"maven":      "maven",
	"rustbinary": "cargo",
	"cargo":      "cargo",
	"composer":   "composer",
	"gem":        "gem",
	"nuget":      "nuget",
	"cocoapods":  "cocoapods",
	"swift":      "swift",
	"dotnet":     "nuget",
}

func purlType(pkgType string) string {
	if t, ok := pkgTypeToPURL[pkgType]; ok {
		return t
	}
	return "generic"
}

func inferOSPkgType(osName string) string {
	s := strings.ToLower(osName)
	if strings.Contains(s, "ubuntu") || strings.Contains(s, "debian") {
		return "deb"
	}
	if strings.Contains(s, "centos") || strings.Contains(s, "red hat") ||
		strings.Contains(s, "rhel") || strings.Contains(s, "fedora") ||
		strings.Contains(s, "rocky") || strings.Contains(s, "almalinux") ||
		strings.Contains(s, "amazon") {
		return "rpm"
	}
	return "deb"
}

func buildPurl(pkg models.Package, host models.Host) string {
	if pkg.PURL != "" {
		return pkg.PURL
	}
	pt := pkg.PkgType
	if pt == "os" {
		pt = inferOSPkgType(host.OSName)
	}
	purlType := purlType(pt)

	name := pkg.Name
	version := pkg.Version

	switch purlType {
	case "maven":
		if idx := strings.LastIndex(name, ":"); idx > 0 {
			name = strings.Replace(name, ":", "/", 1)
		}
	case "golang":
		if !strings.Contains(name, "/") {
			name = "golang.org/x/" + name
		}
	}

	p := fmt.Sprintf("pkg:%s/%s@%s", purlType, name, version)
	if pkg.Arch != "" && (purlType == "deb" || purlType == "rpm") {
		p += "?arch=" + pkg.Arch
	}
	return p
}

type cycloneDX struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Version     int    `json:"version"`
	Metadata    struct {
		Component struct {
			Type string `json:"type"`
			Name string `json:"name"`
		} `json:"component"`
	} `json:"metadata"`
	Components []cdxComponent `json:"components"`
}

type cdxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	BOMRef  string `json:"bom-ref"`
	PURL    string `json:"purl"`
}

func GenerateCycloneDX(pkgs []models.Package, host models.Host) ([]byte, error) {
	sbom := cycloneDX{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
	}
	sbom.Metadata.Component.Type = "application"
	sbom.Metadata.Component.Name = host.Hostname

	components := make([]cdxComponent, 0, len(pkgs))
	for _, pkg := range pkgs {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		p := buildPurl(pkg, host)
		components = append(components, cdxComponent{
			Type:    "library",
			Name:    pkg.Name,
			Version: pkg.Version,
			BOMRef:  p,
			PURL:    p,
		})
	}

	if len(components) == 0 {
		return nil, fmt.Errorf("no valid packages for SBOM generation")
	}

	sbom.Components = components
	return json.Marshal(sbom)
}
