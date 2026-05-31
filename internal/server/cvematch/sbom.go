package cvematch

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"strings"
	"time"

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
		Timestamp string `json:"timestamp"`
		Tools     []struct {
			Vendor  string `json:"vendor"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"tools"`
		Component struct {
			Type       string        `json:"type"`
			Name       string        `json:"name"`
			Version    string        `json:"version,omitempty"`
			Properties []cdxProperty `json:"properties,omitempty"`
		} `json:"component"`
	} `json:"metadata"`
	Components []cdxComponent `json:"components"`
}

type cdxComponent struct {
	Type       string        `json:"type"`
	Name       string        `json:"name"`
	Version    string        `json:"version"`
	BOMRef     string        `json:"bom-ref"`
	PURL       string        `json:"purl"`
	Scope      string        `json:"scope,omitempty"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type spdxDocument struct {
	SPDXID            string             `json:"SPDXID"`
	SPDXVersion       string             `json:"spdxVersion"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Name              string             `json:"name"`
	DataLicense       string             `json:"dataLicense"`
	DocumentNamespace string             `json:"documentNamespace"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID                  string               `json:"SPDXID"`
	Name                    string               `json:"name"`
	VersionInfo             string               `json:"versionInfo,omitempty"`
	DownloadLocation        string               `json:"downloadLocation"`
	FilesAnalyzed           bool                 `json:"filesAnalyzed"`
	PackageVerificationCode spdxVerificationCode `json:"packageVerificationCode"`
	LicenseConcluded        string               `json:"licenseConcluded"`
	LicenseDeclared         string               `json:"licenseDeclared"`
	CopyrightText           string               `json:"copyrightText"`
	Supplier                string               `json:"supplier"`
	PackageURL              string               `json:"packageUrl,omitempty"`
	ExternalRefs            []spdxExternalRef    `json:"externalRefs,omitempty"`
	Comment                 string               `json:"comment,omitempty"`
}

type spdxVerificationCode struct {
	PackageVerificationCodeValue string `json:"packageVerificationCodeValue"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

func GenerateCycloneDX(pkgs []models.Package, host models.Host) ([]byte, error) {
	sbom := cycloneDX{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
	}
	sbom.Metadata.Timestamp = time.Now().UTC().Format(time.RFC3339)
	sbom.Metadata.Tools = append(sbom.Metadata.Tools, struct {
		Vendor  string `json:"vendor"`
		Name    string `json:"name"`
		Version string `json:"version"`
	}{Vendor: "ziozzang", Name: "bongsu", Version: "0.1.0"})
	sbom.Metadata.Component.Type = "application"
	sbom.Metadata.Component.Name = host.Hostname
	sbom.Metadata.Component.Version = host.OSName + " " + host.OSVersion
	sbom.Metadata.Component.Properties = []cdxProperty{
		{Name: "bongsu:host_id", Value: host.ID},
		{Name: "bongsu:ip_address", Value: host.IPAddress},
		{Name: "bongsu:os_name", Value: host.OSName},
		{Name: "bongsu:os_version", Value: host.OSVersion},
		{Name: "bongsu:kernel", Value: host.Kernel},
		{Name: "bongsu:arch", Value: host.Arch},
		{Name: "bongsu:owner", Value: host.Owner},
		{Name: "bongsu:team", Value: host.Team},
		{Name: "bongsu:environment", Value: host.Environment},
		{Name: "bongsu:criticality", Value: host.Criticality},
		{Name: "bongsu:tags", Value: host.Tags},
	}

	components := make([]cdxComponent, 0, len(pkgs))
	for _, pkg := range pkgs {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		p := buildPurl(pkg, host)
		props := []cdxProperty{
			{Name: "bongsu:package_id", Value: pkg.ID},
			{Name: "bongsu:host_id", Value: pkg.HostID},
			{Name: "bongsu:asset_type", Value: pkg.AssetType},
			{Name: "bongsu:asset_id", Value: pkg.AssetID},
			{Name: "bongsu:source", Value: pkg.Source},
			{Name: "bongsu:pkg_type", Value: pkg.PkgType},
			{Name: "bongsu:ecosystem", Value: pkg.Ecosystem},
			{Name: "bongsu:container", Value: pkg.Container},
			{Name: "bongsu:container_id", Value: pkg.ContainerID},
			{Name: "bongsu:image_name", Value: pkg.ImageName},
			{Name: "bongsu:image_id", Value: pkg.ImageID},
			{Name: "bongsu:file_path", Value: pkg.FilePath},
			{Name: "bongsu:target", Value: pkg.Target},
		}
		components = append(components, cdxComponent{
			Type:       "library",
			Name:       pkg.Name,
			Version:    pkg.Version,
			BOMRef:     p,
			PURL:       p,
			Scope:      "required",
			Properties: props,
		})
	}

	if len(components) == 0 {
		return nil, fmt.Errorf("no valid packages for SBOM generation")
	}

	sbom.Components = components
	return json.Marshal(sbom)
}

func GenerateSPDX(pkgs []models.Package, host models.Host) ([]byte, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	docID := "SPDXRef-DOCUMENT"
	docName := "bongsu-" + sanitizeSPDXID(defaultSPDXName(host.Hostname, host.ID))
	namespaceID := sanitizeSPDXID(defaultSPDXName(host.ID, host.Hostname))
	doc := spdxDocument{
		SPDXID:            docID,
		SPDXVersion:       "SPDX-2.3",
		Name:              docName,
		DataLicense:       "CC0-1.0",
		DocumentNamespace: fmt.Sprintf("https://bongsu.local/spdx/%s/%d", namespaceID, time.Now().UnixNano()),
		CreationInfo: spdxCreationInfo{
			Created:  now,
			Creators: []string{"Tool: bongsu-0.1.0"},
		},
	}
	rootID := "SPDXRef-Host-" + sanitizeSPDXID(defaultSPDXName(host.ID, host.Hostname))
	doc.Packages = append(doc.Packages, spdxPackage{
		SPDXID:                  rootID,
		Name:                    defaultSPDXName(host.Hostname, host.ID),
		VersionInfo:             strings.TrimSpace(host.OSName + " " + host.OSVersion),
		DownloadLocation:        "NOASSERTION",
		FilesAnalyzed:           false,
		PackageVerificationCode: spdxVerificationCode{PackageVerificationCodeValue: spdxPackageVerificationCode(host.ID, host.Hostname, host.OSName, host.OSVersion)},
		LicenseConcluded:        "NOASSERTION",
		LicenseDeclared:         "NOASSERTION",
		CopyrightText:           "NOASSERTION",
		Supplier:                "Organization: bongsu",
		Comment:                 fmt.Sprintf("bongsu host_id=%s ip_address=%s owner=%s team=%s environment=%s criticality=%s", host.ID, host.IPAddress, host.Owner, host.Team, host.Environment, host.Criticality),
	})
	doc.Relationships = append(doc.Relationships, spdxRelationship{SPDXElementID: docID, RelationshipType: "DESCRIBES", RelatedSPDXElement: rootID})

	seen := map[string]int{}
	for _, pkg := range pkgs {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		purl := buildPurl(pkg, host)
		baseID := "SPDXRef-Package-" + sanitizeSPDXID(pkg.Name+"-"+pkg.Version)
		seen[baseID]++
		spdxID := baseID
		if seen[baseID] > 1 {
			spdxID = fmt.Sprintf("%s-%d", baseID, seen[baseID])
		}
		doc.Packages = append(doc.Packages, spdxPackage{
			SPDXID:                  spdxID,
			Name:                    pkg.Name,
			VersionInfo:             pkg.Version,
			DownloadLocation:        "NOASSERTION",
			FilesAnalyzed:           false,
			PackageVerificationCode: spdxVerificationCode{PackageVerificationCodeValue: spdxPackageVerificationCode(spdxPackageIdentity(pkg)...)},
			LicenseConcluded:        "NOASSERTION",
			LicenseDeclared:         "NOASSERTION",
			CopyrightText:           "NOASSERTION",
			Supplier:                "NOASSERTION",
			PackageURL:              purl,
			ExternalRefs: []spdxExternalRef{{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  purl,
			}},
			Comment: fmt.Sprintf("bongsu package_id=%s asset_type=%s asset_id=%s source=%s pkg_type=%s ecosystem=%s container=%s container_id=%s image_name=%s image_id=%s file_path=%s target=%s",
				pkg.ID, pkg.AssetType, pkg.AssetID, pkg.Source, pkg.PkgType, pkg.Ecosystem, pkg.Container, pkg.ContainerID, pkg.ImageName, pkg.ImageID, pkg.FilePath, pkg.Target),
		})
		doc.Relationships = append(doc.Relationships, spdxRelationship{SPDXElementID: rootID, RelationshipType: "CONTAINS", RelatedSPDXElement: spdxID})
	}
	if len(doc.Packages) <= 1 {
		return nil, fmt.Errorf("no valid packages for SBOM generation")
	}
	return json.Marshal(doc)
}

func spdxPackageVerificationCode(parts ...string) string {
	sum := sha1.Sum([]byte(strings.Join(parts, "\x00")))
	return fmt.Sprintf("%x", sum[:])
}

func spdxPackageIdentity(pkg models.Package) []string {
	return []string{
		pkg.AssetType, pkg.AssetID, pkg.Source,
		pkg.Container, pkg.ContainerID, pkg.ImageName, pkg.ImageID,
		pkg.Name, pkg.Version, pkg.Arch, pkg.PkgType, pkg.Ecosystem,
		pkg.PURL, pkg.SrcName, pkg.FilePath, pkg.Target,
	}
}

func defaultSPDXName(primary, fallback string) string {
	if strings.TrimSpace(primary) != "" {
		return strings.TrimSpace(primary)
	}
	if strings.TrimSpace(fallback) != "" {
		return strings.TrimSpace(fallback)
	}
	return "unknown"
}

func sanitizeSPDXID(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-.")
	if out == "" {
		return "unknown"
	}
	return out
}
