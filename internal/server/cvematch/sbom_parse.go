package cvematch

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// SBOMMeta carries the document-level metadata extracted from an ingested SBOM,
// used to synthesize a host/scan for the existing match pipeline.
type SBOMMeta struct {
	Format        string // "CycloneDX" | "SPDX"
	SpecVersion   string
	SerialNumber  string
	ComponentName string // metadata.component.name (CDX) / document name (SPDX) — the SBOM subject
	ComponentVer  string
	Timestamp     string
	// Dependencies maps a component's PURL to the PURLs it depends on, when the
	// document carries a dependency graph (CycloneDX dependencies / SPDX
	// DEPENDS_ON). Empty when the SBOM is a flat component list.
	Dependencies map[string][]string
}

// purlTypeToPkg maps a PURL `type` to Bongsu's (pkg_type, ecosystem). It is the
// inverse of pkgTypeToPURL + ecosystemForType, so an ingested SBOM lands in the
// exact ecosystem the matcher gates on.
var purlTypeToPkg = map[string]struct{ pkgType, ecosystem string }{
	"deb":       {"deb", "Debian"},
	"rpm":       {"rpm", "RHEL"},
	"apk":       {"apk", "Alpine"},
	"pypi":      {"python-pkg", "PyPI"},
	"npm":       {"node-pkg", "npm"},
	"golang":    {"golang", "Go"},
	"maven":     {"jar", "Maven"},
	"cargo":     {"rustbinary", "crates.io"},
	"composer":  {"composer", "Packagist"},
	"gem":       {"gem", "RubyGems"},
	"nuget":     {"nuget", "NuGet"},
	"cocoapods": {"cocoapods", "CocoaPods"},
	"swift":     {"swift", "Swift"},
}

// ParsePURL decomposes a Package URL (pkg:type/namespace/name@version?qualifiers)
// into Bongsu's package fields. It is intentionally lenient: a PURL missing a
// version still parses (version ""), the caller decides whether to keep it.
func ParsePURL(purl string) (name, version, pkgType, ecosystem, arch string, ok bool) {
	s := strings.TrimSpace(purl)
	if !strings.HasPrefix(s, "pkg:") {
		return "", "", "", "", "", false
	}
	s = strings.TrimPrefix(s, "pkg:")
	// PURLs are sometimes written pkg://type/... — tolerate the extra slashes.
	s = strings.TrimLeft(s, "/")

	// Strip subpath (#...) then split qualifiers (?...).
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	var qualifiers string
	if i := strings.IndexByte(s, '?'); i >= 0 {
		qualifiers = s[i+1:]
		s = s[:i]
	}

	// type is up to the first '/'.
	slash := strings.IndexByte(s, '/')
	if slash <= 0 {
		return "", "", "", "", "", false
	}
	ptype := strings.ToLower(s[:slash])
	rest := s[slash+1:]

	// version follows the last '@'.
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		version = urlDecode(rest[i+1:])
		rest = rest[:i]
	}
	if rest == "" {
		return "", "", "", "", "", false
	}

	// rest is namespace/.../name; decode each segment.
	segs := strings.Split(rest, "/")
	for i := range segs {
		segs[i] = urlDecode(segs[i])
	}
	leaf := segs[len(segs)-1]
	ns := segs[:len(segs)-1]
	name = composePURLName(ptype, ns, leaf)

	if qualifiers != "" {
		if vals, err := url.ParseQuery(qualifiers); err == nil {
			arch = vals.Get("arch")
		}
	}

	if m, found := purlTypeToPkg[ptype]; found {
		pkgType, ecosystem = m.pkgType, m.ecosystem
	} else {
		pkgType, ecosystem = ptype, ""
	}
	return name, version, pkgType, ecosystem, arch, name != ""
}

// composePURLName reassembles the registry-native package name from a PURL's
// namespace + leaf, per ecosystem convention.
func composePURLName(ptype string, ns []string, leaf string) string {
	nsJoined := strings.Join(ns, "/")
	switch ptype {
	case "maven":
		// group(dotted)/artifact -> group:artifact (OSV Maven convention).
		if nsJoined != "" {
			return nsJoined + ":" + leaf
		}
		return leaf
	case "golang":
		// full module path.
		if nsJoined != "" {
			return nsJoined + "/" + leaf
		}
		return leaf
	default:
		// npm scope (@scope/name), generic namespaced names.
		if nsJoined != "" {
			return nsJoined + "/" + leaf
		}
		return leaf
	}
}

func urlDecode(s string) string {
	if d, err := url.PathUnescape(s); err == nil {
		return d
	}
	return s
}

// ParseSBOM detects the document format (CycloneDX or SPDX) and returns the
// contained packages plus document metadata. Components without a usable
// (name, version) — and SBOM tool/file/OS root components — are skipped.
func ParseSBOM(data []byte) ([]models.Package, SBOMMeta, error) {
	var probe struct {
		BOMFormat   string `json:"bomFormat"`
		SPDXID      string `json:"SPDXID"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, SBOMMeta{}, fmt.Errorf("sbom is not valid JSON: %w", err)
	}
	switch {
	case strings.EqualFold(probe.BOMFormat, "CycloneDX"):
		return parseCycloneDXDoc(data)
	case probe.SPDXVersion != "" || probe.SPDXID != "":
		return parseSPDXDoc(data)
	default:
		return nil, SBOMMeta{}, fmt.Errorf("unrecognized SBOM format (expected CycloneDX bomFormat or SPDX spdxVersion)")
	}
}

func parseCycloneDXDoc(data []byte) ([]models.Package, SBOMMeta, error) {
	var doc cycloneDX
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, SBOMMeta{}, fmt.Errorf("parse CycloneDX: %w", err)
	}
	meta := SBOMMeta{
		Format:        "CycloneDX",
		SpecVersion:   doc.SpecVersion,
		SerialNumber:  doc.SerialNumber,
		ComponentName: doc.Metadata.Component.Name,
		ComponentVer:  doc.Metadata.Component.Version,
		Timestamp:     doc.Metadata.Timestamp,
	}

	// bom-ref -> purl, to translate the dependency graph into purl edges.
	refToPurl := map[string]string{}
	for _, c := range doc.Components {
		if c.BOMRef != "" && c.PURL != "" {
			refToPurl[c.BOMRef] = c.PURL
		}
	}

	pkgs := make([]models.Package, 0, len(doc.Components))
	for _, c := range doc.Components {
		pkg, ok := componentToPackage(c.PURL, c.Name, c.Version, c.Type)
		if !ok {
			continue
		}
		pkgs = append(pkgs, pkg)
	}

	if len(doc.Dependencies) > 0 {
		meta.Dependencies = map[string][]string{}
		for _, d := range doc.Dependencies {
			from := refToPurl[d.Ref]
			if from == "" {
				continue
			}
			for _, on := range d.DependsOn {
				if p := refToPurl[on]; p != "" {
					meta.Dependencies[from] = append(meta.Dependencies[from], p)
				}
			}
		}
	}
	return pkgs, meta, nil
}

func parseSPDXDoc(data []byte) ([]models.Package, SBOMMeta, error) {
	var doc spdxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, SBOMMeta{}, fmt.Errorf("parse SPDX: %w", err)
	}
	meta := SBOMMeta{
		Format:        "SPDX",
		SpecVersion:   doc.SPDXVersion,
		SerialNumber:  doc.DocumentNamespace,
		ComponentName: doc.Name,
	}
	if len(doc.CreationInfo.Created) > 0 {
		meta.Timestamp = doc.CreationInfo.Created
	}
	pkgs := make([]models.Package, 0, len(doc.Packages))
	for _, p := range doc.Packages {
		purl := spdxPackagePURL(p)
		pkg, ok := componentToPackage(purl, p.Name, p.VersionInfo, "library")
		if !ok {
			continue
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs, meta, nil
}

func spdxPackagePURL(p spdxPackage) string {
	if p.PackageURL != "" {
		return p.PackageURL
	}
	for _, ref := range p.ExternalRefs {
		if strings.EqualFold(ref.ReferenceType, "purl") {
			return ref.ReferenceLocator
		}
	}
	return ""
}

// componentToPackage builds a models.Package from an SBOM component. A PURL is
// preferred (it carries the ecosystem); a component with neither a usable PURL
// nor a name+version is skipped. Non-package component types (operating-system,
// application root, file, device) carry no PURL and are filtered out here.
func componentToPackage(purl, name, version, ctype string) (models.Package, bool) {
	var pkgType, ecosystem, arch string
	if purl != "" {
		pn, pv, pt, eco, parch, ok := ParsePURL(purl)
		if ok {
			if name == "" {
				name = pn
			}
			if version == "" {
				version = pv
			}
			pkgType, ecosystem, arch = pt, eco, parch
		}
	}
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" {
		return models.Package{}, false
	}
	// Without a PURL we cannot derive an ecosystem; such bare components can't be
	// matched against ecosystem-gated advisories, so skip them rather than emit
	// an unmatched, ecosystem-less package.
	if ecosystem == "" && purl == "" {
		return models.Package{}, false
	}
	return models.Package{
		Name:      name,
		Version:   version,
		Arch:      arch,
		PkgType:   pkgType,
		Ecosystem: ecosystem,
		PURL:      purl,
		Source:    "sbom",
	}, true
}
