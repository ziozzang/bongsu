package db

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/ziozzang/bongsu/internal/server/vercmp"
)

func ClassifySecuritySource(source, affectedProducts string) (string, string) {
	type affectedProduct struct {
		Ecosystem string `json:"ecosystem"`
	}
	var products []affectedProduct
	if affectedProducts != "" {
		_ = json.Unmarshal([]byte(affectedProducts), &products)
	}
	ecosystem := ""
	if len(products) > 0 {
		ecosystem = products[0].Ecosystem
	}
	if ecosystem != "" {
		if isOSEcosystem(ecosystem) {
			return "os-package", ecosystem
		}
		return "code-library", ecosystem
	}
	switch strings.ToLower(source) {
	case "osv":
		return "code-library", ""
	case "trivy":
		return "os-package", ""
	case "nvd", "cisa-kev", "epss":
		return "general-cve", ""
	default:
		return "custom", ""
	}
}

type affectedProduct struct {
	Name      string          `json:"name"`
	Ecosystem string          `json:"ecosystem"`
	Fixed     []string        `json:"fixed"`
	Ranges    []affectedRange `json:"ranges"`
}

type affectedRange struct {
	Type   string               `json:"type"`
	Events []affectedRangeEvent `json:"events"`
}

type affectedRangeEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

func packageCategory(pkgType, ecosystem string) string {
	eco := strings.ToLower(strings.TrimSpace(ecosystem))
	pt := strings.ToLower(pkgType)
	if isOSEcosystem(eco) {
		return "os-package"
	}
	switch eco {
	case "pypi", "npm", "go", "maven", "crates.io", "nuget", "rubygems", "packagist", "hex", "pub":
		return "code-library"
	}
	switch pt {
	case "debian", "ubuntu", "deb", "alpine", "apk", "redhat", "centos", "rocky", "alma", "amazon", "rpm", "suse", "wolfi":
		return "os-package"
	case "python-pkg", "pip", "poetry", "node-pkg", "npm", "yarn", "pnpm", "gomod", "go", "gobinary", "golang", "jar", "maven", "cargo", "rustbinary", "composer", "gem", "nuget":
		return "code-library"
	default:
		return ""
	}
}

func isOSEcosystem(ecosystem string) bool {
	eco := strings.ToLower(strings.TrimSpace(ecosystem))
	if idx := strings.Index(eco, ":"); idx >= 0 {
		eco = strings.TrimSpace(eco[:idx])
	}
	switch eco {
	case "debian", "ubuntu", "alpine", "red hat", "redhat", "rhel", "centos", "rocky", "alma", "amazon", "suse", "opensuse", "almalinux", "amazon linux", "wolfi", "chainguard", "rocky linux", "oracle linux", "azure linux", "azurelinux", "cbl-mariner", "openeuler", "mageia", "android":
		return true
	default:
		return false
	}
}

// normalizeEcosystem must stay in sync with normalizeEcosystemSQL: both layers
// gate the same package↔advisory match and a divergence silently drops matches.
func normalizeEcosystem(eco string) string {
	eco = strings.ToLower(strings.TrimSpace(eco))
	switch eco {
	case "python", "python-pkg", "pip", "poetry":
		return "pypi"
	case "node", "node-pkg", "javascript", "yarn", "pnpm":
		return "npm"
	case "golang", "gomod", "gobinary":
		return "go"
	case "ruby", "gem":
		return "rubygems"
	case "rust", "cargo", "rustbinary":
		return "crates.io"
	case "jar":
		return "maven"
	case "composer":
		return "packagist"
	}
	// Distro ecosystems carry release suffixes after ':' (e.g. Alpine:v3.21,
	// Red Hat:enterprise_linux:8::appstream); normalize on the family segment.
	family := eco
	if idx := strings.Index(family, ":"); idx >= 0 {
		family = strings.TrimSpace(family[:idx])
	}
	switch family {
	case "debian", "deb":
		return "debian"
	case "ubuntu":
		return "ubuntu"
	case "alpine", "apk":
		return "alpine"
	case "redhat", "red hat", "red hat enterprise linux", "rhel", "centos", "rocky", "rocky linux", "almalinux", "alma", "amazon", "amazon linux", "oracle linux", "rpm":
		return "rhel"
	case "suse", "opensuse":
		return "suse"
	case "wolfi", "chainguard":
		return "wolfi"
	case "azure linux", "azurelinux", "cbl-mariner":
		return "azurelinux"
	}
	return eco
}

func compatibleSecurityCandidate(pkgName, pkgType, pkgEco, installedVersion, cveCategory, cveEco, affectedProducts string) (affectedProduct, bool) {
	var products []affectedProduct
	if affectedProducts == "" || json.Unmarshal([]byte(affectedProducts), &products) != nil {
		return affectedProduct{}, false
	}
	pkgCat := packageCategory(pkgType, pkgEco)
	pkgNormEco := normalizeEcosystem(pkgEco)
	cveNormEco := normalizeEcosystem(cveEco)
	for _, p := range products {
		if !strings.EqualFold(p.Name, pkgName) {
			continue
		}
		affectedEco := normalizeEcosystem(p.Ecosystem)
		effectiveEco := affectedEco
		if effectiveEco == "" {
			effectiveEco = cveNormEco
		}
		if effectiveEco == "" {
			continue
		}
		if len(fixedVersions(p)) == 0 {
			continue
		}
		if !versionIsAffected(effectiveEco, installedVersion, p) {
			continue
		}
		affectedCat := packageCategory("", effectiveEco)
		effectiveCat := cveCategory
		if effectiveCat == "" || effectiveCat == "general-cve" {
			effectiveCat = affectedCat
		}
		if pkgCat == "" || effectiveCat == "" || pkgCat != effectiveCat {
			continue
		}
		if pkgNormEco == "" || effectiveEco == "" || pkgNormEco != effectiveEco {
			continue
		}
		return p, true
	}
	return affectedProduct{}, false
}

func versionIsAffected(eco, installed string, p affectedProduct) bool {
	if installed == "" {
		return false
	}
	if len(p.Ranges) > 0 {
		for _, r := range p.Ranges {
			if versionInRange(eco, installed, r.Events) {
				return true
			}
		}
		return false
	}
	fixed := uniqueFixedVersions(p.Fixed)
	if len(fixed) != 1 {
		return false
	}
	if less, ok := versionLess(eco, installed, fixed[0]); ok && less {
		return true
	}
	return false
}

func fixedVersions(p affectedProduct) []string {
	out := uniqueFixedVersions(p.Fixed)
	seen := map[string]bool{}
	for _, fixed := range out {
		seen[fixed] = true
	}
	for _, r := range p.Ranges {
		for _, ev := range r.Events {
			fixed := strings.TrimSpace(ev.Fixed)
			if !isSafeFixedVersion(fixed) || seen[fixed] {
				continue
			}
			out = append(out, fixed)
			seen[fixed] = true
		}
	}
	return out
}

func hasSafeFixedEvidence(p affectedProduct) bool {
	if len(uniqueFixedVersions(p.Fixed)) == 1 {
		return true
	}
	for _, r := range p.Ranges {
		for _, ev := range r.Events {
			if fixed := strings.TrimSpace(ev.Fixed); isSafeFixedVersion(fixed) {
				return true
			}
		}
	}
	return false
}

func uniqueFixedVersions(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, fixed := range in {
		fixed = strings.TrimSpace(fixed)
		if !isSafeFixedVersion(fixed) || seen[fixed] {
			continue
		}
		out = append(out, fixed)
		seen[fixed] = true
	}
	return out
}

func isHashOnlyFixedVersion(version string) bool {
	return hashOnlyFixedVersionRe.MatchString(strings.TrimSpace(version))
}

func isSafeFixedVersion(version string) bool {
	version = strings.TrimSpace(version)
	if version == "" {
		return false
	}
	if version == "0" {
		return false
	}
	if !versionLikeFixedVersionRe.MatchString(version) {
		return false
	}
	if hashOnlyFixedVersionRe.MatchString(version) {
		return false
	}
	if urlLikeFixedVersionRe.MatchString(version) {
		return false
	}
	if branchLikeFixedVersionRe.MatchString(version) {
		return false
	}
	return true
}

func versionInRange(eco, installed string, events []affectedRangeEvent) bool {
	active := false
	for _, ev := range events {
		if ev.Introduced != "" {
			if ev.Introduced == "0" {
				active = true
			} else if cmp, ok := compareVersions(eco, installed, ev.Introduced); ok {
				active = cmp >= 0
			} else {
				return false
			}
		}
		if active && ev.Fixed != "" {
			if !isSafeFixedVersion(ev.Fixed) {
				return false
			}
			if less, ok := versionLess(eco, installed, ev.Fixed); ok {
				if less {
					return true
				}
				active = false
			} else {
				return false
			}
		}
		if active && ev.LastAffected != "" {
			if cmp, ok := compareVersions(eco, installed, ev.LastAffected); ok {
				if cmp <= 0 {
					return true
				}
				active = false
			} else {
				return false
			}
		}
		if active && ev.Limit != "" {
			if less, ok := versionLess(eco, installed, ev.Limit); ok {
				if less {
					return true
				}
				active = false
			} else {
				return false
			}
		}
	}
	return active
}

func versionLess(eco, a, b string) (bool, bool) {
	cmp, ok := compareVersions(eco, a, b)
	return cmp < 0, ok
}

// compareVersions orders two version strings under the rules of the given
// ecosystem, delegating to the vercmp package which implements the real
// per-ecosystem algorithms (dpkg, rpmvercmp, apk, semver) — a generic ruleset
// rather than ad-hoc heuristics.
//
// It layers one cross-ecosystem policy on top: epoch-loss tolerance. Image and
// container scanners routinely drop the distro epoch from the installed version
// (a). When a carries no epoch but the advisory version (b) does, we strip b's
// epoch before comparing so an administrative epoch bump can't make a clearly-
// newer upstream look older — the dominant false-positive source. Epoch
// downgrades that reset upstream are rare; this trades that rare miss for a
// major reduction in false positives.
func compareVersions(eco, a, b string) (int, bool) {
	if _, aHasEpoch := numericVersionEpoch(a); !aHasEpoch {
		if be, bHasEpoch := numericVersionEpoch(b); bHasEpoch && be > 0 {
			b = stripVersionEpoch(b)
		}
	}
	return vercmp.Compare(eco, a, b)
}

func stripVersionEpoch(v string) string {
	if idx := strings.Index(v, ":"); idx > 0 {
		if _, err := strconv.Atoi(v[:idx]); err == nil {
			return v[idx+1:]
		}
	}
	return v
}

func numericVersionEpoch(v string) (int, bool) {
	v = strings.TrimSpace(v)
	idx := strings.Index(v, ":")
	if idx <= 0 {
		return 0, false
	}
	epoch, err := strconv.Atoi(v[:idx])
	if err != nil {
		return 0, false
	}
	return epoch, true
}

func fixedVersionSQLCondition(alias string) string {
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	installed := prefix + "installed_version"
	fixed := prefix + "fixed_version"
	return fmt.Sprintf(`%s
			AND %s IS NOT NULL AND %s != ''
			AND %s !~* '(~|alpha|beta|rc|pre|preview|dev|snapshot)'
			AND regexp_replace(regexp_replace(%s, '^[0-9]+:', ''), '[^0-9.]', '.', 'g') != ''
			AND regexp_replace(regexp_replace(%s, '^[0-9]+:', ''), '[^0-9.]', '.', 'g') != ''
			AND array_remove(string_to_array(regexp_replace(regexp_replace(%s, '^[0-9]+:', ''), '[^0-9.]', '.', 'g'), '.'), '')::numeric[]
			  >= array_remove(string_to_array(regexp_replace(regexp_replace(%s, '^[0-9]+:', ''), '[^0-9.]', '.', 'g'), '.'), '')::numeric[]`,
		fixedVersionEvidenceSQL(alias), installed, installed, installed, installed, fixed, installed, fixed)
}

func fixedVersionEvidenceSQL(alias string) string {
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	fixed := prefix + "fixed_version"
	return fmt.Sprintf(`%s IS NOT NULL AND %s != ''
			AND trim(%s) <> '0'
			AND %s ~ '[0-9]'
			AND %s !~* '^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$'
			AND %s !~* '^(?:https?|git|ssh)://'
			AND %s !~* '^git\+'
			AND %s !~* '^pkg:'
			AND %s !~ '/'
			AND %s !~* '^(?:main|master|trunk|head|latest|stable|unstable|develop|development)$'`,
		fixed, fixed, fixed, fixed, fixed, fixed, fixed, fixed, fixed, fixed)
}
