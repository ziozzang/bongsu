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
	// CPE fields (NVD): present on NVD advisories. Vendor/Product identify the
	// software via its CPE 2.3 components; the version bounds gate matching so a
	// runtime is only flagged when its version actually falls in the affected
	// range — never on vendor+product alone.
	Vendor                string `json:"vendor"`
	Product               string `json:"product"`
	Version               string `json:"version"`
	VersionStartIncluding string `json:"version_start_including"`
	VersionStartExcluding string `json:"version_start_excluding"`
	VersionEndIncluding   string `json:"version_end_including"`
	VersionEndExcluding   string `json:"version_end_excluding"`
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
	if pkgNormEco == "" {
		// Detectors sometimes set pkg_type but leave ecosystem empty (e.g. a jar
		// with no registry ecosystem); fall back to the type so the ecosystem
		// gate can still match (jar->maven, composer->packagist, …).
		pkgNormEco = normalizeEcosystem(pkgType)
	}
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
		// An advisory is actionable only if it bounds the affected set: a fixed
		// version, or a range with an upper bound (fixed/last_affected, e.g. an
		// unpatched vuln). An introduced-only range (no upper bound) would flag
		// every version and is dropped as noise.
		if len(fixedVersions(p)) == 0 && !hasUpperBoundedRange(p) {
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

// compatibleCPECandidate matches a software component (typically a language
// runtime detected outside the OS package manager) against NVD CPE advisories.
// It is deliberately conservative to avoid the false-positive explosion of
// matching on vendor+product alone: a candidate matches only when the CPE
// product equals the package's CPE product AND the installed version falls
// inside an explicit version constraint (range bounds or an exact version).
// An NVD entry that names the product but carries no version constraint never
// matches here.
//
// cpeProduct is the package's CPE product (e.g. "python", "nodejs", "jdk").
// installedVersion is compared with the generic/semver comparator since runtime
// versions are not distro-versioned.
func compatibleCPECandidate(cpeProduct, installedVersion, affectedProducts string) (affectedProduct, bool) {
	cpeProduct = strings.ToLower(strings.TrimSpace(cpeProduct))
	installedVersion = strings.TrimSpace(installedVersion)
	if cpeProduct == "" || installedVersion == "" || affectedProducts == "" {
		return affectedProduct{}, false
	}
	var products []affectedProduct
	if json.Unmarshal([]byte(affectedProducts), &products) != nil {
		return affectedProduct{}, false
	}
	for _, p := range products {
		if !cpeProductMatches(cpeProduct, strings.ToLower(strings.TrimSpace(p.Product))) {
			continue
		}
		if !cpeVendorCompatible(cpeProduct, strings.ToLower(strings.TrimSpace(p.Vendor))) {
			continue
		}
		if cpeVersionAffected(installedVersion, p) {
			return p, true
		}
	}
	return affectedProduct{}, false
}

// cpeProductMatches accepts the package product and the advisory product as
// equal modulo the common spelling variants between detector output and CPE
// product names (e.g. nodejs vs node.js, jdk vs jre).
func cpeProductMatches(pkgProduct, advProduct string) bool {
	if pkgProduct == advProduct {
		return true
	}
	return cpeNormProduct(pkgProduct) == cpeNormProduct(advProduct)
}

func cpeNormProduct(s string) string {
	s = strings.ReplaceAll(s, ".", "")
	s = strings.ReplaceAll(s, "_", "")
	s = strings.ReplaceAll(s, "-", "")
	switch s {
	case "nodejs", "node":
		return "nodejs"
	case "jdk", "jre", "openjdk", "java", "javase", "javasedevelopmentkit":
		return "jdk"
	case "go", "golang":
		return "go"
	}
	return s
}

// cpeRuntimeVendors maps each runtime product family to the CPE vendors that
// actually publish that runtime. NVD product names collide across vendors —
// e.g. Microsoft's VS Code Python EXTENSION is (microsoft, python) — and
// without a vendor gate the CPython interpreter would match extension/IDE
// advisories with nonsense fixed versions (the observed CVE-2024-49050 case).
// An advisory with an empty vendor is allowed through (product+version gates
// still apply); an unknown product family is also allowed (no list to check).
var cpeRuntimeVendors = map[string]map[string]bool{
	"python": {"python": true, "python_software_foundation": true},
	"nodejs": {"nodejs": true, "node.js": true},
	"jdk": {
		"oracle": true, "sun": true, "eclipse": true, "adoptium": true, "azul": true,
		"ibm": true, "redhat": true, "red_hat": true, "amazon": true, "bellsoft": true,
		"sap": true, "temurin": true, "openjdk": true,
	},
	"go":   {"golang": true, "google": true},
	"ruby": {"ruby-lang": true, "ruby": true},
	"php":  {"php": true, "php_group": true},
}

// cpeVendorCompatible reports whether the advisory's CPE vendor is a known
// publisher of the runtime product. This is the cross-vendor false-positive
// gate: same product name under a foreign vendor (IDE plugins, wrappers,
// distro meta-products) must not match the runtime itself.
func cpeVendorCompatible(pkgProduct, advVendor string) bool {
	if advVendor == "" {
		return true
	}
	allowed, ok := cpeRuntimeVendors[cpeNormProduct(pkgProduct)]
	if !ok {
		return true
	}
	return allowed[advVendor]
}

// cpeVersionAffected reports whether installed falls within the CPE version
// constraint. It requires at least one bound (start/end) or an exact version —
// a product entry with no version information returns false (no match), which
// is what keeps CPE matching from flagging every version of a product.
func cpeVersionAffected(installed string, p affectedProduct) bool {
	startIncl := strings.TrimSpace(p.VersionStartIncluding)
	startExcl := strings.TrimSpace(p.VersionStartExcluding)
	endIncl := strings.TrimSpace(p.VersionEndIncluding)
	endExcl := strings.TrimSpace(p.VersionEndExcluding)
	exact := strings.TrimSpace(p.Version)

	hasBound := startIncl != "" || startExcl != "" || endIncl != "" || endExcl != ""
	if !hasBound {
		// Only an exact pinned version is actionable without bounds.
		if exact == "" || exact == "*" || exact == "-" {
			return false
		}
		// CPE version fields sometimes carry a wildcard tail (e.g. "1.2.*"),
		// meaning every patch of that minor; treat it as a numeric-segment prefix
		// match rather than a literal equality (which would never hit).
		if i := strings.IndexByte(exact, '*'); i >= 0 {
			prefix := strings.TrimRight(exact[:i], ".")
			return versionLineageHasPrefix(installed, prefix)
		}
		cmp, ok := vercmpGeneric(installed, exact)
		return ok && cmp == 0
	}

	if startIncl != "" {
		if cmp, ok := vercmpGeneric(installed, startIncl); !ok || cmp < 0 {
			return false
		}
	}
	if startExcl != "" {
		if cmp, ok := vercmpGeneric(installed, startExcl); !ok || cmp <= 0 {
			return false
		}
	}
	if endIncl != "" {
		if cmp, ok := vercmpGeneric(installed, endIncl); !ok || cmp > 0 {
			return false
		}
	}
	if endExcl != "" {
		if cmp, ok := vercmpGeneric(installed, endExcl); !ok || cmp >= 0 {
			return false
		}
	}
	return true
}

func vercmpGeneric(a, b string) (int, bool) {
	return vercmp.Compare("", a, b)
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
	switch len(fixed) {
	case 0:
		return false
	case 1:
		if less, ok := versionLess(eco, installed, fixed[0]); ok && less {
			return true
		}
		return false
	default:
		// Multiple fixed versions with no ranges == per-branch backports (e.g.
		// fixed in 1.2.8 AND 1.3.4). The install is affected if it is below the
		// fix in its OWN release branch (same major.minor); if no fix shares the
		// branch, it predates all branches and is affected iff below the lowest
		// fix. Avoids both the old "drop everything" false negative and the naive
		// "below max fix" false positive (1.2.9 vs fixes [1.2.8, 1.3.4]).
		return belowBranchFix(eco, installed, fixed)
	}
}

// hasUpperBoundedRange reports whether any range carries an upper bound (fixed
// or last_affected) that makes it actionable. An introduced-only range has no
// upper bound and must not match every version.
func hasUpperBoundedRange(p affectedProduct) bool {
	for _, r := range p.Ranges {
		for _, ev := range r.Events {
			if strings.TrimSpace(ev.Fixed) != "" || strings.TrimSpace(ev.LastAffected) != "" {
				return true
			}
		}
	}
	return false
}

// belowBranchFix decides affectedness against a set of per-branch fixed versions.
func belowBranchFix(eco, installed string, fixed []string) bool {
	instLineage := versionLineage(installed)
	branchMatched := false
	if instLineage != "" {
		for _, f := range fixed {
			if versionLineage(f) != instLineage {
				continue
			}
			branchMatched = true
			if less, ok := versionLess(eco, installed, f); ok && less {
				return true
			}
		}
	}
	if branchMatched {
		// A fix exists in the install's own branch and it is at/above it -> patched.
		return false
	}
	low := ""
	for _, f := range fixed {
		if low == "" {
			low = f
			continue
		}
		if less, ok := versionLess(eco, f, low); ok && less {
			low = f
		}
	}
	if low == "" {
		return false
	}
	less, ok := versionLess(eco, installed, low)
	return ok && less
}

// versionLineage returns the leading "major.minor" of a version (epoch-stripped)
// used to group per-branch backport fixes; "" when two numeric segments can't
// be parsed.
func versionLineage(v string) string {
	v = stripVersionEpoch(strings.TrimSpace(v))
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		v = v[1:] // drop a leading v (Go/npm convention)
	}
	segs := strings.FieldsFunc(v, func(r rune) bool {
		return r == '.' || r == '-' || r == '_' || r == '+' || r == '~' || r == ':'
	})
	nums := make([]string, 0, 2)
	for _, s := range segs {
		n := ""
		for _, c := range s {
			if c < '0' || c > '9' {
				break
			}
			n += string(c)
		}
		if n == "" {
			break
		}
		nums = append(nums, n)
		if len(nums) == 2 {
			break
		}
	}
	if len(nums) < 2 {
		return ""
	}
	return nums[0] + "." + nums[1]
}

// versionLineageHasPrefix reports whether installed's dotted version begins with
// the given numeric prefix on a segment boundary (so "1.2" matches "1.2.3" but
// not "1.20.0"). Used for CPE wildcard-exact versions like "1.2.*".
func versionLineageHasPrefix(installed, prefix string) bool {
	inst := stripVersionEpoch(strings.TrimSpace(installed))
	prefix = strings.TrimSpace(prefix)
	if inst == "" || prefix == "" {
		return false
	}
	return strings.HasPrefix(inst+".", prefix+".")
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
