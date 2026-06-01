package db

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
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
	case "debian", "ubuntu", "alpine", "red hat", "rhel", "suse", "almalinux", "amazon linux", "wolfi", "chainguard", "rocky linux", "oracle linux":
		return true
	default:
		return false
	}
}

func normalizeEcosystem(eco string) string {
	eco = strings.ToLower(strings.TrimSpace(eco))
	switch eco {
	case "python", "python-pkg", "pip":
		return "pypi"
	case "node", "node-pkg", "javascript":
		return "npm"
	case "golang", "gomod":
		return "go"
	case "ruby", "gem":
		return "rubygems"
	case "rust", "cargo":
		return "crates.io"
	case "debian:10", "debian:11", "debian:12", "debian:13":
		return "debian"
	case "ubuntu:18.04", "ubuntu:20.04", "ubuntu:22.04", "ubuntu:24.04":
		return "ubuntu"
	case "redhat", "red hat enterprise linux", "centos", "rocky", "almalinux", "alma", "amazon":
		return "rhel"
	default:
		if strings.HasPrefix(eco, "debian:") {
			return "debian"
		}
		if strings.HasPrefix(eco, "ubuntu:") {
			return "ubuntu"
		}
		return eco
	}
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
		if !versionIsAffected(installedVersion, p) {
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

func versionIsAffected(installed string, p affectedProduct) bool {
	if installed == "" {
		return false
	}
	if len(p.Ranges) > 0 {
		for _, r := range p.Ranges {
			if versionInRange(installed, r.Events) {
				return true
			}
		}
		return false
	}
	fixed := uniqueFixedVersions(p.Fixed)
	if len(fixed) != 1 {
		return false
	}
	if less, ok := versionLess(installed, fixed[0]); ok && less {
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
			if fixed == "" || isHashOnlyFixedVersion(fixed) || seen[fixed] {
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
			if fixed := strings.TrimSpace(ev.Fixed); fixed != "" && !isHashOnlyFixedVersion(fixed) {
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
		if fixed == "" || isHashOnlyFixedVersion(fixed) || seen[fixed] {
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

func versionInRange(installed string, events []affectedRangeEvent) bool {
	active := false
	for _, ev := range events {
		if ev.Introduced != "" {
			if ev.Introduced == "0" {
				active = true
			} else if cmp, ok := compareVersions(installed, ev.Introduced); ok {
				active = cmp >= 0
			} else {
				return false
			}
		}
		if active && ev.Fixed != "" {
			if isHashOnlyFixedVersion(ev.Fixed) {
				return false
			}
			if less, ok := versionLess(installed, ev.Fixed); ok {
				if less {
					return true
				}
				active = false
			} else {
				return false
			}
		}
		if active && ev.LastAffected != "" {
			if cmp, ok := compareVersions(installed, ev.LastAffected); ok {
				if cmp <= 0 {
					return true
				}
				active = false
			} else {
				return false
			}
		}
		if active && ev.Limit != "" {
			if less, ok := versionLess(installed, ev.Limit); ok {
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

func versionLess(a, b string) (bool, bool) {
	cmp, ok := compareVersions(a, b)
	return cmp < 0, ok
}

func compareVersions(a, b string) (int, bool) {
	as := versionSegments(a)
	bs := versionSegments(b)
	if len(as) == 0 || len(bs) == 0 {
		return 0, false
	}
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if av < bv {
			return -1, true
		}
		if av > bv {
			return 1, true
		}
	}
	aPre := isPreReleaseVersion(a)
	bPre := isPreReleaseVersion(b)
	if aPre && !bPre {
		return -1, true
	}
	if !aPre && bPre {
		return 1, true
	}
	if aPre && bPre {
		if cmp := comparePreRelease(a, b); cmp != 0 {
			return cmp, true
		}
	}
	return 0, true
}

func isPreReleaseVersion(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	if idx := strings.Index(v, "+"); idx >= 0 {
		v = v[:idx]
	}
	if strings.Contains(v, "~") {
		return true
	}
	for _, marker := range preReleaseMarkers() {
		if strings.Contains(v, marker) {
			return true
		}
	}
	return false
}

func versionSegments(v string) []int {
	v = stripPreReleaseSuffix(strings.TrimSpace(v))
	if i := strings.Index(v, ":"); i >= 0 {
		v = v[i+1:]
	}
	parts := strings.FieldsFunc(v, func(r rune) bool {
		return r < '0' || r > '9'
	})
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

func stripPreReleaseSuffix(v string) string {
	low := strings.ToLower(v)
	if idx := strings.IndexAny(low, "+~"); idx >= 0 {
		low = low[:idx]
		v = v[:idx]
	}
	cut := len(v)
	for _, marker := range preReleaseMarkers() {
		if idx := strings.Index(low, marker); idx >= 0 && idx < cut {
			cut = idx
		}
	}
	return strings.TrimRight(v[:cut], "-_.")
}

func preReleaseMarkers() []string {
	return []string{"dev", "snapshot", "preview", "pre", "alpha", "beta", "rc"}
}

func comparePreRelease(a, b string) int {
	aRank, aNum := preReleaseRank(a)
	bRank, bNum := preReleaseRank(b)
	if aRank < bRank {
		return -1
	}
	if aRank > bRank {
		return 1
	}
	if aNum < bNum {
		return -1
	}
	if aNum > bNum {
		return 1
	}
	return 0
}

func preReleaseRank(v string) (int, int) {
	v = strings.ToLower(strings.TrimSpace(v))
	if idx := strings.Index(v, "+"); idx >= 0 {
		v = v[:idx]
	}
	for rank, marker := range preReleaseMarkers() {
		if strings.Contains(v, marker) {
			n, _ := preReleaseNumber(v, marker)
			return rank + 1, n
		}
	}
	if strings.Contains(v, "~") {
		if n, ok := preReleaseNumber(v, "~"); ok {
			return 0, n
		}
		return 0, 0
	}
	return len(preReleaseMarkers()) + 1, 0
}

func preReleaseNumber(v, marker string) (int, bool) {
	idx := strings.Index(v, marker)
	if idx < 0 {
		return 0, false
	}
	rest := v[idx+len(marker):]
	start := -1
	end := -1
	for i, r := range rest {
		if r >= '0' && r <= '9' {
			if start < 0 {
				start = i
			}
			end = i + 1
			continue
		}
		if start >= 0 {
			break
		}
	}
	if start < 0 {
		return 0, false
	}
	n, err := strconv.Atoi(rest[start:end])
	if err != nil {
		return 0, false
	}
	return n, true
}


func fixedVersionSQLCondition(alias string) string {
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	installed := prefix + "installed_version"
	fixed := prefix + "fixed_version"
	return fmt.Sprintf(`%s IS NOT NULL AND %s != ''
			AND %s IS NOT NULL AND %s != ''
			AND %s !~* '(~|alpha|beta|rc|pre|preview|dev|snapshot)'
			AND regexp_replace(regexp_replace(%s, '^[0-9]+:', ''), '[^0-9.]', '.', 'g') != ''
			AND regexp_replace(regexp_replace(%s, '^[0-9]+:', ''), '[^0-9.]', '.', 'g') != ''
			AND array_remove(string_to_array(regexp_replace(regexp_replace(%s, '^[0-9]+:', ''), '[^0-9.]', '.', 'g'), '.'), '')::numeric[]
			  >= array_remove(string_to_array(regexp_replace(regexp_replace(%s, '^[0-9]+:', ''), '[^0-9.]', '.', 'g'), '.'), '')::numeric[]`,
		fixed, fixed, installed, installed, installed, installed, fixed, installed, fixed)
}
