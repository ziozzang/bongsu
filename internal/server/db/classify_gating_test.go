package db

import "testing"

// These tests extend coverage of the pure (no-DB) classification/gating helpers
// in classify.go. They deliberately avoid duplicating cases already asserted in
// classify_test.go; instead they cover the gating edges that protect against
// false-positive matches: ecosystem/category separation, fixed-version safety,
// ecosystem normalization families, and multi-event range semantics.

func TestCompatibleSecurityCandidateGatesOSVsCodeLibraries(t *testing.T) {
	// An OS-package advisory (Debian) must never match a code-library package
	// (PyPI) of the same name, and vice-versa, even when the version would be
	// "in range" — the category gate is what prevents cross-ontology FPs.
	osAdvisory := `[{"name":"jinja2","ecosystem":"Debian","fixed":["2.11.3-1"]}]`
	if _, ok := compatibleSecurityCandidate("jinja2", "python-pkg", "PyPI", "2.11.0", "code-library", "", osAdvisory); ok {
		t.Fatal("Debian OS advisory must not match a PyPI code-library package")
	}

	codeAdvisory := `[{"name":"jinja2","ecosystem":"PyPI","fixed":["2.11.3"]}]`
	if _, ok := compatibleSecurityCandidate("jinja2", "deb", "Debian", "2.11.0", "os-package", "", codeAdvisory); ok {
		t.Fatal("PyPI code-library advisory must not match a Debian OS package")
	}
}

func TestCompatibleSecurityCandidateIsCaseInsensitiveOnName(t *testing.T) {
	affected := `[{"name":"Django","ecosystem":"PyPI","fixed":["4.2.1"]}]`
	if _, ok := compatibleSecurityCandidate("django", "python-pkg", "PyPI", "4.2.0", "code-library", "", affected); !ok {
		t.Fatal("package name match must be case-insensitive (django vs Django)")
	}
	if _, ok := compatibleSecurityCandidate("DJANGO", "python-pkg", "pypi", "4.2.0", "code-library", "", affected); !ok {
		t.Fatal("package name and ecosystem match must both be case-insensitive")
	}
}

func TestCompatibleSecurityCandidateRequiresFixedVersion(t *testing.T) {
	// An affected product with no usable fixed-version evidence is rejected even
	// when name+ecosystem line up and a range would otherwise be open-ended.
	noFixed := `[{"name":"foo","ecosystem":"npm","ranges":[{"events":[{"introduced":"1.0.0"}]}]}]`
	if _, ok := compatibleSecurityCandidate("foo", "npm", "npm", "1.5.0", "code-library", "", noFixed); ok {
		t.Fatal("introduced-only range with no fixed evidence must be rejected")
	}
}

func TestCompatibleSecurityCandidateUsesCveEcosystemFallback(t *testing.T) {
	// When the affected product entry carries no ecosystem, the CVE-level
	// ecosystem (cveEco) must be used as the effective ecosystem so a correctly
	// scoped advisory still matches.
	affected := `[{"name":"foo","fixed":["2.0.0"]}]`
	if _, ok := compatibleSecurityCandidate("foo", "npm", "npm", "1.5.0", "code-library", "npm", affected); !ok {
		t.Fatal("missing product ecosystem should fall back to cveEco (npm) and match")
	}
	// The fallback must still gate: a mismatched cveEco must not match.
	if _, ok := compatibleSecurityCandidate("foo", "npm", "npm", "1.5.0", "code-library", "PyPI", affected); ok {
		t.Fatal("cveEco fallback that mismatches the package ecosystem must not match")
	}
	// With neither product ecosystem nor cveEco there is nothing to gate on.
	if _, ok := compatibleSecurityCandidate("foo", "npm", "npm", "1.5.0", "general-cve", "", affected); ok {
		t.Fatal("no product ecosystem and no cveEco must not match")
	}
}

func TestNormalizeEcosystemFamilySplitsAndAliases(t *testing.T) {
	cases := map[string]string{
		// Distro family splits on ':'.
		"Alpine:v3.21":                          "alpine",
		"Red Hat:enterprise_linux:8::appstream": "rhel",
		// Language ecosystem aliases.
		"pip":      "pypi",
		"poetry":   "pypi",
		"gomod":    "go",
		"golang":   "go",
		"yarn":     "npm",
		"gem":      "rubygems",
		"cargo":    "crates.io",
		"jar":      "maven",
		"composer": "packagist",
	}
	for in, want := range cases {
		if got := normalizeEcosystem(in); got != want {
			t.Fatalf("normalizeEcosystem(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPackageCategoryClassifiesByEcosystemAndType(t *testing.T) {
	cases := []struct {
		name    string
		pkgType string
		eco     string
		want    string
	}{
		{"os ecosystem wins", "", "Debian:12", "os-package"},
		{"code ecosystem", "", "pypi", "code-library"},
		{"code ecosystem npm", "", "npm", "code-library"},
		{"os pkg type fallback", "debian", "", "os-package"},
		{"alpine apk type fallback", "apk", "", "os-package"},
		{"code pkg type fallback", "gomod", "", "code-library"},
		{"unknown", "mystery", "", ""},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := packageCategory(tt.pkgType, tt.eco); got != tt.want {
				t.Fatalf("packageCategory(%q, %q) = %q, want %q", tt.pkgType, tt.eco, got, tt.want)
			}
		})
	}
}

func TestIsOSEcosystem(t *testing.T) {
	osEcos := []string{"Debian", "Ubuntu", "Alpine:v3.21", "Red Hat:enterprise_linux:8", "rocky linux", "AlmaLinux", "amazon linux", "wolfi", "chainguard", "Android"}
	for _, e := range osEcos {
		if !isOSEcosystem(e) {
			t.Fatalf("isOSEcosystem(%q) = false, want true", e)
		}
	}
	nonOS := []string{"pypi", "npm", "go", "maven", "crates.io", "", "github actions"}
	for _, e := range nonOS {
		if isOSEcosystem(e) {
			t.Fatalf("isOSEcosystem(%q) = true, want false", e)
		}
	}
}

func TestIsSafeFixedVersionRejectsNonVersions(t *testing.T) {
	rejected := []string{
		"",
		"0",
		"main",
		"master",
		"stable",
		"latest",
		"develop",
		"https://github.com/foo/bar/commit/abc",
		"git://example.com/repo.git",
		"git+https://example.com/repo",
		"pkg:npm/foo@1.0.0",
		"path/to/fix",
		"0123456789abcdef0123456789abcdef", // 32 hex
		"0123456789abcdef0123456789abcdef01234567",                         // 40 hex
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", // 64 hex
		"no-digits-here",
	}
	for _, v := range rejected {
		if isSafeFixedVersion(v) {
			t.Fatalf("isSafeFixedVersion(%q) = true, want false", v)
		}
	}

	accepted := []string{
		"1.2.3",
		"1.1.1k-14.el8_6",
		"3.0.13-0ubuntu3.6",
		"1:2.0.0-2",
		"1.37.0-r14",
		"v1.2.3",
		// A 39-hex string is not a recognized hash length, so as long as it
		// contains a digit it passes the version-like gate.
		"abcdef0123456789abcdef0123456789abcde12",
	}
	for _, v := range accepted {
		if !isSafeFixedVersion(v) {
			t.Fatalf("isSafeFixedVersion(%q) = false, want true", v)
		}
	}
}

func TestVersionInRangeIntroducedOnlyIsAffectedFromThereOn(t *testing.T) {
	// An introduced event with no terminating fixed/last_affected/limit means
	// every version at or above the introduced point is affected; versions below
	// it are not. This encodes the actual observed behavior of versionInRange.
	events := []affectedRangeEvent{{Introduced: "1.5.0"}}
	if !versionInRange("", "1.5.0", events) {
		t.Fatal("version equal to introduced should be affected")
	}
	if !versionInRange("", "9.9.9", events) {
		t.Fatal("version above introduced (open-ended) should remain affected")
	}
	if versionInRange("", "1.4.0", events) {
		t.Fatal("version below introduced should not be affected")
	}

	// introduced:"0" means affected from the very beginning.
	fromZero := []affectedRangeEvent{{Introduced: "0"}}
	if !versionInRange("", "0.0.1", fromZero) {
		t.Fatal("introduced:0 should mark every version affected")
	}
}

func TestVersionInRangeUnsafeFixedEventRejectsWholeRange(t *testing.T) {
	// A fixed event that is not a safe version (e.g. a git hash) makes the range
	// non-actionable: versionInRange must return false rather than guess.
	events := []affectedRangeEvent{
		{Introduced: "0"},
		{Fixed: "0123456789abcdef0123456789abcdef01234567"},
	}
	if versionInRange("", "1.0.0", events) {
		t.Fatal("range terminated by an unsafe (hash) fixed event must not match")
	}
}

func TestVersionInRangeReintroducedAfterFixed(t *testing.T) {
	// introduced -> fixed -> introduced: a version in the first window matches,
	// a version in the fixed gap does not, and a version in the re-introduced
	// open-ended window matches again.
	events := []affectedRangeEvent{
		{Introduced: "1.0.0"},
		{Fixed: "2.0.0"},
		{Introduced: "3.0.0"},
	}
	if !versionInRange("", "1.5.0", events) {
		t.Fatal("version in first affected window should match")
	}
	if versionInRange("", "2.5.0", events) {
		t.Fatal("version in the fixed gap should not match")
	}
	if !versionInRange("", "3.5.0", events) {
		t.Fatal("version in re-introduced open-ended window should match")
	}
}
