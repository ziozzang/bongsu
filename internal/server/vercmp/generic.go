package vercmp

import (
	"strings"
)

// compareGeneric compares two version strings for language-ecosystem packages
// (npm, PyPI, Go modules, crates.io, Maven, RubyGems, NuGet) using a robust
// semver-2.0-leaning algorithm that also tolerates the common shapes those
// ecosystems use (leading "v", PEP 440 pre-releases attached without a dash,
// Maven/qualifier styles, Go pseudo-versions).
//
// It returns -1, 0, 1 for a<b, a==b, a>b. ok is true when a meaningful ordering
// was possible and false when at least one side has no parseable numeric release
// at all (a git sha, a branch name, ...), which the caller treats as "cannot
// suppress / do not match on version".
//
// Precedence rules (following semver 2.0 with ecosystem tolerance):
//  1. A leading 'v' is stripped (Go/npm tags: v1.2.3).
//  2. Build metadata after the first '+' is split off and ignored.
//  3. Pre-release after the first '-' is split off (1.2.3-rc.1 < 1.2.3). PEP 440
//     pre-releases attached without a dash (1.2.3rc1, 1.2.3a1, 1.2.3.dev1) and
//     Maven-style qualifiers are also recognized.
//  4. Numeric release segments (dot-separated) are compared numerically; the
//     shorter one is zero-padded so 1.2 == 1.2.0.
//  5. If the release segments are equal, a version WITH a pre-release is LESS
//     than one without. Pre-release identifiers are compared per semver: split
//     on '.', numeric identifiers compared numerically, alphanumeric compared
//     lexically, numeric < alphanumeric, and more identifiers > fewer when every
//     shared identifier is equal. Common qualifiers are mapped to a known order:
//     dev < alpha/a < beta/b < pre < rc < (release) < post/rev.
//  6. Build metadata is ignored for precedence.
func compareGeneric(a, b string) (int, bool) {
	pa, oka := parseGeneric(a)
	pb, okb := parseGeneric(b)
	if !oka || !okb {
		return 0, false
	}

	if c := compareRelease(pa.release, pb.release); c != 0 {
		return c, true
	}

	// Release segments are equal. Classify each side's qualifier into a tier
	// relative to the bare release: a pre-release (-1) sorts below, a plain
	// release (0), a post-release (+1) sorts above. This lets PEP 440 post
	// releases (1.2.3.post1 > 1.2.3) coexist with semver pre-releases
	// (1.2.3-rc1 < 1.2.3).
	ta := releaseTier(pa.pre)
	tb := releaseTier(pb.pre)
	if ta != tb {
		return sign(ta - tb), true
	}
	if ta == 0 {
		return 0, true // both bare releases
	}
	return comparePre(pa.pre, pb.pre), true
}

// releaseTier reports where a qualifier list sits relative to the bare release:
// -1 for a pre-release, 0 for none (bare release), +1 for a post-release.
func releaseTier(pre []string) int {
	if len(pre) == 0 {
		return 0
	}
	if rank, ok := qualifierRank(pre[0]); ok && rank > 0 {
		return 1 // post / rev
	}
	return -1
}

// genericVersion is a parsed semver-leaning version: numeric release segments
// plus an ordered list of pre-release identifiers. Build metadata is discarded.
// Release segments are kept as their original digit strings (not ints) so that
// arbitrarily long numeric segments compare correctly without integer overflow.
type genericVersion struct {
	release []string
	pre     []string
}

// parseGeneric parses a version string into release segments and pre-release
// identifiers. ok is false when no numeric release could be found at all.
func parseGeneric(v string) (genericVersion, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return genericVersion{}, false
	}
	// 1. Strip a single leading 'v' or 'V' (v1.2.3).
	if v[0] == 'v' || v[0] == 'V' {
		v = v[1:]
	}
	// 2. Drop build metadata after the first '+'.
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	// Normalize the underscore separators some ecosystems use to '.'.
	v = strings.ReplaceAll(v, "_", ".")

	// 3. Split off an explicit dash-delimited pre-release (semver / Go pseudo).
	var preStr string
	if i := strings.IndexByte(v, '-'); i >= 0 {
		preStr = v[i+1:]
		v = v[:i]
	}

	// The remainder is the release, optionally with a PEP 440 / Maven qualifier
	// glued onto the last numeric segment (1.2.3rc1, 1.2.3.dev1). Walk the
	// dot-separated segments, keeping leading numeric ones and breaking out as
	// soon as a non-numeric (or mixed) segment appears.
	release, embeddedPre := splitReleaseAndQualifier(v)
	if len(release) == 0 {
		// No parseable numeric release (e.g. a git sha or branch name).
		return genericVersion{}, false
	}

	pre := make([]string, 0, 4)
	pre = append(pre, embeddedPre...)
	if preStr != "" {
		pre = append(pre, splitPreIdentifiers(preStr)...)
	}

	return genericVersion{release: release, pre: pre}, true
}

// splitReleaseAndQualifier walks the dot-separated head of a version and returns
// the leading numeric release segments plus any trailing pre-release identifiers
// embedded in PEP 440 / Maven style (e.g. "1.2.3rc1" => [1 2 3], ["rc" "1"];
// "1.2.3.dev1" => [1 2 3], ["dev" "1"]).
func splitReleaseAndQualifier(v string) ([]string, []string) {
	if v == "" {
		return nil, nil
	}
	segs := strings.Split(v, ".")
	release := make([]string, 0, len(segs))
	var pre []string

	for idx, seg := range segs {
		if seg == "" {
			continue
		}
		if allDigits(seg) {
			release = append(release, seg)
			continue
		}
		// A mixed segment like "3rc1": pull off the leading digits as a release
		// number, then treat the rest plus the remaining segments as pre-release.
		num, rest := leadingDigits(seg)
		if num != "" {
			release = append(release, num)
		}
		// Everything from `rest` onward is the qualifier / pre-release.
		tail := []string{}
		if rest != "" {
			tail = append(tail, rest)
		}
		if idx+1 < len(segs) {
			tail = append(tail, segs[idx+1:]...)
		}
		pre = splitPreIdentifiers(strings.Join(tail, "."))
		break
	}
	return release, pre
}

// splitPreIdentifiers splits a pre-release string into semver-style identifiers.
// It splits on '.' and also separates letter/digit boundaries within a single
// dot-segment (so "rc1" => ["rc", "1"] and "alpha2" => ["alpha", "2"]), which is
// how PEP 440 and Maven glue qualifiers to numbers.
func splitPreIdentifiers(s string) []string {
	if s == "" {
		return nil
	}
	out := make([]string, 0, 4)
	for _, part := range strings.Split(s, ".") {
		if part == "" {
			continue
		}
		out = append(out, splitAlphaNum(part)...)
	}
	return out
}

// splitAlphaNum splits a single token at boundaries between letter runs and
// digit runs: "rc1" => ["rc","1"], "20230101000000" => ["20230101000000"],
// "alpha" => ["alpha"], "abc12def" => ["abc","12","def"].
func splitAlphaNum(s string) []string {
	out := []string{}
	start := 0
	prevDigit := isDigit(s[0])
	for i := 1; i < len(s); i++ {
		d := isDigit(s[i])
		if d != prevDigit {
			out = append(out, s[start:i])
			start = i
			prevDigit = d
		}
	}
	out = append(out, s[start:])
	return out
}

// compareRelease compares two numeric release segment lists, zero-padding the
// shorter so 1.2 == 1.2.0. Segments are digit strings compared via
// compareNumStr, so arbitrarily long numbers order correctly without overflow.
func compareRelease(a, b []string) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		ai, bi := "0", "0"
		if i < len(a) {
			ai = a[i]
		}
		if i < len(b) {
			bi = b[i]
		}
		if c := compareNumStr(ai, bi); c != 0 {
			return c
		}
	}
	return 0
}

// compareNumStr orders two non-negative integers given as digit strings without
// converting to a machine integer, so values larger than int64 still compare
// correctly. It mirrors the technique used by deb.go/rpm.go: strip leading
// zeros, then the longer remaining string is greater, else compare lexically.
func compareNumStr(a, b string) int {
	a = stripLeadingZeros(a)
	b = stripLeadingZeros(b)
	if len(a) != len(b) {
		return sign(len(a) - len(b))
	}
	return strings.Compare(a, b)
}

// comparePre compares two non-empty pre-release identifier lists per semver,
// with qualifier-name awareness so "alpha"/"a", "beta"/"b", "rc", "pre", "dev",
// "post"/"rev" order consistently regardless of spelling.
func comparePre(a, b []string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if c := comparePreIdent(a[i], b[i]); c != 0 {
			return c
		}
	}
	// All shared identifiers equal: more identifiers > fewer (1.0.0-a < 1.0.0-a.1).
	return sign(len(a) - len(b))
}

// comparePreIdent compares a single pair of pre-release identifiers.
func comparePreIdent(a, b string) int {
	aIsNum := allDigits(a)
	bIsNum := allDigits(b)

	switch {
	case aIsNum && bIsNum:
		// Compare as digit strings, not parsed ints, so 30+ digit identifiers
		// (which would overflow strconv.Atoi) still order correctly.
		return compareNumStr(a, b)
	case aIsNum && !bIsNum:
		// Numeric identifiers always have lower precedence than alphanumeric.
		return -1
	case !aIsNum && bIsNum:
		return 1
	}

	// Both alphanumeric. Prefer a known qualifier ordering when both map to one;
	// otherwise fall back to a plain lexical comparison.
	ra, aKnown := qualifierRank(a)
	rb, bKnown := qualifierRank(b)
	if aKnown && bKnown {
		if ra != rb {
			return sign(ra - rb)
		}
		return 0
	}
	return strings.Compare(strings.ToLower(a), strings.ToLower(b))
}

// qualifierRank maps a known pre-release / qualifier name to a relative rank.
// Lower ranks sort earlier. The "release" rank (0) is only used as a reference
// point; pre-releases are negative and post-releases positive so the ordering is
// dev < alpha/a < beta/b < pre < rc < release < post/rev.
func qualifierRank(s string) (int, bool) {
	switch strings.ToLower(s) {
	case "dev":
		return -5, true
	case "alpha", "a":
		return -4, true
	case "beta", "b":
		return -3, true
	case "pre", "preview", "c":
		return -2, true
	case "rc":
		return -1, true
	case "post", "rev", "r":
		return 1, true
	default:
		return 0, false
	}
}

// allDigits reports whether s is a non-empty run of ASCII digits. It does not
// parse the value, so it is safe for arbitrarily long numeric strings; callers
// order such strings with compareNumStr instead of integer arithmetic.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

// leadingDigits splits s into its leading ASCII-digit run and the remainder.
func leadingDigits(s string) (digits, rest string) {
	i := 0
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	return s[:i], s[i:]
}
