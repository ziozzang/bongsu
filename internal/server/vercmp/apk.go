package vercmp

import "strings"

// compareAlpine compares two version strings using Alpine's apk algorithm, a
// faithful port of apk-tools src/version.c (apk_version_compare_blob_fuzzy). It
// returns -1, 0, 1 for a<b, a==b, a>b and ok=false only for empty or genuinely
// invalid input.
//
// An apk version is a tokenized stream rather than a fixed [epoch:]upstream-rev
// layout. apk walks both strings token by token; the *expected* token type at
// each step is derived from the previous token and the separator that follows
// it (a small state machine). The first non-equal token decides the result.
// When the two streams diverge in token type, each token type's fixed enum rank
// resolves the comparison so the order is total.
//
// Token types, in apk's enum order:
//
//	END < INVALID  (END means "no more tokens": a shorter version with nothing
//	left is generally OLDER, except for post-release suffixes — see below)
//	DIGIT_OR_ZERO < DIGIT < LETTER < SUFFIX < SUFFIX_NO < REVISION
//
// Suffixes carry their own pre-release/post-release ordering:
//
//	alpha < beta < pre < rc  <  (release)  <  cvs < svn < git < hg < p
//
// Everything before the implicit "release" point (alpha..rc) makes the version
// OLDER than the bare version; everything after (cvs..p) makes it NEWER. So
// "1.0_alpha1" < "1.0" < "1.0_p1".
func compareAlpine(a, b string) (int, bool) {
	if a == "" || b == "" {
		return 0, false
	}
	if !apkValid(a) || !apkValid(b) {
		return 0, false
	}
	return apkCompare(a, b), true
}

// apk token types. The relative ordering of DIGIT_OR_ZERO..REVISION is apk's
// enum order and is used to break ties when the two streams have different
// token types. apkTokEnd is handled specially (see apkCompare).
const (
	apkTokEnd = iota
	apkTokDigitOrZero
	apkTokDigit
	apkTokLetter
	apkTokSuffix
	apkTokSuffixNo
	apkTokRevision
	apkTokInvalid
)

// apkSuffixes lists recognized pre/post-release suffixes in increasing order.
// Index 0..3 (alpha..rc) are pre-release (older than the bare version); index
// 4..8 (cvs..p) are post-release (newer than the bare version).
var apkSuffixes = []string{
	"alpha", "beta", "pre", "rc",
	"cvs", "svn", "git", "hg", "p",
}

const apkPreReleaseCount = 4 // alpha,beta,pre,rc

// apkToken is one parsed token.
type apkToken struct {
	typ    int
	value  int    // numeric value (suffix index for SUFFIX; rune for LETTER)
	digits string // raw digit run, for DIGIT_OR_ZERO fractional comparison
}

// apkScanner walks a version string emitting tokens.
type apkScanner struct {
	s   string
	pos int
	tok int // the token type to parse NEXT
}

func newAPKScanner(s string) *apkScanner {
	return &apkScanner{s: s, tok: apkTokDigit}
}

// next parses and returns the next token. ok is false on a parse error.
func (sc *apkScanner) next() (apkToken, bool) {
	if sc.pos >= len(sc.s) {
		return apkToken{typ: apkTokEnd}, true
	}

	switch sc.tok {
	case apkTokDigitOrZero, apkTokDigit:
		start := sc.pos
		for sc.pos < len(sc.s) && isDigit(sc.s[sc.pos]) {
			sc.pos++
		}
		if sc.pos == start {
			return apkToken{typ: apkTokInvalid}, false
		}
		digits := sc.s[start:sc.pos]
		// A numeric group that starts with '0' is compared as a decimal
		// fraction (string-style), so "1.05" < "1.5"; otherwise it's an
		// ordinary integer.
		typ := apkTokDigit
		if digits[0] == '0' {
			typ = apkTokDigitOrZero
		}
		sc.tok = sc.afterNumber()
		return apkToken{typ: typ, value: atoiSimple(digits), digits: digits}, true

	case apkTokLetter:
		c := sc.s[sc.pos]
		if !isLowerAlpha(c) {
			return apkToken{typ: apkTokInvalid}, false
		}
		sc.pos++
		sc.tok = sc.afterLetter()
		return apkToken{typ: apkTokLetter, value: int(c)}, true

	case apkTokSuffix:
		idx, ok := sc.scanSuffixName()
		if !ok {
			return apkToken{typ: apkTokInvalid}, false
		}
		sc.tok = apkTokSuffixNo
		return apkToken{typ: apkTokSuffix, value: idx}, true

	case apkTokSuffixNo:
		start := sc.pos
		for sc.pos < len(sc.s) && isDigit(sc.s[sc.pos]) {
			sc.pos++
		}
		v := 0
		if sc.pos > start {
			v = atoiSimple(sc.s[start:sc.pos])
		}
		sc.tok = sc.afterSuffixNo()
		return apkToken{typ: apkTokSuffixNo, value: v}, true

	case apkTokRevision:
		if sc.pos >= len(sc.s) || sc.s[sc.pos] != 'r' {
			return apkToken{typ: apkTokInvalid}, false
		}
		sc.pos++
		start := sc.pos
		for sc.pos < len(sc.s) && isDigit(sc.s[sc.pos]) {
			sc.pos++
		}
		if sc.pos == start {
			return apkToken{typ: apkTokInvalid}, false
		}
		v := atoiSimple(sc.s[start:sc.pos])
		sc.tok = apkTokEnd
		return apkToken{typ: apkTokRevision, value: v}, true
	}

	return apkToken{typ: apkTokInvalid}, false
}

// afterNumber returns the token type expected after a numeric group, consuming
// the separator that follows.
func (sc *apkScanner) afterNumber() int {
	if sc.pos >= len(sc.s) {
		return apkTokEnd
	}
	switch c := sc.s[sc.pos]; {
	case c == '.':
		sc.pos++
		return apkTokDigit
	case isLowerAlpha(c):
		// A bare trailing letter is apk's single-letter suffix (e.g. "1.0a").
		// But a multi-letter run that names a known suffix without a leading
		// '_' is not valid here; apk only takes a single letter in this state.
		return apkTokLetter
	case c == '_':
		sc.pos++
		return apkTokSuffix
	case c == '-':
		sc.pos++
		return apkTokRevision
	default:
		return apkTokInvalid
	}
}

func (sc *apkScanner) afterLetter() int {
	if sc.pos >= len(sc.s) {
		return apkTokEnd
	}
	switch c := sc.s[sc.pos]; {
	case c == '_':
		sc.pos++
		return apkTokSuffix
	case c == '-':
		sc.pos++
		return apkTokRevision
	case c == '.':
		sc.pos++
		return apkTokDigit
	default:
		return apkTokInvalid
	}
}

func (sc *apkScanner) afterSuffixNo() int {
	if sc.pos >= len(sc.s) {
		return apkTokEnd
	}
	switch c := sc.s[sc.pos]; {
	case c == '_':
		sc.pos++
		return apkTokSuffix
	case c == '-':
		sc.pos++
		return apkTokRevision
	case isLowerAlpha(c):
		return apkTokLetter
	default:
		return apkTokInvalid
	}
}

// scanSuffixName matches the longest recognized suffix name at the cursor and
// returns its index in apkSuffixes.
func (sc *apkScanner) scanSuffixName() (int, bool) {
	rest := sc.s[sc.pos:]
	bestIdx, bestLen := -1, 0
	for idx, name := range apkSuffixes {
		if len(name) > bestLen && strings.HasPrefix(rest, name) {
			bestIdx, bestLen = idx, len(name)
		}
	}
	if bestIdx < 0 {
		return 0, false
	}
	sc.pos += bestLen
	return bestIdx, true
}

// apkCompare runs the token-by-token comparison.
func apkCompare(a, b string) int {
	sa := newAPKScanner(a)
	sb := newAPKScanner(b)

	for {
		ta, oka := sa.next()
		tb, okb := sb.next()
		if !oka || !okb {
			return 0 // validity was checked up front; defensive.
		}

		if ta.typ != tb.typ {
			return apkCompareDiffTypes(ta, tb)
		}

		switch ta.typ {
		case apkTokEnd:
			return 0
		case apkTokDigitOrZero:
			if c := apkCompareFraction(ta.digits, tb.digits); c != 0 {
				return c
			}
		default:
			if ta.value != tb.value {
				return sign(ta.value - tb.value)
			}
		}
	}
}

// apkCompareDiffTypes resolves a comparison where the two scanners produced
// different token types, implementing apk's pre/post-release handling.
func apkCompareDiffTypes(ta, tb apkToken) int {
	// A SUFFIX on exactly one side: pre-release suffix => that side is OLDER,
	// post-release suffix => that side is NEWER. This is what makes
	// "1.0_alpha1" < "1.0" < "1.0_p1".
	if ta.typ == apkTokSuffix && tb.typ != apkTokSuffix {
		if ta.value < apkPreReleaseCount {
			return -1
		}
		return 1
	}
	if tb.typ == apkTokSuffix && ta.typ != apkTokSuffix {
		if tb.value < apkPreReleaseCount {
			return 1
		}
		return -1
	}
	// Otherwise: lower enum rank sorts first. END (0) is the lowest, so a
	// shorter version (one that has ended) is OLDER than one that continues
	// with a DIGIT/LETTER/SUFFIX_NO/REVISION token. This yields
	// "1.2" < "1.2.0" and "1.36.1-r0" < "1.36.1-r5" via REVISION value compare.
	return sign(ta.typ - tb.typ)
}

// apkCompareFraction compares two digit runs as decimal fractions: right-pad
// the shorter with '0' and compare lexically (i.e. as 0.<a> vs 0.<b>).
func apkCompareFraction(a, b string) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var ca, cb byte = '0', '0'
		if i < len(a) {
			ca = a[i]
		}
		if i < len(b) {
			cb = b[i]
		}
		if ca != cb {
			return sign(int(ca) - int(cb))
		}
	}
	return 0
}

// apkValid reports whether a version string parses cleanly under apk rules.
func apkValid(s string) bool {
	sc := newAPKScanner(s)
	for {
		t, ok := sc.next()
		if !ok {
			return false
		}
		if t.typ == apkTokEnd {
			return true
		}
	}
}

func isLowerAlpha(c byte) bool { return c >= 'a' && c <= 'z' }

func atoiSimple(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}
