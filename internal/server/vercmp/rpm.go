package vercmp

// This file implements RPM's version comparison, mirroring the reference
// rpmvercmp() in rpm's lib/rpmvercmp.c plus the EVR (epoch:version-release)
// ordering layered on top of it. The goal is byte-for-byte behavioral parity
// with rpm, including the digit>alpha rule, tilde (~) "older" handling, caret
// (^) "post-release" handling, and leading-zero stripping for numeric runs.

// compareRPM orders two RPM version strings (EVR) and returns -1, 0, 1 for
// a<b, a==b, a>b. ok is false only when input is empty.
func compareRPM(a, b string) (int, bool) {
	if a == "" || b == "" {
		return 0, false
	}

	ea, va, ra := splitEVR(a)
	eb, vb, rb := splitEVR(b)

	// 1. Epoch is compared numerically (a missing epoch is 0).
	if c := rpmvercmp(ea, eb); c != 0 {
		return c, true
	}
	// 2. Then the version segment via rpmvercmp.
	if c := rpmvercmp(va, vb); c != 0 {
		return c, true
	}
	// 3. Then the release segment via rpmvercmp. An absent release sorts as the
	//    empty string, which rpmvercmp treats as equal-or-lesser as appropriate.
	if c := rpmvercmp(ra, rb); c != 0 {
		return c, true
	}
	return 0, true
}

// splitEVR decomposes an RPM version string into epoch, version, and release.
// Format: [epoch:]version[-release]. Epoch defaults to "0". The epoch is split
// at the FIRST ':' and the release at the LAST '-'.
func splitEVR(s string) (epoch, version, release string) {
	epoch = "0"
	if i := indexByte(s, ':'); i >= 0 {
		// rpm only treats the leading numeric run before ':' as an epoch; in
		// practice rpm strings are well-formed so we take the prefix verbatim.
		epoch = s[:i]
		if epoch == "" {
			epoch = "0"
		}
		s = s[i+1:]
	}
	if i := lastIndexByte(s, '-'); i >= 0 {
		release = s[i+1:]
		version = s[:i]
	} else {
		version = s
	}
	return epoch, version, release
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }

// rpmvercmp is a faithful port of rpm's lib/rpmvercmp.c. It returns -1, 0, 1.
func rpmvercmp(a, b string) int {
	// Easy comparison to see if versions are identical.
	if a == b {
		return 0
	}

	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// Skip all non-alphanumeric, non-tilde, non-caret separators.
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}

		// Handle the tilde separator: it sorts BEFORE everything, including the
		// empty string, so "1.0~rc1" < "1.0".
		aTilde := i < len(a) && a[i] == '~'
		bTilde := j < len(b) && b[j] == '~'
		if aTilde || bTilde {
			if !aTilde {
				return 1
			}
			if !bTilde {
				return -1
			}
			i++
			j++
			continue
		}

		// Handle the caret separator (post-release). This is a faithful port of
		// rpm's lib/rpmvercmp.c caret branch:
		//
		//	if (*one == '^' || *two == '^') {
		//	    if (!*one) return -1;        // a exhausted: a is OLDER
		//	    if (!*two) return 1;         // b exhausted: a is NEWER
		//	    if (*one != '^') return 1;   // only b at '^': a is NEWER
		//	    if (*two != '^') return -1;  // only a at '^': a is OLDER
		//	    one++; two++; continue;      // both at '^': skip and continue
		//	}
		//
		// The order of the checks matters: the string-exhaustion tests come
		// FIRST. So "1.0" < "1.0^git1" (b's '^' beats a's end), but
		// "1.0^git1" < "1.0.1" (a's '^' is older than b's ordinary "1"). A
		// caret is therefore newer than the bare version but older than any
		// ordinary following segment on the other side.
		aCaret := i < len(a) && a[i] == '^'
		bCaret := j < len(b) && b[j] == '^'
		if aCaret || bCaret {
			if i >= len(a) {
				return -1
			}
			if j >= len(b) {
				return 1
			}
			if !aCaret {
				return 1
			}
			if !bCaret {
				return -1
			}
			i++
			j++
			continue
		}

		// If we ran to the end of either string, we are finished.
		if i >= len(a) || j >= len(b) {
			break
		}

		// Grab the next run of digits or letters from each string. The two runs
		// must be of the same type to be compared as such; a digit run always
		// beats an alpha run.
		isNum := isDigit(a[i])
		startA, startB := i, j
		if isNum {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
		}

		segA := a[startA:i]
		segB := b[startB:j]

		// Different segment types: b's run is empty because b's current char is
		// of the other type. Numeric segments are always newer than alpha ones,
		// so an empty b-run means a is newer if a is numeric, older if alpha.
		// (Mirrors rpm's `if (two == str2) return (isnum ? 1 : -1);`.)
		if len(segB) == 0 {
			if isNum {
				return 1
			}
			return -1
		}

		if isNum {
			// Strip leading zeros from each run.
			segA = stripLeadingZeros(segA)
			segB = stripLeadingZeros(segB)
			// The longer run (after stripping) is greater.
			if len(segA) > len(segB) {
				return 1
			}
			if len(segB) > len(segA) {
				return -1
			}
			// Same length: plain strcmp gives the right answer.
			if c := strcmp(segA, segB); c != 0 {
				return c
			}
		} else {
			// Both runs are alpha here; compare them with strcmp.
			if c := strcmp(segA, segB); c != 0 {
				return c
			}
		}
	}

	// Both strings ran out of segments simultaneously: equal. Otherwise the one
	// with remaining segments is newer.
	if i >= len(a) && j >= len(b) {
		return 0
	}
	if i < len(a) {
		return 1
	}
	return -1
}

func stripLeadingZeros(s string) string {
	k := 0
	for k < len(s) && s[k] == '0' {
		k++
	}
	return s[k:]
}

// strcmp returns -1, 0, 1 like C's strcmp, comparing bytes.
func strcmp(a, b string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}
