package vercmp

import "strconv"

// compareDebian compares two version strings using Debian's dpkg algorithm
// (as defined by deb-version(5) and dpkg's verrevcmp). It returns -1, 0, 1 for
// a<b, a==b, a>b, and ok=false only for genuinely empty input.
//
// Debian version ordering is a total order, so for any non-empty pair of
// version strings ok is true.
//
// A version has the form [epoch:]upstream_version[-debian_revision]:
//   - epoch is an optional unsigned integer before the first ':'; absent => 0.
//   - debian_revision is the part after the LAST '-'; absent => "0".
//   - upstream_version is everything in between.
//
// The epoch is compared numerically, then upstream_version and debian_revision
// are each compared with verrevcmp.
func compareDebian(a, b string) (int, bool) {
	if a == "" || b == "" {
		return 0, false
	}

	ea, ua, ra := splitDebianVersion(a)
	eb, ub, rb := splitDebianVersion(b)

	if ea != eb {
		if ea < eb {
			return -1, true
		}
		return 1, true
	}

	if c := verrevcmp(ua, ub); c != 0 {
		return c, true
	}

	return verrevcmp(ra, rb), true
}

// splitDebianVersion parses a Debian version into (epoch, upstream, revision).
// A missing epoch is 0 and a missing debian_revision is treated as "0", matching
// dpkg's parse_version behavior.
func splitDebianVersion(v string) (epoch int, upstream, revision string) {
	// Epoch: digits before the first ':'.
	if i := indexByte(v, ':'); i >= 0 {
		if e, err := strconv.Atoi(v[:i]); err == nil {
			epoch = e
			v = v[i+1:]
		}
	}

	// Debian revision: everything after the LAST '-'.
	if i := lastIndexByte(v, '-'); i >= 0 {
		upstream = v[:i]
		revision = v[i+1:]
	} else {
		upstream = v
		revision = "0"
	}
	return epoch, upstream, revision
}

// verrevcmp implements dpkg's verrevcmp string comparison. It walks both
// strings comparing alternating non-digit and digit runs.
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// Compare a run of non-digit characters lexically, using the special
		// Debian ordering (see debianOrder).
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			var ca, cb int
			if i < len(a) && !isDigit(a[i]) {
				ca = debianOrder(a[i])
			} else {
				ca = debianOrder(0) // end-of-string / digit boundary
			}
			if j < len(b) && !isDigit(b[j]) {
				cb = debianOrder(b[j])
			} else {
				cb = debianOrder(0)
			}
			if ca != cb {
				return sign(ca - cb)
			}
			i++
			j++
		}

		// Skip leading zeros in both digit runs.
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}

		// Compare digit runs numerically. The longer run of (non-zero-leading)
		// digits is the larger number; equal length compares digit by digit.
		firstDiff := 0
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

// debianOrder returns the sort weight of a non-digit character under dpkg's
// rules: '~' sorts before everything (including end-of-string), then end-of-
// string (0), then letters in ASCII order, then all other characters offset
// above the letters so they sort after them.
func debianOrder(c byte) int {
	switch {
	case c == '~':
		return -1
	case c == 0:
		return 0
	case isAlpha(c):
		return int(c)
	default:
		return int(c) + 256
	}
}

// isDigit, isAlpha, indexByte and lastIndexByte are shared helpers defined in
// rpm.go within this package.

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}
