package db

import "testing"

// TestCompareVersionsRealWorldDistroStrings probes the comparator against
// real-world distro version strings. Each row asserts the sign of
// compareVersions(a, b). want: -1 (a<b), 0 (a==b), 1 (a>b). ok must be true —
// a false ok means the comparator gave up, which causes silent missed matches.
func TestCompareVersionsRealWorldDistroStrings(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		// Debian epoch: an installed version that carries the epoch is ordered
		// by it; an installed version WITHOUT an epoch ignores the advisory's
		// epoch (epoch-loss tolerance) and compares upstream, so same-upstream
		// compares equal.
		{"1:2.3.4-1", "2.3.4-1", 1, true},
		{"2.3.4-1", "1:2.3.4-1", 0, true},
		// Debian revisions
		{"1.2.3-1", "1.2.3-2", -1, true},
		{"1.2.3-1", "1.2.3-1", 0, true},
		// Debian/Ubuntu backport suffix ordering
		{"3.0.13-0ubuntu3.5", "3.0.13-0ubuntu3.6", -1, true},
		{"3.0.13-0ubuntu3.6", "3.0.13-0ubuntu3.6", 0, true},
		// Debian tilde pre-release: 1.0~rc1 < 1.0
		{"1.0~rc1", "1.0", -1, true},
		{"1.0", "1.0~rc1", 1, true},
		// +debNuM backport markers compare as upstream-equal-ish
		{"1.0-1", "1.0-1+deb12u1", -1, true},
		// RPM release/dist tag
		{"1.1.1k-7.el8", "1.1.1k-14.el8_6", -1, true},
		{"2.34-83.el9", "2.34-83.el9_3", -1, true},
		// Alpine -r revisions
		{"1.36.1-r0", "1.36.1-r5", -1, true},
		{"1.36.1-r5", "1.36.1-r5", 0, true},
		// semver
		{"4.17.20", "4.17.21", -1, true},
		{"4.17.21", "4.17.21", 0, true},
		// semver pre-release
		{"1.0.0-alpha", "1.0.0", -1, true},
		{"1.0.0-rc.1", "1.0.0", -1, true},
		// numeric ordering, multi-digit
		{"1.9", "1.10", -1, true},
		// Epoch-loss false positives: when the installed version was collected
		// WITHOUT the distro epoch (common with image/container scanners), a
		// clearly-newer upstream must not be declared older just because the
		// fixed version carries an administrative epoch bump.
		{"9.1.1230", "2:9.0.0135-1", 1, true},            // vim: installed upstream newer → not affected
		{"6.9.11.60+dfsg", "8:6.9.9.34+dfsg-3", 1, true}, // imagemagick: newer upstream
		{"9.0.0100", "2:9.0.0135-1", -1, true},           // genuinely older upstream → still affected
		// When installed DOES carry an epoch, trust both epochs normally.
		{"1:1.0", "2:1.0", -1, true},
		{"2:1.0", "1:9.9", 1, true},
	}
	for _, c := range cases {
		got, ok := compareVersions(c.a, c.b)
		sign := 0
		if got < 0 {
			sign = -1
		} else if got > 0 {
			sign = 1
		}
		if ok != c.ok || sign != c.want {
			t.Errorf("compareVersions(%q, %q) = (%d sign=%d, ok=%v), want (sign=%d, ok=%v)",
				c.a, c.b, got, sign, ok, c.want, c.ok)
		}
	}
}
