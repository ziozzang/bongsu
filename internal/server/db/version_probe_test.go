package db

import "testing"

// TestCompareVersionsEpochLossTolerance covers the db-layer policy that sits on
// top of the vercmp per-ecosystem comparators: when the installed version (a)
// carries no distro epoch but the advisory version (b) does, b's epoch is
// stripped before comparing so an administrative epoch bump can't make a
// clearly-newer upstream look older. Pure per-ecosystem ordering is covered by
// the vercmp package tests; this asserts the false-positive-reduction policy.
func TestCompareVersionsEpochLossTolerance(t *testing.T) {
	cases := []struct {
		eco, a, b string
		want      int // sign of compareVersions
	}{
		// Installed has no epoch, advisory does → ignore advisory epoch.
		{"debian", "9.1.1230", "2:9.0.0135-1", 1},  // vim: newer upstream → not affected
		{"rhel", "6.9.11.60", "8:6.9.9.34", 1},     // imagemagick: newer upstream
		{"debian", "9.0.0100", "2:9.0.0135-1", -1}, // genuinely older upstream → still affected
		{"debian", "2.3.4-1", "1:2.3.4-1", 0},      // same upstream → equal
		// Installed carries its own epoch → epochs are honored normally.
		{"debian", "2:1.0", "1:9.9", 1},
		{"debian", "1:1.0", "2:1.0", -1},
	}
	for _, c := range cases {
		got, ok := compareVersions(c.eco, c.a, c.b)
		sign := 0
		if got < 0 {
			sign = -1
		} else if got > 0 {
			sign = 1
		}
		if !ok || sign != c.want {
			t.Errorf("compareVersions(%q, %q, %q) = (%d sign=%d, ok=%v), want sign=%d",
				c.eco, c.a, c.b, got, sign, ok, c.want)
		}
	}
}
