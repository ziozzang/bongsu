package vercmp

import "testing"

func TestRPMCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// Identity / basic equality.
		{"1.0", "1.0", 0},
		{"1", "1", 0},
		{"", "", 0}, // handled by ok=false path, but rpmvercmp("","")==0

		// Basic ordering.
		{"1.0", "1.1", -1},
		{"1.1", "1.0", 1},
		{"1.0", "1.0.1", -1},
		{"1.0.1", "1.0", 1},
		{"2", "10", -1},
		{"1.9", "1.10", -1},

		// Tilde: pre-release, OLDER than the base.
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0~rc1", 1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0~rc2", "1.0~rc1", 1},
		{"1.0~rc1", "1.0~rc1", 0},
		{"1.0~~", "1.0~", -1},

		// Caret: post-release, NEWER than the base.
		{"1.0", "1.0^20240101", -1},
		{"1.0^20240101", "1.0", 1},
		{"1.0^", "1.0", 1},
		{"1.0", "1.0^", -1},
		{"1.0^a", "1.0^a", 0},
		{"1.0^a", "1.0^b", -1},
		// Caret is NEWER than the bare version but OLDER than any ordinary
		// following segment on the other side (rpmvercmp.c caret semantics:
		// 1.0 < 1.0^git1 < 1.0.1).
		{"1.0", "1.0^git1", -1},
		{"1.0^git1", "1.0", 1},
		{"1.0^git1", "1.0.1", -1},
		{"1.0.1", "1.0^git1", 1},
		{"1.0^git1", "1.0^git2", -1},
		{"1.0^git2", "1.0^git1", 1},
		{"1.0^git1.1", "1.0^git1", 1},
		{"1.0^git1", "1.0^git1.1", -1},

		// digit > alpha: numeric segment beats alpha segment.
		// "1.0a" -> [1][0][a]; "1.0.1" -> [1][0][1]; compare 'a' vs '1' => 1 wins.
		{"1.0a", "1.0.1", -1},
		{"1.0.1", "1.0a", 1},
		{"1a", "1", 1}, // a has extra segment, so newer
		{"1", "1a", -1},
		{"1.a", "1.1", -1}, // alpha 'a' vs digit '1' => digit newer
		{"1.1", "1.a", 1},

		// Release / dist comparisons.
		{"1.1.1k-7.el8", "1.1.1k-14.el8_6", -1},
		{"1.1.1k-14.el8_6", "1.1.1k-7.el8", 1},
		{"2.34-83.el9", "2.34-83.el9_3", -1},
		{"2.34-83.el9_3", "2.34-83.el9", 1},
		{"1.0-1", "1.0-2", -1},

		// Epoch comparisons.
		{"1:1.0", "0.9", 1},
		{"0.9", "1:1.0", -1},
		{"2:1.0", "1:9.9", 1},
		{"1:9.9", "2:1.0", -1},
		{"1:1.0", "1:1.0", 0},
		{"0:1.0", "1.0", 0}, // explicit 0 epoch == missing epoch

		// Leading zeros: numeric runs strip leading zeros.
		{"1.01", "1.1", 0},
		{"1.1", "1.01", 0},
		{"1.007", "1.7", 0},
		{"1.010", "1.10", 0},

		// Mixed real-world-ish cases.
		{"1.0.0", "1.0.0", 0},
		{"3.0.0-1.el8", "3.0.0-1.el8", 0},
		{"5.14.0-427.el9", "5.14.0-503.el9", -1},
	}

	for _, c := range cases {
		got, ok := compareRPM(c.a, c.b)
		if c.a == "" || c.b == "" {
			if ok {
				t.Errorf("compareRPM(%q, %q): expected ok=false for empty input", c.a, c.b)
			}
			continue
		}
		if !ok {
			t.Errorf("compareRPM(%q, %q): expected ok=true", c.a, c.b)
			continue
		}
		if got != c.want {
			t.Errorf("compareRPM(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// TestRPMAntisymmetry checks that swapping arguments negates the result, a core
// property of a correct comparator.
func TestRPMAntisymmetry(t *testing.T) {
	vals := []string{
		"1.0", "1.1", "1.0.1", "1.0~rc1", "1.0^20240101",
		"1.0^git1", "1.0^git2", "1.0^git1.1",
		"1:1.0", "2.34-83.el9", "2.34-83.el9_3", "1.01", "1.0a",
	}
	for _, a := range vals {
		for _, b := range vals {
			x, okx := compareRPM(a, b)
			y, oky := compareRPM(b, a)
			if !okx || !oky {
				t.Fatalf("unexpected ok=false for %q/%q", a, b)
			}
			if x != -y {
				t.Errorf("antisymmetry violated: cmp(%q,%q)=%d cmp(%q,%q)=%d", a, b, x, b, a, y)
			}
		}
	}
}

func TestRPMEmpty(t *testing.T) {
	if _, ok := compareRPM("", "1.0"); ok {
		t.Error("empty a should give ok=false")
	}
	if _, ok := compareRPM("1.0", ""); ok {
		t.Error("empty b should give ok=false")
	}
}
