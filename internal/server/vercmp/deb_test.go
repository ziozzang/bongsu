package vercmp

import "testing"

func TestCompareDebian(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		// Equality.
		{"1.2.3-1", "1.2.3-1", 0},
		{"0", "0", 0},
		{"1:2.3-4", "1:2.3-4", 0},
		{"1.0", "1.0", 0},

		// Tilde: sorts before everything, including empty/end-of-string.
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0~rc1", 1},
		{"1.0~~", "1.0~", -1},
		{"1.0~", "1.0", -1},
		{"1.0~~", "1.0", -1},
		{"1.0~beta", "1.0~rc1", -1}, // 'b' < 'r'
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0~rc2", "1.0~rc10", -1}, // numeric: 2 < 10

		// Digit vs non-digit: a non-empty letter run sorts after end-of-string,
		// so "1.0a" > "1.0".
		{"1.0", "1.0a", -1},
		{"1.0a", "1.0", 1},

		// Letters sort before non-letter symbols (e.g. '+').
		// "1.0a" < "1.0+" because 'a' (letter) < '+' (other).
		{"1.0a", "1.0+", -1},

		// Epoch compared numerically first; a bigger epoch always wins.
		{"2.3.4-1", "1:2.3.4-1", -1},
		{"1:2.3.4-1", "2.3.4-1", 1},
		{"1:1.0", "2:0.1", -1},
		{"2:0.1", "1:1.0", 1},
		{"1:1.0", "1.0", 1}, // epoch 1 > implicit epoch 0
		// Equal epoch (explicit vs implicit zero).
		{"0:1.0", "1.0", 0},

		// Debian revisions.
		{"1.2.3-1", "1.2.3-2", -1},
		{"1.2.3-2", "1.2.3-1", 1},
		{"1.2.3-1", "1.2.3-10", -1},
		// +debNuM lives in the revision string and compares greater than a bare
		// revision because the run "+deb12u1" extends past end-of-string.
		{"1.2.3-1+deb12u1", "1.2.3-1", 1},
		{"1.2.3-1", "1.2.3-1+deb12u1", -1},
		{"1.2.3-1+deb12u1", "1.2.3-1+deb12u2", -1},

		// Ubuntu-style revisions.
		{"3.0.13-0ubuntu3.5", "3.0.13-0ubuntu3.6", -1},
		{"3.0.13-0ubuntu3.6", "3.0.13-0ubuntu3.5", 1},
		{"3.0.13-0ubuntu3.5", "3.0.13-0ubuntu3.5", 0},

		// Missing revision is treated as "0".
		{"1.0", "1.0-0", 0},
		{"1.0-1", "1.0", 1},
		{"1.0", "1.0-1", -1},

		// Leading zeros in numeric runs are ignored.
		{"1.01", "1.1", 0},
		{"1.007", "1.7", 0},
		{"1.0", "1.00", 0},

		// Multi-component numeric comparisons.
		{"2.6.32", "2.6.9", 1},
		{"1.10", "1.9", 1},

		// Upstream comparisons with mixed alpha/numeric.
		{"1.0a", "1.0b", -1},
		{"1.0b", "1.0a", 1},
		{"1.2.3", "1.2.3.1", -1},

		// Real-world: openssl-style.
		{"1.1.1n-0+deb11u3", "1.1.1n-0+deb11u4", -1},
		{"1.1.1n-0+deb10u3", "1.1.1n-0+deb11u3", -1},
	}

	for _, tt := range tests {
		got, ok := compareDebian(tt.a, tt.b)
		if !ok {
			t.Errorf("compareDebian(%q, %q): ok=false, want true", tt.a, tt.b)
			continue
		}
		if got != tt.want {
			t.Errorf("compareDebian(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		// Verify antisymmetry: comparing in reverse must negate the result.
		rev, okRev := compareDebian(tt.b, tt.a)
		if !okRev || rev != -tt.want {
			t.Errorf("compareDebian(%q, %q) = %d (ok=%v), want %d (antisymmetry)", tt.b, tt.a, rev, okRev, -tt.want)
		}
	}
}

func TestCompareDebianEmpty(t *testing.T) {
	if _, ok := compareDebian("", "1.0"); ok {
		t.Errorf("compareDebian(\"\", ...): ok=true, want false for empty input")
	}
	if _, ok := compareDebian("1.0", ""); ok {
		t.Errorf("compareDebian(..., \"\"): ok=true, want false for empty input")
	}
}
