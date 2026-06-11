package vercmp

import "testing"

func TestCompareAlpine(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		// -rN package revision: compared numerically, only after the rest is equal.
		{"1.36.1-r0", "1.36.1-r5", -1},
		{"1.36.1-r5", "1.36.1-r5", 0},
		{"1.36.1-r5", "1.36.1-r0", 1},
		{"1.36.1-r0", "1.36.1-r10", -1}, // numeric, not lexical

		// Pre-release suffixes are OLDER than the bare version; "p" is NEWER.
		{"1.0_alpha1", "1.0", -1},
		{"1.0_beta1", "1.0", -1},
		{"1.0_pre1", "1.0", -1},
		{"1.0_rc1", "1.0", -1},
		{"1.0", "1.0_p1", -1},
		{"1.0_p1", "1.0", 1},

		// Suffix ordering: alpha < beta < pre < rc < (release) < cvs < git < p.
		{"1.0_alpha1", "1.0_alpha2", -1},
		{"1.0_alpha2", "1.0_beta1", -1},
		{"1.0_alpha1", "1.0_beta1", -1},
		{"1.0_beta1", "1.0_pre1", -1},
		{"1.0_pre1", "1.0_rc1", -1},
		{"1.0_cvs1", "1.0_svn1", -1},
		{"1.0_svn1", "1.0_git1", -1},
		{"1.0_git1", "1.0_hg1", -1},
		{"1.0_hg1", "1.0_p1", -1},
		{"1.0_rc1", "1.0_cvs1", -1}, // pre-release < post-release across the bare point

		// Suffix number compared numerically.
		{"1.0_alpha10", "1.0_alpha9", 1},
		{"1.0_p2", "1.0_p10", -1},

		// Plain numeric components.
		{"1.2.3", "1.2.4", -1},
		{"1.2.4", "1.2.3", 1},
		{"2.4.4-r0", "2.4.5-r0", -1},
		{"1.37.0-r0", "1.36.1-r99", 1},
		{"1.36.1-r99", "1.37.0-r0", -1},

		// Extra trailing component: "1.2" < "1.2.0". apk treats the side that
		// continues with another numeric group as newer (END < DIGIT).
		{"1.2", "1.2.0", -1},
		{"1.2.0", "1.2", 1},

		// Leading-zero fractional comparison: "1.05" < "1.5".
		{"1.05", "1.5", -1},
		{"1.5", "1.05", 1},

		// Single-letter suffix: "1.0a" sorts after "1.0".
		{"1.0a", "1.0", 1},
		{"1.0", "1.0a", -1},
		{"1.0a", "1.0b", -1},
		{"1.0a", "1.0a", 0},

		// A single-letter suffix is older than a "-r" revision continuation.
		{"1.0a", "1.0-r1", -1},

		// Equality.
		{"1.0", "1.0", 0},
		{"2.4_p20230101-r0", "2.4_p20230101-r0", 0},
		{"2.4_p20230101-r0", "2.4_p20230102-r0", -1},
		{"1.0_alpha1-r2", "1.0_alpha1-r3", -1},
		{"3.2.4-r0", "3.2.4-r0", 0},

		// More real-world Alpine versions.
		{"1.1.1q-r0", "1.1.1r-r0", -1}, // openssl letter releases
		{"1.1.1w-r1", "3.0.0-r0", -1},
	}

	for _, tt := range tests {
		got, ok := compareAlpine(tt.a, tt.b)
		if !ok {
			t.Errorf("compareAlpine(%q,%q): ok=false, want parseable", tt.a, tt.b)
			continue
		}
		if got != tt.want {
			t.Errorf("compareAlpine(%q,%q)=%d, want %d", tt.a, tt.b, got, tt.want)
		}
		// Antisymmetry: comparing the reverse should negate.
		rev, okr := compareAlpine(tt.b, tt.a)
		if okr && rev != -tt.want {
			t.Errorf("antisymmetry: compareAlpine(%q,%q)=%d, want %d", tt.b, tt.a, rev, -tt.want)
		}
	}
}

func TestCompareAlpineInvalid(t *testing.T) {
	for _, in := range []string{"", "   "} {
		if _, ok := compareAlpine(in, "1.0"); ok {
			t.Errorf("compareAlpine(%q,...): ok=true, want false for empty input", in)
		}
	}
}

func TestCompareAlpineParseable(t *testing.T) {
	for _, v := range []string{
		"1.36.1-r5", "2.4_p20230101-r0", "1.0_alpha1-r2", "3.2.4-r0",
		"1.0a", "1.05", "0.1", "1",
	} {
		if _, ok := compareAlpine(v, v); !ok {
			t.Errorf("compareAlpine(%q,%q): ok=false, want parseable", v, v)
		}
	}
}
