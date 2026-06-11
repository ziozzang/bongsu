package vercmp

import "testing"

// TestGenericCompare exercises compareGeneric directly across the version shapes
// of the language ecosystems (npm, PyPI, Go modules, crates.io, Maven, RubyGems,
// NuGet).
func TestGenericCompare(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want int
		ok   bool
	}{
		// Basic equality and normalization.
		{"equal", "1.2.3", "1.2.3", 0, true},
		{"leading v", "v1.2.3", "1.2.3", 0, true},
		{"both leading v", "v1.2.3", "v1.2.3", 0, true},
		{"zero pad", "1.2", "1.2.0", 0, true},
		{"zero pad reverse", "1.2.0", "1.2", 0, true},
		{"deeper zero pad", "1.2.0.0", "1.2", 0, true},

		// Numeric release ordering.
		{"patch less", "4.17.20", "4.17.21", -1, true},
		{"patch greater", "4.17.21", "4.17.20", 1, true},
		{"numeric not lexical", "1.9.0", "1.10.0", -1, true},
		{"major", "2.0.0", "1.99.99", 1, true},
		{"minor", "1.2.0", "1.1.9", 1, true},

		// Semver pre-release ordering.
		{"prerelease lt release", "1.0.0-alpha", "1.0.0", -1, true},
		{"release gt prerelease", "1.0.0", "1.0.0-alpha", 1, true},
		{"alpha lt alpha.1", "1.0.0-alpha", "1.0.0-alpha.1", -1, true},
		{"alpha.1 lt beta", "1.0.0-alpha.1", "1.0.0-beta", -1, true},
		{"beta lt rc.1", "1.0.0-beta", "1.0.0-rc.1", -1, true},
		{"rc.1 lt release", "1.0.0-rc.1", "1.0.0", -1, true},
		{"numeric pre lt alnum pre", "1.0.0-1", "1.0.0-alpha", -1, true},
		{"pre fewer ids", "1.0.0-rc", "1.0.0-rc.1", -1, true},
		{"pre numeric ids", "1.0.0-rc.2", "1.0.0-rc.10", -1, true},

		// PEP 440 pre-releases attached without a dash.
		{"a1 lt b1", "1.2.3a1", "1.2.3b1", -1, true},
		{"b1 lt rc1", "1.2.3b1", "1.2.3rc1", -1, true},
		{"rc1 lt release", "1.2.3rc1", "1.2.3", -1, true},
		{"dev1 lt a1", "1.2.3.dev1", "1.2.3a1", -1, true},
		{"a1 lt a2", "1.2.3a1", "1.2.3a2", -1, true},
		{"alpha equals a", "1.2.3alpha1", "1.2.3a1", 0, true},
		{"beta equals b", "1.2.3beta2", "1.2.3b2", 0, true},
		{"pep dev lt release", "1.2.3.dev1", "1.2.3", -1, true},
		{"post gt release", "1.2.3.post1", "1.2.3", 1, true},

		// Very long numeric segments must not overflow integer parsing; they
		// are compared as digit strings, so ordering stays correct and ok=true.
		{"30-digit release lt", "1.123456789012345678901234567890", "1.123456789012345678901234567891", -1, true},
		{"30-digit release gt", "1.123456789012345678901234567891", "1.123456789012345678901234567890", 1, true},
		{"30-digit release eq", "1.123456789012345678901234567890", "1.123456789012345678901234567890", 0, true},
		{"30-digit pre id", "1.0.0-rc.123456789012345678901234567890", "1.0.0-rc.123456789012345678901234567891", -1, true},

		// Build metadata ignored.
		{"build ignored vs plain", "1.0.0+build1", "1.0.0", 0, true},
		{"build differs", "1.0.0+build1", "1.0.0+build2", 0, true},
		{"build with pre", "1.0.0-rc.1+build1", "1.0.0-rc.1", 0, true},

		// Go pseudo-versions: order by the 0.0.0 base + timestamp pre-release.
		{"go pseudo lt tag", "v0.0.0-20230101000000-abcdef012345", "v0.1.0", -1, true},
		{"go pseudo timestamps", "v0.0.0-20230101000000-abcdef012345", "v0.0.0-20240101000000-abcdef012345", -1, true},

		// Maven-ish qualifiers.
		{"maven RC vs release", "1.0.0-RC1", "1.0.0", -1, true},

		// Cannot order: git sha / branch name on one side.
		{"git sha vs version", "abcdef0123456789abcdef0123456789abcdef01", "1.2.3", 0, false},
		{"version vs git sha", "1.2.3", "abcdef0123456789abcdef0123456789abcdef01", 0, false},
		{"branch name", "main", "1.2.3", 0, false},
		{"both non numeric", "feature-x", "develop", 0, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := compareGeneric(tc.a, tc.b)
			if ok != tc.ok {
				t.Fatalf("compareGeneric(%q, %q) ok = %v, want %v (got=%d)", tc.a, tc.b, ok, tc.ok, got)
			}
			if !tc.ok {
				return // value is meaningless when ok is false
			}
			if got != tc.want {
				t.Fatalf("compareGeneric(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
			// Anti-symmetry check for orderable pairs.
			rev, revOk := compareGeneric(tc.b, tc.a)
			if !revOk || rev != -tc.want {
				t.Fatalf("compareGeneric(%q, %q) = %d (ok=%v), want %d (anti-symmetry)", tc.b, tc.a, rev, revOk, -tc.want)
			}
		})
	}
}

// TestGenericTransitiveChain verifies the documented pre-release chain orders
// strictly increasing end to end.
func TestGenericTransitiveChain(t *testing.T) {
	chain := []string{
		"1.0.0-alpha",
		"1.0.0-alpha.1",
		"1.0.0-beta",
		"1.0.0-rc.1",
		"1.0.0",
	}
	for i := 0; i+1 < len(chain); i++ {
		got, ok := compareGeneric(chain[i], chain[i+1])
		if !ok || got != -1 {
			t.Fatalf("compareGeneric(%q, %q) = %d (ok=%v), want -1", chain[i], chain[i+1], got, ok)
		}
	}
}
