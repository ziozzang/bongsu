package vercmp

import "testing"

// Canonical cases taken from RPM's own tests/rpmvercmp.at — the authoritative
// rpmvercmp behaviour. A failure here means compareRPM diverges from real rpm.
func TestRPMCanonicalVectors(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "2.0", -1},
		{"2.0", "1.0", 1},
		{"2.0.1", "2.0.1", 0},
		{"2.0", "2.0.1", -1},
		{"2.0.1", "2.0", 1},
		{"1.0", "1.0a", -1},
		{"1.0a", "1.0", 1},
		{"5.5p1", "5.5p1", 0},
		{"5.5p1", "5.5p2", -1},
		{"10xyz", "10.1xyz", -1},
		{"xyz10", "xyz10.1", -1},
		{"2_0", "2.0", 0}, // '_' and '.' are both separators
		// tilde — always older
		{"1.0~rc1", "1.0~rc1", 0},
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0~rc1", 1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0~rc1~git123", "1.0~rc1", -1},
		// caret — always newer
		{"1.0^", "1.0^", 0},
		{"1.0^", "1.0", 1},
		{"1.0", "1.0^", -1},
		{"1.0^git1", "1.0^git1", 0},
		{"1.0^git1", "1.0", 1},
		{"1.0", "1.0^git1", -1},
		{"1.0^git1", "1.0^git2", -1},
		{"1.0~rc1^git1", "1.0~rc1", 1},
		{"1.0~rc1", "1.0~rc1^git1", -1},
		{"1.0^git1~pre", "1.0^git1", -1},
		{"1.0^git1", "1.0^git1~pre", 1},
	}
	for _, c := range cases {
		got, ok := compareRPM(c.a, c.b)
		if !ok {
			t.Errorf("compareRPM(%q,%q): ok=false, want comparable", c.a, c.b)
			continue
		}
		if sign3(got) != c.want {
			t.Errorf("compareRPM(%q,%q) = %d, want %d (rpmvercmp canonical)", c.a, c.b, got, c.want)
		}
	}
}

// Canonical dpkg cases from deb-version(7): tilde sorts before everything, epoch
// dominates, leading zeros in numeric parts are equal, more upstream segments win.
func TestDebianCanonicalVectors(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0~rc1", 1},
		{"1.0~~", "1.0~", -1},
		{"1.0~", "1.0", -1},
		{"1:1.0", "2.0", 1},   // epoch 1 > epoch 0 regardless of upstream
		{"2.0", "1:1.0", -1},
		{"1.05", "1.5", 0},    // leading zero in numeric part is irrelevant
		{"1.0", "1.0.0", -1},  // more upstream segments are newer
		{"1.0.0", "1.0", 1},
		{"1.0-1", "1.0-2", -1}, // debian revision
	}
	for _, c := range cases {
		got, ok := compareDebian(c.a, c.b)
		if !ok {
			t.Errorf("compareDebian(%q,%q): ok=false, want comparable", c.a, c.b)
			continue
		}
		if sign3(got) != c.want {
			t.Errorf("compareDebian(%q,%q) = %d, want %d (deb-version canonical)", c.a, c.b, got, c.want)
		}
	}
}

// apk suffix order (Alpine APKBUILD reference):
// alpha < beta < pre < rc < (none) < cvs < svn < git < hg < p, plus -r revisions.
func TestApkCanonicalOrdering(t *testing.T) {
	chain := []string{
		"1.0_alpha", "1.0_beta", "1.0_pre", "1.0_rc",
		"1.0",
		"1.0_cvs", "1.0_svn", "1.0_git", "1.0_hg", "1.0_p",
	}
	assertAscending(t, "compareAlpine", compareAlpine, chain)
	extra := [][3]any{
		{"1.0_alpha1", "1.0_alpha2", -1},
		{"1.0_rc1", "1.0_rc2", -1},
		{"1.0", "1.0-r1", -1}, // 1.0 == 1.0-r0 < 1.0-r1
		{"1.0-r1", "1.0-r2", -1},
		{"1.0_p1", "1.0", 1}, // post > release
	}
	assertPairs(t, "compareAlpine", compareAlpine, extra)
}

// semver 2.0 §11 precedence example (authoritative).
func TestSemverCanonicalOrdering(t *testing.T) {
	chain := []string{
		"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta",
		"1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11",
		"1.0.0-rc.1", "1.0.0",
	}
	assertAscending(t, "compareGeneric", compareGeneric, chain)
	eq := [][3]any{
		{"1.0.0+build1", "1.0.0", 0}, // build metadata ignored
		{"v1.2.3", "1.2.3", 0},       // leading v
		{"1.2", "1.2.0", 0},          // zero-pad
		{"1.0.0-rc.1+b", "1.0.0-rc.1", 0},
		// PEP 440 shapes
		{"1.0a1", "1.0b1", -1},
		{"1.0rc1", "1.0", -1},
		{"1.0", "1.0.post1", -1},
		{"1.0.dev1", "1.0a1", -1},
	}
	assertPairs(t, "compareGeneric", compareGeneric, eq)
}

func assertAscending(t *testing.T, name string, cmp func(string, string) (int, bool), chain []string) {
	t.Helper()
	for i := 0; i+1 < len(chain); i++ {
		got, ok := cmp(chain[i], chain[i+1])
		if !ok || sign3(got) != -1 {
			t.Errorf("%s(%q,%q) = %d ok=%v, want -1 (ascending chain)", name, chain[i], chain[i+1], got, ok)
		}
		rev, _ := cmp(chain[i+1], chain[i])
		if sign3(rev) != 1 {
			t.Errorf("%s(%q,%q) = %d, want 1 (antisymmetry)", name, chain[i+1], chain[i], rev)
		}
	}
}

func assertPairs(t *testing.T, name string, cmp func(string, string) (int, bool), pairs [][3]any) {
	t.Helper()
	for _, p := range pairs {
		a, b, want := p[0].(string), p[1].(string), p[2].(int)
		got, ok := cmp(a, b)
		if !ok {
			t.Errorf("%s(%q,%q): ok=false, want comparable", name, a, b)
			continue
		}
		if sign3(got) != want {
			t.Errorf("%s(%q,%q) = %d, want %d", name, a, b, got, want)
		}
	}
}

func sign3(n int) int {
	if n < 0 {
		return -1
	}
	if n > 0 {
		return 1
	}
	return 0
}
