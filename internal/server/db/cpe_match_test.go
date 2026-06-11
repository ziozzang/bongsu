package db

import "testing"

// TestCompatibleCPECandidate verifies the CPE/runtime matcher is version-gated:
// it matches only when the product matches AND the installed version falls in an
// explicit constraint, and never on vendor+product alone (the false-positive
// trap the user called out).
func TestCompatibleCPECandidate(t *testing.T) {
	// Python interpreter CVE affecting 3.9.0 <= v < 3.9.17.
	pyRange := `[{"vendor":"python","product":"python","version_start_including":"3.9.0","version_end_excluding":"3.9.17"}]`
	if _, ok := compatibleCPECandidate("python", "3.9.5", pyRange); !ok {
		t.Fatal("python 3.9.5 should be affected by 3.9.0<=v<3.9.17")
	}
	if _, ok := compatibleCPECandidate("python", "3.9.17", pyRange); ok {
		t.Fatal("python 3.9.17 is the fixed version (exclusive end) — must not match")
	}
	if _, ok := compatibleCPECandidate("python", "3.10.1", pyRange); ok {
		t.Fatal("python 3.10.1 is outside the affected range — must not match")
	}
	if _, ok := compatibleCPECandidate("python", "3.8.0", pyRange); ok {
		t.Fatal("python 3.8.0 is below the affected range — must not match")
	}

	// No version constraint at all → must NOT match (the FP-explosion guard).
	noVer := `[{"vendor":"python","product":"python"}]`
	if _, ok := compatibleCPECandidate("python", "3.9.5", noVer); ok {
		t.Fatal("a product entry with no version constraint must never match (false-positive guard)")
	}

	// Wildcard exact version is treated as no-constraint.
	wildcard := `[{"vendor":"python","product":"python","version":"*"}]`
	if _, ok := compatibleCPECandidate("python", "3.9.5", wildcard); ok {
		t.Fatal("version=* must not match")
	}

	// Exact pinned version.
	exact := `[{"vendor":"nodejs","product":"node.js","version":"18.16.0"}]`
	if _, ok := compatibleCPECandidate("nodejs", "18.16.0", exact); !ok {
		t.Fatal("exact node.js 18.16.0 should match")
	}
	if _, ok := compatibleCPECandidate("nodejs", "18.16.1", exact); ok {
		t.Fatal("node.js 18.16.1 must not match an exact 18.16.0 advisory")
	}

	// Product-name variants: detector emits "nodejs", CPE product is "node.js".
	if _, ok := compatibleCPECandidate("nodejs", "18.16.0", exact); !ok {
		t.Fatal("nodejs should match CPE product node.js")
	}

	// JDK variants: detector "jdk" vs CPE product "jre"/"openjdk".
	jdkRange := `[{"vendor":"oracle","product":"jre","version_start_including":"21.0.0","version_end_including":"21.0.2"}]`
	if _, ok := compatibleCPECandidate("jdk", "21.0.1", jdkRange); !ok {
		t.Fatal("jdk 21.0.1 should match jre 21.0.0..21.0.2 inclusive")
	}
	if _, ok := compatibleCPECandidate("jdk", "21.0.3", jdkRange); ok {
		t.Fatal("jdk 21.0.3 is above the inclusive end — must not match")
	}

	// Different product must not match.
	if _, ok := compatibleCPECandidate("ruby", "3.9.5", pyRange); ok {
		t.Fatal("ruby must not match a python advisory")
	}

	// Cross-vendor guard: Microsoft's VS Code Python EXTENSION shares the
	// product name "python" but is not the CPython runtime (observed live as
	// CVE-2024-49050 flagging python 3.11.4 with fixed version 2024.18.2).
	vscodeExt := `[{"vendor":"microsoft","product":"python","version_end_excluding":"2024.18.2"}]`
	if _, ok := compatibleCPECandidate("python", "3.11.4", vscodeExt); ok {
		t.Fatal("microsoft/python (VS Code extension) must not match the CPython runtime")
	}
	// The canonical vendor still matches.
	psf := `[{"vendor":"python","product":"python","version_start_including":"3.11.0","version_end_excluding":"3.11.9"}]`
	if _, ok := compatibleCPECandidate("python", "3.11.4", psf); !ok {
		t.Fatal("python/python must still match")
	}
	// Empty vendor passes the gate (product+version constraints still apply).
	noVendor := `[{"product":"python","version_start_including":"3.11.0","version_end_excluding":"3.11.9"}]`
	if _, ok := compatibleCPECandidate("python", "3.11.4", noVendor); !ok {
		t.Fatal("empty-vendor python advisory should still match")
	}
	// JDK family: eclipse/adoptium and oracle are legitimate.
	adoptium := `[{"vendor":"eclipse","product":"openjdk","version_start_including":"21.0.0","version_end_including":"21.0.2"}]`
	if _, ok := compatibleCPECandidate("jdk", "21.0.1", adoptium); !ok {
		t.Fatal("eclipse/openjdk must match a jdk runtime")
	}
}
