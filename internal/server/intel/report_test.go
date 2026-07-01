package intel

import "testing"

func TestNormalizeDedupKey(t *testing.T) {
	cases := map[string]string{
		"  CVE-2024-1234 : openssl  ": "cve-2024-1234 : openssl",
		"CVE-2024-1234\t\nopenssl":    "cve-2024-1234 openssl",
		"UPPER/Case:Pkg":              "upper/case:pkg",
		"weird*&^chars":               "weird---chars",
		"":                            "",
		"   ":                         "",
		":::---":                      "",
	}
	for in, want := range cases {
		if got := normalizeDedupKey(in); got != want {
			t.Errorf("normalizeDedupKey(%q) = %q, want %q", in, got, want)
		}
	}
	// Over-length keys are hash-capped and stay stable.
	long := make([]byte, 400)
	for i := range long {
		long[i] = 'a'
	}
	got1 := normalizeDedupKey(string(long))
	got2 := normalizeDedupKey(string(long))
	if len(got1) > 240 {
		t.Fatalf("over-length key not capped: %d", len(got1))
	}
	if got1 != got2 {
		t.Fatal("hash-capped key must be deterministic")
	}
}

func TestFallbackDedupKey(t *testing.T) {
	// Empty finding -> no key.
	if k := fallbackDedupKey(map[string]any{}); k != "" {
		t.Fatalf("empty report must yield no fallback, got %q", k)
	}
	// Finding + first affected package are stable and prefixed auto:.
	r := map[string]any{
		"finding":         "CVE-2024-1234",
		"affected_assets": []any{map[string]any{"package": "openssl"}},
	}
	k1 := fallbackDedupKey(r)
	k2 := fallbackDedupKey(r)
	if k1 == "" || k1 != k2 {
		t.Fatalf("fallback must be deterministic and non-empty: %q vs %q", k1, k2)
	}
	if k1[:5] != "auto:" {
		t.Fatalf("fallback must be prefixed auto:, got %q", k1)
	}
	// Different package -> different key.
	r["affected_assets"] = []any{map[string]any{"package": "curl"}}
	if fallbackDedupKey(r) == k1 {
		t.Fatal("different package must produce a different fallback key")
	}
}

func TestCanonicalizeSeverity(t *testing.T) {
	cases := map[string]string{
		"CRITICAL": "critical", "High": "high", "moderate": "medium",
		"low": "low", "informational": "info", "bogus": "unknown", "": "unknown",
	}
	for in, want := range cases {
		if got := canonicalizeSeverity(in); got != want {
			t.Errorf("canonicalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractCVSS(t *testing.T) {
	if v := extractCVSS(map[string]any{"cvss": 8.1}, "cvss"); v == nil || *v != 8.1 {
		t.Fatalf("float cvss must parse, got %v", v)
	}
	if v := extractCVSS(map[string]any{"cvss": "7.5"}, "cvss"); v == nil || *v != 7.5 {
		t.Fatalf("string cvss must parse, got %v", v)
	}
	if v := extractCVSS(map[string]any{"cvss": 11.0}, "cvss"); v != nil {
		t.Fatal("out-of-range cvss must be nil")
	}
	if v := extractCVSS(map[string]any{"cvss": "n/a"}, "cvss"); v != nil {
		t.Fatal("unparseable cvss must be nil")
	}
	if v := extractCVSS(map[string]any{}, "cvss"); v != nil {
		t.Fatal("absent cvss must be nil")
	}
}
