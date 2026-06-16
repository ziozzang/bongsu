package aipolicy

import "testing"

func TestNormalizeMode(t *testing.T) {
	cases := map[string]Mode{"off": ModeOff, "OFF": ModeOff, "assisted": ModeAssisted,
		"auto": ModeAuto, "suggest": ModeSuggest, "": ModeSuggest, "garbage": ModeSuggest}
	for in, want := range cases {
		if got := NormalizeMode(in); got != want {
			t.Fatalf("NormalizeMode(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDecideSafetyAndModes(t *testing.T) {
	supLow := Request{Type: "triage.suppress", Suppressing: true, Confidence: 0.99, Severity: "low", CVSSScore: 3}
	supCrit := Request{Type: "triage.suppress", Suppressing: true, Confidence: 0.99, Severity: "critical", CVSSScore: 9.8}
	supKEV := Request{Type: "triage.suppress", Suppressing: true, Confidence: 0.99, KnownExploited: true, Severity: "high", CVSSScore: 8}

	// off denies everything.
	if d := (Config{Mode: ModeOff}).Decide(supLow); d.Verdict != VerdictDeny || d.Outcome != OutcomeNone || d.Rule != "mode_off" {
		t.Fatalf("off mode: %+v", d)
	}
	// Hard safety: critical / KEV suppressions are always denied, even in auto.
	for _, req := range []Request{supCrit, supKEV} {
		if d := (Config{Mode: ModeAuto, MinConfidence: 0.5}).Decide(req); d.Verdict != VerdictDeny || d.Rule != "safety_critical" {
			t.Fatalf("safety not enforced for %+v -> %+v", req, d)
		}
	}
	// Low confidence denied.
	if d := (Config{Mode: ModeAuto, MinConfidence: 0.9}).Decide(Request{Suppressing: true, Confidence: 0.4, Severity: "low"}); d.Rule != "low_confidence" {
		t.Fatalf("low confidence not enforced: %+v", d)
	}
	// suggest never acts.
	if d := (Config{Mode: ModeSuggest}).Decide(supLow); d.Outcome != OutcomeNone {
		t.Fatalf("suggest must not act: %+v", d)
	}
	// assisted: allow -> apply.
	if d := (Config{Mode: ModeAssisted, MinConfidence: 0.5}).Decide(supLow); d.Verdict != VerdictAllow || d.Outcome != OutcomeApply {
		t.Fatalf("assisted allow->apply expected: %+v", d)
	}
	// assisted + protect production high -> ask -> queue.
	prod := supLow
	prod.Environment = "production"
	prod.Criticality = "high"
	if d := (Config{Mode: ModeAssisted, MinConfidence: 0.5, ProtectProduction: true}).Decide(prod); d.Verdict != VerdictAsk || d.Outcome != OutcomeQueue || d.Rule != "protect_production" {
		t.Fatalf("assisted prod-protect should queue: %+v", d)
	}
	// auto + protect production high -> ask -> still applies (auto is aggressive).
	if d := (Config{Mode: ModeAuto, MinConfidence: 0.5, ProtectProduction: true}).Decide(prod); d.Verdict != VerdictAsk || d.Outcome != OutcomeApply {
		t.Fatalf("auto should apply even ask: %+v", d)
	}
	// Non-suppressing actions are not blocked by the critical-finding safety rule.
	nonSup := Request{Type: "rescan", Suppressing: false, Confidence: 0.99, Severity: "critical", CVSSScore: 9.9}
	if d := (Config{Mode: ModeAssisted, MinConfidence: 0.5}).Decide(nonSup); d.Verdict != VerdictAllow {
		t.Fatalf("non-suppressing critical should be allowed: %+v", d)
	}
}
