package intel

import (
	"math"
	"testing"
)

func vote(status string, valid *bool, conf float64) VerificationVote {
	return VerificationVote{Status: status, Valid: valid, Confidence: conf}
}

func boolp(b bool) *bool { return &b }

// TestAggregateVerificationVotes covers the majority rule: strict majority of
// SUCCESSFUL voters, ties refuted, quorum -> inconclusive, all-fail -> failed,
// and the consensus×mean-confidence score.
func TestAggregateVerificationVotes(t *testing.T) {
	cases := []struct {
		name       string
		votes      []VerificationVote
		minSuccess int
		verdict    VerificationVerdict
		status     VerificationStatus
		valid      bool
		confidence float64 // -1 to skip exact check
	}{
		{
			name:       "2 valid / 1 refuted -> valid",
			votes:      []VerificationVote{vote("success", boolp(true), 0.9), vote("success", boolp(true), 0.8), vote("success", boolp(false), 0.5)},
			minSuccess: 2, verdict: VerdictValid, status: StatusComplete, valid: true,
			confidence: (2.0 / 3.0) * ((0.9 + 0.8) / 2.0),
		},
		{
			name:       "1 valid / 2 refuted -> refuted",
			votes:      []VerificationVote{vote("success", boolp(true), 0.9), vote("success", boolp(false), 0.7), vote("success", boolp(false), 0.6)},
			minSuccess: 2, verdict: VerdictRefuted, status: StatusComplete, valid: false,
			confidence: (2.0 / 3.0) * ((0.7 + 0.6) / 2.0),
		},
		{
			name:       "4 voters 2:2 tie -> refuted",
			votes:      []VerificationVote{vote("success", boolp(true), 0.9), vote("success", boolp(true), 0.9), vote("success", boolp(false), 0.5), vote("success", boolp(false), 0.5)},
			minSuccess: 3, verdict: VerdictRefuted, status: StatusComplete, valid: false, confidence: -1,
		},
		{
			name:       "1 success / 2 failed, quorum 2 -> inconclusive",
			votes:      []VerificationVote{vote("success", boolp(true), 0.9), vote("failed", nil, 0), vote("failed", nil, 0)},
			minSuccess: 2, verdict: VerdictInconclusive, status: StatusInconclusive, valid: false, confidence: 0,
		},
		{
			name:       "all failed -> failed",
			votes:      []VerificationVote{vote("failed", nil, 0), vote("failed", nil, 0), vote("failed", nil, 0)},
			minSuccess: 2, verdict: VerdictInconclusive, status: StatusFailed, valid: false, confidence: 0,
		},
		{
			name:       "single voter valid -> valid",
			votes:      []VerificationVote{vote("success", boolp(true), 1.0)},
			minSuccess: 1, verdict: VerdictValid, status: StatusComplete, valid: true, confidence: 1.0,
		},
		{
			name:       "3:0 outranks 2:1 (unanimous full confidence)",
			votes:      []VerificationVote{vote("success", boolp(true), 1.0), vote("success", boolp(true), 1.0), vote("success", boolp(true), 1.0)},
			minSuccess: 2, verdict: VerdictValid, status: StatusComplete, valid: true, confidence: 1.0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, status, valid, conf, counts := aggregateVerificationVotes(tc.votes, tc.minSuccess)
			if verdict != tc.verdict {
				t.Errorf("verdict = %q, want %q", verdict, tc.verdict)
			}
			if status != tc.status {
				t.Errorf("status = %q, want %q", status, tc.status)
			}
			if valid != tc.valid {
				t.Errorf("valid = %v, want %v", valid, tc.valid)
			}
			if tc.confidence >= 0 && math.Abs(conf-tc.confidence) > 1e-6 {
				t.Errorf("confidence = %v, want %v", conf, tc.confidence)
			}
			if counts.Requested != len(tc.votes) {
				t.Errorf("counts.Requested = %d, want %d", counts.Requested, len(tc.votes))
			}
			if conf < 0 || conf > 1 {
				t.Errorf("confidence out of [0,1]: %v", conf)
			}
		})
	}
}

func TestExpandLenses(t *testing.T) {
	// no lenses -> cycle defaults
	got := expandLenses(nil, 3)
	if len(got) != 3 || got[0] != LensAccuracy || got[1] != LensReachability || got[2] != LensVersionPresence {
		t.Fatalf("default expansion wrong: %v", got)
	}
	// more voters than lenses -> cycle
	got = expandLenses([]Lens{LensAccuracy}, 3)
	for i, l := range got {
		if l != LensAccuracy {
			t.Fatalf("cycle single lens: index %d = %q", i, l)
		}
	}
	// fewer voters than lenses -> truncate
	got = expandLenses([]Lens{LensAccuracy, LensReachability, LensVersionPresence, LensEcosystemMatch}, 2)
	if len(got) != 2 {
		t.Fatalf("truncate: got %d", len(got))
	}
}

func TestMajority(t *testing.T) {
	for n, want := range map[int]int{1: 1, 2: 2, 3: 2, 4: 3, 5: 3} {
		if got := majority(n); got != want {
			t.Errorf("majority(%d) = %d, want %d", n, got, want)
		}
	}
}

// TestVerifyLensSuffix ensures each known lens injects a distinct instruction and
// the empty lens leaves the single-shot prompt unchanged.
func TestVerifyLensSuffix(t *testing.T) {
	if verifyLensSuffix("") != "" {
		t.Fatal("empty lens must add no suffix")
	}
	seen := map[string]bool{}
	for _, l := range defaultLenses {
		s := verifyLensSuffix(string(l))
		if s == "" {
			t.Fatalf("lens %q produced no suffix", l)
		}
		if seen[s] {
			t.Fatalf("lens %q produced a duplicate suffix", l)
		}
		seen[s] = true
	}
	if verifyLensSuffix("bogus") != "" {
		t.Fatal("unknown lens must add no suffix")
	}
}
