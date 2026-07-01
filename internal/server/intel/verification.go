package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// Majority-vote adversarial verification. The single-shot `verify` scenario is
// upgraded to N INDEPENDENT voters, each running the scenario in its own session
// (so voters never see each other — decorrelated errors) under a distinct
// refutation LENS (accuracy / reachability / version-presence / ecosystem). The
// verdict is a majority over the SUCCESSFUL voters; a run that can't reach a
// quorum of successful voters is "inconclusive" rather than a false verdict.
// Each voter is a normal, fully-audited intel_runs row; only the aggregate is
// stored in intel_verifications (see design docs/redesign-verify-voting-trinity.md).

// Lens is a refutation perspective assigned to a voter. Diverse lenses beat N
// identical refuters: they fail in different ways, so agreement is meaningful.
type Lens string

const (
	LensAccuracy        Lens = "accuracy"
	LensReachability    Lens = "reachability"
	LensVersionPresence Lens = "version_presence"
	LensEcosystemMatch  Lens = "ecosystem_match"
)

// defaultLenses is cycled to fill the requested voter count when the caller does
// not specify lenses. Ordered by discriminating power for a typical finding.
var defaultLenses = []Lens{LensAccuracy, LensReachability, LensVersionPresence, LensEcosystemMatch}

func knownLens(l Lens) bool {
	switch l {
	case LensAccuracy, LensReachability, LensVersionPresence, LensEcosystemMatch:
		return true
	}
	return false
}

const (
	maxVoters     = 5
	defaultVoters = 3
)

// VerificationRequest asks for a majority-vote verification of a finding.
type VerificationRequest struct {
	CVE         string
	ScanID      string
	Package     string
	Voters      int
	MinSuccess  int
	Lenses      []Lens
	PrincipalID string
	Scope       *Scope
}

// VerificationStatus is the run-level outcome (did we reach a verdict at all).
type VerificationStatus string

const (
	StatusComplete     VerificationStatus = "complete"
	StatusInconclusive VerificationStatus = "inconclusive"
	StatusFailed       VerificationStatus = "failed"
)

// VerificationVerdict is the security judgement over the successful voters.
type VerificationVerdict string

const (
	VerdictValid        VerificationVerdict = "valid"
	VerdictRefuted      VerificationVerdict = "refuted"
	VerdictInconclusive VerificationVerdict = "inconclusive"
)

// VerificationCounts breaks down the vote tally for the API and audit.
type VerificationCounts struct {
	Requested int `json:"requested"`
	Required  int `json:"required"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Valid     int `json:"valid"`
	Refuted   int `json:"refuted"`
}

// VerificationVote is one voter's contribution (success carries a verdict;
// failure carries an error and does not count toward the tally).
type VerificationVote struct {
	Index      int             `json:"index"`
	Lens       Lens            `json:"lens"`
	RunID      string          `json:"run_id,omitempty"`
	Status     string          `json:"status"` // success|failed
	Valid      *bool           `json:"valid,omitempty"`
	Confidence float64         `json:"confidence,omitempty"`
	Refutation string          `json:"refutation,omitempty"`
	Evidence   json.RawMessage `json:"evidence,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// VerificationOutcome is the API-facing aggregate result.
type VerificationOutcome struct {
	VerificationID int64               `json:"verification_id"`
	Status         VerificationStatus  `json:"status"`
	Verdict        VerificationVerdict `json:"verdict"`
	Valid          bool                `json:"valid"`
	Confidence     float64             `json:"confidence"`
	Counts         VerificationCounts  `json:"counts"`
	Voters         []VerificationVote  `json:"voters"`
}

// verifyResponse is the shape a voter's `verify` scenario returns.
type verifyResponse struct {
	Finding    string          `json:"finding"`
	Valid      bool            `json:"valid"`
	Confidence float64         `json:"confidence"`
	Refutation string          `json:"refutation,omitempty"`
	Evidence   json.RawMessage `json:"evidence,omitempty"`
}

// majority returns the smallest number of votes that is strictly more than half.
func majority(n int) int { return n/2 + 1 }

// expandLenses resolves the lens assignment for `voters` voters: use the
// caller's lenses (cycled/truncated to fit) or cycle the defaults.
func expandLenses(requested []Lens, voters int) []Lens {
	src := requested
	if len(src) == 0 {
		src = defaultLenses
	}
	out := make([]Lens, voters)
	for i := 0; i < voters; i++ {
		out[i] = src[i%len(src)]
	}
	return out
}

// aggregateVerificationVotes is the PURE majority rule over the votes. It counts
// only successful voters; if fewer than minSuccess succeeded the result is
// inconclusive (never a verdict on too little evidence). A tie is refuted — the
// adversarial default is "assume false positive unless the majority upholds it".
// Confidence = consensus ratio (winning votes / succeeded) × mean confidence of
// the winning side, so 3:0 outranks 2:1.
func aggregateVerificationVotes(votes []VerificationVote, minSuccess int) (VerificationVerdict, VerificationStatus, bool, float64, VerificationCounts) {
	counts := VerificationCounts{Requested: len(votes), Required: minSuccess}
	var validConf, refutedConf float64
	for _, v := range votes {
		if v.Status != "success" || v.Valid == nil {
			counts.Failed++
			continue
		}
		counts.Succeeded++
		if *v.Valid {
			counts.Valid++
			validConf += v.Confidence
		} else {
			counts.Refuted++
			refutedConf += v.Confidence
		}
	}
	if counts.Succeeded == 0 {
		return VerdictInconclusive, StatusFailed, false, 0, counts
	}
	if counts.Succeeded < minSuccess {
		return VerdictInconclusive, StatusInconclusive, false, 0, counts
	}
	// Strict majority of the successful voters. Ties fall through to refuted.
	if counts.Valid*2 > counts.Succeeded {
		consensus := float64(counts.Valid) / float64(counts.Succeeded)
		conf := consensus * (validConf / float64(counts.Valid))
		return VerdictValid, StatusComplete, true, clamp01(conf), counts
	}
	consensus := float64(counts.Refuted) / float64(counts.Succeeded)
	conf := 0.0
	if counts.Refuted > 0 {
		conf = consensus * (refutedConf / float64(counts.Refuted))
	}
	return VerdictRefuted, StatusComplete, false, clamp01(conf), counts
}

func clamp01(f float64) float64 {
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}

// RunVerification runs a majority-vote verification: it normalizes the request,
// records an aggregate row, runs the voters in parallel (each an independent,
// audited `verify` run under its own lens), tallies the successful voters, and
// persists+returns the verdict. Backbone failures are isolated per-voter and, at
// worst, yield an inconclusive verdict — never a panic or a false positive.
func (s *Service) RunVerification(ctx context.Context, req VerificationRequest) (VerificationOutcome, error) {
	if !s.Enabled() {
		return VerificationOutcome{}, ErrBackboneDisabled
	}
	if req.CVE == "" {
		return VerificationOutcome{}, fmt.Errorf("intel: verification requires a cve")
	}
	voters := req.Voters
	if voters <= 0 {
		voters = defaultVoters
	}
	if voters > maxVoters {
		voters = maxVoters
	}
	for _, l := range req.Lenses {
		if !knownLens(l) {
			return VerificationOutcome{}, fmt.Errorf("intel: unknown lens %q", l)
		}
	}
	lenses := expandLenses(req.Lenses, voters)
	minSuccess := req.MinSuccess
	if minSuccess <= 0 {
		minSuccess = majority(voters)
	}
	if minSuccess > voters {
		minSuccess = voters
	}

	params := map[string]any{"cve": req.CVE}
	if req.ScanID != "" {
		params["scan_id"] = req.ScanID
	}
	if req.Package != "" {
		params["package"] = req.Package
	}

	verID, err := s.store.CreateVerification(ctx, VerificationRecord{
		PrincipalID: req.PrincipalID, Params: params, RequestedVoters: voters,
		MinSuccess: minSuccess, Lenses: lenses,
	})
	if err != nil {
		return VerificationOutcome{}, fmt.Errorf("intel: create verification: %w", err)
	}

	// Run the voters in parallel. Each writes only its own slot, so no mutex is
	// needed; RunScenario already honors ctx (cancellation/timeout) per voter.
	votes := make([]VerificationVote, voters)
	var wg sync.WaitGroup
	for i := 0; i < voters; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			votes[i] = s.runVoter(ctx, req, params, lenses[i], i, verID)
		}(i)
	}
	wg.Wait()

	verdict, status, valid, confidence, counts := aggregateVerificationVotes(votes, minSuccess)
	agg := VerificationAggregate{
		Status: string(status), Verdict: string(verdict), Valid: valid, Confidence: confidence,
		Succeeded: counts.Succeeded, Failed: counts.Failed, ValidVotes: counts.Valid,
		RefutedVotes: counts.Refuted, Votes: votes,
	}
	if err := s.store.UpdateVerification(ctx, verID, agg); err != nil {
		_ = err // persistence failure is non-fatal to returning the verdict
	}
	return VerificationOutcome{
		VerificationID: verID, Status: status, Verdict: verdict, Valid: valid,
		Confidence: confidence, Counts: counts, Voters: votes,
	}, nil
}

// runVoter runs one independent `verify` scenario under the given lens and turns
// its outcome into a vote. A backbone error or an unparseable/invalid response
// makes the vote "failed" (it will not count toward the tally).
func (s *Service) runVoter(ctx context.Context, req VerificationRequest, baseParams map[string]any, lens Lens, index int, verID int64) VerificationVote {
	vote := VerificationVote{Index: index, Lens: lens, Status: "failed"}

	// Per-voter params: copy the base and add the lens (never mutate the shared map).
	p := make(map[string]any, len(baseParams)+1)
	for k, v := range baseParams {
		p[k] = v
	}
	p["lens"] = string(lens)

	outcome, err := s.RunScenario(ctx, RunRequest{
		Scenario: "verify", Params: p, PrincipalID: req.PrincipalID, Scope: req.Scope, SessionID: "",
	})
	vote.RunID = outcome.RunID
	if outcome.RunID != "" {
		// Link the voter run back to its verification (best-effort audit trail).
		s.store.BackfillVoterRun(ctx, outcome.RunID, verID, index, string(lens))
	}
	if err != nil {
		vote.Error = err.Error()
		return vote
	}
	var vr verifyResponse
	if obj, ok := extractJSONObject(outcome.Response); ok {
		raw, _ := json.Marshal(obj)
		_ = json.Unmarshal(raw, &vr)
	} else {
		vote.Error = "voter response was not a JSON object"
		return vote
	}
	if vr.Confidence < 0 || vr.Confidence > 1 {
		vote.Error = fmt.Sprintf("voter confidence out of range: %v", vr.Confidence)
		return vote
	}
	valid := vr.Valid
	vote.Status = "success"
	vote.Valid = &valid
	vote.Confidence = vr.Confidence
	vote.Refutation = vr.Refutation
	vote.Evidence = vr.Evidence
	return vote
}
