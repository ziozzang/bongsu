// Package aipolicy is a reusable decision engine that governs whether an
// AI-proposed action may be taken automatically, must be queued for human
// approval, or is denied. It is provider- and action-agnostic: the AI
// vulnerability triage feature is the first consumer, but the same engine can
// gate future autonomous actions (auto-rescan, auto-annotation, ...).
//
// Modes mirror the familiar agent-permission model (off / suggest / assisted /
// auto). A risk verdict is computed purely from the action context (rules), then
// the mode maps it to a concrete outcome.
package aipolicy

import "strings"

type Mode string

const (
	ModeOff      Mode = "off"      // no AI actions at all
	ModeSuggest  Mode = "suggest"  // produce suggestions only; never apply or queue
	ModeAssisted Mode = "assisted" // apply low-risk; queue the rest for human approval
	ModeAuto     Mode = "auto"     // apply everything the rules allow (hard-deny still applies)
)

type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictAsk   Verdict = "ask"
	VerdictDeny  Verdict = "deny"
)

type Outcome string

const (
	OutcomeApply Outcome = "apply" // perform the action now
	OutcomeQueue Outcome = "queue" // create a pending approval
	OutcomeNone  Outcome = "none"  // do nothing (suggestion stands)
)

// Request describes one AI-proposed action and its risk context.
type Request struct {
	Type           string  // e.g. "triage.suppress"
	Confidence     float64 // 0..1
	Suppressing    bool    // does the action silence/suppress a finding?
	Severity       string
	CVSSScore      float64
	KnownExploited bool
	Environment    string
	Criticality    string
}

// Decision is the engine's ruling.
type Decision struct {
	Verdict Verdict `json:"verdict"`
	Outcome Outcome `json:"outcome"`
	Rule    string  `json:"rule"`
	Reason  string  `json:"reason"`
}

// Config is the policy configuration (typically built from env).
type Config struct {
	Mode              Mode
	MinConfidence     float64
	ProtectProduction bool // suppressing actions on prod+high-criticality always require human approval
}

// NormalizeMode coerces an arbitrary string into a known mode (default suggest).
func NormalizeMode(s string) Mode {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case ModeOff:
		return ModeOff
	case ModeAssisted:
		return ModeAssisted
	case ModeAuto:
		return ModeAuto
	default:
		return ModeSuggest
	}
}

func isCritical(severity string, cvss float64) bool {
	return strings.EqualFold(strings.TrimSpace(severity), "critical") || cvss >= 9.0
}

// Decide computes the risk verdict and maps it to a concrete outcome under the
// configured mode. The ordering matters: hard-safety denials are evaluated
// before mode so a serious finding can never be auto-silenced in any mode.
func (cfg Config) Decide(req Request) Decision {
	if cfg.Mode == ModeOff {
		return Decision{VerdictDeny, OutcomeNone, "mode_off", "AI action mode is off"}
	}
	// Hard safety: the AI may never auto-silence a known-exploited or
	// critical/high-CVSS finding — those always need a human, regardless of mode
	// or confidence (defense against prompt-injection-driven suppression).
	if req.Suppressing && (req.KnownExploited || isCritical(req.Severity, req.CVSSScore)) {
		return Decision{VerdictDeny, OutcomeNone, "safety_critical",
			"known-exploited or critical/high-CVSS findings require human review"}
	}
	if cfg.MinConfidence > 0 && req.Confidence < cfg.MinConfidence {
		return Decision{VerdictDeny, OutcomeNone, "low_confidence", "confidence below the configured threshold"}
	}

	verdict := VerdictAllow
	rule := "allow"
	reason := "within auto-action policy"
	// Production high-criticality suppressing actions escalate to human approval.
	if cfg.ProtectProduction && req.Suppressing &&
		strings.EqualFold(strings.TrimSpace(req.Environment), "production") &&
		strings.EqualFold(strings.TrimSpace(req.Criticality), "high") {
		verdict = VerdictAsk
		rule = "protect_production"
		reason = "production high-criticality host requires human approval"
	}

	return Decision{Verdict: verdict, Outcome: cfg.resolveOutcome(verdict), Rule: rule, Reason: reason}
}

func (cfg Config) resolveOutcome(v Verdict) Outcome {
	switch cfg.Mode {
	case ModeSuggest:
		return OutcomeNone // suggestions only; never apply or queue
	case ModeAssisted:
		if v == VerdictAllow {
			return OutcomeApply
		}
		return OutcomeQueue // ask -> human approval queue
	case ModeAuto:
		return OutcomeApply // allow and ask both auto-apply (deny already returned)
	default:
		return OutcomeNone
	}
}
