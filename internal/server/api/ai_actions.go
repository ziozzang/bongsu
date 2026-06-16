package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/ziozzang/bongsu/internal/server/aipolicy"
	"github.com/ziozzang/bongsu/internal/server/db"
	"github.com/ziozzang/bongsu/internal/shared/models"
)

// AI action governance: every AI-proposed action is routed through the policy
// engine (off / suggest / assisted / auto). Allowed actions execute immediately;
// "ask" actions queue for human approval; denied actions do nothing. The same
// executor runs an action whether it was auto-applied or approved by a human.

func (s *Server) aiPolicy() aipolicy.Config {
	// Min confidence falls back to the older BONGSU_LLM_AUTOAPPLY_CONFIDENCE for
	// continuity. Mode defaults to "suggest" (human-in-the-loop).
	minConf := envFloat("BONGSU_AI_MIN_CONFIDENCE", envFloat("BONGSU_LLM_AUTOAPPLY_CONFIDENCE", 0))
	mode := aipolicy.NormalizeMode(getenvDefault("BONGSU_AI_ACTION_MODE", ""))
	// Back-compat: if a confidence was set the old way but no mode chosen, behave
	// like "auto" so existing auto-apply configs keep working.
	if getenvDefault("BONGSU_AI_ACTION_MODE", "") == "" && envFloat("BONGSU_LLM_AUTOAPPLY_CONFIDENCE", 0) > 0 {
		mode = aipolicy.ModeAuto
	}
	return aipolicy.Config{
		Mode:              mode,
		MinConfidence:     minConf,
		ProtectProduction: envBool("BONGSU_AI_PROTECT_PRODUCTION", true),
	}
}

// triageSuppressPayload is the concrete action a triage.suppress approval carries.
type triageSuppressPayload struct {
	VulnerabilityID string `json:"vulnerability_id"`
	HostID          string `json:"host_id"`
	PkgName         string `json:"pkg_name"`
	TriageStatus    string `json:"triage_status"`
	Reason          string `json:"reason"`
	Comment         string `json:"comment"`
}

// executeAIAction performs an approved/allowed action. It is the single point
// where an AI decision becomes a real mutation, used by both the auto-apply path
// and the human-approval path.
func (s *Server) executeAIAction(ctx context.Context, actionType string, proposed json.RawMessage, actor string) error {
	switch actionType {
	case "triage.suppress":
		var p triageSuppressPayload
		if err := json.Unmarshal(proposed, &p); err != nil {
			return fmt.Errorf("decode triage payload: %w", err)
		}
		// A triage.suppress action may ONLY set a suppressing status, even if the
		// stored payload were tampered with — never 'fixed'/'open'/'ignored'.
		if p.VulnerabilityID == "" || (p.TriageStatus != "accepted_risk" && p.TriageStatus != "false_positive") {
			return fmt.Errorf("invalid triage.suppress payload")
		}
		t := &models.VulnerabilityTriage{
			VulnerabilityID: p.VulnerabilityID,
			HostID:          p.HostID,
			PkgName:         p.PkgName,
			Status:          p.TriageStatus,
			Reason:          p.Reason,
			Comment:         p.Comment,
			UpdatedBy:       actor,
		}
		if err := s.db.UpsertVulnerabilityTriage(ctx, t); err != nil {
			return err
		}
		// Keep derived package-vulnerability summaries consistent, exactly like the
		// manual triage endpoint does.
		if _, err := s.db.RebuildPackageVulnerabilitySummariesForTriage(ctx, *t); err != nil {
			log.Printf("ai-action: triage summary rebuild failed for %s: %v", p.VulnerabilityID, err)
		}
		return nil
	default:
		return fmt.Errorf("unknown AI action type %q", actionType)
	}
}

// governAIAnalysisAction routes an AI triage suggestion through the policy engine.
// Returns true only when the action was applied immediately.
func (s *Server) governAIAnalysisAction(ctx context.Context, c db.AnalysisCandidate, a *db.VulnAnalysis) bool {
	status := triageStatusForAction(a.RecommendedAction)
	if status == "" {
		return false // not a suppressing action — nothing to govern
	}
	req := aipolicy.Request{
		Type:           "triage.suppress",
		Confidence:     a.Confidence,
		Suppressing:    true,
		Severity:       c.Severity,
		CVSSScore:      c.CVSSScore,
		KnownExploited: c.KnownExploited,
		Environment:    c.Environment,
		Criticality:    c.Criticality,
	}
	decision := s.aiPolicy().Decide(req)
	payload, _ := json.Marshal(triageSuppressPayload{
		VulnerabilityID: c.VulnerabilityID, HostID: c.HostID, PkgName: c.PkgName, TriageStatus: status,
		Reason:  fmt.Sprintf("AI auto-triage (%s, confidence %.2f)", a.Model, a.Confidence),
		Comment: a.Reasoning,
	})
	ctxJSON, _ := json.Marshal(map[string]any{
		"model": a.Model, "risk_level": a.RiskLevel, "exploitability": a.Exploitability, "reasoning": a.Reasoning,
	})
	switch decision.Outcome {
	case aipolicy.OutcomeApply:
		if err := s.executeAIAction(ctx, "triage.suppress", payload, "ai-analyzer"); err != nil {
			log.Printf("ai-action apply failed for %s: %v", c.VulnerabilityID, err)
			return false
		}
		s.auditSystem("ai_action.apply", "vulnerability", c.VulnerabilityID, "ok",
			map[string]any{"action": "triage.suppress", "status": status, "rule": decision.Rule, "confidence": a.Confidence, "model": a.Model})
		return true
	case aipolicy.OutcomeQueue:
		// Dedup pending approvals per FINDING (vuln+host+package), not per CVE, so
		// distinct affected assets don't overwrite each other's pending action.
		subject := fmt.Sprintf("%s|%s|%s", c.VulnerabilityID, c.HostID, c.PkgName)
		ap := &db.AIApproval{ActionType: "triage.suppress", Subject: subject, Proposed: payload, Context: ctxJSON,
			Confidence: a.Confidence, Rule: decision.Rule, Reason: decision.Reason}
		if err := s.db.CreateAIApproval(ctx, ap); err != nil {
			log.Printf("ai-action queue failed for %s: %v", c.VulnerabilityID, err)
			return false
		}
		s.auditSystem("ai_action.queued", "vulnerability", c.VulnerabilityID, "ok",
			map[string]any{"action": "triage.suppress", "rule": decision.Rule, "confidence": a.Confidence})
		return false
	default:
		return false
	}
}

// --- Handlers ---

func (s *Server) handleAIPolicyStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	cfg := s.aiPolicy()
	counts, _ := s.db.CountAIApprovalsByStatus(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"mode":               string(cfg.Mode),
		"min_confidence":     cfg.MinConfidence,
		"protect_production": cfg.ProtectProduction,
		"approval_counts":    counts,
	})
}

func (s *Server) handleListAIApprovals(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	list, err := s.db.ListAIApprovals(r.Context(), status, limitParam(r, 200))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	counts, _ := s.db.CountAIApprovalsByStatus(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"approvals": list, "total": len(list), "counts": counts})
}

func (s *Server) handleDecideAIApproval(w http.ResponseWriter, r *http.Request, approve bool) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	actor := s.actorID(r)
	if approve {
		// Atomically CLAIM the pending approval (status -> approved) BEFORE
		// executing, so two concurrent approvers can't both execute. The loser
		// (or an approve racing a reject) gets claimed=false -> 409.
		claimed, actionType, proposed, err := s.db.ClaimAIApprovalForApproval(r.Context(), id, actor)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "db error")
			return
		}
		if !claimed {
			writeError(w, http.StatusConflict, "approval not pending")
			return
		}
		if err := s.executeAIAction(r.Context(), actionType, proposed, actor); err != nil {
			// Roll the claim back so the action can be retried/re-decided.
			_ = s.db.RevertAIApproval(r.Context(), id)
			log.Printf("ai-approval execute failed (%s): %v", id, err)
			writeError(w, http.StatusInternalServerError, "failed to execute approved action")
			return
		}
		s.audit(r, "ai_action.approve", "ai_approval", id, "ok", map[string]any{"action_type": actionType})
		writeJSON(w, http.StatusOK, map[string]any{"status": "approved"})
		return
	}
	rejected, err := s.db.RejectAIApproval(r.Context(), id, actor)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	if !rejected {
		writeError(w, http.StatusConflict, "approval not pending")
		return
	}
	s.audit(r, "ai_action.reject", "ai_approval", id, "ok", nil)
	writeJSON(w, http.StatusOK, map[string]any{"status": "rejected"})
}

func (s *Server) handleApproveAIApproval(w http.ResponseWriter, r *http.Request) {
	s.handleDecideAIApproval(w, r, true)
}

func (s *Server) handleRejectAIApproval(w http.ResponseWriter, r *http.Request) {
	s.handleDecideAIApproval(w, r, false)
}
