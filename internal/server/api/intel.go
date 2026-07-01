package api

import (
	"encoding/json"
	"net/http"

	"github.com/ziozzang/bongsu/internal/server/intel"
)

// intelAuthorized gates who may trigger/read intelligence runs. By default an
// admin is required; BONGSU_INTEL_REQUIRE_ADMIN=false relaxes it to any
// authenticated web caller (RBAC can be loosened by config, since the run
// operates under a service scope, not the caller's per-host scope).
func (s *Server) intelAuthorized(r *http.Request) bool {
	if s.intel != nil && !s.intel.RequireAdmin() {
		return s.authenticateWeb(r)
	}
	return s.authenticateAdmin(r)
}

// handleIntelScenarios lists the available intelligence scenarios.
func (s *Server) handleIntelScenarios(w http.ResponseWriter, r *http.Request) {
	if !s.intelAuthorized(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if s.intel == nil || !s.intel.Enabled() {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "scenarios": []string{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "scenarios": s.intel.Scenarios()})
}

// handleIntelRun triggers a scenario run on the jikji backbone over HTTP and
// returns the structured outcome. The backbone is optional: when unconfigured or
// unreachable the endpoint returns 503 and the rest of Bongsu is unaffected.
func (s *Server) handleIntelRun(w http.ResponseWriter, r *http.Request) {
	if !s.intelAuthorized(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if s.intel == nil || !s.intel.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "intelligence backbone not configured (set BONGSU_INTEL_JIKJI_URL)")
		return
	}
	if err := s.intel.Health(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "intelligence backbone unreachable")
		return
	}
	var body struct {
		Scenario  string         `json:"scenario"`
		Params    map[string]any `json:"params"`
		SessionID string         `json:"session_id"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Scenario == "" {
		writeError(w, http.StatusBadRequest, "scenario is required")
		return
	}

	p := s.principal(r)
	scope := &intel.Scope{Admin: p.Admin, Subjects: append([]string(nil), p.Subjects...)}
	outcome, err := s.intel.RunScenario(r.Context(), intel.RunRequest{
		Scenario: body.Scenario, Params: body.Params, PrincipalID: p.ID, Scope: scope, SessionID: body.SessionID,
	})
	if err != nil {
		s.audit(r, "intel.run", "scenario", body.Scenario, "error", map[string]any{"error": err.Error(), "run_id": outcome.RunID})
		// A failed run still persisted; surface the run id with a 502.
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "run_id": outcome.RunID, "status": "failed"})
		return
	}
	s.audit(r, "intel.run", "scenario", body.Scenario, "success", map[string]any{"run_id": outcome.RunID, "tool_steps": outcome.ToolSteps})
	writeJSON(w, http.StatusOK, outcome)
}

// handleIntelGetRun returns a persisted run by id.
func (s *Server) handleIntelGetRun(w http.ResponseWriter, r *http.Request) {
	if !s.intelAuthorized(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if s.intel == nil {
		writeError(w, http.StatusServiceUnavailable, "intelligence backbone not configured")
		return
	}
	view, err := s.intel.GetRun(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "run not found")
		return
	}
	writeJSON(w, http.StatusOK, view)
}
