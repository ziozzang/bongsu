package api

import (
	"net/http"
	"strconv"

	"github.com/ziozzang/bongsu/internal/server/db"
)

func (s *Server) handleGetTopAtRiskHosts(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	limit := envInt("BONGSU_INTELLIGENCE_TOP_RISK_LIMIT", 10)
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	hosts, err := s.db.GetTopAtRiskHosts(r.Context(), limit)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if hosts == nil {
		hosts = []db.AtRiskHost{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": hosts})
}

func (s *Server) handleGetRecommendations(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	recs, err := s.db.GetRecommendations(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if recs == nil {
		recs = []db.Recommendation{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": recs})
}

func (s *Server) handleGetVulnPosture(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	days := envInt("BONGSU_INTELLIGENCE_POSTURE_COMPARISON_DAYS", 7)
	if d := r.URL.Query().Get("days"); d != "" {
		if v, err := strconv.Atoi(d); err == nil && v > 0 {
			days = v
		}
	}
	pc, err := s.db.GetVulnPostureComparison(r.Context(), days)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, pc)
}
