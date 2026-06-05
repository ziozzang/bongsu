package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/ziozzang/bongsu/internal/server/db"
)

func (s *Server) handleGetExecutiveSummary(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	scope := s.accessScope(r)
	if scope.Empty() {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	hostIDs := scopeHostFilter(scope, scope.HostIDs)
	summary, err := s.db.GetExecutiveSummary(r.Context(), hostIDs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.audit(r, "report.generate", "report", "executive-summary", "ok", map[string]any{"format": "json", "scoped_hosts": len(hostIDs), "scope_all": scope.All})
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleGetRiskBreakdown(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	groupBy := r.URL.Query().Get("group_by")
	if groupBy == "" {
		groupBy = "owner"
	}
	scope := s.accessScope(r)
	if scope.Empty() {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	hostIDs := scopeHostFilter(scope, scope.HostIDs)
	rows, err := s.db.GetRiskBreakdown(r.Context(), groupBy, hostIDs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if rows == nil {
		rows = []db.RiskBreakdownRow{}
	}
	s.audit(r, "report.generate", "report", "risk-breakdown", "ok", map[string]any{"group_by": groupBy, "scoped_hosts": len(hostIDs), "scope_all": scope.All})
	writeJSON(w, http.StatusOK, map[string]any{"items": rows, "group_by": groupBy})
}

func (s *Server) handleGetSLACompliance(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	scope := s.accessScope(r)
	if scope.Empty() {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	hostIDs := scopeHostFilter(scope, scope.HostIDs)
	report, err := s.db.GetSLAComplianceReport(r.Context(), hostIDs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.audit(r, "report.generate", "report", "sla-compliance", "ok", map[string]any{"scoped_hosts": len(hostIDs), "scope_all": scope.All})
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleExportReport(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateExport(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	scope := s.exportScope(r)
	if scope.Empty() {
		s.audit(r, "report.export", "report", r.URL.Query().Get("type"), "forbidden", map[string]any{"reason": "empty export scope"})
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	hostIDs := scopeHostFilter(scope, scope.HostIDs)
	reportType := r.URL.Query().Get("type")
	if reportType == "" {
		reportType = "executive"
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	s.audit(r, "report.export", "report", reportType, "ok", map[string]any{"type": reportType, "format": format, "scoped_hosts": len(hostIDs), "scope_all": scope.All})
	switch reportType {
	case "executive":
		summary, err := s.db.GetExecutiveSummary(r.Context(), hostIDs)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		writeJSON(w, http.StatusOK, summary)
	case "sla":
		report, err := s.db.GetSLAComplianceReport(r.Context(), hostIDs)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		writeJSON(w, http.StatusOK, report)
	default:
		groupBy := r.URL.Query().Get("group_by")
		if groupBy == "" {
			groupBy = "owner"
		}
		limit := 100
		if l := r.URL.Query().Get("limit"); l != "" {
			if v, err := strconv.Atoi(l); err == nil && v > 0 {
				limit = v
			}
		}
		rows, err := s.db.GetRiskBreakdown(r.Context(), groupBy, hostIDs)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if len(rows) > limit {
			rows = rows[:limit]
		}
		if rows == nil {
			rows = []db.RiskBreakdownRow{}
		}
		if format == "csv" {
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", "attachment; filename=risk-breakdown.csv")
			w.Write([]byte("group,total,critical,high,medium,low\n"))
			for _, row := range rows {
				w.Write([]byte(fmt.Sprintf("%s,%d,%d,%d,%d,%d\n",
					row.Group, row.Total,
					row.SeverityCounts["CRITICAL"], row.SeverityCounts["HIGH"],
					row.SeverityCounts["MEDIUM"], row.SeverityCounts["LOW"])))
			}
			return
		}
		body, _ := json.Marshal(map[string]any{"items": rows, "group_by": groupBy})
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}
}
