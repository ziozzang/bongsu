package api

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/ziozzang/bongsu/internal/server/db"
)

func (s *Server) handleListScheduledScans(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	schedules, err := s.db.ListScheduledScans(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if schedules == nil {
		schedules = []db.ScheduledScan{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": schedules})
}

func (s *Server) handleCreateScheduledScan(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		Name         string `json:"name"`
		CronExpr     string `json:"cron_expr"`
		ScanType     string `json:"scan_type"`
		HostFilter   string `json:"host_filter"`
		PackagesOnly *bool  `json:"packages_only"`
		Enabled      *bool  `json:"enabled"`
	}
	if err := decodeJSONBody(w, r, &req, false); err != nil {
		writeJSONBodyError(w, err, "invalid request body")
		return
	}
	if req.Name == "" || req.CronExpr == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and cron_expr are required"})
		return
	}
	scanType := "manual"
	if req.ScanType != "" {
		scanType = req.ScanType
	}
	nextRun, err := computeNextRun(req.CronExpr, time.Now())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid cron_expr: " + err.Error()})
		return
	}
	packagesOnly := true
	if req.PackagesOnly != nil {
		packagesOnly = *req.PackagesOnly
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	schedule := &db.ScheduledScan{
		ID:           uuid.New().String(),
		Name:         req.Name,
		CronExpr:     req.CronExpr,
		ScanType:     scanType,
		HostFilter:   req.HostFilter,
		PackagesOnly: packagesOnly,
		Enabled:      enabled,
		NextRun:      &nextRun,
	}
	if err := s.db.CreateScheduledScan(r.Context(), schedule); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.audit(r, "schedule.create", "scheduled_scan", schedule.ID, "ok", map[string]any{
		"name": req.Name, "cron_expr": req.CronExpr,
	})
	writeJSON(w, http.StatusCreated, schedule)
}

func (s *Server) handleGetScheduledScan(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	schedule, err := s.db.GetScheduledScan(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, schedule)
}

func (s *Server) handleUpdateScheduledScan(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	existing, err := s.db.GetScheduledScan(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	var req struct {
		Name         *string `json:"name"`
		CronExpr     *string `json:"cron_expr"`
		ScanType     *string `json:"scan_type"`
		HostFilter   *string `json:"host_filter"`
		PackagesOnly *bool   `json:"packages_only"`
		Enabled      *bool   `json:"enabled"`
	}
	if err := decodeJSONBody(w, r, &req, true); err != nil {
		writeJSONBodyError(w, err, "invalid request body")
		return
	}
	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.CronExpr != nil {
		existing.CronExpr = *req.CronExpr
	}
	if req.ScanType != nil {
		existing.ScanType = *req.ScanType
	}
	if req.HostFilter != nil {
		existing.HostFilter = *req.HostFilter
	}
	if req.PackagesOnly != nil {
		existing.PackagesOnly = *req.PackagesOnly
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	nextRun, err := computeNextRun(existing.CronExpr, time.Now())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid cron_expr: " + err.Error()})
		return
	}
	existing.NextRun = &nextRun
	if err := s.db.UpdateScheduledScan(r.Context(), existing); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.audit(r, "schedule.update", "scheduled_scan", id, "ok", map[string]any{"name": existing.Name})
	writeJSON(w, http.StatusOK, existing)
}

func (s *Server) handleDeleteScheduledScan(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	if err := s.db.DeleteScheduledScan(r.Context(), id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	s.audit(r, "schedule.delete", "scheduled_scan", id, "ok", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
