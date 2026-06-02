package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/ziozzang/bongsu/internal/server/db"
	"github.com/ziozzang/bongsu/internal/shared/models"
)

func validateRuleExpr(expr string) error {
	if expr == "" {
		return nil
	}
	conditions := strings.Split(expr, ",")
	for _, cond := range conditions {
		cond = strings.TrimSpace(cond)
		if cond == "" {
			continue
		}
		if strings.HasPrefix(cond, "tags:") {
			tagPart := strings.TrimPrefix(cond, "tags:")
			if tagPart == "" {
				return fmt.Errorf("empty tag expression")
			}
			continue
		}
		kv := strings.SplitN(cond, "=", 2)
		if len(kv) != 2 {
			return fmt.Errorf("invalid condition: %s", cond)
		}
		key := strings.TrimSpace(kv[0])
		switch strings.ToLower(key) {
		case "owner", "team", "environment", "criticality":
		default:
			return fmt.Errorf("unknown field: %s (allowed: owner, team, environment, criticality, tags:*", key)
		}
	}
	return nil
}

func (s *Server) handleListAssetGroups(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	groups, err := s.db.ListAssetGroups(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if groups == nil {
		groups = []db.AssetGroup{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": groups})
}

func (s *Server) handleCreateAssetGroup(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		RuleType    string `json:"rule_type"`
		RuleExpr    string `json:"rule_expr"`
	}
	if err := decodeJSONBody(w, r, &req, false); err != nil {
		writeJSONBodyError(w, err, "invalid request body")
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	ruleType := "static"
	if req.RuleType != "" {
		ruleType = req.RuleType
	}
	if ruleType != "static" && ruleType != "dynamic" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "rule_type must be static or dynamic"})
		return
	}
	if ruleType == "dynamic" && req.RuleExpr != "" {
		if err := validateRuleExpr(req.RuleExpr); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid rule_expr: " + err.Error()})
			return
		}
	}
	group := &db.AssetGroup{
		ID:          uuid.New().String(),
		Name:        req.Name,
		Description: req.Description,
		RuleType:    ruleType,
		RuleExpr:    req.RuleExpr,
	}
	if err := s.db.CreateAssetGroup(r.Context(), group); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.audit(r, "asset_group.create", "asset_group", group.ID, "ok", map[string]any{"name": req.Name, "rule_type": ruleType})
	writeJSON(w, http.StatusCreated, group)
}

func (s *Server) handleGetAssetGroup(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := r.PathValue("id")
	group, err := s.db.GetAssetGroup(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	hostIDs, _ := s.db.GetAssetGroupHostIDs(r.Context(), id)
	if hostIDs == nil {
		hostIDs = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"group": group, "host_ids": hostIDs})
}

func (s *Server) handleDeleteAssetGroup(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := r.PathValue("id")
	if err := s.db.DeleteAssetGroup(r.Context(), id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	s.audit(r, "asset_group.delete", "asset_group", id, "ok", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleAddHostToAssetGroup(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	groupID := r.PathValue("id")
	group, err := s.db.GetAssetGroup(r.Context(), groupID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "group not found"})
		return
	}
	if group.RuleType != "static" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot add hosts to dynamic group"})
		return
	}
	var req struct {
		HostID string `json:"host_id"`
	}
	if err := decodeJSONBody(w, r, &req, false); err != nil {
		writeJSONBodyError(w, err, "invalid request body")
		return
	}
	if req.HostID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host_id is required"})
		return
	}
	if err := s.db.AddHostToAssetGroup(r.Context(), groupID, req.HostID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.audit(r, "asset_group.add_host", "asset_group", groupID, "ok", map[string]any{"host_id": req.HostID})
	writeJSON(w, http.StatusOK, map[string]string{"status": "added"})
}

func (s *Server) handleRemoveHostFromAssetGroup(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	groupID := r.PathValue("id")
	hostID := r.PathValue("hostId")
	if err := s.db.RemoveHostFromAssetGroup(r.Context(), groupID, hostID); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "asset_group.remove_host", "asset_group", groupID, "ok", map[string]any{"host_id": hostID})
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

func (s *Server) handleTriggerAssetGroupScan(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	groupID := r.PathValue("id")
	group, err := s.db.GetAssetGroup(r.Context(), groupID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "group not found"})
		return
	}
	var hostIDs []string
	if group.RuleType == "dynamic" {
		hostIDs, err = s.db.ExpandDynamicGroup(r.Context(), groupID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	} else {
		hostIDs, err = s.db.GetAssetGroupHostIDs(r.Context(), groupID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	queued := 0
	for _, hid := range hostIDs {
		req := &models.ScanRequest{
			HostID:   hid,
			ScanType: "manual",
			Reason:   fmt.Sprintf("asset group scan: %s", group.Name),
		}
		if err := s.db.CreateScanRequest(r.Context(), req); err != nil {
			continue
		}
		queued++
	}
	s.audit(r, "asset_group.scan", "asset_group", groupID, "ok", map[string]any{
		"name": group.Name, "queued": queued, "total": len(hostIDs),
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "queued": queued, "total": len(hostIDs)})
}
