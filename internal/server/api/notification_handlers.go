package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/ziozzang/bongsu/internal/server/db"
)

func (s *Server) handleListNotificationRules(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	rules, err := s.db.ListNotificationRules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if rules == nil {
		rules = []db.NotificationRule{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rules})
}

func (s *Server) handleCreateNotificationRule(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		Name          string          `json:"name"`
		Enabled       *bool           `json:"enabled"`
		TriggerEvent  string          `json:"trigger_event"`
		MinSeverity   string          `json:"min_severity"`
		MinRiskLevel  string          `json:"min_risk_level"`
		ExploitedOnly bool            `json:"exploited_only"`
		HostFilter    string          `json:"host_filter"`
		ChannelType   string          `json:"channel_type"`
		ChannelConfig json.RawMessage `json:"channel_config"`
	}
	if err := decodeJSONBody(w, r, &req, false); err != nil {
		writeJSONBodyError(w, err, "invalid request body")
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	if req.TriggerEvent == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "trigger_event is required"})
		return
	}
	channelType := "webhook"
	if req.ChannelType != "" {
		channelType = req.ChannelType
	}
	if err := validateNotificationChannel(channelType, req.ChannelConfig); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	cfg := req.ChannelConfig
	if cfg == nil {
		cfg = json.RawMessage(`{}`)
	}
	rule := &db.NotificationRule{
		ID:            uuid.New().String(),
		Name:          req.Name,
		Enabled:       enabled,
		TriggerEvent:  req.TriggerEvent,
		MinSeverity:   req.MinSeverity,
		MinRiskLevel:  req.MinRiskLevel,
		ExploitedOnly: req.ExploitedOnly,
		HostFilter:    req.HostFilter,
		ChannelType:   channelType,
		ChannelConfig: cfg,
	}
	if err := s.db.CreateNotificationRule(r.Context(), rule); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.audit(r, "notification_rule.create", "notification_rule", rule.ID, "ok", map[string]any{"name": req.Name})
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) handleGetNotificationRule(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	rule, err := s.db.GetNotificationRule(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) handleUpdateNotificationRule(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	existing, err := s.db.GetNotificationRule(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	var req struct {
		Name          *string         `json:"name"`
		Enabled       *bool           `json:"enabled"`
		TriggerEvent  *string         `json:"trigger_event"`
		MinSeverity   *string         `json:"min_severity"`
		MinRiskLevel  *string         `json:"min_risk_level"`
		ExploitedOnly *bool           `json:"exploited_only"`
		HostFilter    *string         `json:"host_filter"`
		ChannelType   *string         `json:"channel_type"`
		ChannelConfig json.RawMessage `json:"channel_config"`
	}
	if err := decodeJSONBody(w, r, &req, false); err != nil {
		writeJSONBodyError(w, err, "invalid request body")
		return
	}
	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	if req.TriggerEvent != nil {
		existing.TriggerEvent = *req.TriggerEvent
	}
	if req.MinSeverity != nil {
		existing.MinSeverity = *req.MinSeverity
	}
	if req.MinRiskLevel != nil {
		existing.MinRiskLevel = *req.MinRiskLevel
	}
	if req.ExploitedOnly != nil {
		existing.ExploitedOnly = *req.ExploitedOnly
	}
	if req.HostFilter != nil {
		existing.HostFilter = *req.HostFilter
	}
	if req.ChannelType != nil {
		existing.ChannelType = *req.ChannelType
	}
	if req.ChannelConfig != nil {
		existing.ChannelConfig = req.ChannelConfig
	}
	if err := validateNotificationChannel(existing.ChannelType, existing.ChannelConfig); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := s.db.UpdateNotificationRule(r.Context(), existing); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.audit(r, "notification_rule.update", "notification_rule", id, "ok", nil)
	writeJSON(w, http.StatusOK, existing)
}

func (s *Server) handleDeleteNotificationRule(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	if err := s.db.DeleteNotificationRule(r.Context(), id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	s.audit(r, "notification_rule.delete", "notification_rule", id, "ok", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleTestNotificationRule(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	rule, err := s.db.GetNotificationRule(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err := s.ruleNotifier.dispatchTest(r.Context(), rule); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "notification_rule.test", "notification_rule", id, "ok", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

func (s *Server) handleListNotificationLog(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	ruleID := r.URL.Query().Get("rule_id")
	limit := 50
	offset := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}
	entries, total, err := s.db.ListNotificationLog(r.Context(), ruleID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if entries == nil {
		entries = []db.NotificationLog{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": entries, "total": total})
}

// validateNotificationChannel rejects unknown channel types and ensures the
// channel_config carries the fields each sender requires.
func validateNotificationChannel(channelType string, cfgRaw json.RawMessage) error {
	cfg := map[string]string{}
	if len(cfgRaw) > 0 {
		if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
			return fmt.Errorf("channel_config must be a JSON object of strings")
		}
	}
	switch channelType {
	case "webhook":
		if strings.TrimSpace(cfg["url"]) == "" {
			return fmt.Errorf("channel_config.url is required for webhook channel")
		}
	case "email":
		if len(emailRecipients(cfg)) == 0 {
			return fmt.Errorf("channel_config.to must contain at least one email address")
		}
		if _, err := smtpConfigFromEnv(); err != nil {
			return fmt.Errorf("smtp is not configured on the server: %v", err)
		}
	case "log":
	default:
		return fmt.Errorf("channel_type must be webhook, email, or log")
	}
	return nil
}
