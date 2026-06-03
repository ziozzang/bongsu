package api

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ziozzang/bongsu/internal/server/db"
	"github.com/ziozzang/bongsu/internal/shared/models"
)


func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	ctx := r.Context()

	hostID := r.URL.Query().Get("host_id")
	scope := s.accessScope(r)
	if scope.Empty() {
		writeJSON(w, http.StatusOK, map[string]any{"items": []models.Scan{}, "total": 0})
		return
	}
	if hostID != "" && !scope.CanReadHost(hostID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	limit := limitParam(r, 50)
	offset := offsetParam(r)

	scans, total, err := s.db.ListScans(ctx, hostID, scope.HostIDs, limit, offset)
	if err != nil {
		log.Printf("list scans: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items": scans,
		"total": total,
	})
}

func (s *Server) handleListScanRequests(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	scope := s.accessScope(r)
	if scope.Empty() {
		writeJSON(w, http.StatusOK, map[string]any{"items": []models.ScanRequest{}, "total": 0})
		return
	}
	hostID := r.URL.Query().Get("host_id")
	if hostID != "" && !scope.CanReadHost(hostID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if status != "" && !validScanRequestStatus(status) {
		writeError(w, http.StatusBadRequest, "invalid status")
		return
	}
	scanType := strings.TrimSpace(r.URL.Query().Get("scan_type"))
	if scanType != "" && !validScanRequestType(scanType) {
		writeError(w, http.StatusBadRequest, "invalid scan_type")
		return
	}
	staleOnly := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("stale")), "true")
	items, total, err := s.db.ListScanRequests(
		r.Context(),
		hostID,
		scope.HostIDs,
		status,
		scanType,
		strings.TrimSpace(r.URL.Query().Get("security_db_revision")),
		staleOnly,
		scanRequestClaimTimeoutSeconds(),
		limitParam(r, 50),
		offsetParam(r),
	)
	if err != nil {
		log.Printf("list scan requests: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	annotateScanRequestStaleness(items, scanRequestClaimTimeoutSeconds())
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

func annotateScanRequestStaleness(items []models.ScanRequest, timeoutSeconds int64) {
	for i := range items {
		if items[i].Status == "pending" && items[i].RequestAgeS > timeoutSeconds {
			items[i].RequestStale = true
		}
		if items[i].Status == "claimed" && items[i].ClaimAgeS > timeoutSeconds {
			items[i].ClaimStale = true
		}
	}
}

func scanRequestClaimTimeoutSeconds() int64 {
	timeoutMinutes := envInt("BONGSU_SCAN_REQUEST_CLAIM_TIMEOUT_MINUTES", 60)
	if timeoutMinutes <= 0 {
		timeoutMinutes = 60
	}
	return int64(timeoutMinutes) * 60
}

func (s *Server) handleCancelScanRequest(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	if err := s.db.CompleteScanRequest(r.Context(), id, "cancelled", "cancelled by admin"); err != nil {
		log.Printf("cancel scan request: %v", err)
		writeError(w, scanRequestErrorStatus(err), scanRequestErrorMessage(err))
		return
	}
	req, _ := s.db.GetScanRequest(r.Context(), id)
	s.audit(r, "scan_request.cancel", "scan_request", id, "cancelled", scanRequestAuditMeta(req, "cancelled by admin", ""))
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

func (s *Server) handleRequeueScanRequest(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	var body struct {
		Message string `json:"message"`
	}
	if err := decodeJSONBody(w, r, &body, true); err != nil {
		writeJSONBodyError(w, err, "invalid request body")
		return
	}
	body.Message = normalizeScanRequestMessage(body.Message)
	if body.Message == "" {
		body.Message = "requeued by admin"
	}
	if err := s.db.RequeueScanRequest(r.Context(), id, body.Message); err != nil {
		log.Printf("requeue scan request: %v", err)
		writeError(w, scanRequestErrorStatus(err), scanRequestErrorMessage(err))
		return
	}
	req, _ := s.db.GetScanRequest(r.Context(), id)
	s.audit(r, "scan_request.requeue", "scan_request", id, "ok", scanRequestAuditMeta(req, body.Message, ""))
	writeJSON(w, http.StatusOK, map[string]string{"status": "pending"})
}

func (s *Server) handleRequeueStaleScanRequests(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var body struct {
		TimeoutMinutes int `json:"timeout_minutes"`
	}
	if err := decodeJSONBody(w, r, &body, true); err != nil {
		writeJSONBodyError(w, err, "invalid request body")
		return
	}
	if body.TimeoutMinutes <= 0 {
		body.TimeoutMinutes = envInt("BONGSU_SCAN_REQUEST_CLAIM_TIMEOUT_MINUTES", 60)
	}
	if body.TimeoutMinutes <= 0 {
		body.TimeoutMinutes = 60
	}
	result, err := s.db.RequeueStaleScanRequests(r.Context(), time.Duration(body.TimeoutMinutes)*time.Minute)
	if err != nil {
		log.Printf("requeue stale scan requests: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	s.audit(r, "scan_request.requeue_stale", "scan_request", "stale_claims", "ok", map[string]any{
		"timeout_minutes":      body.TimeoutMinutes,
		"requeued":             result.Requeued,
		"cancelled_duplicates": result.CancelledDuplicates,
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "requeued": result.Requeued, "cancelled_duplicates": result.CancelledDuplicates, "timeout_minutes": body.TimeoutMinutes})
}

func (s *Server) handleRequeueFilteredScanRequests(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var body struct {
		HostID             string `json:"host_id"`
		Status             string `json:"status"`
		ScanType           string `json:"scan_type"`
		SecurityDBRevision string `json:"security_db_revision"`
		Message            string `json:"message"`
	}
	if err := decodeJSONBody(w, r, &body, true); err != nil {
		writeJSONBodyError(w, err, "invalid request body")
		return
	}
	body.HostID = strings.TrimSpace(body.HostID)
	body.Status = strings.TrimSpace(body.Status)
	body.ScanType = strings.TrimSpace(body.ScanType)
	body.SecurityDBRevision = strings.TrimSpace(body.SecurityDBRevision)
	body.Message = normalizeScanRequestMessage(body.Message)
	if body.HostID == "" && body.Status == "" && body.ScanType == "" && body.SecurityDBRevision == "" {
		writeError(w, http.StatusBadRequest, "at least one filter is required")
		return
	}
	if body.Status != "" && body.Status != "failed" && body.Status != "degraded" && body.Status != "cancelled" {
		writeError(w, http.StatusBadRequest, "status must be failed, degraded, or cancelled")
		return
	}
	if body.ScanType != "" && !validScanRequestType(body.ScanType) {
		writeError(w, http.StatusBadRequest, "invalid scan_type")
		return
	}
	if body.HostID != "" {
		if _, err := s.db.GetHost(r.Context(), body.HostID); err != nil {
			writeError(w, http.StatusNotFound, "host not found")
			return
		}
	}
	if body.Message == "" {
		body.Message = "bulk requeued by admin"
	}
	count, err := s.db.RequeueScanRequestsByFilter(r.Context(), body.HostID, body.Status, body.ScanType, body.SecurityDBRevision, body.Message)
	if err != nil {
		log.Printf("requeue filtered scan requests: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	s.audit(r, "scan_request.requeue_filtered", "scan_request", "filtered", "ok", map[string]any{
		"host_id":              body.HostID,
		"status":               body.Status,
		"scan_type":            body.ScanType,
		"security_db_revision": body.SecurityDBRevision,
		"message":              body.Message,
		"requeued":             count,
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "requeued": count})
}

func (s *Server) handleCreateScanRequest(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req models.ScanRequest
	if err := decodeJSONBody(w, r, &req, false); err != nil {
		writeJSONBodyError(w, err, "invalid request body")
		return
	}
	if err := normalizeScanRequestCreate(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.HostID != "" {
		if _, err := s.db.GetHost(r.Context(), req.HostID); err != nil {
			writeError(w, http.StatusNotFound, "host not found")
			return
		}
	}
	if err := s.db.CreateScanRequest(r.Context(), &req); err != nil {
		log.Printf("create scan request: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	s.audit(r, "scan_request.create", "scan_request", req.ID, "ok", map[string]any{
		"host_id":       req.HostID,
		"scan_type":     req.ScanType,
		"packages_only": req.PackagesOnly,
		"reason":        req.Reason,
	})
	writeJSON(w, http.StatusAccepted, req)
}

func normalizeScanRequestCreate(req *models.ScanRequest) error {
	req.HostID = strings.TrimSpace(req.HostID)
	req.RequestedBy = strings.TrimSpace(req.RequestedBy)
	req.ScanType = strings.TrimSpace(req.ScanType)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.RequestedBy == "" {
		req.RequestedBy = "api"
	}
	if req.ScanType == "" {
		req.ScanType = "manual"
	}
	if !validScanRequestType(req.ScanType) {
		return fmt.Errorf("invalid scan_type")
	}
	req.Status = "pending"
	req.ErrorMessage = ""
	req.SecurityDBRevision = strings.TrimSpace(req.SecurityDBRevision)
	req.ClaimedByHostID = ""
	req.ClaimedAt = nil
	req.CompletedAt = nil
	return nil
}

func validScanRequestType(scanType string) bool {
	switch scanType {
	case "manual", "daily", "security-db-update":
		return true
	default:
		return false
	}
}

func validScanRequestStatus(status string) bool {
	switch status {
	case "pending", "claimed", "completed", "degraded", "failed", "cancelled":
		return true
	default:
		return false
	}
}

func validAgentScanRequestCompletionStatus(status string) bool {
	switch status {
	case "completed", "degraded", "failed":
		return true
	default:
		return false
	}
}

func (s *Server) handleClaimScanRequest(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAgent(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	hostID := r.URL.Query().Get("host_id")
	if hostID == "" {
		writeError(w, http.StatusBadRequest, "host_id is required")
		return
	}
	if err := s.verifyAgentHostBinding(r, hostID); err != nil {
		s.audit(r, "scan_request.claim", "host", hostID, "forbidden", map[string]any{"reason": err.Error()})
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	timeoutMinutes := int(scanRequestClaimTimeoutSeconds() / 60)
	req, requeueResult, err := s.db.ClaimScanRequest(r.Context(), hostID, time.Duration(timeoutMinutes)*time.Minute)
	if err != nil {
		log.Printf("claim scan request: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	if requeueResult != nil && (requeueResult.Requeued > 0 || requeueResult.CancelledDuplicates > 0) {
		s.audit(r, "scan_request.requeue_stale", "scan_request", "stale_claims", "ok", map[string]any{
			"timeout_minutes":      timeoutMinutes,
			"requeued":             requeueResult.Requeued,
			"cancelled_duplicates": requeueResult.CancelledDuplicates,
			"trigger":              "agent_claim",
		})
	}
	if req == nil {
		writeJSON(w, http.StatusOK, map[string]any{"request": nil})
		return
	}
	s.audit(r, "scan_request.claim", "scan_request", req.ID, "ok", map[string]any{
		"host_id":              hostID,
		"target_host_id":       req.HostID,
		"scan_type":            req.ScanType,
		"packages_only":        req.PackagesOnly,
		"security_db_revision": req.SecurityDBRevision,
	})
	writeJSON(w, http.StatusOK, map[string]any{"request": req})
}

func (s *Server) handleCompleteScanRequest(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAgent(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	var body struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		HostID  string `json:"host_id"`
	}
	if err := decodeJSONBody(w, r, &body, false); err != nil {
		writeJSONBodyError(w, err, "invalid request body")
		return
	}
	body.HostID = strings.TrimSpace(body.HostID)
	body.Status = strings.TrimSpace(body.Status)
	body.Message = normalizeScanRequestMessage(body.Message)
	if body.Status == "" {
		body.Status = "completed"
	}
	if !validAgentScanRequestCompletionStatus(body.Status) {
		writeError(w, http.StatusBadRequest, "invalid scan request status")
		return
	}
	if err := s.verifyAgentHostBinding(r, body.HostID); err != nil {
		s.audit(r, "scan_request.complete", "host", body.HostID, "forbidden", map[string]any{"reason": err.Error()})
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if err := s.db.CompleteClaimedScanRequest(r.Context(), id, body.HostID, body.Status, body.Message); err != nil {
		log.Printf("complete scan request: %v", err)
		writeError(w, scanRequestErrorStatus(err), scanRequestErrorMessage(err))
		return
	}
	req, _ := s.db.GetScanRequest(r.Context(), id)
	s.audit(r, "scan_request.complete", "scan_request", id, body.Status, scanRequestAuditMeta(req, body.Message, body.HostID))
	writeJSON(w, http.StatusOK, map[string]string{"status": body.Status})
}

func normalizeScanRequestMessage(message string) string {
	message = strings.TrimSpace(message)
	if len(message) > maxScanRequestMessageBytes {
		message = truncateValidUTF8(message, maxScanRequestMessageBytes) + "...(truncated)"
	}
	return message
}

func scanRequestAuditMeta(req *models.ScanRequest, message, completedByHostID string) map[string]any {
	meta := map[string]any{}
	if message != "" {
		meta["message"] = message
	}
	if completedByHostID != "" {
		meta["host_id"] = completedByHostID
	}
	if req == nil {
		return meta
	}
	meta["target_host_id"] = req.HostID
	meta["requested_by"] = req.RequestedBy
	meta["scan_type"] = req.ScanType
	meta["packages_only"] = req.PackagesOnly
	meta["reason"] = req.Reason
	meta["security_db_revision"] = req.SecurityDBRevision
	meta["claimed_by_host_id"] = req.ClaimedByHostID
	return meta
}

func scanRequestErrorStatus(err error) int {
	switch {
	case errors.Is(err, db.ErrInvalidScanRequestStatus):
		return http.StatusBadRequest
	case errors.Is(err, db.ErrScanRequestNotFound):
		return http.StatusNotFound
	case errors.Is(err, db.ErrScanRequestNotActive):
		return http.StatusConflict
	case errors.Is(err, db.ErrScanRequestClaimMismatch):
		return http.StatusForbidden
	case errors.Is(err, db.ErrScanRequestNotRetryable):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func scanRequestErrorMessage(err error) string {
	switch {
	case errors.Is(err, db.ErrInvalidScanRequestStatus):
		return "invalid scan request status"
	case errors.Is(err, db.ErrScanRequestNotFound):
		return "scan request not found"
	case errors.Is(err, db.ErrScanRequestNotActive):
		return "scan request is not pending or claimed"
	case errors.Is(err, db.ErrScanRequestClaimMismatch):
		return "scan request was not claimed by this host"
	case errors.Is(err, db.ErrScanRequestNotRetryable):
		return "scan request is not failed, degraded, or cancelled"
	default:
		return "db error"
	}
}
