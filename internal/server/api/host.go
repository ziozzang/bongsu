package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ziozzang/bongsu/internal/server/cvematch"
	"github.com/ziozzang/bongsu/internal/server/db"
	"github.com/ziozzang/bongsu/internal/shared/models"
)

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	ctx := r.Context()
	scope := s.accessScope(r)
	statusFilter := r.URL.Query().Get("agent_status")
	inventoryStatusFilter := r.URL.Query().Get("inventory_status")
	agentVersionStateFilter := r.URL.Query().Get("agent_version_state")
	latestAgentVersion := binaryVersion(agentBinaryPath())
	inventoryStaleAfter := time.Duration(envInt("BONGSU_INVENTORY_STALE_HOURS", 48)) * time.Hour
	hosts, err := s.db.ListHosts(ctx)
	if err != nil {
		log.Printf("list hosts: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}

	vulnCounts, err := s.db.GetVulnCountsByHost(ctx)
	if err != nil {
		log.Printf("vuln counts: %v", err)
		vulnCounts = map[string]map[string]int{}
	}
	activeVulnCounts, err := s.db.GetCurrentActionableVulnCountsByHost(ctx, scopeHostFilter(scope, scope.HostIDs))
	if err != nil {
		log.Printf("active vuln counts: %v", err)
		activeVulnCounts = map[string]map[string]int{}
	}
	inventory, err := s.db.GetHostInventorySummaries(ctx)
	if err != nil {
		log.Printf("host inventory summaries: %v", err)
		inventory = map[string]db.HostInventorySummary{}
	}

	type hostWithVulns struct {
		models.Host
		VulnCounts       map[string]int          `json:"vuln_counts"`
		ActiveVulnCounts map[string]int          `json:"active_vuln_counts"`
		LatestInventory  db.HostInventorySummary `json:"latest_inventory"`
	}

	now := time.Now()
	result := make([]hostWithVulns, 0, len(hosts))
	for _, h := range hosts {
		if !scope.CanReadHost(h.ID) {
			continue
		}
		applyAgentStatus(&h, now)
		if statusFilter != "" && h.AgentStatus != statusFilter {
			continue
		}
		if agentVersionStateFilter != "" && agentVersionState(h.AgentVersion, latestAgentVersion) != agentVersionStateFilter {
			continue
		}
		item := hostWithVulns{Host: h, VulnCounts: vulnCounts[h.ID], ActiveVulnCounts: activeVulnCounts[h.ID], LatestInventory: inventory[h.ID]}
		if inventoryStatusFilter != "" && hostInventoryStatus(item.LatestInventory, now, inventoryStaleAfter) != inventoryStatusFilter {
			continue
		}
		if item.VulnCounts == nil {
			item.VulnCounts = map[string]int{}
		}
		if item.ActiveVulnCounts == nil {
			item.ActiveVulnCounts = map[string]int{}
		}
		result = append(result, item)
	}
	writeJSON(w, http.StatusOK, result)
}

func hostInventoryStatus(inv db.HostInventorySummary, now time.Time, staleAfter time.Duration) string {
	if inv.ScanID == "" {
		return "none"
	}
	if inv.PackageCount == 0 {
		return "empty"
	}
	if inv.ScanStatus == "degraded" {
		return "degraded"
	}
	if staleAfter > 0 && inv.ScannedAt != nil && now.Sub(*inv.ScannedAt) > staleAfter {
		return "stale"
	}
	return "healthy"
}

func (s *Server) handleGetHost(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	hostID := r.PathValue("id")
	if !s.canReadHost(r, hostID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	ctx := r.Context()

	host, err := s.db.GetHost(ctx, hostID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	applyAgentStatus(host, time.Now())
	writeJSON(w, http.StatusOK, host)
}

func (s *Server) handleUpdateHostMetadata(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	hostID := r.PathValue("id")
	if hostID == "" {
		writeError(w, http.StatusBadRequest, "host id is required")
		return
	}
	var body struct {
		Owner       string `json:"owner"`
		Team        string `json:"team"`
		Environment string `json:"environment"`
		Criticality string `json:"criticality"`
		Tags        string `json:"tags"`
	}
	if err := decodeJSONBody(w, r, &body, false); err != nil {
		writeJSONBodyError(w, err, "invalid request body")
		return
	}
	if body.Tags == "" {
		body.Tags = "{}"
	}
	var tags any
	if err := json.Unmarshal([]byte(body.Tags), &tags); err != nil {
		writeError(w, http.StatusBadRequest, "tags must be valid JSON")
		return
	}
	if err := s.db.UpdateHostMetadata(r.Context(), hostID, body.Owner, body.Team, body.Environment, body.Criticality, body.Tags); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "host not found")
			return
		}
		log.Printf("update host metadata: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	host, err := s.db.GetHost(r.Context(), hostID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	s.audit(r, "host.metadata.update", "host", hostID, "ok", map[string]any{
		"owner":       body.Owner,
		"team":        body.Team,
		"environment": body.Environment,
		"criticality": body.Criticality,
	})
	writeJSON(w, http.StatusOK, host)
}

func (s *Server) handleResetHostAgentToken(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	hostID := r.PathValue("id")
	if hostID == "" {
		writeError(w, http.StatusBadRequest, "host id is required")
		return
	}
	if _, err := s.db.GetHost(r.Context(), hostID); err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	if err := s.db.ResetHostAgentToken(r.Context(), hostID); err != nil {
		log.Printf("reset host agent token: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	s.audit(r, "host.agent_token.reset", "host", hostID, "ok", map[string]any{
		"host_id": hostID,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleHostPackages(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	hostID := r.PathValue("id")
	if !s.canReadHost(r, hostID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	ctx := r.Context()

	limit := limitParam(r, 100)
	offset := offsetParam(r)

	pkgs, total, err := s.db.GetLatestPackages(ctx, hostID, limit, offset)
	if err != nil {
		log.Printf("host packages: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items": pkgs,
		"total": total,
	})
}

func (s *Server) handleHostUsers(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	hostID := r.PathValue("id")
	if !s.canReadHost(r, hostID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	items, total, err := s.db.GetLatestUserAccounts(r.Context(), hostID, limitParam(r, 100), offsetParam(r))
	if err != nil {
		log.Printf("host users: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	if items == nil {
		items = []models.UserAccount{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

func (s *Server) handleHostProcesses(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	hostID := r.PathValue("id")
	if !s.canReadHost(r, hostID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	items, total, err := s.db.GetLatestProcessSnapshots(r.Context(), hostID, limitParam(r, 100), offsetParam(r))
	if err != nil {
		log.Printf("host processes: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	if items == nil {
		items = []models.ProcessSnapshot{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

func (s *Server) handleHostPorts(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	hostID := r.PathValue("id")
	if !s.canReadHost(r, hostID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	items, total, err := s.db.GetLatestPorts(r.Context(), hostID, limitParam(r, 100), offsetParam(r))
	if err != nil {
		log.Printf("host ports: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	if items == nil {
		items = []models.PortInfo{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

func (s *Server) handleHostSBOM(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateExport(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	hostID := r.PathValue("id")
	if !s.exportScope(r).CanReadHost(hostID) {
		s.audit(r, "sbom.export", "host", hostID, "forbidden", map[string]any{"reason": "missing export permission"})
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	ctx := r.Context()

	host, err := s.db.GetHost(ctx, hostID)
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	pkgs, err := s.db.GetLatestPackagesForSBOM(ctx, hostID)
	if err != nil {
		log.Printf("host sbom packages: %v", err)
		s.audit(r, "sbom.export", "host", hostID, "error", map[string]any{"error": "package lookup failed"})
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	if len(pkgs) == 0 {
		s.audit(r, "sbom.export", "host", hostID, "error", map[string]any{"error": "no packages available"})
		writeError(w, http.StatusNotFound, "no packages available for host")
		return
	}
	scanID := latestPackageScanID(pkgs)
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "cyclonedx"
	}
	var data []byte
	var contentType, suffix, auditFormat string
	switch format {
	case "spdx":
		data, err = cvematch.GenerateSPDX(pkgs, *host)
		contentType = "application/spdx+json"
		suffix = "spdx.json"
		auditFormat = "SPDX 2.3"
	case "cyclonedx", "cdx":
		data, err = cvematch.GenerateCycloneDX(pkgs, *host)
		contentType = "application/vnd.cyclonedx+json"
		suffix = "cyclonedx.json"
		auditFormat = "CycloneDX 1.5"
	default:
		writeError(w, http.StatusBadRequest, "unsupported sbom format")
		return
	}
	if err != nil {
		log.Printf("generate host sbom: %v", err)
		s.audit(r, "sbom.export", "host", hostID, "error", map[string]any{"format": auditFormat, "scan_id": scanID, "error": "generation failed"})
		writeError(w, http.StatusInternalServerError, "sbom generation failed")
		return
	}
	filename := sanitizeFilename(host.Hostname)
	if filename == "" {
		filename = sanitizeFilename(host.ID)
	}
	auditMeta := map[string]any{
		"hostname": host.Hostname,
		"scan_id":  scanID,
		"packages": len(pkgs),
		"format":   auditFormat,
	}
	s.audit(r, "sbom.export", "host", hostID, "started", auditMeta)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s"`, filename, suffix))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(data); err != nil {
		log.Printf("write host sbom: %v", err)
		errMeta := cloneMetadata(auditMeta)
		errMeta["error"] = "response write failed"
		s.audit(r, "sbom.export", "host", hostID, "error", errMeta)
		return
	}
	s.audit(r, "sbom.export", "host", hostID, "ok", auditMeta)
}

func latestPackageScanID(pkgs []models.Package) string {
	for _, pkg := range pkgs {
		if strings.TrimSpace(pkg.ScanID) != "" {
			return strings.TrimSpace(pkg.ScanID)
		}
	}
	return ""
}

func (s *Server) handleHostVulnCounts(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	hostID := r.PathValue("id")
	if !s.canReadHost(r, hostID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	ctx := r.Context()

	counts, err := s.db.GetHostVulnCounts(ctx, hostID)
	if err != nil {
		log.Printf("vuln counts: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, counts)
}

func scopeHostFilter(scope db.AccessScope, visibleHostIDs []string) []string {
	if scope.All {
		return nil
	}
	return visibleHostIDs
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func fallbackHostID(host models.Host) string {
	if temporaryHostIdentity(host.Hostname) && strings.TrimSpace(host.IPAddress) != "" {
		return "ip:" + strings.TrimSpace(host.IPAddress)
	}
	if host.Hostname != "" {
		return "hostname:" + strings.ToLower(strings.TrimSpace(host.Hostname))
	}
	if host.IPAddress != "" {
		return "ip:" + strings.TrimSpace(host.IPAddress)
	}
	return uuid.New().String()
}

func temporaryHostIdentity(hostname string) bool {
	name := strings.ToUpper(strings.TrimSpace(hostname))
	if !strings.HasPrefix(name, "TEMP-") {
		return false
	}
	rest := strings.TrimPrefix(name, "TEMP-")
	if rest == "" {
		return false
	}
	for _, r := range rest {
		if (r < '0' || r > '9') && (r < 'A' || r > 'F') && r != '-' {
			return false
		}
	}
	return true
}
