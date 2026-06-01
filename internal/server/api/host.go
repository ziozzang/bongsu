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
		http.Error(w, "unauthorized", http.StatusUnauthorized)
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
		http.Error(w, "db error", http.StatusInternalServerError)
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
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	hostID := r.PathValue("id")
	if !s.canReadHost(r, hostID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ctx := r.Context()

	host, err := s.db.GetHost(ctx, hostID)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	applyAgentStatus(host, time.Now())
	writeJSON(w, http.StatusOK, host)
}

func (s *Server) handleUpdateHostMetadata(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	hostID := r.PathValue("id")
	if hostID == "" {
		http.Error(w, "host id is required", http.StatusBadRequest)
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
		http.Error(w, "tags must be valid JSON", http.StatusBadRequest)
		return
	}
	if err := s.db.UpdateHostMetadata(r.Context(), hostID, body.Owner, body.Team, body.Environment, body.Criticality, body.Tags); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "host not found", http.StatusNotFound)
			return
		}
		log.Printf("update host metadata: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	host, err := s.db.GetHost(r.Context(), hostID)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
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
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	hostID := r.PathValue("id")
	if hostID == "" {
		http.Error(w, "host id is required", http.StatusBadRequest)
		return
	}
	if _, err := s.db.GetHost(r.Context(), hostID); err != nil {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}
	if err := s.db.ResetHostAgentToken(r.Context(), hostID); err != nil {
		log.Printf("reset host agent token: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	s.audit(r, "host.agent_token.reset", "host", hostID, "ok", map[string]any{
		"host_id": hostID,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleHostPackages(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	hostID := r.PathValue("id")
	if !s.canReadHost(r, hostID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ctx := r.Context()

	limit := limitParam(r, 100)
	offset := offsetParam(r)

	pkgs, total, err := s.db.GetLatestPackages(ctx, hostID, limit, offset)
	if err != nil {
		log.Printf("host packages: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items": pkgs,
		"total": total,
	})
}

func (s *Server) handleHostSBOM(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateExport(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	hostID := r.PathValue("id")
	if !s.exportScope(r).CanReadHost(hostID) {
		s.audit(r, "sbom.export", "host", hostID, "forbidden", map[string]any{"reason": "missing export permission"})
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ctx := r.Context()

	host, err := s.db.GetHost(ctx, hostID)
	if err != nil {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}
	pkgs, err := s.db.GetLatestPackagesForSBOM(ctx, hostID)
	if err != nil {
		log.Printf("host sbom packages: %v", err)
		s.audit(r, "sbom.export", "host", hostID, "error", map[string]any{"error": "package lookup failed"})
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if len(pkgs) == 0 {
		s.audit(r, "sbom.export", "host", hostID, "error", map[string]any{"error": "no packages available"})
		http.Error(w, "no packages available for host", http.StatusNotFound)
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
		http.Error(w, "unsupported sbom format", http.StatusBadRequest)
		return
	}
	if err != nil {
		log.Printf("generate host sbom: %v", err)
		s.audit(r, "sbom.export", "host", hostID, "error", map[string]any{"format": auditFormat, "scan_id": scanID, "error": "generation failed"})
		http.Error(w, "sbom generation failed", http.StatusInternalServerError)
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
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	hostID := r.PathValue("id")
	if !s.canReadHost(r, hostID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ctx := r.Context()

	counts, err := s.db.GetHostVulnCounts(ctx, hostID)
	if err != nil {
		log.Printf("vuln counts: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
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
