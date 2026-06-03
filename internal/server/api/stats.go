package api

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ziozzang/bongsu/internal/server/db"
)

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	ctx := r.Context()
	scope := s.accessScope(r)

	hosts, _ := s.db.ListHosts(ctx)
	vulnCounts, _ := s.db.GetVulnCountsByHost(ctx)
	inventory, err := s.db.GetHostInventorySummaries(ctx)
	if err != nil {
		log.Printf("stats inventory summaries: %v", err)
		inventory = map[string]db.HostInventorySummary{}
	}

	totalVulns := 0
	sevCounts := map[string]int{}
	visibleHosts := 0
	visibleHostIDs := []string{}
	agentStatusCounts := map[string]int{}
	agentVersionCounts := map[string]int{}
	inventoryStatusCounts := map[string]int{}
	totalInventoryPackages := 0
	totalInventoryVulnerabilities := 0
	totalInventoryContainers := 0
	inventoryCoveredHosts := 0
	inventoryFreshHosts := 0
	inventoryStaleAfter := time.Duration(envInt("BONGSU_INVENTORY_STALE_HOURS", 48)) * time.Hour
	now := time.Now()
	for _, h := range hosts {
		if !scope.CanReadHost(h.ID) {
			continue
		}
		applyAgentStatus(&h, now)
		agentStatus := h.AgentStatus
		if agentStatus == "" {
			agentStatus = "unknown"
		}
		agentStatusCounts[agentStatus]++
		version := strings.TrimSpace(h.AgentVersion)
		if version == "" {
			version = "unknown"
		}
		agentVersionCounts[version]++
		summary := inventory[h.ID]
		inventoryStatus := hostInventoryStatus(summary, now, inventoryStaleAfter)
		inventoryStatusCounts[inventoryStatus]++
		if summary.ScanID != "" {
			inventoryCoveredHosts++
		}
		if inventoryStatus == "healthy" || inventoryStatus == "degraded" {
			inventoryFreshHosts++
		}
		totalInventoryPackages += summary.PackageCount
		totalInventoryVulnerabilities += summary.VulnCount
		totalInventoryContainers += summary.ContainerCount
		visibleHosts++
		visibleHostIDs = append(visibleHostIDs, h.ID)
		vc := vulnCounts[h.ID]
		for sev, cnt := range vc {
			totalVulns += cnt
			sevCounts[sev] += cnt
		}
	}
	activeVulnCounts, err := s.db.GetCurrentActionableVulnCountsByHost(ctx, scopeHostFilter(scope, visibleHostIDs))
	if err != nil {
		log.Printf("active vuln status counts: %v", err)
		activeVulnCounts = map[string]map[string]int{}
	}
	activeRiskCountsByHost, err := s.db.GetCurrentActionableVulnRiskCountsByHost(ctx, scopeHostFilter(scope, visibleHostIDs))
	if err != nil {
		log.Printf("active vuln risk counts: %v", err)
		activeRiskCountsByHost = map[string]map[string]int{}
	}
	overdueRiskCountsByHost, err := s.db.GetCurrentActionableOverdueRiskCountsByHost(ctx, scopeHostFilter(scope, visibleHostIDs))
	if err != nil {
		log.Printf("active overdue vuln risk counts: %v", err)
		overdueRiskCountsByHost = map[string]map[string]int{}
	}
	activeTotalVulns := 0
	activeSevCounts := map[string]int{}
	activeRiskCounts := map[string]int{}
	overdueTotalVulns := 0
	overdueRiskCounts := map[string]int{}
	for hostID, vc := range activeVulnCounts {
		if !scope.CanReadHost(hostID) {
			continue
		}
		for sev, cnt := range vc {
			activeTotalVulns += cnt
			activeSevCounts[sev] += cnt
		}
	}
	for hostID, rc := range activeRiskCountsByHost {
		if !scope.CanReadHost(hostID) {
			continue
		}
		for riskLevel, cnt := range rc {
			activeRiskCounts[riskLevel] += cnt
		}
	}
	for hostID, rc := range overdueRiskCountsByHost {
		if !scope.CanReadHost(hostID) {
			continue
		}
		for riskLevel, cnt := range rc {
			overdueTotalVulns += cnt
			overdueRiskCounts[riskLevel] += cnt
		}
	}
	scanRequestCounts, err := s.db.CountScanRequestsByStatus(ctx, visibleHostIDs, scope.All)
	if err != nil {
		log.Printf("scan request status counts: %v", err)
		scanRequestCounts = map[string]int{}
	}
	staleScanRequestCounts, err := s.db.CountStaleScanRequestsByState(ctx, visibleHostIDs, scope.All, scanRequestClaimTimeoutSeconds())
	if err != nil {
		log.Printf("stale scan request counts: %v", err)
		staleScanRequestCounts = map[string]int{}
	}
	securityDBRevision := ""
	securityDBRescanCounts := map[string]int{}
	securityDBRescanProgress := map[string]any{}
	var securityDBScanCoverage *db.SecurityDBScanCoverage
	if revision, err := s.db.GetSecurityDBRevision(ctx); err != nil {
		log.Printf("security db revision stats: %v", err)
	} else {
		securityDBRevision = revision
		if counts, err := s.db.CountSecurityDBRescanRequestsByStatus(ctx, visibleHostIDs, scope.All, revision); err != nil {
			log.Printf("security db rescan status counts: %v", err)
		} else {
			securityDBRescanCounts = counts
			securityDBRescanProgress = securityDBRescanProgressSummary(revision, counts)
		}
		if coverage, err := s.db.GetSecurityDBScanCoverage(ctx, visibleHostIDs, scope.All, revision); err != nil {
			log.Printf("security db scan coverage: %v", err)
		} else {
			securityDBScanCoverage = coverage
		}
	}

	resp := map[string]any{
		"total_hosts":                       visibleHosts,
		"total_vulnerabilities":             totalVulns,
		"severity_counts":                   sevCounts,
		"agent_status_counts":               agentStatusCounts,
		"agent_version_counts":              agentVersionCounts,
		"latest_agent_version":              binaryVersion(agentBinaryPath()),
		"inventory_status_counts":           inventoryStatusCounts,
		"inventory_covered_hosts":           inventoryCoveredHosts,
		"inventory_coverage_percent":        percent(inventoryCoveredHosts, visibleHosts),
		"inventory_fresh_hosts":             inventoryFreshHosts,
		"inventory_fresh_percent":           percent(inventoryFreshHosts, visibleHosts),
		"inventory_latest_packages":         totalInventoryPackages,
		"inventory_latest_vulnerabilities":  totalInventoryVulnerabilities,
		"inventory_latest_containers":       totalInventoryContainers,
		"active_vulnerabilities":            activeTotalVulns,
		"active_severity_counts":            activeSevCounts,
		"active_risk_level_counts":          activeRiskCounts,
		"overdue_sla_count":                 overdueTotalVulns,
		"overdue_sla_risk_counts":           overdueRiskCounts,
		"scan_request_counts":               scanRequestCounts,
		"scan_request_stale_counts":         staleScanRequestCounts,
		"security_db_revision":              securityDBRevision,
		"security_db_rescan_request_counts": securityDBRescanCounts,
		"security_db_rescan_progress":       securityDBRescanProgress,
		"security_db_scan_coverage":         securityDBScanCoverage,
	}
	resp["agent_version_drift_counts"] = agentVersionDriftCounts(agentVersionCounts, fmt.Sprint(resp["latest_agent_version"]))
	if s.authenticateAdmin(r) || !s.webAuth {
		triageActiveCounts := map[string]int{}
		triageExpiredCounts := map[string]int{}
		if triageCounts, err := s.db.CountVulnerabilityTriageByStatus(ctx); err != nil {
			log.Printf("triage status counts: %v", err)
		} else {
			for _, count := range triageCounts {
				if count.State == "expired" {
					triageExpiredCounts[count.Status] += count.Count
				} else {
					triageActiveCounts[count.Status] += count.Count
				}
			}
		}
		triageExpiringSoonDays := envInt("BONGSU_TRIAGE_EXPIRING_SOON_DAYS", 14)
		if triageExpiringSoonDays <= 0 {
			triageExpiringSoonDays = 14
		}
		triageExpiringSoonCounts := map[string]int{}
		if counts, err := s.db.CountVulnerabilityTriageExpiringSoonByStatus(ctx, triageExpiringSoonDays); err != nil {
			log.Printf("triage expiring soon counts: %v", err)
		} else {
			triageExpiringSoonCounts = counts
		}
		resp["triage_active_counts"] = triageActiveCounts
		resp["triage_expired_counts"] = triageExpiredCounts
		resp["triage_expiring_soon_counts"] = triageExpiringSoonCounts
		resp["triage_expiring_soon_days"] = triageExpiringSoonDays
	}
	writeJSON(w, http.StatusOK, resp)
}
