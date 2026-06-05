package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ziozzang/bongsu/internal/server/db"
	"github.com/ziozzang/bongsu/internal/shared/models"
)

func (s *Server) handleAdminMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	metricsTimeout := envInt("BONGSU_ADMIN_METRICS_DB_TIMEOUT_SECONDS", 30)
	if metricsTimeout < 1 {
		metricsTimeout = 1
	}
	if metricsTimeout > 60 {
		metricsTimeout = 60
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(metricsTimeout)*time.Second)
	defer cancel()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	io.WriteString(w, s.adminMetrics(ctx))
}

func (s *Server) adminMetrics(ctx context.Context) string {
	var b strings.Builder
	writePromGauge(&b, "bongsu_build_info", map[string]string{"service": "bongsu"}, 1)
	if s.db != nil {
		stats := s.db.Stats()
		writePromGauge(&b, "bongsu_database_max_open_connections", nil, float64(stats.MaxOpenConnections))
		writePromGauge(&b, "bongsu_database_open_connections", nil, float64(stats.OpenConnections))
		writePromGauge(&b, "bongsu_database_in_use_connections", nil, float64(stats.InUse))
		writePromGauge(&b, "bongsu_database_idle_connections", nil, float64(stats.Idle))
		writePromCounter(&b, "bongsu_database_wait_total", nil, float64(stats.WaitCount))
		writePromCounter(&b, "bongsu_database_wait_duration_seconds_total", nil, stats.WaitDuration.Seconds())
		writePromCounter(&b, "bongsu_database_max_idle_closed_total", nil, float64(stats.MaxIdleClosed))
		writePromCounter(&b, "bongsu_database_max_idle_time_closed_total", nil, float64(stats.MaxIdleTimeClosed))
		writePromCounter(&b, "bongsu_database_max_lifetime_closed_total", nil, float64(stats.MaxLifetimeClosed))
	}
	recalc := s.securityRecalculationStatus(true)
	writePromGauge(&b, "bongsu_security_recalculation_running", nil, boolMetric(recalc["running"]))
	writePromGauge(&b, "bongsu_security_recalculation_pending", nil, boolMetric(recalc["pending"]))
	if last := s.securityRecalculationLastResult(ctx, true); last != nil {
		if ts, ok := last["finished_at_unix"].(float64); ok {
			writePromGauge(&b, "bongsu_security_recalculation_last_finished_timestamp_seconds", nil, ts)
		}
		writePromGauge(&b, "bongsu_security_recalculation_last_error", nil, boolMetric(last["status"] == "error"))
		writePromGauge(&b, "bongsu_security_recalculation_last_cvss_updated", nil, metricNumber(last["cvss_updated"]))
		writePromGauge(&b, "bongsu_security_recalculation_last_findings_enriched", nil, metricNumber(last["findings_enriched"]))
		writePromGauge(&b, "bongsu_security_recalculation_last_stale_rematch_removed", nil, metricNumber(last["stale_rematch_removed"]))
		writePromGauge(&b, "bongsu_security_recalculation_last_stale_rematch_scanned", nil, metricNumber(last["stale_rematch_scanned"]))
		writePromGauge(&b, "bongsu_security_recalculation_last_stale_rematch_batches", nil, metricNumber(last["stale_rematch_batches"]))
		writePromGauge(&b, "bongsu_security_recalculation_last_stale_rematch_batch_size", nil, metricNumber(last["stale_rematch_batch_size"]))
		writePromGauge(&b, "bongsu_security_recalculation_last_rematch_new_vulns", nil, metricNumber(last["rematch_new_vulns"]))
		writePromGauge(&b, "bongsu_security_recalculation_last_rematch_limited", nil, boolMetric(last["rematch_limited"]))
		writePromGauge(&b, "bongsu_security_recalculation_last_rematch_candidates", nil, metricNumber(last["rematch_candidates"]))
		writePromGauge(&b, "bongsu_security_recalculation_last_rematch_scanned_candidates", nil, metricNumber(last["rematch_scanned_candidates"]))
		writePromGauge(&b, "bongsu_security_recalculation_last_rematch_candidate_limit", nil, metricNumber(last["rematch_candidate_limit"]))
		writePromGauge(&b, "bongsu_security_recalculation_last_rematch_eligible_sources", nil, metricNumber(last["rematch_eligible_sources"]))
		writePromGauge(&b, "bongsu_security_recalculation_last_rematch_excluded_sources", nil, metricNumber(last["rematch_excluded_sources"]))
	}
	if last := s.cveDBRematchLastResult(ctx, true); last != nil {
		if ts, ok := last["finished_at_unix"].(float64); ok {
			writePromGauge(&b, "bongsu_cve_db_last_manual_rematch_timestamp_seconds", nil, ts)
		}
		writePromGauge(&b, "bongsu_cve_db_last_manual_rematch_limited", nil, boolMetric(last["limited"]))
		writePromGauge(&b, "bongsu_cve_db_last_manual_rematch_matches", nil, metricNumber(last["matched"]))
		writePromGauge(&b, "bongsu_cve_db_last_manual_rematch_scanned_candidates", nil, metricNumber(last["scanned_candidates"]))
		writePromGauge(&b, "bongsu_cve_db_last_manual_rematch_candidate_limit", nil, metricNumber(last["candidate_limit"]))
		writePromGauge(&b, "bongsu_cve_db_last_manual_rematch_new_vulns", nil, metricNumber(last["new_vulns"]))
		writePromGauge(&b, "bongsu_cve_db_last_manual_rematch_eligible_sources", nil, metricNumber(last["eligible_sources"]))
		writePromGauge(&b, "bongsu_cve_db_last_manual_rematch_excluded_sources", nil, metricNumber(last["excluded_sources"]))
	}
	if last := s.securityDBAutoRescanLastResult(ctx, true); last != nil {
		if ts, ok := last["finished_at_unix"].(float64); ok {
			writePromGauge(&b, "bongsu_security_db_auto_rescan_last_finished_timestamp_seconds", nil, ts)
		}
		writePromGauge(&b, "bongsu_security_db_auto_rescan_last_error", nil, boolMetric(last["status"] == "error"))
		writePromGauge(&b, "bongsu_security_db_auto_rescan_last_disabled", nil, boolMetric(last["status"] == "disabled"))
		writePromGauge(&b, "bongsu_security_db_auto_rescan_last_eligible", nil, metricNumber(last["eligible"]))
		writePromGauge(&b, "bongsu_security_db_auto_rescan_last_queued", nil, metricNumber(last["queued"]))
		writePromGauge(&b, "bongsu_security_db_auto_rescan_last_already_pending", nil, metricNumber(last["already_pending"]))
	}
	if s.dbMgr != nil && s.dbMgr.IsReady() {
		writePromGauge(&b, "bongsu_trivy_db_ready", nil, 1)
	} else {
		writePromGauge(&b, "bongsu_trivy_db_ready", nil, 0)
	}
	if s.secMgr != nil {
		status := s.secMgr.Status()
		writePromGauge(&b, "bongsu_security_db_sync_configured", nil, boolMetric(status["configured"]))
		writePromGauge(&b, "bongsu_security_db_sync_running", nil, boolMetric(status["running"]))
		writePromGauge(&b, "bongsu_security_db_sync_last_error", nil, boolMetric(strings.TrimSpace(fmt.Sprint(status["last_error"])) != ""))
		writePromGauge(&b, "bongsu_security_db_sync_last_attempt_timestamp_seconds", nil, metricTimestamp(status["last_attempt"]))
		writePromGauge(&b, "bongsu_security_db_sync_last_success_timestamp_seconds", nil, metricTimestamp(status["last_sync"]))
		writePromGauge(&b, "bongsu_security_db_sync_next_timestamp_seconds", nil, metricTimestamp(status["next_sync"]))
	}
	agentInstaller := installerBinaryReadiness("bongsu-agent", agentBinaryPath())
	trivyInstaller := installerBinaryReadiness("trivy", trivyBinaryPath())
	writePromGauge(&b, "bongsu_installer_ready", nil, boolMetric(s.installToken != "" && agentInstaller.Ready))
	writePromGauge(&b, "bongsu_installer_install_token_configured", nil, boolMetric(s.installToken != ""))
	writeInstallerBinaryMetrics(&b, agentInstaller)
	writeInstallerBinaryMetrics(&b, trivyInstaller)
	if s.db != nil {
		if hosts, err := s.db.ListHosts(ctx); err == nil {
			agentStatusCounts := map[string]int{}
			agentVersionCounts := map[string]int{}
			now := time.Now()
			for _, host := range hosts {
				applyAgentStatus(&host, now)
				status := host.AgentStatus
				if status == "" {
					status = "unknown"
				}
				version := strings.TrimSpace(host.AgentVersion)
				if version == "" {
					version = "unknown"
				}
				agentStatusCounts[status]++
				agentVersionCounts[version]++
			}
			for _, status := range []string{"online", "stale", "offline", "unknown"} {
				writePromGauge(&b, "bongsu_agent_hosts", map[string]string{"status": status}, float64(agentStatusCounts[status]))
			}
			for version, count := range agentVersionCounts {
				writePromGauge(&b, "bongsu_agent_version_hosts", map[string]string{"version": version}, float64(count))
			}
			latestVersion := agentInstaller.Version
			if latestVersion == "" {
				latestVersion = binaryVersion(agentBinaryPath())
			}
			driftCounts := agentVersionDriftCounts(agentVersionCounts, latestVersion)
			for state, count := range driftCounts {
				writePromGauge(&b, "bongsu_agent_version_drift_hosts", map[string]string{"state": state}, float64(count))
			}
			staleScanRequestCounts := map[string]int{}
			if counts, err := s.db.CountStaleScanRequestsByState(ctx, nil, true, scanRequestClaimTimeoutSeconds()); err == nil {
				staleScanRequestCounts = counts
			}
			securityDBRescanStaleCounts := map[string]int{}
			if revision, err := s.db.GetSecurityDBRevision(ctx); err == nil {
				if counts, err := s.db.CountStaleSecurityDBRescanRequestsByState(ctx, nil, true, revision, scanRequestClaimTimeoutSeconds()); err == nil {
					securityDBRescanStaleCounts = counts
				}
			}
			fleetStatus, warnings, _ := agentFleetOperationalStatus(len(hosts), agentStatusCounts, driftCounts, staleScanRequestCounts, securityDBRescanStaleCounts, s.installToken != "", agentInstaller, trivyInstaller)
			writePromGauge(&b, "bongsu_agent_fleet_degraded", nil, boolMetric(fleetStatus != "ok"))
			writePromGauge(&b, "bongsu_agent_fleet_warnings", nil, float64(len(warnings)))
			writePromGauge(&b, "bongsu_agent_fleet_total_hosts", nil, float64(len(hosts)))
			writePromGauge(&b, "bongsu_agent_outdated_percent", nil, percent(driftCounts["outdated"], len(hosts)))
		} else {
			writePromGauge(&b, "bongsu_agent_metrics_error", nil, 1)
		}
		if hosts, err := s.db.ListHosts(ctx); err == nil {
			inventoryStaleAfter := time.Duration(envInt("BONGSU_INVENTORY_STALE_HOURS", 48)) * time.Hour
			inventory, err := s.db.GetHostInventorySummaries(ctx)
			if err == nil {
				inventoryStatusCounts := map[string]int{}
				totalPackages := 0
				totalVulns := 0
				totalContainers := 0
				now := time.Now()
				for _, host := range hosts {
					summary := inventory[host.ID]
					status := hostInventoryStatus(summary, now, inventoryStaleAfter)
					inventoryStatusCounts[status]++
					totalPackages += summary.PackageCount
					totalVulns += summary.VulnCount
					totalContainers += summary.ContainerCount
				}
				for _, status := range []string{"healthy", "degraded", "stale", "empty", "none"} {
					writePromGauge(&b, "bongsu_inventory_hosts", map[string]string{"status": status}, float64(inventoryStatusCounts[status]))
				}
				writePromGauge(&b, "bongsu_inventory_latest_packages", nil, float64(totalPackages))
				writePromGauge(&b, "bongsu_inventory_latest_vulnerabilities", nil, float64(totalVulns))
				writePromGauge(&b, "bongsu_inventory_latest_containers", nil, float64(totalContainers))
			} else {
				writePromGauge(&b, "bongsu_inventory_metrics_error", nil, 1)
			}
		} else {
			writePromGauge(&b, "bongsu_inventory_metrics_error", nil, 1)
		}
		triageExpiringSoonDays := envInt("BONGSU_TRIAGE_EXPIRING_SOON_DAYS", 14)
		if triageExpiringSoonDays <= 0 {
			triageExpiringSoonDays = 14
		}
		writePromGauge(&b, "bongsu_vulnerability_triage_expiring_soon_days", nil, float64(triageExpiringSoonDays))
		if triageCounts, err := s.db.CountVulnerabilityTriageByStatus(ctx); err == nil {
			for _, count := range triageCounts {
				writePromGauge(&b, "bongsu_vulnerability_triage_decisions", map[string]string{"status": count.Status, "state": count.State}, float64(count.Count))
			}
		} else {
			writePromGauge(&b, "bongsu_vulnerability_triage_metrics_error", nil, 1)
		}
		if expiringCounts, err := s.db.CountVulnerabilityTriageExpiringSoonByStatus(ctx, triageExpiringSoonDays); err == nil {
			for _, status := range []string{"open", "in_progress", "accepted_risk", "false_positive", "fixed", "ignored"} {
				writePromGauge(&b, "bongsu_vulnerability_triage_expiring_soon", map[string]string{"status": status}, float64(expiringCounts[status]))
			}
		} else {
			writePromGauge(&b, "bongsu_vulnerability_triage_expiring_soon_metrics_error", nil, 1)
		}
		if riskCountsByHost, err := s.db.GetCurrentActionableVulnRiskCountsByHost(ctx, nil); err == nil {
			activeRiskCounts := map[string]int{}
			for _, counts := range riskCountsByHost {
				for riskLevel, count := range counts {
					activeRiskCounts[riskLevel] += count
				}
			}
			for _, riskLevel := range []string{"critical", "high", "medium", "low"} {
				writePromGauge(&b, "bongsu_active_vulnerabilities_by_risk_level", map[string]string{"risk_level": riskLevel}, float64(activeRiskCounts[riskLevel]))
			}
		} else {
			writePromGauge(&b, "bongsu_active_vulnerability_risk_metrics_error", nil, 1)
		}
		if overdueCountsByHost, err := s.db.GetCurrentActionableOverdueRiskCountsByHost(ctx, nil); err == nil {
			overdueRiskCounts := map[string]int{}
			for _, counts := range overdueCountsByHost {
				for riskLevel, count := range counts {
					overdueRiskCounts[riskLevel] += count
				}
			}
			for _, riskLevel := range []string{"critical", "high", "medium", "low"} {
				writePromGauge(&b, "bongsu_overdue_sla_vulnerabilities_by_risk_level", map[string]string{"risk_level": riskLevel}, float64(overdueRiskCounts[riskLevel]))
			}
		} else {
			writePromGauge(&b, "bongsu_overdue_sla_vulnerability_risk_metrics_error", nil, 1)
		}
		freshness := s.securityDBFreshnessStatus(ctx, true)
		effectiveStatus := strings.TrimSpace(fmt.Sprint(freshness["status"]))
		for _, status := range []string{"ok", "stale", "missing_sources", "empty", "error", "unavailable"} {
			writePromGauge(&b, "bongsu_security_db_effective_status", map[string]string{"status": status}, boolMetric(effectiveStatus == status))
		}
		if effectiveSource := strings.TrimSpace(fmt.Sprint(freshness["latest_source"])); effectiveSource != "" {
			writePromGauge(&b, "bongsu_security_db_effective_source_info", map[string]string{"source": effectiveSource}, 1)
		}
		writePromGauge(&b, "bongsu_security_db_effective_last_sync_timestamp_seconds", nil, metricTimestamp(freshness["latest_last_update"]))
		writePromGauge(&b, "bongsu_security_db_sync_persisted_last_success_timestamp_seconds", nil, metricTimestamp(freshness["latest_last_update"]))
		writePromGauge(&b, "bongsu_security_db_effective_age_seconds", nil, metricNumber(freshness["latest_age_seconds"]))
		writePromGauge(&b, "bongsu_security_db_source_stale", nil, boolMetric(freshness["stale"]))
		if count, ok := freshness["source_count"].(int); ok {
			writePromGauge(&b, "bongsu_security_db_source_count", nil, float64(count))
		}
		if missing, ok := freshness["missing_sources"].([]string); ok {
			writePromGauge(&b, "bongsu_security_db_required_source_missing_count", nil, float64(len(missing)))
			for _, source := range missing {
				writePromGauge(&b, "bongsu_security_db_required_source_missing", map[string]string{"source": source}, 1)
			}
		}
		if oldestAge, ok := freshness["oldest_age_seconds"].(float64); ok {
			writePromGauge(&b, "bongsu_security_db_source_oldest_age_seconds", nil, oldestAge)
		}
		if status, _ := freshness["status"].(string); status == "error" {
			writePromGauge(&b, "bongsu_security_db_freshness_metrics_error", nil, 1)
		}
		if registrySources, err := s.db.ListSecuritySourceStatuses(ctx); err == nil {
			enabledCount := 0
			okCount := 0
			exportStaleCount := 0
			totalRegistryRecords := int64(0)
			for _, source := range registrySources {
				labels := map[string]string{
					"source":   source.ID,
					"category": source.Category,
					"status":   source.LastStatus,
				}
				if source.Enabled {
					enabledCount++
				}
				if source.Enabled && source.LastStatus == "ok" && source.RecordCount > 0 && source.LastError == "" {
					okCount++
				}
				totalRegistryRecords += source.RecordCount
				writePromGauge(&b, "bongsu_security_source_registry_enabled", labels, boolMetric(source.Enabled))
				writePromGauge(&b, "bongsu_security_source_registry_ok", labels, boolMetric(source.Enabled && source.LastStatus == "ok" && source.RecordCount > 0 && source.LastError == ""))
				writePromGauge(&b, "bongsu_security_source_registry_records", labels, float64(source.RecordCount))
				writePromGauge(&b, "bongsu_security_source_registry_error", labels, boolMetric(source.LastError != "" || source.LastStatus == "error"))
				if source.LastSyncFinishedAt != nil {
					writePromGauge(&b, "bongsu_security_source_registry_last_sync_timestamp_seconds", labels, float64(source.LastSyncFinishedAt.Unix()))
					writePromGauge(&b, "bongsu_security_source_registry_age_seconds", labels, time.Since(*source.LastSyncFinishedAt).Seconds())
				}
				if source.LastExportedAt != nil {
					writePromGauge(&b, "bongsu_security_source_registry_last_export_timestamp_seconds", labels, float64(source.LastExportedAt.Unix()))
					writePromGauge(&b, "bongsu_security_source_registry_export_age_seconds", labels, time.Since(*source.LastExportedAt).Seconds())
				}
				exportStale := source.Enabled && source.LastSyncFinishedAt != nil && (source.LastExportedAt == nil || source.LastExportedAt.Before(*source.LastSyncFinishedAt))
				if exportStale {
					exportStaleCount++
				}
				writePromGauge(&b, "bongsu_security_source_registry_export_stale", labels, boolMetric(exportStale))
			}
			writePromGauge(&b, "bongsu_security_source_registry_sources", nil, float64(len(registrySources)))
			writePromGauge(&b, "bongsu_security_source_registry_enabled_sources", nil, float64(enabledCount))
			writePromGauge(&b, "bongsu_security_source_registry_ok_sources", nil, float64(okCount))
			writePromGauge(&b, "bongsu_security_source_registry_records_total", nil, float64(totalRegistryRecords))
			writePromGauge(&b, "bongsu_security_source_registry_export_stale_sources", nil, float64(exportStaleCount))
		} else {
			writePromGauge(&b, "bongsu_security_source_registry_metrics_error", nil, 1)
		}
		totalRecords := 0
		totalMatchable := 0
		eligibleSources := 0
		excludedSources := 0
		if sourceStats, err := s.db.GetCveSourceStats(ctx); err == nil {
			rematchPolicy, eligible, excluded := rematchSourcePolicySummary(sourceStats, rematchOptionsFromEnv())
			eligibleSources = eligible
			excludedSources = excluded
			for _, stat := range sourceStats {
				totalRecords += stat.Count
				totalMatchable += stat.Matchable
				labels := map[string]string{"source": stat.Source}
				writePromGauge(&b, "bongsu_security_db_source_records", labels, float64(stat.Count))
				writePromGauge(&b, "bongsu_security_db_source_matchable_records", labels, float64(stat.Matchable))
				writePromGauge(&b, "bongsu_security_db_source_matchable_percent", labels, stat.MatchablePercent)
				writePromGauge(&b, "bongsu_security_db_source_with_ecosystem_records", labels, float64(stat.WithEcosystem))
				writePromGauge(&b, "bongsu_security_db_source_with_fixed_records", labels, float64(stat.WithFixed))
				writePromGauge(&b, "bongsu_security_db_source_with_ranges_records", labels, float64(stat.WithRanges))
				writePromGauge(&b, "bongsu_security_db_source_with_cvss_records", labels, float64(stat.WithCVSS))
				writePromGauge(&b, "bongsu_security_db_source_rematch_eligible", labels, boolMetric(rematchPolicy[stat.Source]["eligible"]))
			}
		} else {
			writePromGauge(&b, "bongsu_security_db_source_quality_metrics_error", nil, 1)
		}
		if osvEcosystems, err := s.db.GetCveOsvEcosystemStats(ctx, 100); err == nil {
			for _, stat := range osvEcosystems {
				labels := map[string]string{"ecosystem": stat.Ecosystem}
				writePromGauge(&b, "bongsu_cve_osv_ecosystem_indexed_rows", labels, float64(stat.IndexedRows))
				writePromGauge(&b, "bongsu_cve_osv_ecosystem_matchable_cves", labels, float64(stat.MatchableCVEs))
				if stat.LastUpdate != nil {
					writePromGauge(&b, "bongsu_cve_osv_ecosystem_last_update_timestamp_seconds", labels, float64(stat.LastUpdate.Unix()))
				}
			}
		} else {
			writePromGauge(&b, "bongsu_cve_osv_ecosystem_metrics_error", nil, 1)
		}
		var indexStats *db.CveAffectedPackageIndexStats
		var indexErr error
		if indexStats, indexErr = s.db.GetCveAffectedPackageIndexStats(ctx); indexErr == nil {
			writePromGauge(&b, "bongsu_cve_affected_package_index_records", nil, float64(indexStats.Count))
			writePromGauge(&b, "bongsu_cve_affected_package_index_sources", nil, float64(indexStats.SourceCount))
			writePromGauge(&b, "bongsu_cve_affected_package_index_indexed_cves", nil, float64(indexStats.IndexedCVEs))
			writePromGauge(&b, "bongsu_cve_affected_package_index_matchable_cves", nil, float64(indexStats.MatchableCVEs))
			writePromGauge(&b, "bongsu_cve_affected_package_index_coverage_percent", nil, indexStats.CoveragePercent)
			writePromGauge(&b, "bongsu_cve_affected_package_index_missing_matchable_sources", nil, float64(len(indexStats.MissingMatchableSources)))
			writePromGauge(&b, "bongsu_cve_affected_package_index_orphans", nil, float64(indexStats.Orphans))
			writePromGauge(&b, "bongsu_cve_affected_package_index_stale", nil, boolMetric(indexStats.Stale))
			if indexStats.LastUpdate != nil {
				writePromGauge(&b, "bongsu_cve_affected_package_index_last_update_timestamp_seconds", nil, float64(indexStats.LastUpdate.Unix()))
			}
			if indexStats.LatestMatchableUpdate != nil {
				writePromGauge(&b, "bongsu_cve_affected_package_index_latest_matchable_update_timestamp_seconds", nil, float64(indexStats.LatestMatchableUpdate.Unix()))
			}
		} else {
			writePromGauge(&b, "bongsu_cve_affected_package_index_metrics_error", nil, 1)
		}
		var referenceIndexStats *db.CveReferenceKeyIndexStats
		var referenceIndexErr error
		if referenceIndexStats, referenceIndexErr = s.db.GetCveReferenceKeyIndexStats(ctx); referenceIndexErr == nil {
			writePromGauge(&b, "bongsu_cve_reference_key_index_records", nil, float64(referenceIndexStats.Count))
			writePromGauge(&b, "bongsu_cve_reference_key_index_indexed_cves", nil, float64(referenceIndexStats.IndexedCVEs))
			writePromGauge(&b, "bongsu_cve_reference_key_index_total_cves", nil, float64(referenceIndexStats.TotalCVEs))
			writePromGauge(&b, "bongsu_cve_reference_key_index_canonical_cves", nil, float64(referenceIndexStats.CanonicalCVEs))
			writePromGauge(&b, "bongsu_cve_reference_key_index_vendor_keys", nil, float64(referenceIndexStats.VendorKeys))
			writePromGauge(&b, "bongsu_cve_reference_key_index_repository_keys", nil, float64(referenceIndexStats.RepositoryKeys))
			writePromGauge(&b, "bongsu_cve_reference_key_index_coverage_percent", nil, referenceIndexStats.CoveragePercent)
			writePromGauge(&b, "bongsu_cve_reference_key_index_orphans", nil, float64(referenceIndexStats.Orphans))
			writePromGauge(&b, "bongsu_cve_reference_key_index_stale", nil, boolMetric(referenceIndexStats.Stale))
			if referenceIndexStats.LastUpdate != nil {
				writePromGauge(&b, "bongsu_cve_reference_key_index_last_update_timestamp_seconds", nil, float64(referenceIndexStats.LastUpdate.Unix()))
			}
			if referenceIndexStats.LatestCVEUpdate != nil {
				writePromGauge(&b, "bongsu_cve_reference_key_index_latest_cve_update_timestamp_seconds", nil, float64(referenceIndexStats.LatestCVEUpdate.Unix()))
			}
		} else {
			writePromGauge(&b, "bongsu_cve_reference_key_index_metrics_error", nil, 1)
		}
		var epssStats *db.CveEPSSMergeStats
		var epssErr error
		if epssStats, epssErr = s.db.GetCveEPSSMergeStats(ctx); epssErr == nil {
			writePromGauge(&b, "bongsu_cve_epss_records", nil, float64(epssStats.EPSSRecords))
			writePromGauge(&b, "bongsu_cve_epss_cves", nil, float64(epssStats.EPSSCVEs))
			writePromGauge(&b, "bongsu_cve_epss_matched_cves", nil, float64(epssStats.MatchedCVEs))
			writePromGauge(&b, "bongsu_cve_epss_unmatched_cves", nil, float64(epssStats.UnmatchedCVEs))
			writePromGauge(&b, "bongsu_cve_epss_non_epss_cves", nil, float64(epssStats.NonEPSSCVEs))
			writePromGauge(&b, "bongsu_cve_epss_non_epss_cves_with_epss", nil, float64(epssStats.NonEPSSCVEsWithEPSS))
			writePromGauge(&b, "bongsu_cve_epss_non_epss_coverage_percent", nil, epssStats.NonEPSSCoveragePercent)
			writePromGauge(&b, "bongsu_cve_epss_enriched_records", nil, float64(epssStats.EnrichedRecords))
			writePromGauge(&b, "bongsu_cve_epss_enriched_cves", nil, float64(epssStats.EnrichedCVEs))
			writePromGauge(&b, "bongsu_cve_epss_enriched_sources", nil, float64(epssStats.EnrichedSourceCount))
			writePromGauge(&b, "bongsu_cve_epss_merge_coverage_percent", nil, epssStats.MergeCoveragePercent)
			writePromGauge(&b, "bongsu_cve_epss_universe_match_percent", nil, epssStats.EPSSUniverseMatchPercent)
			writePromGauge(&b, "bongsu_cve_epss_loaded_without_enrichment", nil, boolMetric(epssStats.EPSSCVEs > 0 && epssStats.EnrichedRecords == 0))
		} else {
			writePromGauge(&b, "bongsu_cve_epss_merge_metrics_error", nil, 1)
		}
		placeholderStats, placeholderErr := s.db.GetCvePlaceholderStats(ctx)
		quality := buildCveDBQualitySummary(cveDBQualityInput{
			TotalRecords:          totalRecords,
			TotalMatchable:        totalMatchable,
			EligibleSources:       eligibleSources,
			ExcludedSources:       excludedSources,
			Placeholders:          placeholderStats,
			AffectedIndex:         indexStats,
			ReferenceIndex:        referenceIndexStats,
			EPSS:                  epssStats,
			AffectedIndexError:    indexErr,
			ReferenceIndexError:   referenceIndexErr,
			EPSSMergeError:        epssErr,
			PlaceholderStatsError: placeholderErr,
		})
		if quality != nil {
			writePromGauge(&b, "bongsu_cve_db_quality_status", map[string]string{"status": "ok"}, boolMetric(quality["status"] == "ok"))
			writePromGauge(&b, "bongsu_cve_db_quality_status", map[string]string{"status": "warning"}, boolMetric(quality["status"] == "warning"))
			writePromGauge(&b, "bongsu_cve_db_quality_status", map[string]string{"status": "degraded"}, boolMetric(quality["status"] == "degraded"))
			writePromGauge(&b, "bongsu_cve_db_quality_warning_count", nil, metricNumber(quality["warning_count"]))
			writePromGauge(&b, "bongsu_cve_db_temporary_placeholders", nil, metricNumber(quality["temporary_placeholders"]))
			writePromGauge(&b, "bongsu_cve_db_empty_vulnerability_ids", nil, metricNumber(quality["empty_vulnerability_ids"]))
		} else {
			writePromGauge(&b, "bongsu_cve_db_quality_metrics_error", nil, 1)
		}
		if revision, err := s.db.GetSecurityDBRevision(ctx); err == nil {
			writePromGauge(&b, "bongsu_security_db_revision_info", map[string]string{"revision": revision}, 1)
			if counts, err := s.db.CountSecurityDBRescanRequestsByStatus(ctx, nil, true, revision); err == nil {
				for _, status := range []string{"pending", "claimed", "completed", "degraded", "failed", "cancelled"} {
					writePromGauge(&b, "bongsu_security_db_rescan_requests", map[string]string{"status": status}, float64(counts[status]))
				}
				if staleCounts, err := s.db.CountStaleSecurityDBRescanRequestsByState(ctx, nil, true, revision, scanRequestClaimTimeoutSeconds()); err == nil {
					for _, state := range []string{"pending", "claimed"} {
						writePromGauge(&b, "bongsu_security_db_rescan_stale", map[string]string{"state": state}, float64(staleCounts[state]))
					}
				} else {
					writePromGauge(&b, "bongsu_security_db_rescan_stale_metrics_error", nil, 1)
				}
				progress := securityDBRescanProgressSummary(revision, counts)
				writePromGauge(&b, "bongsu_security_db_rescan_total", nil, metricNumber(progress["total"]))
				writePromGauge(&b, "bongsu_security_db_rescan_open", nil, metricNumber(progress["open"]))
				writePromGauge(&b, "bongsu_security_db_rescan_terminal", nil, metricNumber(progress["terminal"]))
				writePromGauge(&b, "bongsu_security_db_rescan_complete_percent", nil, metricNumber(progress["complete_percent"]))
				writePromGauge(&b, "bongsu_security_db_rescan_healthy_percent", nil, metricNumber(progress["healthy_percent"]))
				if coverage, err := s.db.GetSecurityDBScanCoverage(ctx, nil, true, revision); err == nil {
					writePromGauge(&b, "bongsu_security_db_scan_coverage_hosts_total", nil, float64(coverage.TotalHosts))
					writePromGauge(&b, "bongsu_security_db_scan_coverage_current_hosts", nil, float64(coverage.CurrentHosts))
					writePromGauge(&b, "bongsu_security_db_scan_coverage_stale_hosts", nil, float64(coverage.StaleHosts))
					writePromGauge(&b, "bongsu_security_db_scan_coverage_unknown_hosts", nil, float64(coverage.UnknownHosts))
					writePromGauge(&b, "bongsu_security_db_scan_coverage_no_scan_hosts", nil, float64(coverage.NoScanHosts))
					writePromGauge(&b, "bongsu_security_db_scan_coverage_percent", nil, coverage.CoveragePercent)
				} else {
					writePromGauge(&b, "bongsu_security_db_scan_coverage_metrics_error", nil, 1)
				}
			} else {
				writePromGauge(&b, "bongsu_security_db_rescan_metrics_error", nil, 1)
			}
		} else {
			writePromGauge(&b, "bongsu_security_db_revision_metrics_error", nil, 1)
		}
		if counts, err := s.db.CountStaleScanRequestsByState(ctx, nil, true, scanRequestClaimTimeoutSeconds()); err == nil {
			for _, state := range []string{"pending", "claimed"} {
				writePromGauge(&b, "bongsu_scan_request_stale", map[string]string{"state": state}, float64(counts[state]))
			}
		} else {
			writePromGauge(&b, "bongsu_scan_request_stale_metrics_error", nil, 1)
		}
	}
	return b.String()
}

func writeInstallerBinaryMetrics(b *strings.Builder, status installerBinaryStatus) {
	labels := map[string]string{"binary": status.Name}
	writePromGauge(b, "bongsu_installer_binary_ready", labels, boolMetric(status.Ready))
	writePromGauge(b, "bongsu_installer_binary_bytes", labels, float64(status.Bytes))
	if status.Ready {
		infoLabels := map[string]string{
			"binary":  status.Name,
			"version": status.Version,
			"sha256":  status.SHA256,
		}
		writePromGauge(b, "bongsu_installer_binary_info", infoLabels, 1)
	}
	if status.Error != "" {
		writePromGauge(b, "bongsu_installer_binary_error", map[string]string{"binary": status.Name, "error": status.Error}, 1)
	}
}

func boolMetric(v any) float64 {
	if b, ok := v.(bool); ok && b {
		return 1
	}
	return 0
}

func metricNumber(v any) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case float64:
		return n
	case json.Number:
		f, _ := n.Float64()
		return f
	default:
		return 0
	}
}

func metricTimestamp(v any) float64 {
	if t, ok := v.(time.Time); ok && !t.IsZero() {
		return float64(t.Unix())
	}
	if s, ok := v.(string); ok {
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(s)); err == nil && !t.IsZero() {
			return float64(t.Unix())
		}
	}
	return 0
}

func percent(numerator, denominator int) float64 {
	if denominator <= 0 {
		return 0
	}
	return math.Round(float64(numerator)*1000/float64(denominator)) / 10
}

func securityDBRescanProgressSummary(revision string, counts map[string]int) map[string]any {
	pending := counts["pending"]
	claimed := counts["claimed"]
	completed := counts["completed"]
	degraded := counts["degraded"]
	failed := counts["failed"]
	cancelled := counts["cancelled"]
	open := pending + claimed
	terminal := completed + degraded + failed + cancelled
	total := open + terminal
	return map[string]any{
		"revision":         revision,
		"total":            total,
		"open":             open,
		"terminal":         terminal,
		"succeeded":        completed + degraded,
		"failed":           failed,
		"cancelled":        cancelled,
		"complete_percent": percent(terminal, total),
		"healthy_percent":  percent(completed+degraded, total),
	}
}

func writePromGauge(b *strings.Builder, name string, labels map[string]string, value float64) {
	writePromMetric(b, "gauge", name, labels, value)
}

func writePromCounter(b *strings.Builder, name string, labels map[string]string, value float64) {
	writePromMetric(b, "counter", name, labels, value)
}

func writePromMetric(b *strings.Builder, metricType, name string, labels map[string]string, value float64) {
	typeLine := fmt.Sprintf("# TYPE %s %s\n", name, metricType)
	if !promMetricTypeWritten(b, name) {
		b.WriteString(typeLine)
	}
	fmt.Fprint(b, name)
	if len(labels) > 0 {
		keys := make([]string, 0, len(labels))
		for k := range labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(b, "%s=\"%s\"", k, prometheusLabelValue(labels[k]))
		}
		b.WriteByte('}')
	}
	fmt.Fprintf(b, " %g\n", value)
}

func promMetricTypeWritten(b *strings.Builder, name string) bool {
	return strings.Contains(b.String(), "# TYPE "+name+" ")
}

func prometheusLabelValue(v string) string {
	v = strings.ReplaceAll(v, "\\", "\\\\")
	v = strings.ReplaceAll(v, "\n", "\\n")
	return strings.ReplaceAll(v, "\"", "\\\"")
}

func (s *Server) securityRecalculationStatus(includeReason bool) map[string]any {
	s.securityRecalcMu.Lock()
	defer s.securityRecalcMu.Unlock()
	status := map[string]any{
		"running": s.securityRecalcRunning,
		"pending": s.securityRecalcPending,
	}
	if includeReason && s.securityRecalcReason != "" {
		status["pending_reason"] = s.securityRecalcReason
	}
	return status
}

func (s *Server) securityRecalculationLastResult(ctx context.Context, includeDetails bool) map[string]any {
	if s.db == nil {
		return nil
	}
	item, err := s.db.GetLatestAuditLog(ctx, db.AuditLogFilter{
		Action:       "security_db.recalculation",
		ResourceType: "security_db",
		ResourceID:   "aggregate",
	}, []string{"started", "queued"})
	if err != nil {
		if includeDetails {
			return map[string]any{"status": "error", "error": err.Error()}
		}
		return nil
	}
	if item == nil {
		return nil
	}
	meta := map[string]any{}
	if len(item.Metadata) > 0 {
		_ = json.Unmarshal(item.Metadata, &meta)
	}
	out := map[string]any{
		"status":           item.Status,
		"finished_at":      item.CreatedAt.Format(time.RFC3339),
		"finished_at_unix": float64(item.CreatedAt.Unix()),
	}
	if reason, _ := meta["reason"].(string); reason != "" {
		out["reason"] = reason
	}
	for _, key := range []string{
		"security_db_revision",
		"cvss_updated",
		"findings_enriched",
		"stale_rematch_removed",
		"stale_rematch_scanned",
		"stale_rematch_batches",
		"stale_rematch_batch_size",
		"rematch_candidates",
		"rematch_scanned_candidates",
		"rematch_new_vulns",
		"rematch_skipped",
		"rematch_limited",
		"rematch_candidate_limit",
		"rematch_eligible_sources",
		"rematch_excluded_sources",
		"severity_normalized",
	} {
		if v, ok := meta[key]; ok {
			out[key] = v
		}
	}
	if includeDetails {
		if errors, ok := meta["errors"]; ok {
			out["errors"] = errors
		}
		if policy, ok := meta["rematch_source_policy"]; ok {
			out["rematch_source_policy"] = policy
		}
	}
	return out
}

func (s *Server) securityDBBundleImportLastResult(ctx context.Context, includeDetails bool) map[string]any {
	if s.db == nil {
		return nil
	}
	item, err := s.db.GetLatestAuditLog(ctx, db.AuditLogFilter{
		Action:       "security_db.import",
		ResourceType: "security_db",
		ResourceID:   "bundle",
	}, nil)
	if err != nil {
		if includeDetails {
			return map[string]any{"status": "error", "error": err.Error()}
		}
		return nil
	}
	if item == nil {
		return nil
	}
	meta := map[string]any{}
	if len(item.Metadata) > 0 {
		_ = json.Unmarshal(item.Metadata, &meta)
	}
	out := map[string]any{
		"status":           item.Status,
		"finished_at":      item.CreatedAt.Format(time.RFC3339),
		"finished_at_unix": float64(item.CreatedAt.Unix()),
	}
	for _, key := range []string{
		"stage",
		"message",
		"imported",
		"trivy_db_loaded",
		"security_db_revision",
		"bundle_created_at",
		"bundle_source_count",
		"bundle_cve_records",
		"bundle_trivy_db_included",
	} {
		if v, ok := meta[key]; ok {
			out[key] = v
		}
	}
	if includeDetails {
		if errText, ok := meta["error"]; ok {
			out["error"] = errText
		}
	}
	return out
}

func (s *Server) securityDBAutoRescanLastResult(ctx context.Context, includeDetails bool) map[string]any {
	if s.db == nil {
		return nil
	}
	item, err := s.db.GetLatestAuditLog(ctx, db.AuditLogFilter{
		Action:       "security_db.auto_rescan",
		ResourceType: "scan_request",
		ResourceID:   "security-db-update",
	}, nil)
	if err != nil {
		if includeDetails {
			return map[string]any{"status": "error", "error": err.Error()}
		}
		return nil
	}
	if item == nil {
		return nil
	}
	meta := map[string]any{}
	if len(item.Metadata) > 0 {
		_ = json.Unmarshal(item.Metadata, &meta)
	}
	out := map[string]any{
		"status":           item.Status,
		"finished_at":      item.CreatedAt.Format(time.RFC3339),
		"finished_at_unix": float64(item.CreatedAt.Unix()),
	}
	for _, key := range []string{
		"reason",
		"recalculation_status",
		"eligible",
		"queued",
		"already_pending",
		"security_db_revision",
		"last_seen_hours",
		"stage",
	} {
		if v, ok := meta[key]; ok {
			out[key] = v
		}
	}
	if includeDetails {
		for _, key := range []string{"last_seen_after", "error"} {
			if v, ok := meta[key]; ok {
				out[key] = v
			}
		}
	}
	return out
}

func (s *Server) referenceIndexRebuildStatus() map[string]any {
	s.referenceIndexMu.Lock()
	defer s.referenceIndexMu.Unlock()
	status := map[string]any{
		"running":         s.referenceIndexRunning,
		"timeout_seconds": envInt("BONGSU_CVE_REFERENCE_INDEX_REBUILD_TIMEOUT_SECONDS", 900),
	}
	if s.referenceIndexRunning && !s.referenceIndexStartedAt.IsZero() {
		status["started_at"] = s.referenceIndexStartedAt.UTC().Format(time.RFC3339)
		status["duration_ms"] = time.Since(s.referenceIndexStartedAt).Milliseconds()
	}
	if s.referenceIndexLast != nil {
		status["last_result"] = cloneMap(s.referenceIndexLast)
	}
	return status
}

func (s *Server) affectedIndexRebuildStatus() map[string]any {
	s.affectedIndexMu.Lock()
	defer s.affectedIndexMu.Unlock()
	status := map[string]any{
		"running":         s.affectedIndexRunning,
		"timeout_seconds": envInt("BONGSU_CVE_AFFECTED_INDEX_REBUILD_TIMEOUT_SECONDS", 900),
	}
	if s.affectedIndexRunning && !s.affectedIndexStartedAt.IsZero() {
		status["started_at"] = s.affectedIndexStartedAt.UTC().Format(time.RFC3339)
		status["duration_ms"] = time.Since(s.affectedIndexStartedAt).Milliseconds()
	}
	if s.affectedIndexLast != nil {
		status["last_result"] = cloneMap(s.affectedIndexLast)
	}
	return status
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (s *Server) cveDBRematchLastResult(ctx context.Context, includeDetails bool) map[string]any {
	if s.db == nil {
		return nil
	}
	item, err := s.db.GetLatestAuditLog(ctx, db.AuditLogFilter{
		Action:       "cve_db.rematch",
		ResourceType: "cve_db",
		ResourceID:   "all",
	}, []string{"started", "queued"})
	if err != nil {
		if includeDetails {
			return map[string]any{"status": "error", "error": err.Error()}
		}
		return nil
	}
	if item == nil {
		return nil
	}
	meta := map[string]any{}
	if len(item.Metadata) > 0 {
		_ = json.Unmarshal(item.Metadata, &meta)
	}
	out := map[string]any{
		"status":           item.Status,
		"finished_at":      item.CreatedAt.Format(time.RFC3339),
		"finished_at_unix": float64(item.CreatedAt.Unix()),
	}
	for _, key := range []string{
		"matched",
		"new_vulns",
		"skipped",
		"scanned_candidates",
		"candidate_limit",
		"limited",
		"eligible_sources",
		"excluded_sources",
		"security_db_revision",
	} {
		if v, ok := meta[key]; ok {
			out[key] = v
		}
	}
	if includeDetails {
		if sources, ok := meta["sources"]; ok {
			out["sources"] = sources
		}
		if minQuality, ok := meta["min_source_matchable_percent"]; ok {
			out["min_source_matchable_percent"] = minQuality
		}
		if scanID, ok := meta["scan_id"]; ok {
			out["scan_id"] = scanID
		}
		if policy, ok := meta["source_policy"]; ok {
			out["source_policy"] = policy
		}
		if errMsg, _ := meta["security_db_revision_error"].(string); errMsg != "" {
			out["security_db_revision_error"] = errMsg
		}
	}
	return out
}

func (s *Server) handleRetentionPrune(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var body struct {
		DryRun      *bool `json:"dry_run"`
		ScanDays    int   `json:"scan_days"`
		RequestDays int   `json:"request_days"`
		AuditDays   int   `json:"audit_days"`
	}
	if err := decodeJSONBody(w, r, &body, true); err != nil {
		writeJSONBodyError(w, err, "invalid request body")
		return
	}
	if body.ScanDays <= 0 {
		body.ScanDays = envInt("BONGSU_RETENTION_SCAN_DAYS", 180)
	}
	if body.ScanDays <= 0 {
		body.ScanDays = 180
	}
	if body.RequestDays <= 0 {
		body.RequestDays = envInt("BONGSU_RETENTION_SCAN_REQUEST_DAYS", 90)
	}
	if body.RequestDays <= 0 {
		body.RequestDays = 90
	}
	if body.AuditDays <= 0 {
		body.AuditDays = envInt("BONGSU_RETENTION_AUDIT_DAYS", 365)
	}
	if body.AuditDays <= 0 {
		body.AuditDays = 365
	}
	dryRun := true
	if body.DryRun != nil {
		dryRun = *body.DryRun
	}
	result, err := s.db.PruneOperationalData(r.Context(), body.ScanDays, body.RequestDays, body.AuditDays, dryRun)
	if err != nil {
		log.Printf("retention prune: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	status := "dry_run"
	if !dryRun {
		status = "pruned"
	}
	s.audit(r, "retention.prune", "retention", "operational_data", status, map[string]any{
		"dry_run":         result.DryRun,
		"scan_days":       result.ScanDays,
		"request_days":    result.RequestDays,
		"audit_days":      result.AuditDays,
		"scan_cutoff":     result.ScanCutoff,
		"request_cutoff":  result.RequestCutoff,
		"audit_cutoff":    result.AuditCutoff,
		"scans":           result.Scans,
		"packages":        result.Packages,
		"vulnerabilities": result.Vulns,
		"containers":      result.Containers,
		"users":           result.Users,
		"processes":       result.Processes,
		"ports":           result.Ports,
		"scan_requests":   result.Requests,
		"audit_logs":      result.AuditLogs,
	})
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleUpsertAccessSubject(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var body struct {
		ID          string `json:"id"`
		SubjectType string `json:"subject_type"`
		ExternalID  string `json:"external_id"`
		DisplayName string `json:"display_name"`
	}
	if err := decodeJSONBody(w, r, &body, false); err != nil {
		writeJSONBodyError(w, err, "invalid request body")
		return
	}
	if body.SubjectType == "" {
		body.SubjectType = "user"
	}
	switch body.SubjectType {
	case "user", "group":
	default:
		writeError(w, http.StatusBadRequest, "invalid subject_type")
		return
	}
	if body.ExternalID == "" {
		writeError(w, http.StatusBadRequest, "external_id is required")
		return
	}
	if err := s.db.UpsertAccessSubject(r.Context(), body.ID, body.SubjectType, body.ExternalID, body.DisplayName); err != nil {
		log.Printf("upsert access subject: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	s.audit(r, "rbac.subject.upsert", "access_subject", body.ExternalID, "ok", map[string]any{
		"subject_type": body.SubjectType,
		"display_name": body.DisplayName,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListAccessSubjects(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	items, err := s.db.ListAccessSubjects(r.Context())
	if err != nil {
		log.Printf("list access subjects: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	if items == nil {
		items = []models.AccessSubject{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleListAccessPolicies(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	items, err := s.db.ListAccessPolicies(r.Context(), r.URL.Query().Get("subject_external_id"))
	if err != nil {
		log.Printf("list access policies: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	if items == nil {
		items = []models.AccessPolicy{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleAccessControlStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	stats, err := s.db.GetAccessControlStats(r.Context())
	if err != nil {
		log.Printf("access control status: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	status := "ok"
	warnings := []string{}
	if stats.OrphanPolicyCount > 0 {
		status = "degraded"
		warnings = append(warnings, "access policies reference missing subjects")
	}
	authStatus := s.accessControlAuthStatus()
	if configured, _ := authStatus["trusted_identity_configured"].(bool); configured {
		if count, _ := authStatus["trusted_proxy_cidr_count"].(int); count == 0 {
			status = "degraded"
			warnings = append(warnings, "trusted identity headers are configured but no trusted proxy CIDRs are valid")
		}
	}
	if adminConfigured, _ := authStatus["trusted_identity_admin_configured"].(bool); adminConfigured {
		if configured, _ := authStatus["trusted_identity_configured"].(bool); !configured {
			status = "degraded"
			warnings = append(warnings, "trusted identity admin allowlists are configured without trusted identity headers")
		}
	}
	if oidcConfigured, _ := authStatus["oidc_configured"].(bool); oidcConfigured {
		if jwksConfigured, _ := authStatus["oidc_jwks_configured"].(bool); !jwksConfigured {
			status = "degraded"
			warnings = append(warnings, "OIDC is configured but JWKS URL is missing")
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       status,
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"warnings":     warnings,
		"stats":        stats,
		"auth":         authStatus,
	})
}

func (s *Server) accessControlAuthStatus() map[string]any {
	trustedConfigured := s.trustedAuth.userHeader != "" || s.trustedAuth.groupsHeader != ""
	return map[string]any{
		"web_auth_enabled":                  s.webAuth,
		"viewer_key_count":                  len(s.viewerKeys),
		"oidc_configured":                   s.oidcAuth != nil,
		"oidc_jwks_configured":              s.oidcAuth != nil && s.oidcAuth.jwksURL != "",
		"oidc_admin_user_count":             oidcAdminUserCount(s.oidcAuth),
		"oidc_admin_group_count":            oidcAdminGroupCount(s.oidcAuth),
		"trusted_identity_configured":       trustedConfigured,
		"trusted_user_header_configured":    s.trustedAuth.userHeader != "",
		"trusted_groups_header_configured":  s.trustedAuth.groupsHeader != "",
		"trusted_proxy_cidr_count":          len(s.trustedAuth.proxyNets),
		"trusted_admin_user_count":          len(s.trustedAuth.adminUsers),
		"trusted_admin_group_count":         len(s.trustedAuth.adminGroups),
		"trusted_identity_admin_configured": len(s.trustedAuth.adminUsers) > 0 || len(s.trustedAuth.adminGroups) > 0,
	}
}

func oidcAdminUserCount(v *oidcTokenVerifier) int {
	if v == nil {
		return 0
	}
	return len(v.adminUsers)
}

func oidcAdminGroupCount(v *oidcTokenVerifier) int {
	if v == nil {
		return 0
	}
	return len(v.adminGroups)
}

func (s *Server) handleDeleteAccessSubject(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	subject, policyCount, err := s.db.DeleteAccessSubject(r.Context(), id)
	if err != nil {
		if err == sql.ErrNoRows {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		log.Printf("delete access subject: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	s.audit(r, "rbac.subject.delete", "access_subject", id, "ok", map[string]any{
		"subject_type":       subject.SubjectType,
		"external_id":        subject.ExternalID,
		"display_name":       subject.DisplayName,
		"revoked_policies":   policyCount,
		"cascade_policy_del": true,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleDeleteAccessPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	policy, err := s.db.DeleteAccessPolicy(r.Context(), id)
	if err != nil {
		if err == sql.ErrNoRows {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		log.Printf("delete access policy: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	s.audit(r, "rbac.policy.delete", "access_policy", id, "ok", map[string]any{
		"subject_id":          policy.SubjectID,
		"subject_type":        policy.SubjectType,
		"subject_external_id": policy.SubjectExternalID,
		"resource_type":       policy.ResourceType,
		"resource_id":         policy.ResourceID,
		"permission":          policy.Permission,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleUpsertAccessPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var body struct {
		ID                string `json:"id"`
		SubjectID         string `json:"subject_id"`
		SubjectExternalID string `json:"subject_external_id"`
		ResourceType      string `json:"resource_type"`
		ResourceID        string `json:"resource_id"`
		Permission        string `json:"permission"`
	}
	if err := decodeJSONBody(w, r, &body, false); err != nil {
		writeJSONBodyError(w, err, "invalid request body")
		return
	}
	if body.SubjectID == "" && body.SubjectExternalID == "" {
		writeError(w, http.StatusBadRequest, "subject_id or subject_external_id is required")
		return
	}
	if body.ResourceType == "" {
		writeError(w, http.StatusBadRequest, "resource_type is required")
		return
	}
	switch body.ResourceType {
	case "host", "container", "image", "asset_group", "cve_db", "all":
	default:
		writeError(w, http.StatusBadRequest, "invalid resource_type")
		return
	}
	if body.Permission == "" {
		body.Permission = "read"
	}
	switch body.Permission {
	case "read", "write", "admin", "export":
	default:
		writeError(w, http.StatusBadRequest, "invalid permission")
		return
	}
	if err := s.db.UpsertAccessPolicy(r.Context(), body.ID, body.SubjectID, body.SubjectExternalID, body.ResourceType, body.ResourceID, body.Permission); err != nil {
		log.Printf("upsert access policy: %v", err)
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	subjectAuditID := body.SubjectExternalID
	if subjectAuditID == "" {
		subjectAuditID = body.SubjectID
	}
	s.audit(r, "rbac.policy.upsert", "access_policy", subjectAuditID, "ok", map[string]any{
		"subject_id":    body.SubjectID,
		"resource_type": body.ResourceType,
		"resource_id":   body.ResourceID,
		"permission":    body.Permission,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	createdFrom, err := auditTimeParam(r, "created_from", false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	createdTo, err := auditTimeParam(r, "created_to", true)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if createdFrom != nil && createdTo != nil && createdFrom.After(*createdTo) {
		writeError(w, http.StatusBadRequest, "created_from must be before created_to")
		return
	}
	filter := db.AuditLogFilter{
		ActorType:    r.URL.Query().Get("actor_type"),
		ActorID:      r.URL.Query().Get("actor_id"),
		Action:       r.URL.Query().Get("action"),
		ResourceType: r.URL.Query().Get("resource_type"),
		ResourceID:   r.URL.Query().Get("resource_id"),
		Status:       r.URL.Query().Get("status"),
		CreatedFrom:  createdFrom,
		CreatedTo:    createdTo,
	}
	items, total, err := s.db.ListAuditLogs(r.Context(), filter, limitParam(r, 100), offsetParam(r))
	if err != nil {
		log.Printf("list audit logs: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}
