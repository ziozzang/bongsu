package api

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ziozzang/bongsu/internal/server/db"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	isAdmin := s.authenticateAdmin(r)
	includeOperationalDetails := isAdmin
	// fresh=true bypasses the short-TTL cache. The sync script polls this
	// endpoint to watch async index-rebuild progress; an up-to-8s stale snapshot
	// can show a just-queued rebuild as not-running with an empty last_result,
	// which the poller would misread as a failed/unknown rebuild. Admin only.
	fresh := isAdmin && r.URL.Query().Get("fresh") == "true"
	// The admin operational health block runs ~10 aggregate/index-stat queries
	// over large tables and the dashboard polls it constantly; serve it from a
	// short TTL cache so polling is a map lookup. Non-admin liveness is cheap
	// and always computed fresh.
	if includeOperationalDetails && !fresh {
		if cached, ok := s.healthCache.get("admin"); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}
	}
	healthTimeout := envInt("BONGSU_HEALTH_DB_TIMEOUT_SECONDS", 2)
	if healthTimeout < 1 {
		healthTimeout = 1
	}
	if healthTimeout > 30 {
		healthTimeout = 30
	}
	healthDBTimeout := time.Duration(healthTimeout) * time.Second
	withHealthDBTimeout := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(r.Context(), healthDBTimeout)
	}
	recalcStatus := s.securityRecalculationStatus(isAdmin)
	if includeOperationalDetails {
		dbCtx, cancel := withHealthDBTimeout()
		if last := s.securityRecalculationLastResult(dbCtx, isAdmin); last != nil {
			recalcStatus["last_result"] = last
		}
		cancel()
	}
	resp := map[string]any{
		"status":                 "ok",
		"trivy_db_ready":         false,
		"web_auth":               s.webAuth,
		"security_recalculation": recalcStatus,
		"version":                s.buildInfo.Version,
		"commit":                 s.buildInfo.Commit,
		"build_date":             s.buildInfo.BuildDate,
	}
	if !s.buildInfo.StartTime.IsZero() {
		resp["uptime_seconds"] = int64(time.Since(s.buildInfo.StartTime).Seconds())
	}
	if includeOperationalDetails {
		var healthAffectedIndex *db.CveAffectedPackageIndexStats
		var healthReferenceIndex *db.CveReferenceKeyIndexStats
		var healthAffectedIndexErr error
		var healthAffectedIndexPartial bool
		var healthReferenceIndexErr error
		var healthReferenceIndexPartial bool
		dbCtx, cancel := withHealthDBTimeout()
		if last := s.cveDBRematchLastResult(dbCtx, isAdmin); last != nil {
			resp["cve_db_rematch"] = map[string]any{"last_result": last}
		}
		cancel()
		dbCtx, cancel = withHealthDBTimeout()
		if last := s.securityDBAutoRescanLastResult(dbCtx, isAdmin); last != nil {
			resp["security_db_auto_rescan"] = map[string]any{"last_result": last}
		}
		cancel()
		dbCtx, cancel = withHealthDBTimeout()
		if lightStats, err := s.db.GetCveAffectedPackageIndexHealthStats(dbCtx); err == nil {
			resp["cve_affected_package_index"] = lightStats
			healthAffectedIndex = cveAffectedPackageIndexStatsFromHealthMap(lightStats)
			healthAffectedIndexPartial = healthAffectedIndex != nil
		} else {
			healthAffectedIndexErr = err
			resp["cve_affected_package_index"] = map[string]any{"error": err.Error()}
		}
		cancel()
		dbCtx, cancel = withHealthDBTimeout()
		if lightStats, err := s.db.GetCveReferenceKeyIndexHealthStats(dbCtx); err == nil {
			resp["cve_reference_key_index"] = lightStats
			healthReferenceIndex = cveReferenceKeyIndexStatsFromHealthMap(lightStats)
			healthReferenceIndexPartial = healthReferenceIndex != nil
		} else {
			healthReferenceIndexErr = err
			resp["cve_reference_key_index"] = map[string]any{"error": err.Error()}
		}
		cancel()
		dbCtx, cancel = withHealthDBTimeout()
		placeholderStats, placeholderErr := s.db.GetCvePlaceholderStats(dbCtx)
		if quality := s.cveDBQualitySummary(dbCtx, cveDBQualityInput{
			Placeholders:          placeholderStats,
			PlaceholderStatsError: placeholderErr,
			AffectedIndex:         healthAffectedIndex,
			AffectedIndexPartial:  healthAffectedIndexPartial,
			AffectedIndexError:    healthAffectedIndexErr,
			ReferenceIndex:        healthReferenceIndex,
			ReferenceIndexPartial: healthReferenceIndexPartial,
			ReferenceIndexError:   healthReferenceIndexErr,
			SkipMissingFetch:      true,
		}); quality != nil {
			resp["cve_db_quality"] = quality
			if status, _ := quality["status"].(string); status == "degraded" {
				resp["status"] = "degraded"
			}
		}
		cancel()
		resp["cve_affected_index_rebuild"] = s.affectedIndexRebuildStatus()
		resp["cve_reference_index_rebuild"] = s.referenceIndexRebuildStatus()
	}
	dbCtx, cancel := withHealthDBTimeout()
	if err := s.db.PingContext(dbCtx); err != nil {
		resp["status"] = "degraded"
		resp["db_error"] = "connection failed"
		if isAdmin {
			resp["db_error_detail"] = err.Error()
		}
	}
	cancel()
	dbCtx, cancel = withHealthDBTimeout()
	for k, v := range s.securityDBRevisionMeta(dbCtx) {
		if k == "security_db_revision" || isAdmin {
			resp[k] = v
		}
	}
	cancel()
	if s.db != nil {
		dbCtx, cancel = withHealthDBTimeout()
		freshness := s.securityDBFreshnessStatus(dbCtx, isAdmin)
		timedOut := dbCtx.Err() != nil
		cancel()
		resp["security_db_freshness"] = freshness
		if latest, ok := freshness["latest_last_update"]; ok {
			resp["security_db_updated_at"] = latest
		}
		enrichSecurityDBManagerStatus(resp["security_db"], freshness)
		if timedOut {
			resp["security_db_freshness_timeout"] = true
		} else if status, _ := freshness["status"].(string); status != "" && status != "ok" {
			resp["status"] = "degraded"
		}
	}
	if s.dbMgr != nil {
		resp["trivy_db_ready"] = s.dbMgr.IsReady()
		if lu := s.dbMgr.LastUpdate(); !lu.IsZero() {
			resp["trivy_db_last_update"] = lu.Format("2006-01-02T15:04:05Z07:00")
		}
		if isAdmin {
			resp["trivy_db"] = s.dbMgr.Status()
		} else {
			resp["trivy_db"] = s.dbMgr.PublicStatus()
		}
	}
	if s.secMgr != nil {
		if isAdmin {
			resp["security_db"] = s.secMgr.Status()
		} else {
			resp["security_db"] = s.secMgr.PublicStatus()
		}
		if freshness, ok := resp["security_db_freshness"].(map[string]any); ok {
			enrichSecurityDBManagerStatus(resp["security_db"], freshness)
		}
	}
	if includeOperationalDetails {
		s.healthCache.put("admin", resp)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) securityDBFreshnessStatus(ctx context.Context, includeDetails bool) map[string]any {
	maxAgeHours := envFloat("BONGSU_SECURITY_DB_MAX_SOURCE_AGE_HOURS", defaultSecurityDBMaxSourceAgeHours)
	if maxAgeHours < 0 {
		maxAgeHours = defaultSecurityDBMaxSourceAgeHours
	}
	maxAge := time.Duration(maxAgeHours * float64(time.Hour))
	requiredSources := requiredSecurityDBSources()
	resp := map[string]any{
		"max_age_hours":    maxAgeHours,
		"required_sources": requiredSources,
	}
	if s.db == nil {
		resp["status"] = "unavailable"
		resp["stale"] = true
		return resp
	}
	stats, err := s.db.GetCveSourceFreshnessStats(ctx)
	if err != nil {
		resp["status"] = "error"
		resp["stale"] = true
		resp["source_count"] = 0
		if includeDetails {
			resp["error"] = err.Error()
		}
		return resp
	}
	resp["source_count"] = len(stats)
	if len(stats) == 0 {
		resp["missing_sources"] = requiredSources
		resp["missing_source_count"] = len(requiredSources)
		resp["status"] = "empty"
		resp["stale"] = true
		if includeDetails {
			resp["stale_sources"] = []map[string]any{}
		}
		return resp
	}

	now := time.Now()
	var oldestSource string
	var oldestLastUpdate *time.Time
	var oldestAge time.Duration
	var latestSource string
	var latestLastUpdate *time.Time
	var latestAge time.Duration
	staleSources := make([]map[string]any, 0)
	presentSources := make(map[string]bool, len(stats))
	for _, stat := range stats {
		source := strings.ToLower(strings.TrimSpace(stat.Source))
		presentSources[source] = true
		sourceStatus := map[string]any{"source": source}
		isStale := false
		if stat.LastUpdate == nil {
			isStale = true
		} else {
			age := now.Sub(*stat.LastUpdate)
			if age < 0 {
				age = 0
			}
			if oldestLastUpdate == nil || age > oldestAge {
				oldestSource = source
				oldestLastUpdate = stat.LastUpdate
				oldestAge = age
			}
			if latestLastUpdate == nil || stat.LastUpdate.After(*latestLastUpdate) {
				latestSource = source
				latestLastUpdate = stat.LastUpdate
				latestAge = age
			}
			sourceStatus["last_update"] = stat.LastUpdate.Format(time.RFC3339)
			sourceStatus["age_seconds"] = age.Seconds()
			if maxAge > 0 && age > maxAge {
				isStale = true
			}
		}
		if isStale {
			staleSources = append(staleSources, sourceStatus)
		}
	}
	missingSources := make([]string, 0)
	for _, source := range requiredSources {
		if !presentSources[source] {
			missingSources = append(missingSources, source)
		}
	}
	resp["missing_sources"] = missingSources
	resp["missing_source_count"] = len(missingSources)
	if oldestLastUpdate != nil {
		resp["oldest_source"] = oldestSource
		resp["oldest_last_update"] = oldestLastUpdate.Format(time.RFC3339)
		resp["oldest_age_seconds"] = oldestAge.Seconds()
	} else if len(stats) > 0 {
		resp["oldest_source"] = stats[0].Source
	}
	if latestLastUpdate != nil {
		resp["latest_source"] = latestSource
		resp["latest_last_update"] = latestLastUpdate.Format(time.RFC3339)
		resp["latest_age_seconds"] = latestAge.Seconds()
	}
	if len(missingSources) > 0 {
		resp["status"] = "missing_sources"
		resp["stale"] = true
	} else if len(staleSources) > 0 {
		resp["status"] = "stale"
		resp["stale"] = true
	} else {
		resp["status"] = "ok"
		resp["stale"] = false
	}
	if includeDetails {
		resp["stale_sources"] = staleSources
	}
	return resp
}

func cveAffectedPackageIndexStatsFromHealthMap(in map[string]any) *db.CveAffectedPackageIndexStats {
	if in == nil {
		return nil
	}
	stats := &db.CveAffectedPackageIndexStats{}
	if v, ok := intFromAny(in["count"]); ok {
		stats.Count = v
	}
	if v, ok := intFromAny(in["source_count"]); ok {
		stats.SourceCount = v
	}
	if v, ok := intFromAny(in["indexed_cves"]); ok {
		stats.IndexedCVEs = v
	}
	if v, ok := intFromAny(in["orphans"]); ok {
		stats.Orphans = v
	}
	if v, ok := in["last_update"].(*time.Time); ok {
		stats.LastUpdate = v
	} else if v, ok := in["last_update"].(time.Time); ok {
		stats.LastUpdate = &v
	}
	return stats
}

func cveReferenceKeyIndexStatsFromHealthMap(in map[string]any) *db.CveReferenceKeyIndexStats {
	if in == nil {
		return nil
	}
	stats := &db.CveReferenceKeyIndexStats{}
	if v, ok := intFromAny(in["count"]); ok {
		stats.Count = v
	}
	if v, ok := intFromAny(in["indexed_cves"]); ok {
		stats.IndexedCVEs = v
	}
	if v, ok := intFromAny(in["canonical_cves"]); ok {
		stats.CanonicalCVEs = v
	}
	if v, ok := intFromAny(in["vendor_keys"]); ok {
		stats.VendorKeys = v
	}
	if v, ok := intFromAny(in["repository_keys"]); ok {
		stats.RepositoryKeys = v
	}
	if v, ok := intFromAny(in["orphans"]); ok {
		stats.Orphans = v
	}
	if v, ok := in["last_update"].(*time.Time); ok {
		stats.LastUpdate = v
	} else if v, ok := in["last_update"].(time.Time); ok {
		stats.LastUpdate = &v
	}
	return stats
}

func intFromAny(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case int32:
		return int(n), true
	case float64:
		return int(n), true
	default:
		return 0, false
	}
}

func requiredSecurityDBSources() []string {
	raw := strings.TrimSpace(os.Getenv("BONGSU_SECURITY_DB_REQUIRED_SOURCES"))
	if raw == "" {
		raw = "cisa-kev,epss,osv,nvd,trivy"
	}
	sources, err := normalizeCveSources(splitCSV(raw))
	if err != nil {
		return []string{"cisa-kev", "epss", "osv", "nvd", "trivy"}
	}
	return sources
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	readyTimeout := envInt("BONGSU_HEALTH_DB_TIMEOUT_SECONDS", 2)
	if readyTimeout < 1 {
		readyTimeout = 1
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(readyTimeout)*time.Second)
	defer cancel()

	if err := s.db.PingContext(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "not_ready",
			"db":     "unavailable",
		})
		return
	}

	if s.dbMgr != nil && !s.dbMgr.IsReady() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status":   "not_ready",
			"db":       "connected",
			"trivy_db": "not_loaded",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}

func (s *Server) handleLiveness(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "alive"})
}
