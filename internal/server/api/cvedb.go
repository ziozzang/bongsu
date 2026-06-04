package api

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ziozzang/bongsu/internal/server/db"
	"github.com/ziozzang/bongsu/internal/server/trivydb"
	"github.com/ziozzang/bongsu/internal/shared/models"
)

func (s *Server) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	scanID := r.PathValue("id")
	force := r.URL.Query().Get("force") == "true"
	if err := s.db.DeleteScan(r.Context(), scanID, force); err != nil {
		if errors.Is(err, db.ErrLatestInventoryScan) {
			writeError(w, http.StatusConflict, "latest inventory scan requires force=true")
			return
		}
		if errors.Is(err, db.ErrScanNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		log.Printf("delete scan %s: %v", scanID, err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	s.audit(r, "scan.delete", "scan", scanID, "ok", map[string]any{"force": force})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleTrivyDBUpload(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if s.dbMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "trivy db manager not available")
		return
	}

	uploadLimit := maxTrivyDBUploadBytes()
	r.Body = http.MaxBytesReader(w, r.Body, uploadLimit)
	if err := r.ParseMultipartForm(maxMultipartMemoryBytes()); err != nil {
		writeError(w, http.StatusBadRequest, "file too large or invalid form")
		return
	}

	file, _, err := r.FormFile("db")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing 'db' file field")
		return
	}
	defer file.Close()

	tmpFile, err := os.CreateTemp("", "trivy-db-*.tar.gz")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "temp file error")
		return
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := io.Copy(tmpFile, file); err != nil {
		writeError(w, http.StatusInternalServerError, "file write error")
		return
	}
	tmpFile.Close()

	if err := s.dbMgr.LoadFromFile(tmpFile.Name()); err != nil {
		log.Printf("load trivy-db: %v", err)
		status := trivyDBLoadErrorStatus(err)
		s.audit(r, "trivy_db.upload", "security_db", "trivy", "error", map[string]any{
			"status": status,
			"error":  err.Error(),
		})
		writeError(w, status, trivyDBLoadErrorMessage(err))
		return
	}

	s.audit(r, "trivy_db.upload", "security_db", "trivy", "ok", nil)
	s.SecurityDatabaseUpdated("trivy-db upload")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "trivy-db loaded"})
}

func trivyDBLoadErrorStatus(err error) int {
	if errors.Is(err, trivydb.ErrInvalidArchive) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func trivyDBLoadErrorMessage(err error) string {
	if trivyDBLoadErrorStatus(err) == http.StatusBadRequest {
		return "invalid trivy db archive"
	}
	return "failed to load db"
}

func (s *Server) handleTrivyDBUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if s.dbMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "trivy db manager not available")
		return
	}

	if err := s.dbMgr.UpdateNow(r.Context()); err != nil {
		log.Printf("trivy-db update failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"status": "error", "message": "download failed"})
		return
	}

	s.audit(r, "trivy_db.update", "security_db", "trivy", "ok", nil)
	s.SecurityDatabaseUpdated("trivy-db update")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"message":        "trivy-db updated",
		"trivy_db_ready": s.dbMgr.IsReady(),
		"last_update":    s.dbMgr.LastUpdate().Format("2006-01-02T15:04:05Z07:00"),
	})
}

func (s *Server) handleSecurityDbUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if s.secMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "security db manager not available")
		return
	}
	if err := s.secMgr.UpdateNowWithReason(r.Context(), "security-db update"); err != nil {
		log.Printf("security-db update failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"status": "error", "message": err.Error(), "security_db": s.secMgr.Status()})
		return
	}
	s.audit(r, "security_db.update", "security_db", "aggregate", "ok", nil)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "security_db": s.secMgr.Status()})
}

func (s *Server) handleSecurityDbStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	timeoutSeconds := envInt("BONGSU_SECURITY_DB_STATUS_TIMEOUT_SECONDS", 15)
	if timeoutSeconds < 1 {
		timeoutSeconds = 1
	}
	if timeoutSeconds > 30 {
		timeoutSeconds = 30
	}
	withTimeout := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(r.Context(), time.Duration(timeoutSeconds)*time.Second)
	}

	out := map[string]any{
		"status":                 "ok",
		"timeout_seconds":        timeoutSeconds,
		"security_recalculation": s.securityRecalculationStatus(true),
		"cve_affected_index":     s.affectedIndexRebuildStatus(),
		"cve_reference_index":    s.referenceIndexRebuildStatus(),
	}
	if s.secMgr != nil {
		out["security_db"] = s.secMgr.Status()
	} else {
		out["security_db"] = map[string]any{"configured": false, "status": "unavailable"}
	}

	dbCtx, cancel := withTimeout()
	for k, v := range s.securityDBRevisionMeta(dbCtx) {
		out[k] = v
	}
	cancel()

	dbCtx, cancel = withTimeout()
	freshness := s.securityDBFreshnessStatus(dbCtx, true)
	freshnessTimedOut := dbCtx.Err() != nil
	cancel()
	out["security_db_freshness"] = freshness
	enrichSecurityDBManagerStatus(out["security_db"], freshness)
	if freshnessTimedOut {
		out["security_db_freshness_timeout"] = true
	}
	if status, _ := freshness["status"].(string); status != "" && status != "ok" {
		out["status"] = "degraded"
	}

	dbCtx, cancel = withTimeout()
	if last := s.securityRecalculationLastResult(dbCtx, true); last != nil {
		if recalc, ok := out["security_recalculation"].(map[string]any); ok {
			recalc["last_result"] = last
		}
	}
	cancel()

	dbCtx, cancel = withTimeout()
	if sources, err := s.db.ListSecuritySourceStatuses(dbCtx); err == nil {
		out["security_sources"] = sources
	} else {
		out["security_sources_error"] = err.Error()
	}
	cancel()

	cveQuality, affectedIndex, referenceIndex := s.securityDbStatusQuality(r.Context(), timeoutSeconds)
	if affectedIndex != nil {
		out["cve_affected_package_index"] = affectedIndex
	}
	if referenceIndex != nil {
		out["cve_reference_key_index"] = referenceIndex
	}
	if cveQuality != nil {
		out["cve_db_quality"] = cveQuality
		if status, _ := cveQuality["status"].(string); status == "degraded" {
			out["status"] = "degraded"
		}
	}
	warnings, actions := securityDBOperationalGuidance(out["security_db"], freshness, cveQuality, freshnessTimedOut)
	out["warnings"] = warnings
	out["recommended_actions"] = actions

	writeJSON(w, http.StatusOK, out)
}

func (s *Server) securityDbStatusQuality(parent context.Context, timeoutSeconds int) (map[string]any, any, any) {
	withTimeout := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(parent, time.Duration(timeoutSeconds)*time.Second)
	}
	var affectedIndex *db.CveAffectedPackageIndexStats
	var affectedIndexPartial bool
	var affectedIndexDetailErr error
	var affectedIndexErr error
	var affectedIndexOut any
	var referenceIndex *db.CveReferenceKeyIndexStats
	var referenceIndexPartial bool
	var referenceIndexDetailErr error
	var referenceIndexErr error
	var referenceIndexOut any

	dbCtx, cancel := withTimeout()
	if indexStats, err := s.db.GetCveAffectedPackageIndexStats(dbCtx); err == nil {
		affectedIndex = indexStats
		affectedIndexOut = indexStats
	} else {
		detailErr := err
		cancel()
		dbCtx, cancel = withTimeout()
		if lightStats, lightErr := s.db.GetCveAffectedPackageIndexHealthStats(dbCtx); lightErr == nil {
			lightStats["detail_error"] = detailErr.Error()
			affectedIndex = cveAffectedPackageIndexStatsFromHealthMap(lightStats)
			affectedIndexPartial = affectedIndex != nil
			affectedIndexDetailErr = detailErr
			affectedIndexOut = lightStats
		} else {
			affectedIndexErr = detailErr
			affectedIndexOut = map[string]any{"error": detailErr.Error(), "fallback_error": lightErr.Error()}
		}
	}
	cancel()

	dbCtx, cancel = withTimeout()
	if stats, err := s.db.GetCveReferenceKeyIndexStats(dbCtx); err == nil {
		referenceIndex = stats
		referenceIndexOut = stats
	} else {
		detailErr := err
		cancel()
		dbCtx, cancel = withTimeout()
		if lightStats, lightErr := s.db.GetCveReferenceKeyIndexHealthStats(dbCtx); lightErr == nil {
			lightStats["detail_error"] = detailErr.Error()
			referenceIndex = cveReferenceKeyIndexStatsFromHealthMap(lightStats)
			referenceIndexPartial = referenceIndex != nil
			referenceIndexDetailErr = detailErr
			referenceIndexOut = lightStats
		} else {
			referenceIndexErr = detailErr
			referenceIndexOut = map[string]any{"error": detailErr.Error(), "fallback_error": lightErr.Error()}
		}
	}
	cancel()

	dbCtx, cancel = withTimeout()
	placeholderStats, placeholderErr := s.db.GetCvePlaceholderStats(dbCtx)
	quality := s.cveDBQualitySummary(dbCtx, cveDBQualityInput{
		Placeholders:          placeholderStats,
		PlaceholderStatsError: placeholderErr,
		AffectedIndex:         affectedIndex,
		AffectedIndexPartial:  affectedIndexPartial,
		AffectedIndexDetail:   affectedIndexDetailErr,
		AffectedIndexError:    affectedIndexErr,
		ReferenceIndex:        referenceIndex,
		ReferenceIndexPartial: referenceIndexPartial,
		ReferenceIndexDetail:  referenceIndexDetailErr,
		ReferenceIndexError:   referenceIndexErr,
		SkipMissingFetch:      true,
	})
	cancel()
	return quality, affectedIndexOut, referenceIndexOut
}

func enrichSecurityDBManagerStatus(status any, freshness map[string]any) {
	m, ok := status.(map[string]any)
	if !ok || freshness == nil {
		return
	}
	for _, pair := range []struct {
		from string
		to   string
	}{
		{"latest_source", "persisted_latest_source"},
		{"latest_last_update", "persisted_latest_update"},
		{"latest_age_seconds", "persisted_latest_age_seconds"},
		{"source_count", "persisted_source_count"},
		{"missing_sources", "persisted_missing_sources"},
		{"stale_sources", "persisted_stale_sources"},
		{"status", "persisted_status"},
	} {
		if v, ok := freshness[pair.from]; ok {
			m[pair.to] = v
		}
	}
	if v, ok := freshness["status"]; ok {
		m["effective_status"] = v
	} else if v, ok := m["status"]; ok {
		m["effective_status"] = v
	}
	if v, ok := freshness["latest_last_update"]; ok {
		m["effective_last_sync"] = v
	}
	if v, ok := freshness["latest_source"]; ok {
		m["effective_source"] = v
	}
	if v, ok := freshness["latest_age_seconds"]; ok {
		m["effective_age_seconds"] = v
	}
	if status, _ := m["status"].(string); status == "never" {
		if latest, ok := freshness["latest_last_update"]; ok {
			if freshnessStatus, _ := freshness["status"].(string); freshnessStatus == "ok" {
				m["status_detail"] = "process has not run a sync since startup; effective security DB status is ok from persisted CVE DB freshness"
			} else {
				m["status_detail"] = "process has not run a sync since startup; using persisted CVE DB freshness"
			}
			m["last_sync_persisted"] = latest
		}
	}
}

func securityDBOperationalGuidance(manager any, freshness, quality map[string]any, freshnessTimedOut bool) ([]string, []string) {
	warnings := []string{}
	actions := []string{}
	add := func(warning, action string) {
		if warning != "" {
			warnings = append(warnings, warning)
		}
		if action != "" {
			actions = append(actions, action)
		}
	}
	if freshnessTimedOut {
		add("security DB freshness check timed out", "increase BONGSU_SECURITY_DB_STATUS_TIMEOUT_SECONDS or inspect database load")
	}
	if m, ok := manager.(map[string]any); ok {
		if configured, ok := m["configured"].(bool); ok && !configured {
			add("security DB sync command is not configured", "set BONGSU_SECURITY_DB_SYNC_CMD for connected environments or use import/export in air-gapped environments")
		}
		if rawErr, ok := m["last_error"]; ok {
			if errText := strings.TrimSpace(fmt.Sprint(rawErr)); errText != "" {
				add("last security DB sync attempt failed", "inspect security_db.last_error and rerun /api/admin/security-db/update after fixing the source")
			}
		}
		if status, _ := m["status"].(string); status == "never" {
			freshnessStatus, _ := freshness["status"].(string)
			if _, ok := m["last_sync_persisted"]; ok && freshnessStatus != "ok" {
				add("sync manager has not completed since this process started", "use persisted freshness for current DB state or trigger /api/admin/security-db/update to refresh now")
			}
		}
	}
	if freshness != nil {
		switch status, _ := freshness["status"].(string); status {
		case "missing_sources":
			add("one or more required security DB sources are missing", "run the connected sync or import an air-gapped bundle containing all required sources")
		case "stale":
			add("one or more security DB sources are stale", "refresh stale sources or import a newer security DB bundle")
		case "empty":
			add("security DB has no source records", "run the connected sync or import a security DB bundle before relying on matching")
		case "error":
			add("security DB freshness check failed", "inspect security_db_freshness.error and database connectivity")
		case "unavailable":
			add("security DB database handle is unavailable", "check server database configuration")
		}
		if missing, ok := freshness["missing_sources"].([]string); ok && len(missing) > 0 {
			add("missing security DB sources: "+strings.Join(missing, ", "), "include these sources in the next connected sync or air-gap import")
		}
		staleNames := staleSecurityDBSourceNames(freshness["stale_sources"])
		if len(staleNames) > 0 {
			add("stale security DB sources: "+strings.Join(staleNames, ", "), "refresh these sources before running fleet-wide rematch decisions")
		}
	}
	if quality != nil {
		if status, _ := quality["status"].(string); status == "degraded" || status == "warning" {
			add("CVE DB quality status is "+status, "inspect cve_db_quality warnings and rebuild affected/reference indexes if needed")
		}
	}
	return warnings, actions
}

func staleSecurityDBSourceNames(v any) []string {
	switch items := v.(type) {
	case []map[string]any:
		out := make([]string, 0, len(items))
		for _, item := range items {
			if source := strings.TrimSpace(fmt.Sprint(item["source"])); source != "" {
				out = append(out, source)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(items))
		for _, raw := range items {
			if item, ok := raw.(map[string]any); ok {
				if source := strings.TrimSpace(fmt.Sprint(item["source"])); source != "" {
					out = append(out, source)
				}
			}
		}
		return out
	default:
		return []string{}
	}
}

func (s *Server) handleSecurityDbRecalculate(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	reason := "manual security-db recalculation"
	var body struct {
		Reason string `json:"reason"`
	}
	if r.Body != nil {
		if err := decodeJSONBody(w, r, &body, true); err != nil {
			writeJSONBodyError(w, err, "invalid json")
			return
		}
		if trimmed := strings.TrimSpace(body.Reason); trimmed != "" {
			reason = truncateValidUTF8(trimmed, 200)
		}
	}
	s.recalculateSecurityFindings(reason)
	status := s.securityRecalculationStatus(true)
	revisionMeta := s.securityDBRevisionMeta(r.Context())
	out := map[string]any{"status": "queued", "reason": reason, "security_recalculation": status}
	for k, v := range revisionMeta {
		out[k] = v
	}
	writeJSON(w, http.StatusOK, out)
	auditMeta := map[string]any{"reason": reason}
	for k, v := range revisionMeta {
		auditMeta[k] = v
	}
	s.audit(r, "security_db.recalculation.request", "security_db", "aggregate", "queued", auditMeta)
}

func (s *Server) handleSecurityDbExport(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	includeTrivy := r.URL.Query().Get("include_trivy") != "false"
	bundleFile, cveCount, trivyIncluded, bundleSize, revision, err := s.buildSecurityDBBundleTemp(r.Context(), includeTrivy)
	if err != nil {
		log.Printf("security-db bundle export: %v", err)
		writeError(w, http.StatusInternalServerError, "export failed")
		return
	}
	defer os.Remove(bundleFile)

	f, err := os.Open(bundleFile)
	if err != nil {
		log.Printf("security-db bundle open: %v", err)
		writeError(w, http.StatusInternalServerError, "export failed")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=bongsu-security-db-bundle.tar.gz")
	w.Header().Set("Content-Length", strconv.FormatInt(bundleSize, 10))
	if _, err := io.Copy(w, f); err != nil {
		log.Printf("security-db bundle copy: %v", err)
		return
	}
	exportedAt := time.Now().UTC()
	exportCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := s.db.MarkSecuritySourcesExported(exportCtx, "", exportedAt); err != nil {
		log.Printf("security-db bundle export source registry update: %v", err)
	}
	cancel()
	s.audit(r, "security_db.export", "security_db", "bundle", "ok", map[string]any{
		"cve_records":          cveCount,
		"trivy_db_included":    trivyIncluded,
		"bytes":                bundleSize,
		"security_db_revision": revision,
		"exported_at":          exportedAt.Format(time.RFC3339),
	})
}

func (s *Server) buildSecurityDBBundleTemp(ctx context.Context, includeTrivy bool) (string, int, bool, int64, string, error) {
	cveFile, cveCount, cveSHA, err := s.writeCveJSONLTemp(ctx, "")
	if err != nil {
		return "", 0, false, 0, "", err
	}
	defer os.Remove(cveFile)

	var trivyBytes []byte
	trivySHA := ""
	if includeTrivy && s.dbMgr != nil && s.dbMgr.IsReady() {
		if b, err := s.dbMgr.ArchiveBytes(); err == nil {
			trivyBytes = b
			sum := sha256.Sum256(b)
			trivySHA = hex.EncodeToString(sum[:])
		} else {
			log.Printf("security-db bundle trivy export skipped: %v", err)
		}
	}

	sourceStats, _ := s.db.GetCveSourceStats(ctx)
	revision, err := s.db.GetSecurityDBRevision(ctx)
	if err != nil {
		return "", 0, false, 0, "", err
	}
	manifest := securityDBBundleManifest{
		Format:             "bongsu-security-db-bundle",
		Version:            1,
		CreatedAt:          time.Now().UTC().Format(time.RFC3339),
		SecurityDBRevision: revision,
		CveRecords:         cveCount,
		CveDatabaseSHA256:  cveSHA,
		TrivyDBIncluded:    len(trivyBytes) > 0,
		TrivyDBSHA256:      trivySHA,
		Sources:            sourceStats,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", 0, false, 0, "", err
	}

	tmp, err := os.CreateTemp("", "bongsu-security-db-bundle-*.tar.gz")
	if err != nil {
		return "", 0, false, 0, "", err
	}
	path := tmp.Name()
	cleanup := func(err error) (string, int, bool, int64, string, error) {
		tmp.Close()
		os.Remove(path)
		return "", 0, false, 0, "", err
	}

	gz := gzip.NewWriter(tmp)
	tw := tar.NewWriter(gz)
	if err := writeTarBytes(tw, "manifest.json", manifestBytes); err != nil {
		return cleanup(err)
	}
	if err := writeTarFile(tw, "cve-database.jsonl", cveFile); err != nil {
		return cleanup(err)
	}
	if len(trivyBytes) > 0 {
		if err := writeTarBytes(tw, "trivy-db.tar.gz", trivyBytes); err != nil {
			return cleanup(err)
		}
	}
	if err := tw.Close(); err != nil {
		return cleanup(err)
	}
	if err := gz.Close(); err != nil {
		return cleanup(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(path)
		return "", 0, false, 0, "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		os.Remove(path)
		return "", 0, false, 0, "", err
	}
	return path, cveCount, len(trivyBytes) > 0, info.Size(), revision, nil
}

func (s *Server) handleSecurityDbImport(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	fail := func(status int, msg, stage string, err error) {
		meta := map[string]any{"stage": stage, "message": msg}
		if err != nil {
			meta["error"] = err.Error()
		}
		s.audit(r, "security_db.import", "security_db", "bundle", "error", meta)
		writeError(w, status, msg)
	}
	uploadLimit := maxSecurityDBBundleBytes()
	r.Body = http.MaxBytesReader(w, r.Body, uploadLimit)
	if err := r.ParseMultipartForm(maxMultipartMemoryBytes()); err != nil {
		fail(http.StatusBadRequest, "file too large or invalid form", "parse_form", err)
		return
	}
	file, _, err := r.FormFile("bundle")
	if err != nil {
		fail(http.StatusBadRequest, "missing 'bundle' file field", "form_file", err)
		return
	}
	defer file.Close()

	gz, err := gzip.NewReader(file)
	if err != nil {
		fail(http.StatusBadRequest, "invalid gzip bundle", "gzip", err)
		return
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	imported := 0
	var manifest *securityDBBundleManifest
	var cveFile string
	var cveSHA string
	var trivyArchive string
	var trivySHA string
	defer func() {
		if cveFile != "" {
			os.Remove(cveFile)
		}
		if trivyArchive != "" {
			os.Remove(trivyArchive)
		}
	}()
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			fail(http.StatusBadRequest, "invalid tar bundle", "tar", err)
			return
		}
		if err := validateSecurityDBBundleEntry(hdr); err != nil {
			fail(http.StatusBadRequest, err.Error(), "tar_entry", err)
			return
		}
		switch hdr.Name {
		case "manifest.json":
			if manifest != nil {
				fail(http.StatusBadRequest, "duplicate manifest.json", "manifest", nil)
				return
			}
			var m securityDBBundleManifest
			if err := json.NewDecoder(tr).Decode(&m); err != nil {
				fail(http.StatusBadRequest, "invalid bundle manifest", "manifest", err)
				return
			}
			if m.Format != "bongsu-security-db-bundle" {
				fail(http.StatusBadRequest, "unsupported bundle format", "manifest", nil)
				return
			}
			manifest = &m
		case "cve-database.jsonl":
			if cveFile != "" {
				fail(http.StatusBadRequest, "duplicate cve-database.jsonl", "cve", nil)
				return
			}
			cveFile, cveSHA, err = writeBundleEntryTemp(tr, "bongsu-bundle-cve-*.jsonl")
			if err != nil {
				fail(http.StatusInternalServerError, "cve archive write failed", "stage_cve", err)
				return
			}
		case "trivy-db.tar.gz":
			if trivyArchive != "" {
				fail(http.StatusBadRequest, "duplicate trivy-db.tar.gz", "trivy", nil)
				return
			}
			trivyArchive, trivySHA, err = writeBundleEntryTemp(tr, "bongsu-bundle-trivy-db-*.tar.gz")
			if err != nil {
				fail(http.StatusInternalServerError, "trivy archive write failed", "stage_trivy", err)
				return
			}
		}
	}
	if err := validateSecurityDBBundle(manifest, cveFile, cveSHA, trivyArchive, trivySHA); err != nil {
		fail(http.StatusBadRequest, err.Error(), "validate", err)
		return
	}
	if trivyArchive != "" && s.dbMgr == nil {
		fail(http.StatusServiceUnavailable, "bundle contains trivy db but manager is unavailable", "precondition", nil)
		return
	}
	if trivyArchive != "" {
		if err := s.dbMgr.ValidateArchive(trivyArchive); err != nil {
			log.Printf("security-db bundle trivy validation: %v", err)
			fail(http.StatusBadRequest, "trivy db archive validation failed", "validate_trivy", err)
			return
		}
	}
	cveReader, err := os.Open(cveFile)
	if err != nil {
		fail(http.StatusInternalServerError, "cve archive read failed", "read_cve", err)
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		cveReader.Close()
		fail(http.StatusInternalServerError, "cve import transaction failed", "begin_tx", err)
		return
	}
	if _, err := s.db.DeleteAllCveEntriesTx(r.Context(), tx); err != nil {
		cveReader.Close()
		tx.Rollback()
		fail(http.StatusInternalServerError, "cve import reset failed", "reset_cve", err)
		return
	}
	imported, err = s.importCveJSONLTx(r.Context(), cveReader, "", tx)
	cveReader.Close()
	if err != nil {
		tx.Rollback()
		log.Printf("security-db bundle cve import: %v", err)
		fail(cveImportErrorStatus(err), cveImportErrorMessage(err), "import_cve", err)
		return
	}
	if imported == 0 {
		tx.Rollback()
		fail(http.StatusBadRequest, "no valid cve entries found", "import_cve", errNoValidCveEntries)
		return
	}
	if err := validateSecurityDBBundleImportedCount(manifest, imported); err != nil {
		tx.Rollback()
		fail(http.StatusBadRequest, err.Error(), "validate_cve_count", err)
		return
	}
	if _, err := s.db.SyncEPSSPriorityColumnsTx(r.Context(), tx); err != nil {
		tx.Rollback()
		fail(http.StatusInternalServerError, "cve epss merge failed", "merge_epss", err)
		return
	}
	if _, err := s.db.RefreshCveAffectedPackagesForSourceTx(r.Context(), tx, ""); err != nil {
		tx.Rollback()
		fail(http.StatusInternalServerError, "cve affected package index failed", "index_cve", err)
		return
	}
	if _, err := s.db.RefreshCveReferenceKeysForSourceTx(r.Context(), tx, ""); err != nil {
		tx.Rollback()
		fail(http.StatusInternalServerError, "cve reference key index failed", "index_cve_references", err)
		return
	}
	if err := s.db.RefreshSecuritySourceStatusTx(r.Context(), tx, ""); err != nil {
		tx.Rollback()
		fail(http.StatusInternalServerError, "security source status update failed", "source_status", err)
		return
	}
	if err := tx.Commit(); err != nil {
		fail(http.StatusInternalServerError, "cve import commit failed", "commit_cve", err)
		return
	}
	trivyLoaded := false
	if trivyArchive != "" {
		if err := s.dbMgr.LoadFromFile(trivyArchive); err != nil {
			log.Printf("security-db bundle trivy import: %v", err)
			fail(http.StatusInternalServerError, "trivy db import failed after cve commit", "import_trivy", err)
			return
		}
		trivyLoaded = true
	}
	importMeta := securityDBBundleImportMeta(manifest)
	importMeta["imported"] = imported
	importMeta["trivy_db_loaded"] = trivyLoaded
	s.audit(r, "security_db.import", "security_db", "bundle", "ok", importMeta)
	s.SecurityDatabaseUpdated("security-db bundle import")
	s.clearCveStatsCache()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":                   "ok",
		"imported":                 imported,
		"trivy_db_loaded":          trivyLoaded,
		"security_db_revision":     manifest.SecurityDBRevision,
		"bundle_created_at":        manifest.CreatedAt,
		"bundle_source_count":      len(manifest.Sources),
		"bundle_cve_records":       manifest.CveRecords,
		"bundle_trivy_db_included": manifest.TrivyDBIncluded,
	})
}

type securityDBBundleManifest struct {
	Format             string              `json:"format"`
	Version            int                 `json:"version"`
	CreatedAt          string              `json:"created_at"`
	SecurityDBRevision string              `json:"security_db_revision,omitempty"`
	CveRecords         int                 `json:"cve_records"`
	CveDatabaseSHA256  string              `json:"cve_database_sha256"`
	TrivyDBIncluded    bool                `json:"trivy_db_included"`
	TrivyDBSHA256      string              `json:"trivy_db_sha256"`
	Sources            []db.CveSourceStats `json:"sources,omitempty"`
}

func securityDBBundleImportMeta(manifest *securityDBBundleManifest) map[string]any {
	meta := map[string]any{}
	if manifest == nil {
		return meta
	}
	meta["security_db_revision"] = manifest.SecurityDBRevision
	meta["bundle_created_at"] = manifest.CreatedAt
	meta["bundle_source_count"] = len(manifest.Sources)
	meta["bundle_cve_records"] = manifest.CveRecords
	meta["bundle_trivy_db_included"] = manifest.TrivyDBIncluded
	return meta
}

var errNoValidCveEntries = errors.New("no valid cve entries")
var errInvalidCveSource = errors.New("invalid cve source")

func writeBundleEntryTemp(r io.Reader, pattern string) (string, string, error) {
	tmp, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", "", err
	}
	path := tmp.Name()
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, hash), r); err != nil {
		tmp.Close()
		os.Remove(path)
		return "", "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(path)
		return "", "", err
	}
	return path, hex.EncodeToString(hash.Sum(nil)), nil
}

func validateSecurityDBBundle(manifest *securityDBBundleManifest, cveFile, cveSHA, trivyArchive, trivySHA string) error {
	if manifest == nil {
		return fmt.Errorf("missing bundle manifest")
	}
	if manifest.Version != 1 {
		return fmt.Errorf("unsupported bundle version")
	}
	if strings.TrimSpace(manifest.CreatedAt) != "" {
		if _, err := time.Parse(time.RFC3339, manifest.CreatedAt); err != nil {
			return fmt.Errorf("invalid bundle created_at")
		}
	}
	if cveFile == "" {
		return fmt.Errorf("missing cve-database.jsonl")
	}
	if manifest.CveDatabaseSHA256 == "" {
		return fmt.Errorf("missing cve database checksum")
	}
	if !strings.EqualFold(manifest.CveDatabaseSHA256, cveSHA) {
		return fmt.Errorf("cve database checksum mismatch")
	}
	if manifest.TrivyDBIncluded && trivyArchive == "" {
		return fmt.Errorf("manifest requires trivy db but archive is missing")
	}
	if trivyArchive != "" {
		if manifest.TrivyDBSHA256 == "" {
			return fmt.Errorf("missing trivy db checksum")
		}
		if !strings.EqualFold(manifest.TrivyDBSHA256, trivySHA) {
			return fmt.Errorf("trivy db checksum mismatch")
		}
	}
	return nil
}

func validateSecurityDBBundleImportedCount(manifest *securityDBBundleManifest, imported int) error {
	if manifest == nil {
		return fmt.Errorf("missing bundle manifest")
	}
	if manifest.CveRecords != imported {
		return fmt.Errorf("bundle cve record count mismatch: manifest=%d imported=%d", manifest.CveRecords, imported)
	}
	return nil
}

func validateSecurityDBBundleEntry(hdr *tar.Header) error {
	if hdr == nil {
		return fmt.Errorf("invalid tar entry")
	}
	if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
		return fmt.Errorf("unsupported bundle entry type: %s", hdr.Name)
	}
	switch hdr.Name {
	case "manifest.json", "cve-database.jsonl", "trivy-db.tar.gz":
		return nil
	default:
		return fmt.Errorf("unexpected bundle entry: %s", hdr.Name)
	}
}

func (s *Server) SecurityDatabaseUpdated(reason string) {
	meta := s.securityDBChangedMeta(reason)
	s.auditSystem("security_db.changed", "security_db", "aggregate", "ok", meta)
	if s.notifier.Enabled() {
		s.notifier.Send("security_db.updated", meta)
	}
	s.recalculateSecurityFindings(reason)
}

func (s *Server) securityDBChangedMeta(reason string) map[string]any {
	meta := map[string]any{"reason": reason}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for k, v := range s.securityDBRevisionMeta(ctx) {
		meta[k] = v
	}
	return meta
}

func (s *Server) SecurityDatabaseSyncFailed(reason string, err error) {
	meta := map[string]any{"reason": reason}
	if err != nil {
		meta["error"] = err.Error()
	}
	s.auditSystem("security_db.update", "security_db", "aggregate", "error", meta)
}

func (s *Server) recalculateSecurityFindings(reason string) {
	s.securityRecalcMu.Lock()
	if s.securityRecalcRunning {
		s.securityRecalcPending = true
		s.securityRecalcReason = coalesceSecurityRecalcReason(s.securityRecalcReason, reason)
		s.securityRecalcMu.Unlock()
		log.Printf("security recalculation already running; queued another pass (%s)", reason)
		s.auditSystem("security_db.recalculation", "security_db", "aggregate", "queued", map[string]any{"reason": reason})
		return
	}
	s.securityRecalcRunning = true
	s.securityRecalcMu.Unlock()

	go func() {
		for currentReason := reason; ; {
			s.runSecurityRecalculation(currentReason)

			s.securityRecalcMu.Lock()
			if !s.securityRecalcPending {
				s.securityRecalcRunning = false
				s.securityRecalcMu.Unlock()
				return
			}
			currentReason = s.securityRecalcReason
			s.securityRecalcPending = false
			s.securityRecalcReason = ""
			s.securityRecalcMu.Unlock()
		}
	}()
}

func (s *Server) runSecurityRecalculation(reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	log.Printf("security recalculation started (%s)", reason)
	meta := map[string]any{"reason": reason}
	failures := []string{}
	if revision, err := s.db.GetSecurityDBRevision(ctx); err == nil {
		meta["security_db_revision"] = revision
	} else {
		failures = append(failures, "security_db_revision: "+err.Error())
	}
	s.auditSystem("security_db.recalculation", "security_db", "aggregate", "started", meta)
	if n, err := s.db.SyncEPSSPriorityColumns(ctx); err != nil {
		log.Printf("security recalculation EPSS merge failed: %v", err)
		failures = append(failures, "epss_merge: "+err.Error())
	} else {
		log.Printf("security recalculation merged EPSS columns for %d CVE records", n)
		meta["epss_merged"] = n
	}
	if n, err := s.db.CalcCvssScores(ctx); err != nil {
		log.Printf("security recalculation cvss failed: %v", err)
		failures = append(failures, "cvss: "+err.Error())
	} else if n > 0 {
		log.Printf("security recalculation updated CVSS for %d CVE records", n)
		meta["cvss_updated"] = n
	} else {
		meta["cvss_updated"] = n
	}
	if n, err := s.db.EnrichVulnerabilities(ctx); err != nil {
		log.Printf("security recalculation enrich failed: %v", err)
		failures = append(failures, "enrich: "+err.Error())
	} else if n > 0 {
		log.Printf("security recalculation enriched %d findings", n)
		meta["findings_enriched"] = n
	} else {
		meta["findings_enriched"] = n
	}
	if cleanup, err := s.db.RemoveStaleRematchedVulnerabilities(ctx); err != nil {
		log.Printf("security recalculation stale rematch cleanup failed: %v", err)
		failures = append(failures, "stale_rematch_cleanup: "+err.Error())
	} else {
		log.Printf("security recalculation stale rematch cleanup scanned=%d removed=%d batches=%d batch_size=%d", cleanup.Scanned, cleanup.Removed, cleanup.Batches, cleanup.BatchSize)
		meta["stale_rematch_removed"] = cleanup.Removed
		meta["stale_rematch_scanned"] = cleanup.Scanned
		meta["stale_rematch_batches"] = cleanup.Batches
		meta["stale_rematch_batch_size"] = cleanup.BatchSize
	}
	rematchOpts := rematchOptionsFromEnv()
	if r, err := s.db.RematchCVEs(ctx, rematchOpts); err != nil {
		log.Printf("security recalculation rematch failed: %v", err)
		failures = append(failures, "rematch: "+err.Error())
	} else {
		log.Printf("security recalculation rematched candidates=%d scanned=%d new=%d skipped=%d limited=%v limit=%d", r.Matched, r.ScannedCandidates, r.NewVulns, r.Skipped, r.Limited, r.CandidateLimit)
		meta["rematch_candidates"] = r.Matched
		meta["rematch_scanned_candidates"] = r.ScannedCandidates
		meta["rematch_new_vulns"] = r.NewVulns
		meta["rematch_skipped"] = r.Skipped
		meta["rematch_limited"] = r.Limited
		meta["rematch_candidate_limit"] = r.CandidateLimit
		if stats, err := s.db.GetCveSourceStats(ctx); err == nil {
			policy, eligible, excluded := rematchSourcePolicySummary(stats, rematchOpts)
			meta["rematch_source_policy"] = policy
			meta["rematch_eligible_sources"] = eligible
			meta["rematch_excluded_sources"] = excluded
		} else {
			failures = append(failures, "rematch_source_policy: "+err.Error())
		}
	}
	if n, err := s.db.NormalizeVulnSeverity(ctx); err != nil {
		log.Printf("security recalculation severity normalization failed: %v", err)
		failures = append(failures, "severity: "+err.Error())
	} else if n > 0 {
		log.Printf("security recalculation normalized %d findings", n)
		meta["severity_normalized"] = n
	} else {
		meta["severity_normalized"] = n
	}
	log.Printf("security recalculation finished (%s)", reason)
	status := "ok"
	if len(failures) > 0 {
		status = "error"
		meta["errors"] = failures
	}
	s.auditSystem("security_db.recalculation", "security_db", "aggregate", status, meta)
	s.queueSecurityDBRescans(reason, status)
}

func coalesceSecurityRecalcReason(previous, next string) string {
	if previous == "" {
		return next
	}
	if previous == next {
		return previous
	}
	for _, existing := range strings.Split(previous, "; ") {
		if existing == next {
			return previous
		}
	}
	return previous + "; " + next
}

func (s *Server) queueSecurityDBRescans(reason, recalculationStatus string) {
	if !envBool("BONGSU_AUTO_RESCAN_ON_DB_UPDATE", true) {
		log.Printf("security-db auto rescan disabled (%s)", reason)
		s.auditSystem("security_db.auto_rescan", "scan_request", "security-db-update", "disabled", map[string]any{
			"reason":               reason,
			"recalculation_status": recalculationStatus,
		})
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		lookbackHours := envInt("BONGSU_AUTO_RESCAN_LAST_SEEN_HOURS", 720)
		var lastSeenAfter time.Time
		if lookbackHours > 0 {
			lastSeenAfter = time.Now().Add(-time.Duration(lookbackHours) * time.Hour)
		}
		revision, err := s.db.GetSecurityDBRevision(ctx)
		if err != nil {
			log.Printf("security-db auto rescan revision failed (%s): %v", reason, err)
			s.auditSystem("security_db.auto_rescan", "scan_request", "security-db-update", "error", map[string]any{
				"reason":               reason,
				"recalculation_status": recalculationStatus,
				"last_seen_after":      lastSeenAfter,
				"last_seen_hours":      lookbackHours,
				"error":                err.Error(),
				"stage":                "security_db_revision",
			})
			return
		}
		result, err := s.db.QueueSecurityDBRescans(ctx, "system", reason, revision, lastSeenAfter)
		if err != nil {
			log.Printf("security-db auto rescan queue failed (%s): %v", reason, err)
			s.auditSystem("security_db.auto_rescan", "scan_request", "security-db-update", "error", map[string]any{
				"reason":               reason,
				"recalculation_status": recalculationStatus,
				"last_seen_after":      lastSeenAfter,
				"last_seen_hours":      lookbackHours,
				"security_db_revision": revision,
				"error":                err.Error(),
			})
			return
		}
		log.Printf("security-db auto rescan eligible=%d queued=%d already_pending=%d revision=%s (%s)", result.Eligible, result.Queued, result.AlreadyPending, revision, reason)
		s.auditSystem("security_db.auto_rescan", "scan_request", "security-db-update", "ok", map[string]any{
			"reason":               reason,
			"recalculation_status": recalculationStatus,
			"eligible":             result.Eligible,
			"queued":               result.Queued,
			"already_pending":      result.AlreadyPending,
			"last_seen_after":      lastSeenAfter,
			"last_seen_hours":      lookbackHours,
			"security_db_revision": revision,
		})
	}()
}

func (s *Server) handleCveDbImport(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	ctx := r.Context()

	uploadLimit := maxCveDBImportBytes()
	r.Body = http.MaxBytesReader(w, r.Body, uploadLimit)
	if err := r.ParseMultipartForm(maxMultipartMemoryBytes()); err != nil {
		writeError(w, http.StatusBadRequest, "file too large")
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "no file provided")
		return
	}
	defer file.Close()

	source, err := normalizeCveSource(r.FormValue("source"), "custom")
	if err != nil {
		s.audit(r, "cve_db.import", "cve_db", "invalid", "error", map[string]any{
			"source": r.FormValue("source"),
			"error":  err.Error(),
		})
		writeError(w, http.StatusBadRequest, "invalid source")
		return
	}

	replace := !strings.EqualFold(strings.TrimSpace(r.FormValue("replace")), "false")
	finalize := !strings.EqualFold(strings.TrimSpace(r.FormValue("finalize")), "false")
	count, err := s.importCveJSONL(ctx, file, source, replace, finalize)
	if err != nil {
		log.Printf("cve-db import: %v", err)
		if errors.Is(err, errNoValidCveEntries) {
			s.audit(r, "cve_db.import", "cve_db", source, "error", map[string]any{
				"source": source,
				"reason": "no valid entries",
			})
			writeError(w, http.StatusBadRequest, "no valid entries found")
			return
		}
		status := cveImportErrorStatus(err)
		s.audit(r, "cve_db.import", "cve_db", source, "error", map[string]any{
			"source": source,
			"status": status,
			"error":  err.Error(),
		})
		writeError(w, status, cveImportErrorMessage(err))
		return
	}
	if count == 0 {
		s.audit(r, "cve_db.import", "cve_db", source, "error", map[string]any{
			"source": source,
			"reason": "no valid entries",
		})
		writeError(w, http.StatusBadRequest, "no valid entries found")
		return
	}

	revisionMeta := s.securityDBRevisionMeta(ctx)
	s.clearCveStatsCache()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":               "ok",
		"imported":             count,
		"total":                count,
		"finalized":            finalize,
		"security_db_revision": revisionMeta["security_db_revision"],
	})
	auditMeta := map[string]any{
		"imported": count,
		"source":   source,
		"replace":  replace,
		"finalize": finalize,
	}
	for k, v := range revisionMeta {
		auditMeta[k] = v
	}
	s.audit(r, "cve_db.import", "cve_db", source, "ok", auditMeta)
	if finalize {
		s.SecurityDatabaseUpdated("cve-db import")
	}
}

func (s *Server) handleCveDbPruneStaleSource(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	source, err := normalizeCveSource(r.PathValue("source"), "")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid source")
		return
	}
	rawBefore := strings.TrimSpace(r.URL.Query().Get("before"))
	if rawBefore == "" {
		writeError(w, http.StatusBadRequest, "missing before timestamp")
		return
	}
	before, err := time.Parse(time.RFC3339, rawBefore)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid before timestamp")
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		log.Printf("cve-db prune stale begin tx: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	defer tx.Rollback()
	pruned, err := s.db.DeleteCveEntriesBySourceUpdatedBeforeTx(r.Context(), tx, source, before)
	if err != nil {
		log.Printf("cve-db prune stale delete: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	if err := tx.Commit(); err != nil {
		log.Printf("cve-db prune stale commit: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	revisionMeta := s.securityDBRevisionMeta(r.Context())
	s.clearCveStatsCache()
	out := map[string]any{
		"status":               "ok",
		"source":               source,
		"before":               before.Format(time.RFC3339),
		"pruned":               pruned,
		"security_db_revision": revisionMeta["security_db_revision"],
	}
	writeJSON(w, http.StatusOK, out)
	auditMeta := map[string]any{"source": source, "before": before.Format(time.RFC3339), "pruned": pruned}
	for k, v := range revisionMeta {
		auditMeta[k] = v
	}
	s.audit(r, "cve_db.prune_stale_source", "cve_db", source, "ok", auditMeta)
	if pruned > 0 {
		s.SecurityDatabaseUpdated("cve-db stale source prune")
	}
}

func (s *Server) importCveJSONL(ctx context.Context, reader io.Reader, source string, replace, finalize bool) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	source, err = normalizeCveSource(source, "")
	if err != nil {
		return 0, err
	}
	if replace && source != "" {
		if _, err := s.db.DeleteCveEntriesBySourceTx(ctx, tx, source); err != nil {
			return 0, err
		}
	}
	count, err := s.importCveJSONLTx(ctx, reader, source, tx)
	if err != nil {
		return 0, err
	}
	if count == 0 {
		return 0, errNoValidCveEntries
	}
	if finalize {
		if _, err := s.db.SyncEPSSPriorityColumnsTx(ctx, tx); err != nil {
			return 0, err
		}
		if _, err := s.db.RefreshCveAffectedPackagesForSourceTx(ctx, tx, source); err != nil {
			return 0, err
		}
		if _, err := s.db.RefreshCveReferenceKeysForSourceTx(ctx, tx, source); err != nil {
			return 0, err
		}
	}
	if err := s.db.RefreshSecuritySourceStatusTx(ctx, tx, source); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Server) importCveJSONLTx(ctx context.Context, reader io.Reader, source string, tx *sql.Tx) (int, error) {
	return s.importCveJSONLWithUpsert(ctx, reader, source, func(ctx context.Context, batch []models.CveEntry) (int, error) {
		return s.db.UpsertCveEntriesWithoutAffectedIndexTx(ctx, tx, batch)
	})
}

func (s *Server) importCveJSONLWithUpsert(ctx context.Context, reader io.Reader, source string, upsert func(context.Context, []models.CveEntry) (int, error)) (int, error) {
	source, err := normalizeCveSource(source, "")
	if err != nil {
		return 0, err
	}
	decoder := json.NewDecoder(reader)
	batch := make([]models.CveEntry, 0, 1000)
	total := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		n, err := upsert(ctx, batch)
		if err != nil {
			return err
		}
		total += n
		batch = batch[:0]
		return nil
	}
	for {
		var input cveEntryJSON
		if err := decoder.Decode(&input); err != nil {
			if err == io.EOF {
				break
			}
			return total, err
		}
		e := input.toModel()
		normalizeCveEntry(&e)
		if e.VulnerabilityID == "" || strings.HasPrefix(strings.ToUpper(e.VulnerabilityID), "CGA-") || temporaryCvePlaceholder(e.VulnerabilityID) || temporaryCvePlaceholder(e.ID) {
			continue
		}
		if source != "" {
			e.Source = source
		} else {
			normalized, err := normalizeCveSource(e.Source, "bundle")
			if err != nil {
				return total, err
			}
			e.Source = normalized
		}
		batch = append(batch, e)
		if len(batch) >= 1000 {
			if err := flush(); err != nil {
				return total, err
			}
		}
	}
	return total, flush()
}

type cveEntryJSON struct {
	ID               string          `json:"id"`
	VulnerabilityID  string          `json:"vulnerability_id"`
	Source           string          `json:"source"`
	Category         string          `json:"category,omitempty"`
	Ecosystem        string          `json:"ecosystem,omitempty"`
	Severity         string          `json:"severity"`
	CVSSScore        float64         `json:"cvss_score"`
	CVSSVector       string          `json:"cvss_vector"`
	EPSSScore        float64         `json:"epss_score,omitempty"`
	EPSSPercentile   float64         `json:"epss_percentile,omitempty"`
	Title            string          `json:"title"`
	Description      string          `json:"description"`
	PublishedDate    flexibleCveTime `json:"published_date,omitempty"`
	ModifiedDate     flexibleCveTime `json:"modified_date,omitempty"`
	AffectedProducts string          `json:"affected_products"`
	References       string          `json:"references"`
	RawData          string          `json:"raw_data"`
	UpdatedAt        flexibleCveTime `json:"updated_at"`
}

func (e cveEntryJSON) toModel() models.CveEntry {
	return models.CveEntry{
		ID:               e.ID,
		VulnerabilityID:  e.VulnerabilityID,
		Source:           e.Source,
		Category:         e.Category,
		Ecosystem:        e.Ecosystem,
		Severity:         e.Severity,
		CVSSScore:        e.CVSSScore,
		CVSSVector:       e.CVSSVector,
		EPSSScore:        e.EPSSScore,
		EPSSPercentile:   e.EPSSPercentile,
		Title:            e.Title,
		Description:      e.Description,
		PublishedDate:    e.PublishedDate.Time,
		ModifiedDate:     e.ModifiedDate.Time,
		AffectedProducts: e.AffectedProducts,
		References:       e.References,
		RawData:          e.RawData,
		UpdatedAt:        e.UpdatedAt.Value(),
	}
}

type flexibleCveTime struct {
	Time *time.Time
}

func (t *flexibleCveTime) UnmarshalJSON(data []byte) error {
	raw := strings.TrimSpace(string(data))
	if raw == "" || raw == "null" {
		t.Time = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	s = strings.TrimSpace(s)
	if s == "" {
		t.Time = nil
		return nil
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05.999999",
		"2006-01-02T15:04:05.999",
		"2006-01-02T15:04:05",
		"2006-01-02",
	} {
		parsed, err := time.Parse(layout, s)
		if err == nil {
			if layout != time.RFC3339Nano {
				parsed = time.Date(parsed.Year(), parsed.Month(), parsed.Day(), parsed.Hour(), parsed.Minute(), parsed.Second(), parsed.Nanosecond(), time.UTC)
			}
			t.Time = &parsed
			return nil
		}
	}
	return fmt.Errorf("invalid CVE timestamp %q", s)
}

func (t flexibleCveTime) Value() time.Time {
	if t.Time == nil {
		return time.Time{}
	}
	return *t.Time
}

func normalizeCveEntry(e *models.CveEntry) {
	e.ID = strings.TrimSpace(e.ID)
	e.VulnerabilityID = strings.TrimSpace(e.VulnerabilityID)
	e.Source = strings.TrimSpace(e.Source)
	e.Category = strings.TrimSpace(e.Category)
	e.Ecosystem = strings.TrimSpace(e.Ecosystem)
	e.Severity = strings.ToUpper(strings.TrimSpace(e.Severity))
	e.CVSSVector = strings.TrimSpace(e.CVSSVector)
	e.Title = strings.TrimSpace(e.Title)
	e.Description = strings.TrimSpace(e.Description)
}

func temporaryCvePlaceholder(id string) bool {
	vulnID := strings.ToUpper(strings.TrimSpace(id))
	for _, prefix := range []string{"TEMP-", "CVD-"} {
		if strings.HasPrefix(vulnID, prefix) {
			rest := strings.TrimPrefix(vulnID, prefix)
			return strings.TrimSpace(rest) != ""
		}
	}
	return false
}

func normalizeCveSource(source, fallback string) (string, error) {
	source = strings.ToLower(strings.TrimSpace(source))
	if source == "" {
		source = strings.ToLower(strings.TrimSpace(fallback))
	}
	if source == "" {
		return "", nil
	}
	if len(source) > 64 {
		return "", fmt.Errorf("%w: source is too long", errInvalidCveSource)
	}
	for _, r := range source {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return "", fmt.Errorf("%w: source must contain only lowercase letters, digits, dot, underscore, or hyphen", errInvalidCveSource)
	}
	return source, nil
}

func cveImportErrorStatus(err error) int {
	if errors.Is(err, errInvalidCveSource) {
		return http.StatusBadRequest
	}
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &syntaxErr) || errors.As(err, &typeErr) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func cveImportErrorMessage(err error) string {
	if errors.Is(err, errInvalidCveSource) {
		return "invalid cve source"
	}
	if cveImportErrorStatus(err) == http.StatusBadRequest {
		return "invalid cve jsonl"
	}
	return "import failed"
}

func (s *Server) handleCveDbRematch(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var err error
	opts := rematchOptionsFromEnv()
	if r.Body != nil {
		var body struct {
			Sources                   []string `json:"sources"`
			MinSourceMatchablePercent float64  `json:"min_source_matchable_percent"`
			ScanID                    string   `json:"scan_id"`
			CandidateLimit            int      `json:"candidate_limit"`
		}
		if err := decodeJSONBody(w, r, &body, true); err != nil {
			writeJSONBodyError(w, err, "invalid json")
			return
		}
		if len(body.Sources) > 0 {
			opts.Sources = cleanCSV(body.Sources)
		}
		if body.MinSourceMatchablePercent > 0 {
			opts.MinSourceMatchablePercent = body.MinSourceMatchablePercent
		}
		opts.ScanID = strings.TrimSpace(body.ScanID)
		if body.CandidateLimit > 0 {
			opts.CandidateLimit = body.CandidateLimit
		}
	}
	opts, err = normalizeRematchOptions(opts)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid source")
		return
	}
	result, err := s.db.RematchCVEs(r.Context(), opts)
	if err != nil {
		log.Printf("cve-db rematch: %v", err)
		writeError(w, http.StatusInternalServerError, "rematch failed")
		return
	}
	if stats, err := s.db.GetCveSourceStats(r.Context()); err == nil {
		result.SourcePolicy, result.EligibleSources, result.ExcludedSources = rematchSourcePolicySummary(stats, opts)
	}
	revisionMeta := s.securityDBRevisionMeta(r.Context())
	if v, ok := revisionMeta["security_db_revision"].(string); ok {
		result.SecurityDBRevision = v
	}
	if v, ok := revisionMeta["security_db_revision_error"].(string); ok {
		result.SecurityDBRevisionError = v
	}
	writeJSON(w, http.StatusOK, result)
	auditMeta := map[string]any{
		"matched":                      result.Matched,
		"new_vulns":                    result.NewVulns,
		"skipped":                      result.Skipped,
		"scanned_candidates":           result.ScannedCandidates,
		"candidate_limit":              result.CandidateLimit,
		"limited":                      result.Limited,
		"sources":                      opts.Sources,
		"min_source_matchable_percent": opts.MinSourceMatchablePercent,
		"eligible_sources":             result.EligibleSources,
		"excluded_sources":             result.ExcludedSources,
		"source_policy":                result.SourcePolicy,
		"scan_id":                      opts.ScanID,
	}
	for k, v := range revisionMeta {
		auditMeta[k] = v
	}
	s.audit(r, "cve_db.rematch", "cve_db", "all", "ok", auditMeta)
	enriched, _ := s.db.EnrichVulnerabilities(r.Context())
	log.Printf("Enriched %d vulnerabilities with CVE DB data", enriched)
}

func (s *Server) handleCveDbAffectedIndexRebuild(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if r.URL.Query().Get("async") == "true" {
		started, status := s.startAffectedIndexRebuild()
		code := http.StatusAccepted
		if !started {
			code = http.StatusConflict
		}
		writeJSON(w, code, map[string]any{"status": status, "affected_index_rebuild": s.affectedIndexRebuildStatus()})
		return
	}
	started := time.Now()
	count, err := s.db.RebuildCveAffectedPackages(r.Context())
	durationMS := time.Since(started).Milliseconds()
	if err != nil {
		log.Printf("cve affected package index rebuild failed after %dms: %v", durationMS, err)
		writeError(w, http.StatusInternalServerError, "rebuild failed")
		return
	}
	stats, _ := s.db.GetCveAffectedPackageIndexStats(r.Context())
	revisionMeta := s.securityDBRevisionMeta(r.Context())
	s.clearCveStatsCache()
	out := map[string]any{"status": "ok", "indexed": count, "duration_ms": durationMS, "index": stats}
	for k, v := range revisionMeta {
		out[k] = v
	}
	writeJSON(w, http.StatusOK, out)
	auditMeta := map[string]any{"indexed": count, "duration_ms": durationMS}
	if stats != nil {
		auditMeta["index_count"] = stats.Count
		auditMeta["index_sources"] = stats.SourceCount
		auditMeta["index_coverage_percent"] = stats.CoveragePercent
		auditMeta["index_missing_matchable_sources"] = stats.MissingMatchableSources
		auditMeta["index_orphans"] = stats.Orphans
	}
	for k, v := range revisionMeta {
		auditMeta[k] = v
	}
	s.audit(r, "cve_db.affected_index_rebuild", "cve_db", "affected_index", "ok", auditMeta)
}

func (s *Server) startAffectedIndexRebuild() (bool, string) {
	s.affectedIndexMu.Lock()
	if s.affectedIndexRunning {
		s.affectedIndexMu.Unlock()
		return false, "running"
	}
	s.affectedIndexRunning = true
	s.affectedIndexStartedAt = time.Now()
	s.affectedIndexMu.Unlock()

	go s.runAffectedIndexRebuild()
	return true, "queued"
}

func (s *Server) runAffectedIndexRebuild() {
	started := time.Now()
	log.Printf("CVE affected package index rebuild started")
	s.auditSystem("cve_db.affected_index_rebuild", "cve_db", "affected_index", "started", map[string]any{"started_at": started.UTC().Format(time.RFC3339)})
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(envInt("BONGSU_CVE_AFFECTED_INDEX_TIMEOUT_SECONDS", 180))*time.Second)
	defer cancel()
	count, err := s.db.RebuildCveAffectedPackages(ctx)
	durationMS := time.Since(started).Milliseconds()
	status := "ok"
	meta := map[string]any{"indexed": count, "duration_ms": durationMS}
	if err != nil {
		status = "error"
		meta["error"] = err.Error()
		log.Printf("CVE affected package index rebuild failed after %dms: %v", durationMS, err)
	} else {
		log.Printf("CVE affected package index rebuild finished indexed=%d duration_ms=%d", count, durationMS)
		ctxStats, cancelStats := context.WithTimeout(context.Background(), 10*time.Second)
		if stats, statsErr := s.db.GetCveAffectedPackageIndexStats(ctxStats); statsErr == nil && stats != nil {
			meta["index_count"] = stats.Count
			meta["index_sources"] = stats.SourceCount
			meta["index_coverage_percent"] = stats.CoveragePercent
			meta["index_missing_matchable_sources"] = stats.MissingMatchableSources
			meta["index_orphans"] = stats.Orphans
		}
		cancelStats()
	}
	ctxMeta, cancelMeta := context.WithTimeout(context.Background(), 5*time.Second)
	for k, v := range s.securityDBRevisionMeta(ctxMeta) {
		meta[k] = v
	}
	cancelMeta()
	s.auditSystem("cve_db.affected_index_rebuild", "cve_db", "affected_index", status, meta)
	result := cloneMap(meta)
	result["status"] = status
	result["finished_at"] = time.Now().UTC().Format(time.RFC3339)
	s.affectedIndexMu.Lock()
	s.affectedIndexRunning = false
	s.affectedIndexStartedAt = time.Time{}
	s.affectedIndexLast = result
	s.affectedIndexMu.Unlock()
	if err == nil {
		s.clearCveStatsCache()
	}
}

func (s *Server) handleCveDbReferenceIndexRebuild(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if r.URL.Query().Get("async") == "true" {
		started, status := s.startReferenceIndexRebuild()
		code := http.StatusAccepted
		if !started {
			code = http.StatusConflict
		}
		writeJSON(w, code, map[string]any{"status": status, "reference_index_rebuild": s.referenceIndexRebuildStatus()})
		return
	}
	started := time.Now()
	count, err := s.db.RebuildCveReferenceKeys(r.Context())
	durationMS := time.Since(started).Milliseconds()
	if err != nil {
		log.Printf("cve reference key index rebuild failed after %dms: %v", durationMS, err)
		writeError(w, http.StatusInternalServerError, "rebuild failed")
		return
	}
	revisionMeta := s.securityDBRevisionMeta(r.Context())
	s.clearCveStatsCache()
	out := map[string]any{"status": "ok", "indexed": count, "duration_ms": durationMS}
	for k, v := range revisionMeta {
		out[k] = v
	}
	writeJSON(w, http.StatusOK, out)
	auditMeta := map[string]any{"indexed": count, "duration_ms": durationMS}
	for k, v := range revisionMeta {
		auditMeta[k] = v
	}
	s.audit(r, "cve_db.reference_index_rebuild", "cve_db", "reference_index", "ok", auditMeta)
}

func (s *Server) startReferenceIndexRebuild() (bool, string) {
	s.referenceIndexMu.Lock()
	if s.referenceIndexRunning {
		s.referenceIndexMu.Unlock()
		return false, "running"
	}
	s.referenceIndexRunning = true
	s.referenceIndexStartedAt = time.Now()
	s.referenceIndexMu.Unlock()

	go s.runReferenceIndexRebuild()
	return true, "queued"
}

func (s *Server) runReferenceIndexRebuild() {
	started := time.Now()
	log.Printf("CVE reference key index rebuild started")
	s.auditSystem("cve_db.reference_index_rebuild", "cve_db", "reference_index", "started", map[string]any{"started_at": started.UTC().Format(time.RFC3339)})
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(envInt("BONGSU_CVE_REFERENCE_INDEX_TIMEOUT_SECONDS", 180))*time.Second)
	defer cancel()
	count, err := s.db.RebuildCveReferenceKeys(ctx)
	durationMS := time.Since(started).Milliseconds()
	status := "ok"
	meta := map[string]any{"indexed": count, "duration_ms": durationMS}
	if err != nil {
		status = "error"
		meta["error"] = err.Error()
		log.Printf("CVE reference key index rebuild failed after %dms: %v", durationMS, err)
	} else {
		log.Printf("CVE reference key index rebuild finished indexed=%d duration_ms=%d", count, durationMS)
	}
	ctxMeta, cancelMeta := context.WithTimeout(context.Background(), 5*time.Second)
	for k, v := range s.securityDBRevisionMeta(ctxMeta) {
		meta[k] = v
	}
	cancelMeta()
	s.auditSystem("cve_db.reference_index_rebuild", "cve_db", "reference_index", status, meta)
	result := cloneMap(meta)
	result["status"] = status
	result["finished_at"] = time.Now().UTC().Format(time.RFC3339)
	s.referenceIndexMu.Lock()
	s.referenceIndexRunning = false
	s.referenceIndexStartedAt = time.Time{}
	s.referenceIndexLast = result
	s.referenceIndexMu.Unlock()
	if err == nil {
		s.clearCveStatsCache()
	}
}

func rematchOptionsFromEnv() db.RematchOptions {
	opts, err := normalizeRematchOptions(db.RematchOptions{
		Sources:                   splitCSV(os.Getenv("BONGSU_CVE_MATCH_SOURCES")),
		MinSourceMatchablePercent: envFloat("BONGSU_CVE_MATCH_MIN_SOURCE_MATCHABLE_PERCENT", 0),
		CandidateLimit:            envInt("BONGSU_CVE_MATCH_CANDIDATE_LIMIT", db.DefaultRematchCandidateLimit),
	})
	if err != nil {
		log.Printf("invalid BONGSU_CVE_MATCH_SOURCES ignored: %v", err)
		opts.Sources = nil
	}
	return opts
}

func normalizeRematchOptions(opts db.RematchOptions) (db.RematchOptions, error) {
	var err error
	opts.Sources, err = normalizeCveSources(opts.Sources)
	if err != nil {
		return opts, err
	}
	opts.ScanID = strings.TrimSpace(opts.ScanID)
	if opts.MinSourceMatchablePercent < 0 {
		opts.MinSourceMatchablePercent = 0
	}
	if opts.MinSourceMatchablePercent > 100 {
		opts.MinSourceMatchablePercent = 100
	}
	if opts.CandidateLimit <= 0 {
		opts.CandidateLimit = db.DefaultRematchCandidateLimit
	}
	if opts.CandidateLimit > db.MaxRematchCandidateLimit {
		opts.CandidateLimit = db.MaxRematchCandidateLimit
	}
	return opts, nil
}

func normalizeCveSources(sources []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range sources {
		source, err := normalizeCveSource(raw, "")
		if err != nil {
			return nil, err
		}
		if source == "" || seen[source] {
			continue
		}
		seen[source] = true
		out = append(out, source)
	}
	return out, nil
}

func (s *Server) handleCveDbRecalcCVSS(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	count, err := s.db.RecalcCVSSFromVectors(r.Context())
	if err != nil {
		log.Printf("cvss recalc: %v", err)
		writeError(w, http.StatusInternalServerError, "recalc failed")
		return
	}
	revisionMeta := s.securityDBRevisionMeta(r.Context())
	auditMeta := map[string]any{"updated": count}
	resp := map[string]any{"status": "ok", "updated": count}
	for k, v := range revisionMeta {
		auditMeta[k] = v
		resp[k] = v
	}
	s.audit(r, "cve_db.recalc_cvss", "cve_db", "all", "ok", auditMeta)
	writeJSON(w, http.StatusOK, resp)
}
func (s *Server) handleCveDbExport(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	source, err := normalizeCveSource(r.URL.Query().Get("source"), "")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid source")
		return
	}
	revisionMeta := s.securityDBRevisionMeta(r.Context())

	cveFile, count, cveSHA, err := s.writeCveJSONLTemp(r.Context(), source)
	if err != nil {
		log.Printf("cve-db export: %v", err)
		writeError(w, http.StatusInternalServerError, "export failed")
		return
	}
	defer os.Remove(cveFile)
	info, err := os.Stat(cveFile)
	if err != nil {
		log.Printf("cve-db export stat: %v", err)
		writeError(w, http.StatusInternalServerError, "export failed")
		return
	}
	f, err := os.Open(cveFile)
	if err != nil {
		log.Printf("cve-db export open: %v", err)
		writeError(w, http.StatusInternalServerError, "export failed")
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", "attachment; filename=cve-database.jsonl")
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	w.Header().Set("X-Bongsu-CVE-Records", strconv.Itoa(count))
	w.Header().Set("X-Bongsu-SHA256", cveSHA)
	if revision, ok := revisionMeta["security_db_revision"].(string); ok && revision != "" {
		w.Header().Set("X-Bongsu-Security-DB-Revision", revision)
	}
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, f); err != nil {
		log.Printf("cve-db export write: %v", err)
		return
	}
	auditMeta := map[string]any{"source": source, "records": count, "bytes": info.Size(), "sha256": cveSHA}
	for k, v := range revisionMeta {
		auditMeta[k] = v
	}
	s.audit(r, "cve_db.export", "cve_db", source, "ok", auditMeta)
}

func (s *Server) securityDBRevisionMeta(ctx context.Context) map[string]any {
	meta := map[string]any{}
	revision, err := s.db.GetSecurityDBRevision(ctx)
	if err != nil {
		meta["security_db_revision_error"] = err.Error()
		return meta
	}
	meta["security_db_revision"] = revision
	return meta
}

func (s *Server) writeCveJSONLTemp(ctx context.Context, source string) (string, int, string, error) {
	source, err := normalizeCveSource(source, "")
	if err != nil {
		return "", 0, "", err
	}
	tmp, err := os.CreateTemp("", "bongsu-cve-database-*.jsonl")
	if err != nil {
		return "", 0, "", err
	}
	path := tmp.Name()
	defer tmp.Close()

	q := "SELECT " + db.CveCols + " FROM cve_database"
	args := []any{}
	if source != "" {
		q += " WHERE source=$1"
		args = append(args, source)
	}
	q += " ORDER BY vulnerability_id, source"

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		os.Remove(path)
		return "", 0, "", err
	}
	defer rows.Close()

	hash := sha256.New()
	writer := io.MultiWriter(tmp, hash)
	encoder := json.NewEncoder(writer)
	count := 0
	for rows.Next() {
		var e models.CveEntry
		if err := db.ScanCveEntry(rows, &e); err != nil {
			os.Remove(path)
			return "", 0, "", err
		}
		if err := encoder.Encode(e); err != nil {
			os.Remove(path)
			return "", 0, "", err
		}
		count++
	}
	if err := rows.Err(); err != nil {
		os.Remove(path)
		return "", 0, "", err
	}
	return path, count, hex.EncodeToString(hash.Sum(nil)), nil
}

func writeTarBytes(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0644,
		Size:    int64(len(data)),
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func writeTarFile(tw *tar.Writer, name, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	hdr := &tar.Header{
		Name:    name,
		Mode:    0644,
		Size:    info.Size(),
		ModTime: info.ModTime(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}

func (s *Server) handleCveDbSources(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if !s.canReadCveDB(r) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	sources, err := s.db.GetCveSources(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": sources})
}

func (s *Server) handleCveDbStats(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if !s.canReadCveDB(r) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	cacheGen := int64(0)
	if r.URL.Query().Get("refresh") != "true" {
		if cached, ok := s.getCveStatsCache(); ok {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Bongsu-Cache", "hit")
			w.WriteHeader(http.StatusOK)
			w.Write(cached)
			return
		}
		if stale, ok := s.getCveStatsStaleCache(); ok {
			if _, staleGen, wait := s.beginCveStatsBuild(); !wait {
				s.startCveStatsBackgroundBuild(staleGen)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Bongsu-Cache", "stale")
			w.WriteHeader(http.StatusOK)
			w.Write(stale)
			return
		}
		var ch <-chan cveStatsBuildResult
		var wait bool
		ch, cacheGen, wait = s.beginCveStatsBuild()
		if wait {
			select {
			case result := <-ch:
				if result.status != http.StatusOK {
					writeError(w, result.status, result.msg)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Bongsu-Cache", "shared")
				w.WriteHeader(http.StatusOK)
				w.Write(result.body)
				return
			case <-r.Context().Done():
				writeError(w, http.StatusRequestTimeout, "request cancelled while waiting for CVE stats")
				return
			}
		}
		defer func() {
			if rec := recover(); rec != nil {
				s.finishCveStatsBuild(cveStatsBuildResult{status: http.StatusInternalServerError, msg: "panic building CVE stats"})
				panic(rec)
			}
		}()
	}
	result := s.buildCveDbStatsBody(r.Context())
	if result.status != http.StatusOK {
		if r.URL.Query().Get("refresh") != "true" {
			s.finishCveStatsBuild(result)
		}
		writeError(w, result.status, result.msg)
		return
	}
	if r.URL.Query().Get("refresh") != "true" {
		s.setCveStatsCache(result.body, cacheGen)
		s.finishCveStatsBuild(result)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Bongsu-Cache", "miss")
	w.WriteHeader(http.StatusOK)
	w.Write(result.body)
}

func (s *Server) beginCveStatsBuild() (<-chan cveStatsBuildResult, int64, bool) {
	s.cveStatsCacheMu.Lock()
	defer s.cveStatsCacheMu.Unlock()
	if s.cveStatsInflight {
		ch := make(chan cveStatsBuildResult, 1)
		s.cveStatsWaiters = append(s.cveStatsWaiters, ch)
		return ch, 0, true
	}
	s.cveStatsInflight = true
	return nil, s.cveStatsCacheGen, false
}

func (s *Server) finishCveStatsBuild(result cveStatsBuildResult) {
	s.cveStatsCacheMu.Lock()
	waiters := s.cveStatsWaiters
	s.cveStatsWaiters = nil
	s.cveStatsInflight = false
	s.cveStatsCacheMu.Unlock()
	for _, ch := range waiters {
		ch <- result
		close(ch)
	}
}

func (s *Server) buildCveDbStatsBody(ctx context.Context) cveStatsBuildResult {
	started := time.Now()
	durations := map[string]int64{}

	var stats []db.CveSourceStats
	var statsErr error
	var indexStats *db.CveAffectedPackageIndexStats
	var indexErr error
	var referenceIndexStats *db.CveReferenceKeyIndexStats
	var referenceIndexErr error
	var epssStats *db.CveEPSSMergeStats
	var epssErr error
	var placeholderStats *db.CvePlaceholderStats
	var placeholderErr error
	var osvEcosystemStats []db.CveOsvEcosystemStats
	var osvEcosystemErr error
	var securityMeta map[string]any

	var sourceStatsMS, affectedIndexMS, referenceIndexMS, epssMS, placeholderMS, osvEcosystemMS, securityRevisionMS int64
	var wg sync.WaitGroup
	querySlots := make(chan struct{}, cveStatsQueryConcurrency())
	measure := func(dst *int64, fn func()) {
		defer wg.Done()
		querySlots <- struct{}{}
		defer func() { <-querySlots }()
		stepStarted := time.Now()
		fn()
		*dst = time.Since(stepStarted).Milliseconds()
	}
	wg.Add(7)
	go measure(&sourceStatsMS, func() { stats, statsErr = s.db.GetCveSourceStats(ctx) })
	go measure(&affectedIndexMS, func() { indexStats, indexErr = s.db.GetCveAffectedPackageIndexStats(ctx) })
	go measure(&referenceIndexMS, func() { referenceIndexStats, referenceIndexErr = s.db.GetCveReferenceKeyIndexStats(ctx) })
	go measure(&epssMS, func() { epssStats, epssErr = s.db.GetCveEPSSMergeStats(ctx) })
	go measure(&placeholderMS, func() { placeholderStats, placeholderErr = s.db.GetCvePlaceholderStats(ctx) })
	go measure(&osvEcosystemMS, func() { osvEcosystemStats, osvEcosystemErr = s.db.GetCveOsvEcosystemStats(ctx, 40) })
	go measure(&securityRevisionMS, func() { securityMeta = s.securityDBRevisionMeta(ctx) })
	wg.Wait()
	durations["source_stats"] = sourceStatsMS
	durations["affected_package_index"] = affectedIndexMS
	durations["reference_key_index"] = referenceIndexMS
	durations["epss_merge"] = epssMS
	durations["placeholder_quality"] = placeholderMS
	durations["osv_ecosystems"] = osvEcosystemMS
	durations["security_db_revision"] = securityRevisionMS

	if statsErr != nil {
		return cveStatsBuildResult{status: http.StatusInternalServerError, msg: "db error"}
	}
	opts := rematchOptionsFromEnv()
	policy, eligible, excluded := rematchSourcePolicySummary(stats, opts)
	sources := make([]map[string]any, 0, len(stats))
	totalRecords := 0
	totalMatchable := 0
	for _, stat := range stats {
		totalRecords += stat.Count
		totalMatchable += stat.Matchable
		source := map[string]any{
			"source":            stat.Source,
			"count":             stat.Count,
			"matchable":         stat.Matchable,
			"matchable_percent": stat.MatchablePercent,
			"with_ecosystem":    stat.WithEcosystem,
			"with_fixed":        stat.WithFixed,
			"with_ranges":       stat.WithRanges,
			"with_cvss":         stat.WithCVSS,
			"last_update":       stat.LastUpdate,
			"rematch_eligible":  policy[stat.Source]["eligible"],
			"rematch_exclusion": policy[stat.Source]["reason"],
		}
		sources = append(sources, source)
	}
	totalMatchablePercent := 0.0
	if totalRecords > 0 {
		totalMatchablePercent = float64(totalMatchable) / float64(totalRecords) * 100
	}
	resp := map[string]any{
		"generated_at":            time.Now().UTC().Format(time.RFC3339),
		"source_count":            len(stats),
		"total_records":           totalRecords,
		"total_matchable":         totalMatchable,
		"total_matchable_percent": totalMatchablePercent,
		"sources":                 sources,
		"rematch_policy": map[string]any{
			"sources":                      opts.Sources,
			"min_source_matchable_percent": opts.MinSourceMatchablePercent,
			"candidate_limit":              opts.CandidateLimit,
			"eligible_sources":             eligible,
			"excluded_sources":             excluded,
		},
	}
	if osvEcosystemErr == nil {
		resp["osv_ecosystems"] = osvEcosystemStats
	} else {
		resp["osv_ecosystems_error"] = osvEcosystemErr.Error()
	}
	if indexErr == nil {
		resp["affected_package_index"] = indexStats
	} else {
		resp["affected_package_index_error"] = indexErr.Error()
	}
	if referenceIndexErr == nil {
		resp["reference_key_index"] = referenceIndexStats
	} else {
		resp["reference_key_index_error"] = referenceIndexErr.Error()
	}
	if epssErr == nil {
		resp["epss_merge"] = epssStats
	} else {
		resp["epss_merge_error"] = epssErr.Error()
	}
	if placeholderErr == nil {
		resp["cve_db_quality"] = buildCveDBQualitySummary(cveDBQualityInput{
			TotalRecords:          totalRecords,
			TotalMatchable:        totalMatchable,
			EligibleSources:       eligible,
			ExcludedSources:       excluded,
			Placeholders:          placeholderStats,
			AffectedIndex:         indexStats,
			ReferenceIndex:        referenceIndexStats,
			EPSS:                  epssStats,
			AffectedIndexError:    indexErr,
			ReferenceIndexError:   referenceIndexErr,
			EPSSMergeError:        epssErr,
			PlaceholderStatsError: placeholderErr,
		})
	} else {
		resp["cve_db_quality_error"] = placeholderErr.Error()
	}
	for k, v := range securityMeta {
		resp[k] = v
	}
	durations["total"] = time.Since(started).Milliseconds()
	resp["durations_ms"] = durations
	body, err := json.Marshal(resp)
	if err != nil {
		return cveStatsBuildResult{status: http.StatusInternalServerError, msg: "json error"}
	}
	return cveStatsBuildResult{body: body, status: http.StatusOK}
}

func cveStatsQueryConcurrency() int {
	n := envInt("BONGSU_CVE_STATS_QUERY_CONCURRENCY", 2)
	if n < 1 {
		return 1
	}
	if n > 7 {
		return 7
	}
	return n
}

func (s *Server) startCveStatsBackgroundBuild(cacheGen int64) {
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic building CVE stats in background: %v", rec)
				s.finishCveStatsBuild(cveStatsBuildResult{status: http.StatusInternalServerError, msg: "panic building CVE stats"})
			}
		}()
		timeout := envInt("BONGSU_CVE_STATS_BACKGROUND_TIMEOUT_SECONDS", 30)
		if timeout <= 0 {
			timeout = 30
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer cancel()
		result := s.buildCveDbStatsBody(ctx)
		if result.status == http.StatusOK {
			s.setCveStatsCache(result.body, cacheGen)
		}
		s.finishCveStatsBuild(result)
	}()
}

func (s *Server) getCveStatsCache() ([]byte, bool) {
	ttl := envInt("BONGSU_CVE_STATS_CACHE_SECONDS", 15)
	if ttl <= 0 {
		return nil, false
	}
	s.cveStatsCacheMu.Lock()
	defer s.cveStatsCacheMu.Unlock()
	if time.Now().After(s.cveStatsCacheUntil) || len(s.cveStatsCacheJSON) == 0 {
		return nil, false
	}
	out := make([]byte, len(s.cveStatsCacheJSON))
	copy(out, s.cveStatsCacheJSON)
	return out, true
}

func (s *Server) getCveStatsStaleCache() ([]byte, bool) {
	staleSeconds := envInt("BONGSU_CVE_STATS_STALE_SECONDS", 300)
	if staleSeconds <= 0 {
		return nil, false
	}
	s.cveStatsCacheMu.Lock()
	defer s.cveStatsCacheMu.Unlock()
	if len(s.cveStatsCacheJSON) == 0 || s.cveStatsCacheUntil.IsZero() {
		return nil, false
	}
	now := time.Now()
	if now.Before(s.cveStatsCacheUntil) || now.After(s.cveStatsCacheUntil.Add(time.Duration(staleSeconds)*time.Second)) {
		return nil, false
	}
	out := make([]byte, len(s.cveStatsCacheJSON))
	copy(out, s.cveStatsCacheJSON)
	return out, true
}

func (s *Server) setCveStatsCache(body []byte, generation int64) {
	ttl := envInt("BONGSU_CVE_STATS_CACHE_SECONDS", 15)
	if ttl <= 0 {
		return
	}
	s.cveStatsCacheMu.Lock()
	defer s.cveStatsCacheMu.Unlock()
	if generation != s.cveStatsCacheGen {
		return
	}
	s.cveStatsCacheUntil = time.Now().Add(time.Duration(ttl) * time.Second)
	s.cveStatsCacheJSON = append(s.cveStatsCacheJSON[:0], body...)
}

func (s *Server) clearCveStatsCache() {
	s.cveStatsCacheMu.Lock()
	defer s.cveStatsCacheMu.Unlock()
	s.cveStatsCacheUntil = time.Time{}
	s.cveStatsCacheJSON = nil
	s.cveStatsCacheGen++
}

func rematchSourcePolicy(stats []db.CveSourceStats, opts db.RematchOptions) map[string]map[string]any {
	policy, _, _ := rematchSourcePolicySummary(stats, opts)
	return policy
}

func rematchSourcePolicySummary(stats []db.CveSourceStats, opts db.RematchOptions) (map[string]map[string]any, int, int) {
	allowlist := map[string]bool{}
	for _, source := range opts.Sources {
		allowlist[source] = true
	}
	out := make(map[string]map[string]any, len(stats))
	eligibleCount := 0
	for _, stat := range stats {
		eligible := true
		reason := ""
		if len(allowlist) > 0 && !allowlist[stat.Source] {
			eligible = false
			reason = "source not in rematch allowlist"
		} else if stat.Matchable == 0 {
			eligible = false
			reason = "source has no matchable affected packages"
		} else if opts.MinSourceMatchablePercent > 0 && stat.MatchablePercent < opts.MinSourceMatchablePercent {
			eligible = false
			reason = fmt.Sprintf("matchable %.1f%% below %.1f%% policy", stat.MatchablePercent, opts.MinSourceMatchablePercent)
		}
		if eligible {
			eligibleCount++
		}
		out[stat.Source] = map[string]any{"eligible": eligible, "reason": reason}
	}
	return out, eligibleCount, len(stats) - eligibleCount
}

type cveDBQualityInput struct {
	TotalRecords          int
	TotalMatchable        int
	EligibleSources       int
	ExcludedSources       int
	Placeholders          *db.CvePlaceholderStats
	AffectedIndex         *db.CveAffectedPackageIndexStats
	AffectedIndexPartial  bool
	AffectedIndexDetail   error
	ReferenceIndex        *db.CveReferenceKeyIndexStats
	ReferenceIndexPartial bool
	ReferenceIndexDetail  error
	EPSS                  *db.CveEPSSMergeStats
	AffectedIndexError    error
	ReferenceIndexError   error
	EPSSMergeError        error
	PlaceholderStatsError error
	SkipMissingFetch      bool
}

func (s *Server) cveDBQualitySummary(ctx context.Context, input cveDBQualityInput) map[string]any {
	if !input.SkipMissingFetch && input.Placeholders == nil && input.PlaceholderStatsError == nil {
		input.Placeholders, input.PlaceholderStatsError = s.db.GetCvePlaceholderStats(ctx)
	}
	if !input.SkipMissingFetch && input.AffectedIndex == nil && input.AffectedIndexError == nil {
		input.AffectedIndex, input.AffectedIndexError = s.db.GetCveAffectedPackageIndexStats(ctx)
	}
	if !input.SkipMissingFetch && input.ReferenceIndex == nil && input.ReferenceIndexError == nil {
		input.ReferenceIndex, input.ReferenceIndexError = s.db.GetCveReferenceKeyIndexStats(ctx)
	}
	if !input.SkipMissingFetch && input.EPSS == nil && input.EPSSMergeError == nil {
		input.EPSS, input.EPSSMergeError = s.db.GetCveEPSSMergeStats(ctx)
	}
	if ctx.Err() != nil && input.Placeholders == nil && input.AffectedIndex == nil && input.ReferenceIndex == nil && input.EPSS == nil {
		return nil
	}
	return buildCveDBQualitySummary(input)
}

func buildCveDBQualitySummary(input cveDBQualityInput) map[string]any {
	warnings := []string{}
	severity := 0
	addWarning := func(level int, msg string) {
		if msg == "" {
			return
		}
		warnings = append(warnings, msg)
		if level > severity {
			severity = level
		}
	}
	totalRecords := input.TotalRecords
	if totalRecords == 0 && input.ReferenceIndex != nil && input.ReferenceIndex.TotalCVEs > 0 {
		totalRecords = input.ReferenceIndex.TotalCVEs
	}
	totalMatchable := input.TotalMatchable
	if totalMatchable == 0 && input.AffectedIndex != nil && input.AffectedIndex.IndexedCVEs > 0 {
		totalMatchable = input.AffectedIndex.IndexedCVEs
	}
	eligibleSources := input.EligibleSources
	if eligibleSources == 0 && input.AffectedIndex != nil && input.AffectedIndex.SourceCount > 0 {
		eligibleSources = input.AffectedIndex.SourceCount
	}
	out := map[string]any{
		"status":                  "ok",
		"warnings":                warnings,
		"warning_count":           0,
		"total_records":           totalRecords,
		"total_matchable":         totalMatchable,
		"eligible_sources":        eligibleSources,
		"excluded_sources":        input.ExcludedSources,
		"temporary_placeholders":  0,
		"empty_vulnerability_ids": 0,
		"empty_sources":           0,
	}
	if input.Placeholders != nil {
		out["temporary_placeholders"] = input.Placeholders.TemporaryPlaceholders
		out["empty_vulnerability_ids"] = input.Placeholders.EmptyVulnerabilityIDs
		out["empty_sources"] = input.Placeholders.EmptySources
		if input.Placeholders.TemporaryPlaceholders > 0 {
			addWarning(2, "temporary CVE placeholders present")
		}
		if input.Placeholders.EmptyVulnerabilityIDs > 0 {
			addWarning(2, "empty vulnerability IDs present")
		}
		if input.Placeholders.EmptySources > 0 {
			addWarning(1, "CVE records with empty source present")
		}
	} else if input.PlaceholderStatsError != nil {
		out["placeholder_stats_error"] = input.PlaceholderStatsError.Error()
		addWarning(1, "placeholder quality check unavailable")
	}
	if input.AffectedIndex != nil {
		out["affected_index_orphans"] = input.AffectedIndex.Orphans
		if input.AffectedIndexPartial {
			out["affected_index_summary_mode"] = "indexed-only"
			out["affected_index_indexed_cves"] = input.AffectedIndex.IndexedCVEs
			out["affected_index_records"] = input.AffectedIndex.Count
			if input.AffectedIndexDetail != nil {
				out["affected_index_detail_error"] = input.AffectedIndexDetail.Error()
				addWarning(1, "affected package index detailed quality unavailable")
			}
		} else {
			out["affected_index_coverage_percent"] = input.AffectedIndex.CoveragePercent
			out["affected_index_stale"] = input.AffectedIndex.Stale
		}
		if input.AffectedIndex.Orphans > 0 {
			addWarning(2, "affected package index has orphan rows")
		}
		if !input.AffectedIndexPartial && input.AffectedIndex.Stale {
			addWarning(2, "affected package index is stale")
		}
		if !input.AffectedIndexPartial && len(input.AffectedIndex.MissingMatchableSources) > 0 {
			addWarning(2, "affected package index missing matchable sources")
		}
	} else if input.AffectedIndexError != nil {
		out["affected_index_error"] = input.AffectedIndexError.Error()
		addWarning(1, "affected package index quality unavailable")
	}
	if input.ReferenceIndex != nil {
		out["reference_index_orphans"] = input.ReferenceIndex.Orphans
		if input.ReferenceIndexPartial {
			out["reference_index_summary_mode"] = "indexed-only"
			out["reference_index_indexed_cves"] = input.ReferenceIndex.IndexedCVEs
			out["reference_index_records"] = input.ReferenceIndex.Count
			if input.ReferenceIndexDetail != nil {
				out["reference_index_detail_error"] = input.ReferenceIndexDetail.Error()
				addWarning(1, "reference key index detailed quality unavailable")
			}
		} else {
			out["reference_index_coverage_percent"] = input.ReferenceIndex.CoveragePercent
			out["reference_index_stale"] = input.ReferenceIndex.Stale
		}
		if input.ReferenceIndex.Orphans > 0 {
			addWarning(2, "reference key index has orphan rows")
		}
		if !input.ReferenceIndexPartial && input.ReferenceIndex.Stale {
			addWarning(2, "reference key index is stale")
		}
		if !input.ReferenceIndexPartial && input.ReferenceIndex.TotalCVEs > 0 && input.ReferenceIndex.CoveragePercent < 90 {
			addWarning(1, "reference key coverage below 90%")
		}
	} else if input.ReferenceIndexError != nil {
		out["reference_index_error"] = input.ReferenceIndexError.Error()
		addWarning(1, "reference key index quality unavailable")
	}
	if input.EPSS != nil {
		out["epss_merge_coverage_percent"] = input.EPSS.MergeCoveragePercent
		out["epss_non_epss_coverage_percent"] = input.EPSS.NonEPSSCoveragePercent
		if input.EPSS.EPSSCVEs > 0 && input.EPSS.EnrichedRecords == 0 {
			addWarning(2, "EPSS records loaded without CVE enrichment")
		} else if input.EPSS.NonEPSSCVEs > 0 && input.EPSS.NonEPSSCoveragePercent < 90 {
			addWarning(1, "EPSS applicable CVE coverage below 90%")
		}
	} else if input.EPSSMergeError != nil {
		out["epss_merge_error"] = input.EPSSMergeError.Error()
		addWarning(1, "EPSS merge quality unavailable")
	}
	if totalRecords > 0 && eligibleSources == 0 {
		addWarning(2, "no rematch eligible CVE sources")
	}
	status := "ok"
	if severity >= 2 {
		status = "degraded"
	} else if severity == 1 {
		status = "warning"
	}
	out["status"] = status
	out["warnings"] = warnings
	out["warning_count"] = len(warnings)
	return out
}

func (s *Server) handleCveDbSearch(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if !s.canReadCveDB(r) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	searchTimeout := envInt("BONGSU_CVE_SEARCH_TIMEOUT_SECONDS", 15)
	if searchTimeout <= 0 {
		searchTimeout = 15
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(searchTimeout)*time.Second)
	defer cancel()

	query := r.URL.Query().Get("q")
	referenceKey := strings.TrimSpace(r.URL.Query().Get("reference_key"))
	severity := r.URL.Query().Get("severity")
	source, err := normalizeCveSource(r.URL.Query().Get("source"), "")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid source")
		return
	}
	minCVSS := floatParam(r, "min_cvss", 0)
	minEPSS := floatParam(r, "min_epss", 0)
	minEPSSPercentile := floatParam(r, "min_epss_percentile", 0)
	matchableOnly := boolQuery(r, "matchable")
	includePrioritySources := boolQuery(r, "include_priority_sources")
	sortBy := r.URL.Query().Get("sort_by")
	sortOrder := r.URL.Query().Get("sort_order")
	limit := limitParam(r, 50)
	offset := offsetParam(r)

	entries, total, err := s.db.SearchCveDatabase(ctx, query, referenceKey, severity, source, minCVSS, minEPSS, minEPSSPercentile, matchableOnly, includePrioritySources, sortBy, sortOrder, limit, offset)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			log.Printf("cve-db search timeout after %ds: %v", searchTimeout, err)
			writeError(w, http.StatusGatewayTimeout, "search timeout")
			return
		}
		log.Printf("cve-db search: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	if entries == nil {
		entries = []models.CveEntry{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items": entries,
		"total": total,
	})
}

func (s *Server) handleCveDbReferenceGroup(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if !s.canReadCveDB(r) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	key := strings.TrimSpace(r.URL.Query().Get("key"))
	if key == "" {
		writeError(w, http.StatusBadRequest, "missing key")
		return
	}
	groupTimeout := envInt("BONGSU_CVE_REFERENCE_GROUP_TIMEOUT_SECONDS", 10)
	if groupTimeout <= 0 {
		groupTimeout = 10
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(groupTimeout)*time.Second)
	defer cancel()
	summary, err := s.db.GetCveReferenceGroupSummary(ctx, key, limitParam(r, 50))
	if err != nil {
		if errors.Is(err, db.ErrInvalidCveReferenceKey) {
			writeError(w, http.StatusBadRequest, "invalid key")
			return
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			log.Printf("cve-db reference group timeout after %ds: %v", groupTimeout, err)
			writeError(w, http.StatusGatewayTimeout, "reference group timeout")
			return
		}
		log.Printf("cve-db reference group: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleCveDbAffectedPackages(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if !s.canReadCveDB(r) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing cve id")
		return
	}
	limit := limitParam(r, 100)
	offset := offsetParam(r)
	affectedTimeout := envInt("BONGSU_CVE_AFFECTED_PACKAGES_TIMEOUT_SECONDS", 10)
	if affectedTimeout <= 0 {
		affectedTimeout = 10
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(affectedTimeout)*time.Second)
	defer cancel()
	items, total, err := s.db.ListCveAffectedPackages(ctx, id, limit, offset)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			log.Printf("cve-db affected packages timeout after %ds: %v", affectedTimeout, err)
			writeError(w, http.StatusGatewayTimeout, "affected packages timeout")
			return
		}
		log.Printf("cve-db affected packages: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	if items == nil {
		items = []db.CveAffectedPackage{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":  items,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}
