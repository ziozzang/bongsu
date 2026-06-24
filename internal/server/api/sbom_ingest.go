package api

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ziozzang/bongsu/internal/server/cvematch"
	"github.com/ziozzang/bongsu/internal/server/db"
	"github.com/ziozzang/bongsu/internal/shared/models"
)

// handleSBOMIngest accepts an externally-generated CycloneDX or SPDX SBOM and
// runs it through the SAME match/triage pipeline as an agent report. This lets
// any CI (cyclonedx-py, syft, ...) feed Bongsu without the agent: the SBOM is
// parsed to packages, attached to a synthetic host derived from the SBOM subject
// (so re-ingesting the same target updates the same host — continuous tracking),
// matched, and persisted.
//
// The subject host identity is stable per name: pass ?subject=<name> (or rely on
// the SBOM metadata.component name). Asset metadata (environment/team/owner/
// criticality) can be supplied as query params and is applied to the host.
func (s *Server) handleSBOMIngest(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAgentReportBytes())
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "sbom too large")
			return
		}
		writeError(w, http.StatusBadRequest, "could not read body")
		return
	}

	pkgs, meta, err := cvematch.ParseSBOM(data)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(pkgs) == 0 {
		writeError(w, http.StatusBadRequest, "sbom contained no matchable packages (need PURLs with an ecosystem)")
		return
	}

	subject := strings.TrimSpace(r.URL.Query().Get("subject"))
	if subject == "" {
		subject = strings.TrimSpace(meta.ComponentName)
	}
	if subject == "" {
		subject = "sbom-import"
	}
	host := s.synthSBOMHost(subject, meta, r)

	ctx := r.Context()
	if err := s.db.UpsertHost(ctx, host); err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}

	report := models.ScanReport{
		Host:      *host,
		ScanType:  "sbom",
		ScanID:    uuid.New().String(),
		Timestamp: time.Now().UTC(),
	}
	if rev, err := s.db.GetSecurityDBRevision(ctx); err == nil {
		report.SecurityDBRevision = rev
	}
	scan := &models.Scan{
		ID:                 report.ScanID,
		HostID:             host.ID,
		ScanType:           "sbom",
		Status:             "running",
		SecurityDBRevision: report.SecurityDBRevision,
		StartedAt:          report.Timestamp,
	}
	if err := s.db.CreateScan(ctx, scan); err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}

	for i := range pkgs {
		pkgs[i].ID = uuid.New().String()
		pkgs[i].ScanID = report.ScanID
		pkgs[i].HostID = host.ID
		pkgs[i].AssetType = "host"
		pkgs[i].AssetID = host.ID
	}
	report.Packages = pkgs

	var ingestErrors []string
	if err := s.db.InsertPackages(ctx, pkgs); err != nil {
		ingestErrors = append(ingestErrors, "packages: "+err.Error())
	}
	// Persist the dependency graph the SBOM carried (PURL->PURL edges).
	if len(meta.Dependencies) > 0 {
		var edges [][2]string
		for parent, children := range meta.Dependencies {
			for _, child := range children {
				edges = append(edges, [2]string{parent, child})
			}
		}
		if err := s.db.StorePackageDependencies(ctx, report.ScanID, edges); err != nil {
			ingestErrors = append(ingestErrors, "dependencies: "+err.Error())
		}
	}

	insertedVulns, skippedVulns, _, ingestErrors := s.runScanMatch(ctx, &report, ingestErrors)

	if _, err := s.db.RebuildPackageVulnerabilitySummariesForScan(ctx, report.ScanID); err != nil {
		ingestErrors = append(ingestErrors, "package_vulnerability_summaries: "+err.Error())
	}
	scanStatus := reportScanStatus(skippedVulns, len(ingestErrors))
	if err := s.db.CompleteScan(ctx, report.ScanID, scanStatus, scanErrorSummary(ingestErrors)); err != nil {
		ingestErrors = append(ingestErrors, "complete_scan: "+err.Error())
	}
	s.statsCache.invalidate()
	s.healthCache.invalidate()

	// Persist the source SBOM for provenance (B).
	s.storeIngestedSBOM(ctx, report.ScanID, host.ID, meta, data)

	s.audit(r, "sbom.ingest", "host", host.ID, "success", map[string]any{
		"scan_id": report.ScanID, "format": meta.Format, "packages": len(pkgs), "new_vulns": insertedVulns,
	})

	resp := map[string]any{
		"scan_id":     report.ScanID,
		"host_id":     host.ID,
		"format":      meta.Format,
		"packages":    len(pkgs),
		"new_vulns":   insertedVulns,
		"scan_status": scanStatus,
	}
	if len(ingestErrors) > 0 {
		resp["errors"] = ingestErrors
	}
	writeJSON(w, http.StatusOK, resp)
}

// storeIngestedSBOM best-effort persists the source SBOM for provenance. A
// failure here never fails the ingest (the findings are already committed).
func (s *Server) storeIngestedSBOM(ctx context.Context, scanID, hostID string, meta cvematch.SBOMMeta, raw []byte) {
	format := "cyclonedx"
	if strings.EqualFold(meta.Format, "SPDX") {
		format = "spdx"
	}
	if err := s.db.StoreScanSBOM(ctx, db.ScanSBOM{
		ScanID:      scanID,
		HostID:      hostID,
		Format:      format,
		Origin:      "ingested",
		SpecVersion: meta.SpecVersion,
		SourceRef:   meta.SerialNumber,
		BOM:         raw,
	}); err != nil {
		log.Printf("store ingested sbom scan=%s: %v", scanID, err)
	}
}

// maybeStoreGeneratedSBOM retains a generated CycloneDX SBOM for an agent scan
// when BONGSU_SBOM_STORE_GENERATED=true. Best-effort; provenance only.
func (s *Server) maybeStoreGeneratedSBOM(ctx context.Context, report *models.ScanReport) {
	if os.Getenv("BONGSU_SBOM_STORE_GENERATED") != "true" || len(report.Packages) == 0 {
		return
	}
	bom, err := cvematch.GenerateCycloneDX(report.Packages, report.Host)
	if err != nil {
		return
	}
	if err := s.db.StoreScanSBOM(ctx, db.ScanSBOM{
		ScanID: report.ScanID, HostID: report.Host.ID, Format: "cyclonedx", Origin: "generated",
		SpecVersion: "1.5", ComponentCount: len(report.Packages), BOM: bom,
	}); err != nil {
		log.Printf("store generated sbom scan=%s: %v", report.ScanID, err)
	}
}

// handleGetScanSBOM returns the SBOM stored for a scan (provenance retrieval).
func (s *Server) handleGetScanSBOM(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	scanID := r.PathValue("id")
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "cyclonedx"
	}
	sbom, err := s.db.GetScanSBOM(r.Context(), scanID, format)
	if err != nil {
		writeError(w, http.StatusNotFound, "no stored sbom for this scan")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\"sbom-"+scanID+"."+format+".json\"")
	_, _ = w.Write(sbom.BOM)
}

// handleScanDependents returns the transitive set of components that depend on
// a given package within a scan — the dependency blast radius of a (typically
// vulnerable) component. ?package=<purl-or-name> selects the target.
func (s *Server) handleScanDependents(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	scanID := r.PathValue("id")
	target := strings.TrimSpace(r.URL.Query().Get("package"))
	if target == "" {
		writeError(w, http.StatusBadRequest, "package query param required (PURL or name)")
		return
	}
	key := db.DependencyKey(target, target)
	dependents, err := s.db.DependentsOf(r.Context(), scanID, key)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"scan_id":    scanID,
		"package":    target,
		"dependents": dependents,
		"count":      len(dependents),
	})
}

// synthSBOMHost builds a stable synthetic host for an SBOM subject. The ID is
// derived deterministically from the subject so repeated CI ingests of the same
// project converge on one host record rather than spawning duplicates.
func (s *Server) synthSBOMHost(subject string, meta cvematch.SBOMMeta, r *http.Request) *models.Host {
	id := uuid.NewSHA1(uuid.NameSpaceURL, []byte("bongsu:sbom-subject:"+subject)).String()
	q := r.URL.Query()
	pick := func(key, def string) string {
		if v := strings.TrimSpace(q.Get(key)); v != "" {
			return v
		}
		return def
	}
	return &models.Host{
		ID:          id,
		Hostname:    subject,
		OSName:      pick("os_name", "sbom"),
		OSVersion:   meta.ComponentVer,
		Owner:       pick("owner", ""),
		Team:        pick("team", ""),
		Environment: pick("environment", ""),
		Criticality: pick("criticality", ""),
		Tags:        pick("tags", "sbom"),
		LastSeen:    time.Now().UTC(),
	}
}
