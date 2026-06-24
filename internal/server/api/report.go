package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/ziozzang/bongsu/internal/server/db"
	"github.com/ziozzang/bongsu/internal/server/live"
	"github.com/ziozzang/bongsu/internal/shared/models"
)

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAgent(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAgentReportBytes())

	var report models.ScanReport
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&report); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "report too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var extra struct{}
	if err := decoder.Decode(&extra); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := normalizeScanReport(&report); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx := r.Context()
	tokenHash, err := s.agentHostTokenHash(r, report.Host.ID)
	if err != nil {
		s.audit(r, "agent.report", "host", report.Host.ID, "forbidden", map[string]any{"reason": err.Error()})
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	if err := s.db.UpsertHostWithAgentToken(ctx, &report.Host, tokenHash); err != nil {
		log.Printf("upsert host: %v", err)
		if errors.Is(err, db.ErrAgentHostTokenMismatch) {
			s.audit(r, "agent.report", "host", report.Host.ID, "forbidden", map[string]any{"reason": "agent token mismatch"})
			writeError(w, http.StatusForbidden, "agent token does not match host binding")
			return
		}
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}

	report.SecurityDBRevision = strings.TrimSpace(report.SecurityDBRevision)
	report.ScanRequestID = strings.TrimSpace(report.ScanRequestID)
	if report.SecurityDBRevision == "" {
		if revision, err := s.db.GetSecurityDBRevision(ctx); err == nil {
			report.SecurityDBRevision = revision
		} else {
			log.Printf("scan report security db revision: %v", err)
		}
	}

	scan := &models.Scan{
		ID:                 report.ScanID,
		HostID:             report.Host.ID,
		ScanType:           report.ScanType,
		Status:             "running",
		SecurityDBRevision: report.SecurityDBRevision,
		ScanRequestID:      report.ScanRequestID,
		StartedAt:          report.Timestamp,
	}
	if err := s.db.CreateScan(ctx, scan); err != nil {
		log.Printf("create scan: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	ingestErrors := append([]string{}, report.Errors...)

	for i := range report.Containers {
		if report.Containers[i].ID == "" {
			report.Containers[i].ID = uuid.New().String()
		}
		report.Containers[i].ScanID = report.ScanID
		report.Containers[i].HostID = report.Host.ID
	}
	if err := s.db.InsertContainers(ctx, report.Containers); err != nil {
		log.Printf("insert containers: %v", err)
		ingestErrors = append(ingestErrors, "containers: "+err.Error())
	}

	for i := range report.Packages {
		if report.Packages[i].ID == "" {
			report.Packages[i].ID = uuid.New().String()
		}
		report.Packages[i].ScanID = report.ScanID
		report.Packages[i].HostID = report.Host.ID
		if report.Packages[i].AssetType == "" {
			report.Packages[i].AssetType = "host"
		}
		if report.Packages[i].AssetID == "" && report.Packages[i].AssetType == "host" {
			report.Packages[i].AssetID = report.Host.ID
		}
	}
	if err := s.db.InsertPackages(ctx, report.Packages); err != nil {
		log.Printf("insert packages: %v", err)
		ingestErrors = append(ingestErrors, "packages: "+err.Error())
	}
	// Persist the dependency graph any package carried (e.g. npm lockfiles), so
	// transitive blast-radius queries are possible. No-op for older agents that
	// don't report dependencies.
	if edges := db.BuildScanDependencyEdges(report.Packages); len(edges) > 0 {
		if err := s.db.StorePackageDependencies(ctx, report.ScanID, edges); err != nil {
			log.Printf("store package dependencies: %v", err)
			ingestErrors = append(ingestErrors, "dependencies: "+err.Error())
		}
	}

	insertedVulns, skippedVulns, newFindings, ingestErrors := s.runScanMatch(ctx, &report, ingestErrors)

	for i := range report.Users {
		if report.Users[i].ID == "" {
			report.Users[i].ID = uuid.New().String()
		}
		report.Users[i].ScanID = report.ScanID
		report.Users[i].HostID = report.Host.ID
	}
	if err := s.db.InsertUserAccounts(ctx, report.Users); err != nil {
		log.Printf("insert users: %v", err)
		ingestErrors = append(ingestErrors, "users: "+err.Error())
	}

	for i := range report.Processes {
		if report.Processes[i].ID == "" {
			report.Processes[i].ID = uuid.New().String()
		}
		report.Processes[i].ScanID = report.ScanID
		report.Processes[i].HostID = report.Host.ID
	}
	if err := s.db.InsertProcessSnapshots(ctx, report.Processes); err != nil {
		log.Printf("insert processes: %v", err)
		ingestErrors = append(ingestErrors, "processes: "+err.Error())
	}

	for i := range report.Ports {
		if report.Ports[i].ID == "" {
			report.Ports[i].ID = uuid.New().String()
		}
		report.Ports[i].ScanID = report.ScanID
		report.Ports[i].HostID = report.Host.ID
	}
	if err := s.db.InsertPorts(ctx, report.Ports); err != nil {
		log.Printf("insert ports: %v", err)
		ingestErrors = append(ingestErrors, "ports: "+err.Error())
	}

	scanStatus := reportScanStatus(skippedVulns, len(ingestErrors))
	errorSummary := scanErrorSummary(ingestErrors)
	if _, err := s.db.RebuildPackageVulnerabilitySummariesForScan(ctx, report.ScanID); err != nil {
		log.Printf("rebuild package vulnerability summaries: %v", err)
		ingestErrors = append(ingestErrors, "package_vulnerability_summaries: "+err.Error())
		scanStatus = reportScanStatus(skippedVulns, len(ingestErrors))
		errorSummary = scanErrorSummary(ingestErrors)
	}
	if err := s.db.CompleteScan(ctx, report.ScanID, scanStatus, errorSummary); err != nil {
		log.Printf("complete scan: %v", err)
		ingestErrors = append(ingestErrors, "complete_scan: "+err.Error())
		errorSummary = scanErrorSummary(ingestErrors)
	}
	// Optionally retain a point-in-time CycloneDX SBOM for this scan so an
	// operator can later answer "what was installed on this host at scan time".
	// Off by default (per-scan-per-host BOM storage adds up); opt in with
	// BONGSU_SBOM_STORE_GENERATED=true. Best-effort; never affects the scan.
	s.maybeStoreGeneratedSBOM(ctx, &report)

	// A new scan changes the dashboard aggregates; drop the cached stats/health
	// responses so the next poll reflects this ingest immediately.
	s.statsCache.invalidate()
	s.healthCache.invalidate()
	sevCounts, vulnTotal, err := s.db.GetVulnCountsByScan(ctx, report.ScanID)
	if err != nil {
		log.Printf("scan vuln counts: %v", err)
		sevCounts = map[string]int{}
	}
	riskCounts, err := s.db.GetVulnRiskCountsByScan(ctx, report.ScanID)
	if err != nil {
		log.Printf("scan vuln risk counts: %v", err)
		riskCounts = map[string]int{}
	}
	inventoryStatus := reportInventoryStatus(len(report.Packages), scanStatus)
	s.audit(r, "agent.report", "scan", report.ScanID, reportAuditStatus(skippedVulns, len(ingestErrors)), map[string]any{
		"host_id":              report.Host.ID,
		"hostname":             report.Host.Hostname,
		"packages":             len(report.Packages),
		"vulnerabilities":      vulnTotal,
		"vulns_inserted":       insertedVulns,
		"vulns_skipped":        skippedVulns,
		"containers":           len(report.Containers),
		"inventory_status":     inventoryStatus,
		"users":                len(report.Users),
		"processes":            len(report.Processes),
		"ports":                len(report.Ports),
		"scan_status":          scanStatus,
		"error_summary":        errorSummary,
		"ingest_errors":        ingestErrors,
		"scan_request_id":      report.ScanRequestID,
		"security_db_revision": report.SecurityDBRevision,
	})
	if s.notifier.ShouldSendScan(sevCounts, riskCounts, inventoryStatus) {
		s.notifier.Send("scan.completed", reportWebhookPayload(&report, scanStatus, inventoryStatus, insertedVulns, skippedVulns, vulnTotal, sevCounts, riskCounts, ingestErrors))
	}
	if autoAssignByOwnerEnabled() {
		// The owner is managed via the admin metadata API and stored on the host
		// row; agents do not send it in their reports, so report.Host.Owner is
		// typically empty. Resolve the authoritative owner from the DB (falling
		// back to any value the report did carry). Auto-assign runs here, after
		// the synchronous CVE matching / vulnerability insert path above, so the
		// scan's vulnerability rows already exist when we assign them.
		owner := strings.TrimSpace(report.Host.Owner)
		if owner == "" {
			if host, err := s.db.GetHost(ctx, report.Host.ID); err != nil {
				log.Printf("auto-assign: resolve owner for host %s: %v", report.Host.ID, err)
			} else {
				owner = strings.TrimSpace(host.Owner)
			}
		}
		if owner != "" {
			if n, err := s.autoAssignFindingsToOwner(ctx, report.Host.ID, owner); err != nil {
				log.Printf("auto-assign findings to owner for host %s: %v", report.Host.ID, err)
			} else if n > 0 {
				log.Printf("Auto-assigned %d finding(s) on host %s to owner %q", n, report.Host.ID, owner)
			}
		}
	}
	scanFailed := scanFailedFromStatus(scanStatus, ingestErrors)
	// Durably enqueue notifications BEFORE responding: the outbox dispatcher
	// delivers them at-least-once with retry, so a crash or a failing webhook no
	// longer silently loses the event (the previous fire-and-forget goroutine).
	webhookData := reportWebhookPayload(&report, scanStatus, inventoryStatus, insertedVulns, skippedVulns, vulnTotal, sevCounts, riskCounts, ingestErrors)
	if _, err := s.db.EnqueueEvent(r.Context(), eventNotification, notificationEventPayload{Event: "scan.completed", Data: webhookData}, ""); err != nil {
		log.Printf("enqueue scan.completed notification for scan %s: %v", report.ScanID, err)
	}
	if scanFailed {
		if _, err := s.db.EnqueueEvent(r.Context(), eventNotification, notificationEventPayload{Event: "scan.failed", Data: scanFailedPayload(&report, scanStatus, errorSummary, ingestErrors)}, ""); err != nil {
			log.Printf("enqueue scan.failed notification for scan %s: %v", report.ScanID, err)
		}
	}
	// Publish to the live monitoring feed (at-most-once; the dashboard resyncs
	// from the next kpi.snapshot if a client missed it). host_id scopes it for RBAC.
	liveSeverity := live.SeverityInfo
	if scanFailed {
		liveSeverity = live.SeverityWarning
	}
	s.publishLive(live.EventScanCompleted, liveSeverity, map[string]any{
		"host_id":         report.Host.ID,
		"hostname":        report.Host.Hostname,
		"scan_id":         report.ScanID,
		"status":          scanStatus,
		"inserted":        insertedVulns,
		"total":           vulnTotal,
		"severity_counts": sevCounts,
	})
	if scanFailed {
		s.publishLive(live.EventScanFailed, live.SeverityWarning, map[string]any{
			"host_id":  report.Host.ID,
			"hostname": report.Host.Hostname,
			"scan_id":  report.ScanID,
			"status":   scanStatus,
			"error":    errorSummary,
		})
	}
	// Emit a live event per newly-discovered critical/high finding so the feed
	// surfaces them in real time (capped to avoid flooding a noisy first scan).
	for i, f := range newFindings {
		if i >= envInt("BONGSU_LIVE_NEW_FINDING_CAP", 25) {
			break
		}
		et := live.EventFindingNewHigh
		sev := live.SeverityWarning
		if f.Severity == "CRITICAL" {
			et, sev = live.EventFindingNewCrit, live.SeverityCritical
		}
		s.publishLive(et, sev, map[string]any{
			"host_id":  f.HostID,
			"hostname": report.Host.Hostname,
			"cve":      f.VulnerabilityID,
			"pkg":      f.PkgName,
			"severity": f.Severity,
			"cvss":     f.CVSSScore,
		})
	}

	// The trend snapshot is best-effort analytics, not an at-least-once event.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.db.RecordVulnTrendSnapshot(ctx, report.Host.ID, report.ScanID); err != nil {
			log.Printf("trend snapshot after scan %s: %v", report.ScanID, err)
		}
	}()

	writeJSON(w, http.StatusOK, map[string]any{
		"status":               "ok",
		"scan_id":              report.ScanID,
		"scan_status":          scanStatus,
		"inventory_status":     inventoryStatus,
		"error_summary":        errorSummary,
		"security_db_revision": report.SecurityDBRevision,
		"ingest_error_count":   len(ingestErrors),
		"skipped_vuln_count":   skippedVulns,
	})
}

func (s *Server) agentHostTokenHash(r *http.Request, hostID string) (string, error) {
	if !envBool("BONGSU_AGENT_HOST_BINDING", true) {
		return "", nil
	}
	token := strings.TrimSpace(r.Header.Get("X-Bongsu-Agent-Token"))
	if token == "" {
		return "", fmt.Errorf("missing agent host token")
	}
	if len(token) < 32 {
		return "", fmt.Errorf("agent host token is too short")
	}
	if strings.TrimSpace(r.Header.Get("X-Bongsu-Host-ID")) != hostID {
		return "", fmt.Errorf("agent host id header mismatch")
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:]), nil
}

func (s *Server) verifyAgentHostBinding(r *http.Request, hostID string) error {
	tokenHash, err := s.agentHostTokenHash(r, hostID)
	if err != nil {
		return err
	}
	if tokenHash == "" {
		return nil
	}
	if err := s.db.VerifyOrBindHostAgentToken(r.Context(), hostID, tokenHash); err != nil {
		if errors.Is(err, db.ErrAgentHostTokenMismatch) {
			return fmt.Errorf("agent token does not match host binding")
		}
		return err
	}
	return nil
}

// runScanMatch derives and persists vulnerabilities for an already-created scan
// whose packages are stored. It runs the identical sequence — agent-reported
// vulns OR server-side matcher, then EnrichVulnerabilities, then CVE-DB rematch
// and CPE/runtime rematch — for both agent reports and ingested SBOMs, so the
// two ingest paths can never drift in how findings are produced. Returns the
// inserted/skipped counts, any new findings, and the accumulated error list.
func (s *Server) runScanMatch(ctx context.Context, report *models.ScanReport, ingestErrors []string) (insertedVulns, skippedVulns int, newFindings []db.NewFinding, errs []string) {
	if len(report.Vulns) > 0 {
		for i := range report.Vulns {
			if report.Vulns[i].ID == "" {
				report.Vulns[i].ID = uuid.New().String()
			}
			report.Vulns[i].ScanID = report.ScanID
			report.Vulns[i].HostID = report.Host.ID
		}
		if result, err := s.db.InsertVulnerabilities(ctx, report.Vulns); err != nil {
			log.Printf("insert vulns: %v", err)
			ingestErrors = append(ingestErrors, "vulnerabilities: "+err.Error())
		} else if result != nil {
			insertedVulns += result.Inserted
			skippedVulns += result.Skipped
			newFindings = append(newFindings, result.NewFindings...)
		}
		if n, err := s.db.EnrichVulnerabilities(ctx); err == nil && n > 0 {
			log.Printf("Enriched %d vulnerabilities with CVE DB info", n)
		}
	} else if s.matcher != nil && s.dbMgr != nil && s.dbMgr.IsReady() && len(report.Packages) > 0 {
		log.Printf("Running server-side CVE matching for scan %s (%d packages)", report.ScanID, len(report.Packages))
		vulns, err := s.matcher.Match(ctx, report.Packages, report.Host)
		if err != nil {
			log.Printf("Server-side CVE matching failed: %v", err)
			ingestErrors = append(ingestErrors, "server_match: "+err.Error())
		} else {
			log.Printf("Matched %d vulnerabilities for scan %s", len(vulns), report.ScanID)
			for i := range vulns {
				if vulns[i].ID == "" {
					vulns[i].ID = uuid.New().String()
				}
				vulns[i].ScanID = report.ScanID
				vulns[i].HostID = report.Host.ID
			}
			if result, err := s.db.InsertVulnerabilities(ctx, vulns); err != nil {
				log.Printf("insert matched vulns: %v", err)
				ingestErrors = append(ingestErrors, "matched_vulnerabilities: "+err.Error())
			} else if result != nil {
				insertedVulns += result.Inserted
				skippedVulns += result.Skipped
				newFindings = append(newFindings, result.NewFindings...)
			}
			if n, err := s.db.EnrichVulnerabilities(ctx); err == nil && n > 0 {
				log.Printf("Enriched %d vulnerabilities with CVE DB scores", n)
			}
		}
	}
	if len(report.Packages) > 0 {
		opts := rematchOptionsFromEnv()
		opts.ScanID = report.ScanID
		if result, err := s.db.RematchCVEs(ctx, opts); err != nil {
			log.Printf("scan CVE DB rematch failed: %v", err)
			ingestErrors = append(ingestErrors, "cve_db_rematch: "+err.Error())
		} else {
			if result.Limited {
				ingestErrors = append(ingestErrors, fmt.Sprintf("cve_db_rematch: candidate limit %d reached", result.CandidateLimit))
			}
			if result.NewVulns > 0 {
				log.Printf("CVE DB rematched %d vulnerabilities for scan %s", result.NewVulns, report.ScanID)
				insertedVulns += result.NewVulns
			}
		}
		// CPE/runtime matching: flag detected runtimes (python/node/jdk) against
		// NVD CPE advisories, version-gated to avoid false positives.
		if result, err := s.db.RematchCPE(ctx, opts); err != nil {
			log.Printf("scan CPE rematch failed: %v", err)
			ingestErrors = append(ingestErrors, "cpe_rematch: "+err.Error())
		} else if result.NewVulns > 0 {
			log.Printf("CPE matched %d runtime vulnerabilities for scan %s", result.NewVulns, report.ScanID)
			insertedVulns += result.NewVulns
		}
	}
	return insertedVulns, skippedVulns, newFindings, ingestErrors
}

func normalizeScanReport(report *models.ScanReport) error {
	report.ScanID = strings.TrimSpace(report.ScanID)
	if report.ScanID == "" {
		report.ScanID = uuid.New().String()
	} else if _, err := uuid.Parse(report.ScanID); err != nil {
		return fmt.Errorf("invalid scan_id")
	}
	report.ScanType = strings.TrimSpace(report.ScanType)
	if report.ScanType == "" {
		report.ScanType = "inventory"
	}
	switch report.ScanType {
	case "inventory", "daily", "manual", "security-db-update":
	default:
		return fmt.Errorf("invalid scan_type")
	}
	if report.Timestamp.IsZero() {
		report.Timestamp = time.Now().UTC()
	}
	report.Host.ID = strings.TrimSpace(report.Host.ID)
	report.Host.Hostname = strings.TrimSpace(report.Host.Hostname)
	report.Host.IPAddress = strings.TrimSpace(report.Host.IPAddress)
	if temporaryHostIdentity(report.Host.ID) && strings.EqualFold(report.Host.ID, report.Host.Hostname) {
		report.Host.ID = ""
	}
	if report.Host.ID == "" {
		report.Host.ID = fallbackHostID(report.Host)
	}
	if report.Host.Hostname == "" {
		report.Host.Hostname = report.Host.ID
	}
	report.Errors = normalizeReportErrors(report.Errors)
	if err := normalizeReportAssetContext(report); err != nil {
		return err
	}
	return nil
}

func normalizeReportAssetContext(report *models.ScanReport) error {
	containersByName := map[string]models.ContainerAsset{}
	containersByID := map[string]models.ContainerAsset{}
	for i := range report.Containers {
		report.Containers[i].Name = strings.TrimSpace(report.Containers[i].Name)
		report.Containers[i].ContainerID = strings.TrimSpace(report.Containers[i].ContainerID)
		report.Containers[i].ImageName = strings.TrimSpace(report.Containers[i].ImageName)
		report.Containers[i].ImageID = strings.TrimSpace(report.Containers[i].ImageID)
		if report.Containers[i].Name != "" {
			containersByName[report.Containers[i].Name] = report.Containers[i]
		}
		if report.Containers[i].ContainerID != "" {
			containersByID[report.Containers[i].ContainerID] = report.Containers[i]
		}
	}
	for i := range report.Packages {
		if err := normalizePackageAssetContext(&report.Packages[i], report.Host.ID, containersByName, containersByID); err != nil {
			return err
		}
	}
	for i := range report.Vulns {
		if err := normalizeVulnerabilityAssetContext(&report.Vulns[i], containersByName, containersByID); err != nil {
			return err
		}
	}
	return nil
}

func normalizePackageAssetContext(pkg *models.Package, hostID string, containersByName, containersByID map[string]models.ContainerAsset) error {
	pkg.AssetType = strings.TrimSpace(pkg.AssetType)
	pkg.AssetID = strings.TrimSpace(pkg.AssetID)
	pkg.Container = strings.TrimSpace(pkg.Container)
	pkg.ContainerID = strings.TrimSpace(pkg.ContainerID)
	pkg.ImageName = strings.TrimSpace(pkg.ImageName)
	pkg.ImageID = strings.TrimSpace(pkg.ImageID)
	if pkg.AssetType == "" {
		if pkg.Container != "" || pkg.ContainerID != "" || pkg.ImageName != "" || pkg.ImageID != "" {
			pkg.AssetType = "container"
		} else {
			pkg.AssetType = "host"
		}
	}
	switch pkg.AssetType {
	case "host":
		if pkg.AssetID == "" {
			pkg.AssetID = hostID
		}
	case "container":
		applyContainerContext(&pkg.Container, &pkg.ContainerID, &pkg.ImageName, &pkg.ImageID, containersByName, containersByID)
		if pkg.AssetID == "" {
			pkg.AssetID = pkg.ContainerID
			if pkg.AssetID == "" {
				pkg.AssetID = pkg.Container
			}
		}
	default:
		return fmt.Errorf("invalid package asset_type")
	}
	return nil
}

func normalizeVulnerabilityAssetContext(v *models.Vulnerability, containersByName, containersByID map[string]models.ContainerAsset) error {
	v.AssetType = strings.TrimSpace(v.AssetType)
	v.Container = strings.TrimSpace(v.Container)
	v.ContainerID = strings.TrimSpace(v.ContainerID)
	v.ImageName = strings.TrimSpace(v.ImageName)
	v.ImageID = strings.TrimSpace(v.ImageID)
	if v.AssetType == "" {
		if v.Container != "" || v.ContainerID != "" || v.ImageName != "" || v.ImageID != "" {
			v.AssetType = "container"
		}
	}
	switch v.AssetType {
	case "", "host":
	case "container":
		applyContainerContext(&v.Container, &v.ContainerID, &v.ImageName, &v.ImageID, containersByName, containersByID)
	default:
		return fmt.Errorf("invalid vulnerability asset_type")
	}
	return nil
}

func applyContainerContext(name, containerID, imageName, imageID *string, containersByName, containersByID map[string]models.ContainerAsset) {
	c, ok := containersByID[*containerID]
	if !ok && *name != "" {
		c, ok = containersByName[*name]
	}
	if !ok {
		return
	}
	if *name == "" {
		*name = c.Name
	}
	if *containerID == "" {
		*containerID = c.ContainerID
	}
	if *imageName == "" {
		*imageName = c.ImageName
	}
	if *imageID == "" {
		*imageID = c.ImageID
	}
}

func normalizeReportErrors(errs []string) []string {
	if len(errs) == 0 {
		return nil
	}
	normalized := make([]string, 0, min(len(errs), maxReportErrors))
	for _, entry := range errs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if len(entry) > maxReportErrorBytes {
			entry = truncateValidUTF8(entry, maxReportErrorBytes) + "...(truncated)"
		}
		normalized = append(normalized, entry)
		if len(normalized) == maxReportErrors {
			break
		}
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func truncateValidUTF8(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	s = s[:limit]
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s
}

func reportAuditStatus(skippedVulns, ingestErrorCount int) string {
	if skippedVulns > 0 || ingestErrorCount > 0 {
		return "degraded"
	}
	return "ok"
}

func reportScanStatus(skippedVulns, ingestErrorCount int) string {
	if ingestErrorCount > 0 {
		return "degraded"
	}
	return "completed"
}

func scanErrorSummary(errors []string) string {
	if len(errors) == 0 {
		return ""
	}
	const maxSummaryBytes = 512
	summary := fmt.Sprintf("%d error(s): %s", len(errors), strings.Join(errors, "; "))
	if len(summary) > maxSummaryBytes {
		return truncateValidUTF8(summary, maxSummaryBytes) + "...(truncated)"
	}
	return summary
}

func reportInventoryStatus(packageCount int, scanStatus string) string {
	if packageCount == 0 {
		return "empty"
	}
	if scanStatus == "degraded" {
		return "degraded"
	}
	return "healthy"
}

// scanFailedFromStatus reports whether a completed scan should fire the
// "scan.failed" notification trigger. A scan is considered failed/degraded when
// it did not complete cleanly (degraded/failed status) or carried ingest errors.
func scanFailedFromStatus(scanStatus string, ingestErrors []string) bool {
	switch scanStatus {
	case "degraded", "failed":
		return true
	}
	return len(ingestErrors) > 0
}

// scanFailedPayload builds the notification data for the "scan.failed" trigger.
// It carries host/scan identity, the resulting status and a short error summary
// so rules (and their channels) can surface the failure to operators.
func scanFailedPayload(report *models.ScanReport, scanStatus, errorSummary string, ingestErrors []string) map[string]any {
	return map[string]any{
		"scan_id":              report.ScanID,
		"scan_status":          scanStatus,
		"host_id":              report.Host.ID,
		"hostname":             report.Host.Hostname,
		"ip_address":           report.Host.IPAddress,
		"scan_type":            report.ScanType,
		"scan_request_id":      report.ScanRequestID,
		"security_db_revision": report.SecurityDBRevision,
		"error_summary":        errorSummary,
		"ingest_errors":        ingestErrors,
		"ingest_error_count":   len(ingestErrors),
	}
}

func autoAssignByOwnerEnabled() bool {
	return envBool("BONGSU_AUTO_ASSIGN_BY_OWNER", true)
}

// autoAssignFindingsToOwner defaults the triage assignee of a host's findings to
// the host owner. It only creates triage rows that do not yet exist (ON CONFLICT
// DO NOTHING), so a human-set triage/assignee is never overwritten. It is a no-op
// when the host has no owner. Returns the number of findings auto-assigned.
func (s *Server) autoAssignFindingsToOwner(ctx context.Context, hostID, owner string) (int64, error) {
	owner = strings.TrimSpace(owner)
	if hostID == "" || owner == "" {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx, `
INSERT INTO vulnerability_triage
	(id, vulnerability_id, host_id, pkg_name, status, assignee, updated_by, created_at, updated_at)
SELECT DISTINCT gen_random_uuid()::text, v.vulnerability_id, v.host_id, v.pkg_name, 'open', $2, 'auto-assign', now(), now()
FROM vulnerabilities v
WHERE v.host_id = $1
ON CONFLICT (vulnerability_id, host_id, pkg_name) DO NOTHING`, hostID, owner)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func reportWebhookPayload(report *models.ScanReport, scanStatus, inventoryStatus string, insertedVulns, skippedVulns, vulnTotal int, sevCounts, riskCounts map[string]int, ingestErrors []string) map[string]any {
	return map[string]any{
		"scan_id":              report.ScanID,
		"scan_status":          scanStatus,
		"host_id":              report.Host.ID,
		"hostname":             report.Host.Hostname,
		"ip_address":           report.Host.IPAddress,
		"os_name":              report.Host.OSName,
		"os_version":           report.Host.OSVersion,
		"scan_type":            report.ScanType,
		"scan_request_id":      report.ScanRequestID,
		"security_db_revision": report.SecurityDBRevision,
		"inventory_status":     inventoryStatus,
		"packages":             len(report.Packages),
		"containers":           len(report.Containers),
		"vulnerabilities":      vulnTotal,
		"vulns_inserted":       insertedVulns,
		"vulns_skipped":        skippedVulns,
		"error_summary":        scanErrorSummary(ingestErrors),
		"ingest_errors":        ingestErrors,
		"severity_counts":      sevCounts,
		"risk_level_counts":    riskCounts,
	}
}
