package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/ziozzang/bongsu/internal/server/db"
	"github.com/ziozzang/bongsu/internal/shared/models"
)


func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAgent(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAgentReportBytes())

	var report models.ScanReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "report too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := normalizeScanReport(&report); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	tokenHash, err := s.agentHostTokenHash(r, report.Host.ID)
	if err != nil {
		s.audit(r, "agent.report", "host", report.Host.ID, "forbidden", map[string]any{"reason": err.Error()})
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if err := s.db.UpsertHostWithAgentToken(ctx, &report.Host, tokenHash); err != nil {
		log.Printf("upsert host: %v", err)
		if errors.Is(err, db.ErrAgentHostTokenMismatch) {
			s.audit(r, "agent.report", "host", report.Host.ID, "forbidden", map[string]any{"reason": "agent token mismatch"})
			http.Error(w, "agent token does not match host binding", http.StatusForbidden)
			return
		}
		http.Error(w, "db error", http.StatusInternalServerError)
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
		http.Error(w, "db error", http.StatusInternalServerError)
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

	insertedVulns := 0
	skippedVulns := 0
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
	}

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
	if err := s.db.CompleteScan(ctx, report.ScanID, scanStatus, errorSummary); err != nil {
		log.Printf("complete scan: %v", err)
		ingestErrors = append(ingestErrors, "complete_scan: "+err.Error())
		errorSummary = scanErrorSummary(ingestErrors)
	}
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
	return nil
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
	if skippedVulns > 0 || ingestErrorCount > 0 {
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
