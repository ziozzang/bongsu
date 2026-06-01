package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

type DB struct {
	*sql.DB
}

var ErrLatestInventoryScan = errors.New("cannot delete latest completed or degraded inventory scan")
var ErrScanNotFound = errors.New("scan not found")
var ErrInvalidScanRequestStatus = errors.New("invalid scan request status")
var ErrScanRequestNotFound = errors.New("scan request not found")
var ErrScanRequestNotActive = errors.New("scan request is not pending or claimed")
var ErrScanRequestClaimMismatch = errors.New("scan request was not claimed by this host")
var ErrScanRequestNotRetryable = errors.New("scan request is not failed, degraded, or cancelled")
var ErrAgentHostTokenMismatch = errors.New("agent token does not match host binding")
var ErrInvalidCveReferenceKey = errors.New("invalid CVE reference key")

var (
	cveReferenceKeyRe     = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)
	ghsaReferenceKeyRe    = regexp.MustCompile(`(?i)\bGHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}\b`)
	rustsecReferenceKeyRe = regexp.MustCompile(`(?i)\bRUSTSEC-\d{4}-\d{4,}\b`)
	pysecReferenceKeyRe   = regexp.MustCompile(`(?i)\bPYSEC-\d{4}-\d{1,}\b`)
	goReferenceKeyRe      = regexp.MustCompile(`(?i)\bGO-\d{4}-\d{4,}\b`)
	debianAdvisoryKeyRe   = regexp.MustCompile(`(?i)\bD(?:SA|LA)-\d{1,6}-\d+\b`)
)

type RetentionPruneResult struct {
	DryRun        bool   `json:"dry_run"`
	ScanDays      int    `json:"scan_days"`
	RequestDays   int    `json:"request_days"`
	AuditDays     int    `json:"audit_days"`
	ScanCutoff    string `json:"scan_cutoff"`
	RequestCutoff string `json:"request_cutoff"`
	AuditCutoff   string `json:"audit_cutoff"`
	Scans         int    `json:"scans"`
	Packages      int    `json:"packages"`
	Vulns         int    `json:"vulnerabilities"`
	Containers    int    `json:"containers"`
	Users         int    `json:"users"`
	Processes     int    `json:"processes"`
	Ports         int    `json:"ports"`
	Requests      int    `json:"scan_requests"`
	AuditLogs     int    `json:"audit_logs"`
}

func New(ctx context.Context, dsn string) (*DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	applyDBPoolConfig(db, dbPoolConfigFromEnv())

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	return &DB{db}, nil
}

type poolConfig struct {
	MaxOpenConns       int
	MaxIdleConns       int
	ConnMaxLifetimeMin int
}

func dbPoolConfigFromEnv() poolConfig {
	return poolConfig{
		MaxOpenConns:       envPositiveInt("BONGSU_DB_MAX_OPEN_CONNS", 25),
		MaxIdleConns:       envPositiveInt("BONGSU_DB_MAX_IDLE_CONNS", 5),
		ConnMaxLifetimeMin: envPositiveInt("BONGSU_DB_CONN_MAX_LIFETIME_MINUTES", 5),
	}
}

func applyDBPoolConfig(db *sql.DB, cfg poolConfig) {
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(time.Duration(cfg.ConnMaxLifetimeMin) * time.Minute)
}

func (db *DB) RunMigrations(ctx context.Context) error {
	files, err := os.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	legacyInitialized, err := db.legacySchemaComplete(ctx)
	if err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		filename TEXT PRIMARY KEY,
		checksum TEXT NOT NULL,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`); err != nil {
		return fmt.Errorf("ensure schema_migrations: %w", err)
	}
	applied, err := db.appliedMigrations(ctx)
	if err != nil {
		return err
	}
	if len(applied) == 0 && legacyInitialized {
		return db.baselineMigrations(ctx, files)
	}
	for _, f := range files {
		if f.IsDir() || !(len(f.Name()) > 4 && f.Name()[len(f.Name())-4:] == ".sql") {
			continue
		}
		data, err := os.ReadFile("migrations/" + f.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", f.Name(), err)
		}
		checksum := migrationChecksum(data)
		if got, ok := applied[f.Name()]; ok {
			if got != checksum {
				return fmt.Errorf("migration %s checksum mismatch", f.Name())
			}
			continue
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", f.Name(), err)
		}
		if _, err := tx.ExecContext(ctx, string(data)); err != nil {
			tx.Rollback()
			return fmt.Errorf("run migration %s: %w", f.Name(), err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (filename, checksum, applied_at) VALUES ($1,$2,now())`, f.Name(), checksum); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %s: %w", f.Name(), err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", f.Name(), err)
		}
	}
	return nil
}

func (db *DB) baselineMigrations(ctx context.Context, files []os.DirEntry) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration baseline: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO schema_migrations (filename, checksum, applied_at) VALUES ($1,$2,now()) ON CONFLICT (filename) DO NOTHING`)
	if err != nil {
		return fmt.Errorf("prepare migration baseline: %w", err)
	}
	defer stmt.Close()

	for _, f := range files {
		if f.IsDir() || !(len(f.Name()) > 4 && f.Name()[len(f.Name())-4:] == ".sql") {
			continue
		}
		data, err := os.ReadFile("migrations/" + f.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", f.Name(), err)
		}
		if _, err := stmt.ExecContext(ctx, f.Name(), migrationChecksum(data)); err != nil {
			return fmt.Errorf("baseline migration %s: %w", f.Name(), err)
		}
	}
	return tx.Commit()
}

func (db *DB) legacySchemaComplete(ctx context.Context) (bool, error) {
	checks := []struct {
		table  string
		column string
		index  string
	}{
		{table: "hosts"},
		{table: "hosts", column: "agent_token_hash"},
		{table: "packages", column: "asset_type"},
		{table: "packages", column: "purl"},
		{table: "vulnerabilities", column: "pkg_path"},
		{table: "vulnerabilities", column: "finding_source"},
		{table: "cve_database", column: "category"},
		{table: "cve_database", column: "epss_score"},
		{table: "cve_affected_packages"},
		{table: "cve_reference_keys"},
		{table: "container_assets"},
		{table: "scan_requests", column: "claimed_by_host_id"},
		{table: "scan_requests", column: "security_db_revision"},
		{table: "audit_logs"},
		{table: "vulnerability_triage"},
		{index: "idx_scan_requests_pending_security_db_host"},
		{index: "idx_vulnerabilities_package_scan_vuln"},
		{index: "idx_vulnerabilities_finding_source"},
		{index: "idx_cve_affected_pkg_name_ecosystem"},
		{index: "idx_cve_reference_keys_key"},
	}
	for _, check := range checks {
		var ok bool
		var err error
		switch {
		case check.index != "":
			ok, err = db.indexExists(ctx, check.index)
		case check.column == "":
			ok, err = db.tableExists(ctx, check.table)
		default:
			ok, err = db.columnExists(ctx, check.table, check.column)
		}
		if err != nil || !ok {
			return ok, err
		}
	}
	return true, nil
}

func (db *DB) tableExists(ctx context.Context, table string) (bool, error) {
	var exists bool
	err := db.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, "public."+table).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check table %s: %w", table, err)
	}
	return exists, nil
}

func (db *DB) columnExists(ctx context.Context, table, column string) (bool, error) {
	var exists bool
	err := db.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1
		FROM information_schema.columns
		WHERE table_schema='public' AND table_name=$1 AND column_name=$2
	)`, table, column).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check column %s.%s: %w", table, column, err)
	}
	return exists, nil
}

func (db *DB) indexExists(ctx context.Context, index string) (bool, error) {
	var exists bool
	err := db.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, "public."+index).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check index %s: %w", index, err)
	}
	return exists, nil
}

func (db *DB) appliedMigrations(ctx context.Context) (map[string]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT filename, checksum FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var filename, checksum string
		if err := rows.Scan(&filename, &checksum); err != nil {
			return nil, fmt.Errorf("scan schema_migrations: %w", err)
		}
		out[filename] = checksum
	}
	return out, rows.Err()
}

func migrationChecksum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (db *DB) UpsertHost(ctx context.Context, h *models.Host) error {
	return db.UpsertHostWithAgentToken(ctx, h, "")
}

func (db *DB) UpsertHostWithAgentToken(ctx context.Context, h *models.Host, tokenHash string) error {
	q := `INSERT INTO hosts (id, hostname, ip_address, os_name, os_version, kernel, arch, cpu_model, cpu_cores, memory_mb, agent_version, api_key_hash, agent_token_hash, last_seen, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, '', $12, now(), now(), now())
ON CONFLICT (id) DO UPDATE SET hostname=$2, ip_address=$3, os_name=$4, os_version=$5, kernel=$6, arch=$7, cpu_model=$8, cpu_cores=$9, memory_mb=$10, agent_version=$11, agent_token_hash=CASE WHEN hosts.agent_token_hash='' THEN $12 ELSE hosts.agent_token_hash END, last_seen=now(), updated_at=now()
WHERE $12='' OR hosts.agent_token_hash='' OR hosts.agent_token_hash=$12`
	res, err := db.ExecContext(ctx, q,
		h.ID, h.Hostname, h.IPAddress, h.OSName, h.OSVersion,
		h.Kernel, h.Arch, h.CPUModel, h.CPUCores, h.MemoryMB, h.AgentVersion, tokenHash,
	)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrAgentHostTokenMismatch
	}
	return nil
}

func (db *DB) VerifyOrBindHostAgentToken(ctx context.Context, hostID, tokenHash string) error {
	if hostID == "" || tokenHash == "" {
		return ErrAgentHostTokenMismatch
	}
	res, err := db.ExecContext(ctx, `UPDATE hosts
SET agent_token_hash=CASE WHEN agent_token_hash='' THEN $2 ELSE agent_token_hash END
WHERE id=$1 AND (agent_token_hash='' OR agent_token_hash=$2)`, hostID, tokenHash)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrAgentHostTokenMismatch
	}
	return nil
}

func (db *DB) ResetHostAgentToken(ctx context.Context, hostID string) error {
	res, err := db.ExecContext(ctx, `UPDATE hosts SET agent_token_hash='', updated_at=now() WHERE id=$1`, hostID)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (db *DB) CreateScan(ctx context.Context, s *models.Scan) error {
	q := `INSERT INTO scans (id, host_id, scan_type, status, started_at, created_at) VALUES ($1, $2, $3, $4, $5, now())`
	_, err := db.ExecContext(ctx, q, s.ID, s.HostID, s.ScanType, s.Status, s.StartedAt)
	return err
}

func (db *DB) CompleteScan(ctx context.Context, id, status, errorSummary string) error {
	if status == "" {
		status = "completed"
	}
	if status != "completed" && status != "degraded" {
		return fmt.Errorf("invalid scan status: %s", status)
	}
	q := `UPDATE scans SET status=$2, error_summary=$3, finished_at=now() WHERE id=$1`
	_, err := db.ExecContext(ctx, q, id, status, errorSummary)
	return err
}

func (db *DB) DeleteScan(ctx context.Context, id string, force bool) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if !force {
		var latest bool
		if err := tx.QueryRowContext(ctx, deleteScanLatestInventorySQL(), id).Scan(&latest); err != nil {
			return fmt.Errorf("check latest inventory scan: %w", err)
		}
		if latest {
			return ErrLatestInventoryScan
		}
	}

	tables := []string{"vulnerabilities", "packages", "container_assets", "user_accounts", "process_snapshots", "port_info"}
	for _, t := range tables {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE scan_id=$1", t), id); err != nil {
			return fmt.Errorf("delete from %s: %w", t, err)
		}
	}
	res, err := tx.ExecContext(ctx, "DELETE FROM scans WHERE id=$1", id)
	if err != nil {
		return fmt.Errorf("delete scan: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrScanNotFound
	}
	return tx.Commit()
}

func deleteScanLatestInventorySQL() string {
	return `SELECT EXISTS(
		SELECT 1
		FROM scans s
		JOIN ` + latestScansSub + ` ls ON ls.id = s.id
		WHERE s.id = $1
		  AND s.status IN ('completed','degraded')
	)`
}

func (db *DB) PruneOperationalData(ctx context.Context, scanDays, requestDays, auditDays int, dryRun bool) (*RetentionPruneResult, error) {
	result := &RetentionPruneResult{
		DryRun:      dryRun,
		ScanDays:    scanDays,
		RequestDays: requestDays,
		AuditDays:   auditDays,
	}
	now := time.Now()
	scanCutoff := now.Add(-time.Duration(scanDays) * 24 * time.Hour)
	requestCutoff := now.Add(-time.Duration(requestDays) * 24 * time.Hour)
	auditCutoff := now.Add(-time.Duration(auditDays) * 24 * time.Hour)
	result.ScanCutoff = scanCutoff.UTC().Format(time.RFC3339)
	result.RequestCutoff = requestCutoff.UTC().Format(time.RFC3339)
	result.AuditCutoff = auditCutoff.UTC().Format(time.RFC3339)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	oldScans := pruneOldScansCTE()
	countFor := func(table string) (int, error) {
		var n int
		err := tx.QueryRowContext(ctx, oldScans+fmt.Sprintf(` SELECT count(*) FROM %s WHERE scan_id IN (SELECT id FROM old_scans)`, table), scanCutoff).Scan(&n)
		return n, err
	}
	result.Vulns, err = countFor("vulnerabilities")
	if err != nil {
		return nil, err
	}
	result.Packages, err = countFor("packages")
	if err != nil {
		return nil, err
	}
	result.Containers, err = countFor("container_assets")
	if err != nil {
		return nil, err
	}
	result.Users, err = countFor("user_accounts")
	if err != nil {
		return nil, err
	}
	result.Processes, err = countFor("process_snapshots")
	if err != nil {
		return nil, err
	}
	result.Ports, err = countFor("port_info")
	if err != nil {
		return nil, err
	}
	if err := tx.QueryRowContext(ctx, oldScans+` SELECT count(*) FROM old_scans`, scanCutoff).Scan(&result.Scans); err != nil {
		return nil, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM scan_requests WHERE created_at < $1 AND status IN ('completed','degraded','failed','cancelled')`, requestCutoff).Scan(&result.Requests); err != nil {
		return nil, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE created_at < $1`, auditCutoff).Scan(&result.AuditLogs); err != nil {
		return nil, err
	}
	if dryRun {
		return result, tx.Commit()
	}

	deleteFrom := func(table string) error {
		_, err := tx.ExecContext(ctx, oldScans+fmt.Sprintf(` DELETE FROM %s WHERE scan_id IN (SELECT id FROM old_scans)`, table), scanCutoff)
		return err
	}
	for _, table := range []string{"vulnerabilities", "packages", "container_assets", "user_accounts", "process_snapshots", "port_info"} {
		if err := deleteFrom(table); err != nil {
			return nil, fmt.Errorf("delete old %s: %w", table, err)
		}
	}
	if _, err := tx.ExecContext(ctx, oldScans+` DELETE FROM scans WHERE id IN (SELECT id FROM old_scans)`, scanCutoff); err != nil {
		return nil, fmt.Errorf("delete old scans: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM scan_requests WHERE created_at < $1 AND status IN ('completed','degraded','failed','cancelled')`, requestCutoff); err != nil {
		return nil, fmt.Errorf("delete old scan requests: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM audit_logs WHERE created_at < $1`, auditCutoff); err != nil {
		return nil, fmt.Errorf("delete old audit logs: %w", err)
	}
	return result, tx.Commit()
}

func pruneOldScansCTE() string {
	return `WITH old_scans AS (
		SELECT id FROM scans
		WHERE created_at < $1
		  AND status IN ('completed','degraded','failed')
		  AND id NOT IN (SELECT DISTINCT ON (host_id) id FROM scans WHERE status IN ('completed','degraded') ORDER BY host_id, created_at DESC)
	)`
}

func defaultString(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func ClassifySecuritySource(source, affectedProducts string) (string, string) {
	type affectedProduct struct {
		Ecosystem string `json:"ecosystem"`
	}
	var products []affectedProduct
	if affectedProducts != "" {
		_ = json.Unmarshal([]byte(affectedProducts), &products)
	}
	ecosystem := ""
	if len(products) > 0 {
		ecosystem = products[0].Ecosystem
	}
	if ecosystem != "" {
		if isOSEcosystem(ecosystem) {
			return "os-package", ecosystem
		}
		return "code-library", ecosystem
	}
	switch strings.ToLower(source) {
	case "osv":
		return "code-library", ""
	case "trivy":
		return "os-package", ""
	case "nvd", "cisa-kev", "epss":
		return "general-cve", ""
	default:
		return "custom", ""
	}
}

type affectedProduct struct {
	Name      string          `json:"name"`
	Ecosystem string          `json:"ecosystem"`
	Fixed     []string        `json:"fixed"`
	Ranges    []affectedRange `json:"ranges"`
}

type affectedRange struct {
	Type   string               `json:"type"`
	Events []affectedRangeEvent `json:"events"`
}

type affectedRangeEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

func packageCategory(pkgType, ecosystem string) string {
	eco := strings.ToLower(strings.TrimSpace(ecosystem))
	pt := strings.ToLower(pkgType)
	if isOSEcosystem(eco) {
		return "os-package"
	}
	switch eco {
	case "pypi", "npm", "go", "maven", "crates.io", "nuget", "rubygems", "packagist", "hex", "pub":
		return "code-library"
	}
	switch pt {
	case "debian", "ubuntu", "deb", "alpine", "apk", "redhat", "centos", "rocky", "alma", "amazon", "rpm", "suse", "wolfi":
		return "os-package"
	case "python-pkg", "pip", "poetry", "node-pkg", "npm", "yarn", "pnpm", "gomod", "go", "gobinary", "golang", "jar", "maven", "cargo", "rustbinary", "composer", "gem", "nuget":
		return "code-library"
	default:
		return ""
	}
}

func isOSEcosystem(ecosystem string) bool {
	eco := strings.ToLower(strings.TrimSpace(ecosystem))
	if idx := strings.Index(eco, ":"); idx >= 0 {
		eco = strings.TrimSpace(eco[:idx])
	}
	switch eco {
	case "debian", "ubuntu", "alpine", "red hat", "rhel", "suse", "almalinux", "amazon linux", "wolfi", "chainguard", "rocky linux", "oracle linux":
		return true
	default:
		return false
	}
}

func normalizeEcosystem(eco string) string {
	eco = strings.ToLower(strings.TrimSpace(eco))
	switch eco {
	case "python", "python-pkg", "pip":
		return "pypi"
	case "node", "node-pkg", "javascript":
		return "npm"
	case "golang", "gomod":
		return "go"
	case "ruby", "gem":
		return "rubygems"
	case "rust", "cargo":
		return "crates.io"
	case "debian:10", "debian:11", "debian:12", "debian:13":
		return "debian"
	case "ubuntu:18.04", "ubuntu:20.04", "ubuntu:22.04", "ubuntu:24.04":
		return "ubuntu"
	case "redhat", "red hat enterprise linux", "centos", "rocky", "almalinux", "alma", "amazon":
		return "rhel"
	default:
		if strings.HasPrefix(eco, "debian:") {
			return "debian"
		}
		if strings.HasPrefix(eco, "ubuntu:") {
			return "ubuntu"
		}
		return eco
	}
}

func compatibleSecurityCandidate(pkgName, pkgType, pkgEco, installedVersion, cveCategory, cveEco, affectedProducts string) (affectedProduct, bool) {
	var products []affectedProduct
	if affectedProducts == "" || json.Unmarshal([]byte(affectedProducts), &products) != nil {
		return affectedProduct{}, false
	}
	pkgCat := packageCategory(pkgType, pkgEco)
	pkgNormEco := normalizeEcosystem(pkgEco)
	cveNormEco := normalizeEcosystem(cveEco)
	for _, p := range products {
		if !strings.EqualFold(p.Name, pkgName) {
			continue
		}
		affectedEco := normalizeEcosystem(p.Ecosystem)
		effectiveEco := affectedEco
		if effectiveEco == "" {
			effectiveEco = cveNormEco
		}
		if effectiveEco == "" {
			continue
		}
		if len(fixedVersions(p)) == 0 {
			continue
		}
		if !versionIsAffected(installedVersion, p) {
			continue
		}
		affectedCat := packageCategory("", effectiveEco)
		effectiveCat := cveCategory
		if effectiveCat == "" || effectiveCat == "general-cve" {
			effectiveCat = affectedCat
		}
		if pkgCat == "" || effectiveCat == "" || pkgCat != effectiveCat {
			continue
		}
		if pkgNormEco == "" || effectiveEco == "" || pkgNormEco != effectiveEco {
			continue
		}
		return p, true
	}
	return affectedProduct{}, false
}

func versionIsAffected(installed string, p affectedProduct) bool {
	if installed == "" {
		return false
	}
	if len(p.Ranges) > 0 {
		for _, r := range p.Ranges {
			if versionInRange(installed, r.Events) {
				return true
			}
		}
		return false
	}
	fixed := uniqueFixedVersions(p.Fixed)
	if len(fixed) != 1 {
		return false
	}
	if less, ok := versionLess(installed, fixed[0]); ok && less {
		return true
	}
	return false
}

func fixedVersions(p affectedProduct) []string {
	out := uniqueFixedVersions(p.Fixed)
	seen := map[string]bool{}
	for _, fixed := range out {
		seen[fixed] = true
	}
	for _, r := range p.Ranges {
		for _, ev := range r.Events {
			fixed := strings.TrimSpace(ev.Fixed)
			if fixed == "" || seen[fixed] {
				continue
			}
			out = append(out, fixed)
			seen[fixed] = true
		}
	}
	return out
}

func hasSafeFixedEvidence(p affectedProduct) bool {
	if len(uniqueFixedVersions(p.Fixed)) == 1 {
		return true
	}
	for _, r := range p.Ranges {
		for _, ev := range r.Events {
			if strings.TrimSpace(ev.Fixed) != "" {
				return true
			}
		}
	}
	return false
}

func uniqueFixedVersions(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, fixed := range in {
		fixed = strings.TrimSpace(fixed)
		if fixed == "" || seen[fixed] {
			continue
		}
		out = append(out, fixed)
		seen[fixed] = true
	}
	return out
}

func versionInRange(installed string, events []affectedRangeEvent) bool {
	active := false
	for _, ev := range events {
		if ev.Introduced != "" {
			if ev.Introduced == "0" {
				active = true
			} else if cmp, ok := compareVersions(installed, ev.Introduced); ok {
				active = cmp >= 0
			} else {
				return false
			}
		}
		if active && ev.Fixed != "" {
			if less, ok := versionLess(installed, ev.Fixed); ok {
				if less {
					return true
				}
				active = false
			} else {
				return false
			}
		}
		if active && ev.LastAffected != "" {
			if cmp, ok := compareVersions(installed, ev.LastAffected); ok {
				if cmp <= 0 {
					return true
				}
				active = false
			} else {
				return false
			}
		}
		if active && ev.Limit != "" {
			if less, ok := versionLess(installed, ev.Limit); ok {
				if less {
					return true
				}
				active = false
			} else {
				return false
			}
		}
	}
	return active
}

func versionLess(a, b string) (bool, bool) {
	cmp, ok := compareVersions(a, b)
	return cmp < 0, ok
}

func compareVersions(a, b string) (int, bool) {
	as := versionSegments(a)
	bs := versionSegments(b)
	if len(as) == 0 || len(bs) == 0 {
		return 0, false
	}
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if av < bv {
			return -1, true
		}
		if av > bv {
			return 1, true
		}
	}
	aPre := isPreReleaseVersion(a)
	bPre := isPreReleaseVersion(b)
	if aPre && !bPre {
		return -1, true
	}
	if !aPre && bPre {
		return 1, true
	}
	if aPre && bPre {
		if cmp := comparePreRelease(a, b); cmp != 0 {
			return cmp, true
		}
	}
	return 0, true
}

func isPreReleaseVersion(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	if idx := strings.Index(v, "+"); idx >= 0 {
		v = v[:idx]
	}
	if strings.Contains(v, "~") {
		return true
	}
	for _, marker := range preReleaseMarkers() {
		if strings.Contains(v, marker) {
			return true
		}
	}
	return false
}

func versionSegments(v string) []int {
	v = stripPreReleaseSuffix(strings.TrimSpace(v))
	if i := strings.Index(v, ":"); i >= 0 {
		v = v[i+1:]
	}
	parts := strings.FieldsFunc(v, func(r rune) bool {
		return r < '0' || r > '9'
	})
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

func stripPreReleaseSuffix(v string) string {
	low := strings.ToLower(v)
	if idx := strings.IndexAny(low, "+~"); idx >= 0 {
		low = low[:idx]
		v = v[:idx]
	}
	cut := len(v)
	for _, marker := range preReleaseMarkers() {
		if idx := strings.Index(low, marker); idx >= 0 && idx < cut {
			cut = idx
		}
	}
	return strings.TrimRight(v[:cut], "-_.")
}

func preReleaseMarkers() []string {
	return []string{"dev", "snapshot", "preview", "pre", "alpha", "beta", "rc"}
}

func comparePreRelease(a, b string) int {
	aRank, aNum := preReleaseRank(a)
	bRank, bNum := preReleaseRank(b)
	if aRank < bRank {
		return -1
	}
	if aRank > bRank {
		return 1
	}
	if aNum < bNum {
		return -1
	}
	if aNum > bNum {
		return 1
	}
	return 0
}

func preReleaseRank(v string) (int, int) {
	v = strings.ToLower(strings.TrimSpace(v))
	if idx := strings.Index(v, "+"); idx >= 0 {
		v = v[:idx]
	}
	for rank, marker := range preReleaseMarkers() {
		if strings.Contains(v, marker) {
			n, _ := preReleaseNumber(v, marker)
			return rank + 1, n
		}
	}
	if strings.Contains(v, "~") {
		if n, ok := preReleaseNumber(v, "~"); ok {
			return 0, n
		}
		return 0, 0
	}
	return len(preReleaseMarkers()) + 1, 0
}

func preReleaseNumber(v, marker string) (int, bool) {
	idx := strings.Index(v, marker)
	if idx < 0 {
		return 0, false
	}
	rest := v[idx+len(marker):]
	start := -1
	end := -1
	for i, r := range rest {
		if r >= '0' && r <= '9' {
			if start < 0 {
				start = i
			}
			end = i + 1
			continue
		}
		if start >= 0 {
			break
		}
	}
	if start < 0 {
		return 0, false
	}
	n, err := strconv.Atoi(rest[start:end])
	if err != nil {
		return 0, false
	}
	return n, true
}

const pkgCols = `p.id, p.scan_id, p.host_id, p.asset_type, p.asset_id, p.source, p.container, p.container_id, p.image_name, p.image_id, p.name, p.version, p.arch, p.pkg_type, p.ecosystem, p.purl, p.src_name, p.file_path, p.layer_id, p.target, p.created_at`

var pkgVulnJoin = ` LEFT JOIN (
	SELECT v.package_id, MAX(v.cvss_score) as max_cvss, COUNT(*) as vuln_count
	FROM vulnerabilities v` + vulnTriageJoin + `
	WHERE ` + currentActionableVulnSQL() + `
	GROUP BY v.package_id
) vx ON vx.package_id = p.id`

const pkgVulnSelect = `, COALESCE(vx.max_cvss, 0), COALESCE(vx.vuln_count, 0)`

const pkgInsertCols = `id, scan_id, host_id, asset_type, asset_id, source, container, container_id, image_name, image_id, name, version, arch, pkg_type, ecosystem, purl, src_name, file_path, layer_id, target`

func fixedVersionSQLCondition(alias string) string {
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	installed := prefix + "installed_version"
	fixed := prefix + "fixed_version"
	return fmt.Sprintf(`%s IS NOT NULL AND %s != ''
			AND %s IS NOT NULL AND %s != ''
			AND %s !~* '(~|alpha|beta|rc|pre|preview|dev|snapshot)'
			AND regexp_replace(regexp_replace(%s, '^[0-9]+:', ''), '[^0-9.]', '.', 'g') != ''
			AND regexp_replace(regexp_replace(%s, '^[0-9]+:', ''), '[^0-9.]', '.', 'g') != ''
			AND array_remove(string_to_array(regexp_replace(regexp_replace(%s, '^[0-9]+:', ''), '[^0-9.]', '.', 'g'), '.'), '')::numeric[]
			  >= array_remove(string_to_array(regexp_replace(regexp_replace(%s, '^[0-9]+:', ''), '[^0-9.]', '.', 'g'), '.'), '')::numeric[]`,
		fixed, fixed, installed, installed, installed, installed, fixed, installed, fixed)
}

func scanPkg(scanner interface{ Scan(...interface{}) error }, p *models.Package) error {
	return scanner.Scan(&p.ID, &p.ScanID, &p.HostID, &p.AssetType, &p.AssetID, &p.Source, &p.Container,
		&p.ContainerID, &p.ImageName, &p.ImageID, &p.Name, &p.Version, &p.Arch, &p.PkgType, &p.Ecosystem, &p.PURL, &p.SrcName,
		&p.FilePath, &p.LayerID, &p.Target, &p.CreatedAt,
		&p.MaxCVSS, &p.VulnCount)
}

func (db *DB) InsertPackages(ctx context.Context, pkgs []models.Package) error {
	if len(pkgs) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	q := fmt.Sprintf(`INSERT INTO packages (%s, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,now())`, pkgInsertCols)
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range pkgs {
		_, err := stmt.ExecContext(ctx,
			pkgs[i].ID, pkgs[i].ScanID, pkgs[i].HostID,
			defaultString(pkgs[i].AssetType, "host"), pkgs[i].AssetID,
			pkgs[i].Source, pkgs[i].Container, pkgs[i].ContainerID, pkgs[i].ImageName, pkgs[i].ImageID,
			pkgs[i].Name, pkgs[i].Version, pkgs[i].Arch, pkgs[i].PkgType, pkgs[i].Ecosystem, pkgs[i].PURL,
			pkgs[i].SrcName, pkgs[i].FilePath, pkgs[i].LayerID, pkgs[i].Target,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) InsertContainers(ctx context.Context, containers []models.ContainerAsset) error {
	if len(containers) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	q := `INSERT INTO container_assets (id, scan_id, host_id, runtime, container_id, name, image_name, image_id, image_digest, state, labels, started_at, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,now())`
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range containers {
		labels := defaultString(containers[i].Labels, "{}")
		_, err := stmt.ExecContext(ctx,
			containers[i].ID, containers[i].ScanID, containers[i].HostID,
			defaultString(containers[i].Runtime, "docker"), containers[i].ContainerID,
			containers[i].Name, containers[i].ImageName, containers[i].ImageID,
			containers[i].ImageDigest, containers[i].State, labels, containers[i].StartedAt,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

const vulnCols = `id, package_id, scan_id, host_id, vulnerability_id, severity, title, description, pkg_name, installed_version, fixed_version, cvss_score, cvss_vector, primary_url, pkg_path, layer_id, container, finding_source, created_at`

const vulnExploitedExpr = `EXISTS(SELECT 1 FROM cve_database kev WHERE kev.source = 'cisa-kev' AND kev.vulnerability_id = v.vulnerability_id)`
const vulnEPSSScoreExpr = `COALESCE((SELECT MAX(cve.epss_score) FROM cve_database cve WHERE cve.vulnerability_id = v.vulnerability_id), 0)`
const vulnEPSSPercentileExpr = `COALESCE((SELECT MAX(cve.epss_percentile) FROM cve_database cve WHERE cve.vulnerability_id = v.vulnerability_id), 0)`
const vulnRiskScoreExpr = `LEAST(100, GREATEST(0, (v.cvss_score * 5) + (` + vulnEPSSScoreExpr + ` * 30) + CASE WHEN ` + vulnExploitedExpr + ` THEN 20 ELSE 0 END + CASE lower(COALESCE(h.criticality, '')) WHEN 'critical' THEN 10 WHEN 'high' THEN 5 ELSE 0 END))`
const vulnRiskLevelExpr = `CASE WHEN ` + vulnRiskScoreExpr + ` >= 80 THEN 'critical' WHEN ` + vulnRiskScoreExpr + ` >= 60 THEN 'high' WHEN ` + vulnRiskScoreExpr + ` >= 40 THEN 'medium' ELSE 'low' END`

var vulnAdvisorySourcesExpr = fmt.Sprintf(`COALESCE(ARRAY(
	SELECT DISTINCT c.source
	FROM cve_database c
	JOIN packages source_pkg ON source_pkg.id = v.package_id
	WHERE c.vulnerability_id = v.vulnerability_id
	  AND c.source NOT IN ('cisa-kev', 'epss')
	  AND EXISTS (
		SELECT 1
		FROM jsonb_array_elements(CASE WHEN jsonb_typeof(c.affected_products) = 'array' THEN c.affected_products ELSE '[]'::jsonb END) ap
		WHERE lower(COALESCE(ap->>'name', '')) = lower(v.pkg_name)
		  AND COALESCE(NULLIF(ap->>'ecosystem', ''), NULLIF(c.ecosystem, '')) IS NOT NULL
		  AND %s = %s
		  AND (%s)
	  )
	ORDER BY c.source
), ARRAY[]::text[])`, affectedProductEcosystemSQL("c", "ap"), packageEcosystemSQL("source_pkg"), cveSourceFixedPredicateSQL())

var vulnAdvisoryEvidenceExpr = fmt.Sprintf(`COALESCE((
	SELECT jsonb_agg(jsonb_build_object(
		'source', source,
		'category', category,
		'ecosystem', ecosystem,
		'severity', severity,
		'cvss_score', cvss_score,
		'epss_score', epss_score,
		'fixed_version', fixed_version,
		'title', title
	) ORDER BY source)::text
	FROM (
		SELECT DISTINCT ON (c.source)
		       c.source,
		       c.category,
		       COALESCE(NULLIF(ap->>'ecosystem', ''), c.ecosystem) AS ecosystem,
		       c.severity,
		       c.cvss_score,
		       c.epss_score,
		       COALESCE(%s, NULLIF(jsonb_path_query_first(ap, '$.ranges[*].events[*].fixed ? (@ != "")') #>> '{}', '')) AS fixed_version,
		       c.title
		FROM cve_database c
		JOIN packages source_pkg ON source_pkg.id = v.package_id
		JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(c.affected_products) = 'array' THEN c.affected_products ELSE '[]'::jsonb END) ap ON true
		WHERE c.vulnerability_id = v.vulnerability_id
		  AND c.source NOT IN ('cisa-kev', 'epss')
		  AND lower(COALESCE(ap->>'name', '')) = lower(v.pkg_name)
		  AND COALESCE(NULLIF(ap->>'ecosystem', ''), NULLIF(c.ecosystem, '')) IS NOT NULL
		  AND %s = %s
		  AND (%s)
		ORDER BY c.source, c.cvss_score DESC, c.updated_at DESC
	) evidence
), '[]')`, safeAffectedFixedVersionSQL("ap"), affectedProductEcosystemSQL("c", "ap"), packageEcosystemSQL("source_pkg"), cveSourceFixedPredicateSQL())

var vulnSelectCols = `v.id, v.package_id, v.scan_id, v.host_id, v.vulnerability_id, v.severity, v.title, v.description, v.pkg_name,
COALESCE((SELECT p.asset_type FROM packages p WHERE p.id = v.package_id), ''),
COALESCE((SELECT p.pkg_type FROM packages p WHERE p.id = v.package_id), ''),
COALESCE((SELECT p.ecosystem FROM packages p WHERE p.id = v.package_id), ''),
COALESCE((SELECT p.container_id FROM packages p WHERE p.id = v.package_id), ''),
COALESCE((SELECT p.image_name FROM packages p WHERE p.id = v.package_id), ''),
COALESCE((SELECT p.image_id FROM packages p WHERE p.id = v.package_id), ''),
COALESCE((SELECT p.target FROM packages p WHERE p.id = v.package_id), ''),
v.installed_version, v.fixed_version, v.cvss_score, v.cvss_vector, v.primary_url, v.pkg_path, v.layer_id, v.container, COALESCE(v.finding_source, 'scanner'), ` + vulnAdvisorySourcesExpr + `, ` + vulnAdvisoryEvidenceExpr + `, v.created_at, COALESCE(h.owner, ''), COALESCE(h.team, ''), COALESCE(h.environment, ''), COALESCE(h.criticality, ''),
` + vulnExploitedExpr + `,
` + vulnEPSSScoreExpr + `,
` + vulnEPSSPercentileExpr + `,
` + vulnRiskScoreExpr + `,
` + vulnRiskLevelExpr

const vulnTriageJoin = ` LEFT JOIN LATERAL (
	SELECT status, reason, comment, expires_at, updated_by, updated_at
	FROM vulnerability_triage
	WHERE vulnerability_id = v.vulnerability_id
	  AND (host_id = '' OR host_id = v.host_id)
	  AND (pkg_name = '' OR pkg_name = v.pkg_name)
	  AND (expires_at IS NULL OR expires_at > now())
	ORDER BY (host_id != '') DESC, (pkg_name != '') DESC, updated_at DESC
	LIMIT 1
) vt ON true`

const vulnTriageCols = `, COALESCE(vt.status, 'open'), COALESCE(vt.reason, ''), COALESCE(vt.comment, ''), vt.expires_at, COALESCE(vt.updated_by, ''), vt.updated_at`

func scanVuln(scanner interface{ Scan(...interface{}) error }, v *models.Vulnerability) error {
	var advisoryEvidence sql.NullString
	if err := scanner.Scan(&v.ID, &v.PackageID, &v.ScanID, &v.HostID,
		&v.VulnerabilityID, &v.Severity, &v.Title, &v.Description,
		&v.PkgName, &v.AssetType, &v.PkgType, &v.Ecosystem, &v.ContainerID, &v.ImageName, &v.ImageID, &v.Target, &v.InstalledVer, &v.FixedVersion, &v.CVSSScore,
		&v.CVSSVector, &v.PrimaryURL, &v.PkgPath, &v.LayerID, &v.Container,
		&v.FindingSource, pq.Array(&v.AdvisorySources), &advisoryEvidence, &v.CreatedAt, &v.HostOwner, &v.HostTeam, &v.HostEnvironment, &v.HostCriticality,
		&v.Exploited, &v.EPSSScore, &v.EPSSPercentile, &v.RiskScore, &v.RiskLevel, &v.TriageStatus, &v.TriageReason, &v.TriageComment, &v.TriageExpiresAt, &v.TriageUpdatedBy, &v.TriageUpdatedAt); err != nil {
		return err
	}
	if advisoryEvidence.Valid && advisoryEvidence.String != "" {
		_ = json.Unmarshal([]byte(advisoryEvidence.String), &v.AdvisoryEvidence)
	}
	return nil
}

type VulnerabilityInsertResult struct {
	Inserted int
	Skipped  int
}

func (db *DB) InsertVulnerabilities(ctx context.Context, vulns []models.Vulnerability) (*VulnerabilityInsertResult, error) {
	result := &VulnerabilityInsertResult{}
	result.Skipped = skippedVulnerabilities(vulns)
	vulns = insertableVulnerabilities(vulns)
	if len(vulns) == 0 {
		return result, nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()

	q := fmt.Sprintf(`INSERT INTO vulnerabilities (%s) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,now())
ON CONFLICT (package_id, scan_id, vulnerability_id) DO NOTHING`, vulnCols)
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		return result, err
	}
	defer stmt.Close()

	for i := range vulns {
		res, err := stmt.ExecContext(ctx,
			vulns[i].ID, vulns[i].PackageID, vulns[i].ScanID, vulns[i].HostID,
			vulns[i].VulnerabilityID, vulns[i].Severity, vulns[i].Title,
			vulns[i].Description, vulns[i].PkgName, vulns[i].InstalledVer,
			vulns[i].FixedVersion, vulns[i].CVSSScore, vulns[i].CVSSVector, vulns[i].PrimaryURL,
			vulns[i].PkgPath, vulns[i].LayerID, vulns[i].Container, defaultString(vulns[i].FindingSource, "scanner"),
		)
		if err != nil {
			return result, err
		}
		if affected, _ := res.RowsAffected(); affected > 0 {
			result.Inserted++
		} else {
			result.Skipped++
		}
	}
	return result, tx.Commit()
}

func insertableVulnerabilities(vulns []models.Vulnerability) []models.Vulnerability {
	out := make([]models.Vulnerability, 0, len(vulns))
	for _, v := range vulns {
		if v.ID == "" || v.PackageID == "" || v.ScanID == "" || v.HostID == "" || v.VulnerabilityID == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

func skippedVulnerabilities(vulns []models.Vulnerability) int {
	return len(vulns) - len(insertableVulnerabilities(vulns))
}

func (db *DB) InsertUserAccounts(ctx context.Context, users []models.UserAccount) error {
	if len(users) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	q := `INSERT INTO user_accounts (id, scan_id, host_id, username, uid, gid, home_dir, shell) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range users {
		_, err := stmt.ExecContext(ctx,
			users[i].ID, users[i].ScanID, users[i].HostID,
			users[i].Username, users[i].UID, users[i].GID, users[i].HomeDir, users[i].Shell,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) InsertProcessSnapshots(ctx context.Context, procs []models.ProcessSnapshot) error {
	if len(procs) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	q := `INSERT INTO process_snapshots (id, scan_id, host_id, pid, name, cmdline, user_name, cpu_usage, mem_usage) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range procs {
		_, err := stmt.ExecContext(ctx,
			procs[i].ID, procs[i].ScanID, procs[i].HostID,
			procs[i].PID, procs[i].Name, procs[i].Cmdline, procs[i].User,
			procs[i].CPUUsage, procs[i].MemUsage,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) InsertPorts(ctx context.Context, ports []models.PortInfo) error {
	if len(ports) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	q := `INSERT INTO port_info (id, scan_id, host_id, name, port, protocol, address, pid) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range ports {
		_, err := stmt.ExecContext(ctx,
			ports[i].ID, ports[i].ScanID, ports[i].HostID,
			ports[i].Name, ports[i].Port, ports[i].Protocol, ports[i].Address, ports[i].PID,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) ListScans(ctx context.Context, hostID string, hostIDs []string, limit, offset int) ([]models.Scan, int, error) {
	baseWhere := ` WHERE 1=1`
	args := []any{}
	n := 1

	if hostID != "" {
		baseWhere += fmt.Sprintf(" AND host_id=$%d", n)
		args = append(args, hostID)
		n++
	} else if len(hostIDs) > 0 {
		baseWhere += fmt.Sprintf(" AND host_id = ANY($%d)", n)
		args = append(args, pqStringArray(hostIDs))
		n++
	}

	var total int
	countArgs := make([]any, len(args))
	copy(countArgs, args)
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM scans`+baseWhere, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	dataQ := fmt.Sprintf(`
WITH page_scans AS (
	SELECT id, host_id, scan_type, status, error_summary, started_at, finished_at, created_at
	FROM scans
	%s
	ORDER BY created_at DESC
	LIMIT $%d OFFSET $%d
),
scan_prev AS (
	SELECT s.*,
		(SELECT ps.id FROM scans ps
		 WHERE ps.host_id=s.host_id AND ps.status IN ('completed','degraded') AND ps.created_at < s.created_at
		 ORDER BY ps.created_at DESC LIMIT 1) AS prev_scan_id
	FROM page_scans s
)
SELECT
	s.id, s.host_id, s.scan_type, s.status, s.error_summary,
	(SELECT count(*) FROM packages p WHERE p.scan_id=s.id)::int AS package_count,
	(SELECT count(*) FROM vulnerabilities v WHERE v.scan_id=s.id)::int AS vulnerability_count,
	(SELECT count(*) FROM container_assets c WHERE c.scan_id=s.id)::int AS container_count,
	(SELECT count(*) FROM packages cp
	 WHERE cp.scan_id=s.id AND s.prev_scan_id IS NOT NULL
	   AND NOT EXISTS (
		SELECT 1 FROM packages pp
		WHERE pp.scan_id=s.prev_scan_id AND %s
	   ))::int AS packages_added,
	(SELECT count(*) FROM packages pp
	 WHERE pp.scan_id=s.prev_scan_id AND s.prev_scan_id IS NOT NULL
	   AND NOT EXISTS (
		SELECT 1 FROM packages cp
		WHERE cp.scan_id=s.id AND %s
	   ))::int AS packages_removed,
	(SELECT count(*) FROM packages cp
	 WHERE cp.scan_id=s.id AND s.prev_scan_id IS NOT NULL
	   AND EXISTS (
		SELECT 1 FROM packages pp
		WHERE pp.scan_id=s.prev_scan_id AND %s
		  AND COALESCE(pp.version, '') != COALESCE(cp.version, '')
	   ))::int AS packages_changed,
	s.started_at, s.finished_at, s.created_at
FROM scan_prev s
ORDER BY s.created_at DESC`, baseWhere, n, n+1, packageIdentitySQL("cp", "pp"), packageIdentitySQL("cp", "pp"), packageIdentitySQL("cp", "pp"))
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, dataQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var scans []models.Scan
	for rows.Next() {
		var s models.Scan
		if err := rows.Scan(&s.ID, &s.HostID, &s.ScanType, &s.Status, &s.ErrorSummary, &s.PackageCount, &s.VulnCount, &s.ContainerCount, &s.PackagesAdded, &s.PackagesRemoved, &s.PackagesChanged, &s.StartedAt, &s.FinishedAt, &s.CreatedAt); err != nil {
			return nil, 0, err
		}
		scans = append(scans, s)
	}
	return scans, total, nil
}

func packageIdentitySQL(a, b string) string {
	cols := []string{"asset_type", "asset_id", "source", "container", "container_id", "image_name", "name", "arch", "pkg_type", "ecosystem", "purl", "src_name", "file_path", "target"}
	parts := make([]string, 0, len(cols))
	for _, col := range cols {
		parts = append(parts, fmt.Sprintf("COALESCE(%s.%s, '') = COALESCE(%s.%s, '')", a, col, b, col))
	}
	return strings.Join(parts, " AND ")
}

func (db *DB) CreateScanRequest(ctx context.Context, req *models.ScanRequest) error {
	if req.ID == "" {
		req.ID = uuid.New().String()
	}
	if req.ScanType == "" {
		req.ScanType = "manual"
	}
	if req.Status == "" {
		req.Status = "pending"
	}
	_, err := db.ExecContext(ctx, `INSERT INTO scan_requests (id, host_id, requested_by, scan_type, packages_only, reason, security_db_revision, status, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())`,
		req.ID, req.HostID, req.RequestedBy, req.ScanType, req.PackagesOnly, req.Reason, req.SecurityDBRevision, req.Status)
	return err
}

type SecurityDBRescanQueueResult struct {
	Eligible       int
	Queued         int
	AlreadyPending int
}

type StaleScanRequestRequeueResult struct {
	Requeued            int
	CancelledDuplicates int
}

func (db *DB) QueueSecurityDBRescans(ctx context.Context, requestedBy, reason, securityDBRevision string, lastSeenAfter time.Time) (*SecurityDBRescanQueueResult, error) {
	q := `SELECT id FROM hosts`
	args := []any{}
	if !lastSeenAfter.IsZero() {
		q += ` WHERE last_seen >= $1`
		args = append(args, lastSeenAfter)
	}
	q += ` ORDER BY hostname`

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	result := &SecurityDBRescanQueueResult{}
	for rows.Next() {
		var hostID string
		if err := rows.Scan(&hostID); err != nil {
			return result, err
		}
		result.Eligible++
		var inserted bool
		if err := tx.QueryRowContext(ctx, queueSecurityDBRescanInsertSQL(), uuid.New().String(), hostID, requestedBy, reason, securityDBRevision).Scan(&inserted); err != nil {
			return result, err
		}
		if inserted {
			result.Queued++
		} else {
			result.AlreadyPending++
		}
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	return result, tx.Commit()
}

func queueSecurityDBRescanInsertSQL() string {
	return `
INSERT INTO scan_requests (id, host_id, requested_by, scan_type, packages_only, reason, security_db_revision, status, created_at)
VALUES ($1,$2,$3,'security-db-update',true,$4,$5,'pending',now())
ON CONFLICT (host_id) WHERE host_id <> '' AND scan_type='security-db-update' AND status='pending'
DO UPDATE SET
	requested_by=EXCLUDED.requested_by,
	reason=EXCLUDED.reason,
	security_db_revision=EXCLUDED.security_db_revision,
	error_message=''
RETURNING (xmax = 0) AS inserted`
}

func (db *DB) ListScanRequests(ctx context.Context, hostID string, hostIDs []string, status, scanType, securityDBRevision string, staleOnly bool, timeoutSeconds int64, limit, offset int) ([]models.ScanRequest, int, error) {
	baseQ := `FROM scan_requests WHERE 1=1`
	args := []any{}
	n := 1
	if hostID != "" {
		baseQ += fmt.Sprintf(" AND host_id=$%d", n)
		args = append(args, hostID)
		n++
	} else if len(hostIDs) > 0 {
		baseQ += fmt.Sprintf(" AND host_id = ANY($%d)", n)
		args = append(args, pqStringArray(hostIDs))
		n++
	}
	if status != "" {
		baseQ += fmt.Sprintf(" AND status=$%d", n)
		args = append(args, status)
		n++
	}
	if scanType != "" {
		baseQ += fmt.Sprintf(" AND scan_type=$%d", n)
		args = append(args, scanType)
		n++
	}
	if securityDBRevision != "" {
		baseQ += fmt.Sprintf(" AND security_db_revision=$%d", n)
		args = append(args, securityDBRevision)
		n++
	}
	if staleOnly {
		baseQ += fmt.Sprintf(" AND ((status='pending' AND created_at < now() - ($%d::bigint * interval '1 second')) OR (status='claimed' AND claimed_at IS NOT NULL AND claimed_at < now() - ($%d::bigint * interval '1 second')))", n, n)
		args = append(args, timeoutSeconds)
		n++
	}
	var total int
	if err := db.QueryRowContext(ctx, "SELECT count(*) "+baseQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := `SELECT id, host_id, requested_by, scan_type, packages_only, reason, security_db_revision, status, error_message, claimed_by_host_id, claimed_at, completed_at, created_at,
		EXTRACT(EPOCH FROM (now() - created_at))::bigint AS request_age_seconds,
		CASE WHEN claimed_at IS NULL THEN 0 ELSE EXTRACT(EPOCH FROM (now() - claimed_at))::bigint END AS claim_age_seconds ` + baseQ + fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", n, n+1)
	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []models.ScanRequest
	for rows.Next() {
		var r models.ScanRequest
		if err := rows.Scan(&r.ID, &r.HostID, &r.RequestedBy, &r.ScanType, &r.PackagesOnly, &r.Reason, &r.SecurityDBRevision, &r.Status, &r.ErrorMessage, &r.ClaimedByHostID, &r.ClaimedAt, &r.CompletedAt, &r.CreatedAt, &r.RequestAgeS, &r.ClaimAgeS); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, nil
}

func (db *DB) GetScanRequest(ctx context.Context, id string) (*models.ScanRequest, error) {
	var r models.ScanRequest
	err := db.QueryRowContext(ctx, `SELECT id, host_id, requested_by, scan_type, packages_only, reason, security_db_revision, status, error_message, claimed_by_host_id, claimed_at, completed_at, created_at,
	EXTRACT(EPOCH FROM (now() - created_at))::bigint AS request_age_seconds,
	CASE WHEN claimed_at IS NULL THEN 0 ELSE EXTRACT(EPOCH FROM (now() - claimed_at))::bigint END AS claim_age_seconds
FROM scan_requests
WHERE id=$1`, id).Scan(&r.ID, &r.HostID, &r.RequestedBy, &r.ScanType, &r.PackagesOnly, &r.Reason, &r.SecurityDBRevision, &r.Status, &r.ErrorMessage, &r.ClaimedByHostID, &r.ClaimedAt, &r.CompletedAt, &r.CreatedAt, &r.RequestAgeS, &r.ClaimAgeS)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (db *DB) CountScanRequestsByStatus(ctx context.Context, hostIDs []string, includeGlobal bool) (map[string]int, error) {
	q := `SELECT status, count(*) FROM scan_requests`
	args := []any{}
	where := []string{}
	if len(hostIDs) > 0 {
		if includeGlobal {
			where = append(where, `(host_id='' OR host_id = ANY($1))`)
		} else {
			where = append(where, `host_id = ANY($1)`)
		}
		args = append(args, pqStringArray(hostIDs))
	} else if !includeGlobal {
		where = append(where, `false`)
	}
	if len(where) > 0 {
		q += ` WHERE ` + strings.Join(where, " AND ")
	}
	q += ` GROUP BY status`

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		out[status] = count
	}
	return out, rows.Err()
}

func (db *DB) CountStaleScanRequestsByState(ctx context.Context, hostIDs []string, includeGlobal bool, timeoutSeconds int64) (map[string]int, error) {
	q := `SELECT stale_state, count(*) FROM (
	SELECT CASE
		WHEN status='pending' AND created_at < now() - ($1::bigint * interval '1 second') THEN 'pending'
		WHEN status='claimed' AND claimed_at IS NOT NULL AND claimed_at < now() - ($1::bigint * interval '1 second') THEN 'claimed'
		ELSE ''
	END AS stale_state
	FROM scan_requests
	WHERE status IN ('pending','claimed')`
	args := []any{timeoutSeconds}
	if len(hostIDs) > 0 {
		if includeGlobal {
			q += ` AND (host_id='' OR host_id = ANY($2))`
		} else {
			q += ` AND host_id = ANY($2)`
		}
		args = append(args, pqStringArray(hostIDs))
	} else if !includeGlobal {
		q += ` AND false`
	}
	q += `) stale_requests WHERE stale_state <> '' GROUP BY stale_state`

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var state string
		var count int
		if err := rows.Scan(&state, &count); err != nil {
			return nil, err
		}
		out[state] = count
	}
	return out, rows.Err()
}

func (db *DB) CountSecurityDBRescanRequestsByStatus(ctx context.Context, hostIDs []string, includeGlobal bool, revision string) (map[string]int, error) {
	q := `SELECT status, count(*) FROM scan_requests WHERE scan_type='security-db-update' AND security_db_revision=$1`
	args := []any{revision}
	if len(hostIDs) > 0 {
		if includeGlobal {
			q += ` AND (host_id='' OR host_id = ANY($2))`
		} else {
			q += ` AND host_id = ANY($2)`
		}
		args = append(args, pqStringArray(hostIDs))
	} else if !includeGlobal {
		q += ` AND false`
	}
	q += ` GROUP BY status`

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		out[status] = count
	}
	return out, rows.Err()
}

func (db *DB) RequeueStaleScanRequests(ctx context.Context, timeout time.Duration) (*StaleScanRequestRequeueResult, error) {
	if timeout <= 0 {
		timeout = time.Hour
	}
	cutoff := time.Now().Add(-timeout)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	result := &StaleScanRequestRequeueResult{}
	cancelled, err := cancelStaleSecurityDBDuplicates(ctx, tx, cutoff)
	if err != nil {
		return result, err
	}
	result.CancelledDuplicates = cancelled
	res, err := tx.ExecContext(ctx, `UPDATE scan_requests
SET status='pending', claimed_at=NULL, claimed_by_host_id='', error_message='requeued after claim timeout'
WHERE status='claimed' AND claimed_at < $1`, cutoff)
	if err != nil {
		return result, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return result, err
	}
	result.Requeued = int(n)
	return result, tx.Commit()
}

func (db *DB) ClaimScanRequest(ctx context.Context, hostID string, timeout time.Duration) (*models.ScanRequest, *StaleScanRequestRequeueResult, error) {
	if timeout <= 0 {
		timeout = time.Hour
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()

	cutoff := time.Now().Add(-timeout)
	result := &StaleScanRequestRequeueResult{}
	cancelled, err := cancelStaleSecurityDBDuplicates(ctx, tx, cutoff)
	if err != nil {
		return nil, result, err
	}
	result.CancelledDuplicates = cancelled
	requeued, err := tx.ExecContext(ctx, `UPDATE scan_requests
SET status='pending', claimed_at=NULL, claimed_by_host_id='', error_message='requeued after claim timeout'
WHERE status='claimed' AND claimed_at < $1`, cutoff)
	if err != nil {
		return nil, result, err
	}
	requeuedCount, err := requeued.RowsAffected()
	if err != nil {
		return nil, result, err
	}
	result.Requeued = int(requeuedCount)

	q := `UPDATE scan_requests
SET status='claimed', claimed_at=now(), claimed_by_host_id=$1, error_message=''
WHERE id = (
	SELECT id FROM scan_requests
	WHERE status='pending' AND (host_id='' OR host_id=$1)
	ORDER BY created_at ASC
	FOR UPDATE SKIP LOCKED
	LIMIT 1
)
RETURNING id, host_id, requested_by, scan_type, packages_only, reason, security_db_revision, status, error_message, claimed_by_host_id, claimed_at, completed_at, created_at`
	var r models.ScanRequest
	err = tx.QueryRowContext(ctx, q, hostID).Scan(&r.ID, &r.HostID, &r.RequestedBy, &r.ScanType, &r.PackagesOnly, &r.Reason, &r.SecurityDBRevision, &r.Status, &r.ErrorMessage, &r.ClaimedByHostID, &r.ClaimedAt, &r.CompletedAt, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, result, tx.Commit()
	}
	if err != nil {
		return nil, result, err
	}
	return &r, result, tx.Commit()
}

func cancelStaleSecurityDBDuplicates(ctx context.Context, tx *sql.Tx, cutoff time.Time) (int, error) {
	res, err := tx.ExecContext(ctx, `WITH stale AS (
	SELECT
		sr.id,
		row_number() OVER (PARTITION BY sr.host_id ORDER BY sr.claimed_at DESC, sr.created_at DESC, sr.id DESC) AS rn,
		EXISTS (
			SELECT 1 FROM scan_requests pending
			WHERE pending.host_id=sr.host_id
			  AND pending.scan_type='security-db-update'
			  AND pending.status='pending'
		) AS has_pending
	FROM scan_requests sr
	WHERE sr.status='claimed'
	  AND sr.claimed_at < $1
	  AND sr.host_id <> ''
	  AND sr.scan_type='security-db-update'
)
UPDATE scan_requests sr
SET status='cancelled',
	completed_at=now(),
	error_message='cancelled stale duplicate security-db-update request because a newer pending or claimed request exists'
FROM stale
WHERE sr.id=stale.id
  AND (stale.has_pending OR stale.rn > 1)`, cutoff)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func (db *DB) CompleteScanRequest(ctx context.Context, id, status, message string) error {
	if status != "completed" && status != "degraded" && status != "failed" && status != "cancelled" {
		return fmt.Errorf("%w: %s", ErrInvalidScanRequestStatus, status)
	}
	res, err := db.ExecContext(ctx, `UPDATE scan_requests
SET status=$2, error_message=$3, completed_at=now()
WHERE id=$1 AND status IN ('pending','claimed')`, id, status, message)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected > 0 {
		return nil
	}
	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM scan_requests WHERE id=$1)`, id).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrScanRequestNotFound
	}
	return ErrScanRequestNotActive
}

func (db *DB) RequeueScanRequest(ctx context.Context, id, message string) error {
	if message == "" {
		message = "requeued by admin"
	}
	res, err := db.ExecContext(ctx, `UPDATE scan_requests
SET status='pending', error_message=$2, claimed_at=NULL, claimed_by_host_id='', completed_at=NULL
WHERE id=$1
  AND status IN ('failed','degraded','cancelled')
  AND NOT EXISTS (
	SELECT 1 FROM scan_requests pending
	WHERE pending.id <> scan_requests.id
	  AND pending.host_id=scan_requests.host_id
	  AND pending.host_id <> ''
	  AND pending.scan_type='security-db-update'
	  AND pending.status='pending'
	  AND scan_requests.scan_type='security-db-update'
  )`, id, message)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected > 0 {
		return nil
	}
	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM scan_requests WHERE id=$1)`, id).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrScanRequestNotFound
	}
	return ErrScanRequestNotRetryable
}

func (db *DB) RequeueScanRequestsByFilter(ctx context.Context, hostID string, status string, scanType string, securityDBRevision string, message string) (int, error) {
	if message == "" {
		message = "bulk requeued by admin"
	}
	where := []string{"status IN ('failed','degraded','cancelled')"}
	args := []any{message}
	n := 2
	if hostID != "" {
		where = append(where, fmt.Sprintf("host_id=$%d", n))
		args = append(args, hostID)
		n++
	}
	if status != "" {
		where = append(where, fmt.Sprintf("status=$%d", n))
		args = append(args, status)
		n++
	}
	if scanType != "" {
		where = append(where, fmt.Sprintf("scan_type=$%d", n))
		args = append(args, scanType)
		n++
	}
	if securityDBRevision != "" {
		where = append(where, fmt.Sprintf("security_db_revision=$%d", n))
		args = append(args, securityDBRevision)
	}
	q := `UPDATE scan_requests
SET status='pending', error_message=$1, claimed_at=NULL, claimed_by_host_id='', completed_at=NULL
WHERE ` + strings.Join(where, " AND ") + `
  AND NOT EXISTS (
	SELECT 1 FROM scan_requests pending
	WHERE pending.id <> scan_requests.id
	  AND pending.host_id=scan_requests.host_id
	  AND pending.host_id <> ''
	  AND pending.scan_type='security-db-update'
	  AND pending.status='pending'
	  AND scan_requests.scan_type='security-db-update'
  )`
	res, err := db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(affected), nil
}

func (db *DB) CompleteClaimedScanRequest(ctx context.Context, id, hostID, status, message string) error {
	if hostID == "" {
		return ErrScanRequestClaimMismatch
	}
	if status != "completed" && status != "degraded" && status != "failed" {
		return fmt.Errorf("%w: %s", ErrInvalidScanRequestStatus, status)
	}
	res, err := db.ExecContext(ctx, `UPDATE scan_requests
SET status=$2, error_message=$3, completed_at=now()
WHERE id=$1 AND status='claimed' AND claimed_by_host_id=$4`, id, status, message, hostID)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected > 0 {
		return nil
	}
	var exists, active bool
	var claimedBy string
	if err := db.QueryRowContext(ctx, `SELECT true, status='claimed', claimed_by_host_id FROM scan_requests WHERE id=$1`, id).Scan(&exists, &active, &claimedBy); err != nil {
		if err == sql.ErrNoRows {
			return ErrScanRequestNotFound
		}
		return err
	}
	if !exists {
		return ErrScanRequestNotFound
	}
	if !active {
		return ErrScanRequestNotActive
	}
	if claimedBy != hostID {
		return ErrScanRequestClaimMismatch
	}
	return ErrScanRequestNotActive
}

type AuditLogFilter struct {
	ActorType    string
	ActorID      string
	Action       string
	ResourceType string
	ResourceID   string
	Status       string
	CreatedFrom  *time.Time
	CreatedTo    *time.Time
}

func (db *DB) RecordAuditLog(ctx context.Context, logEntry *models.AuditLog) error {
	if logEntry.ID == "" {
		logEntry.ID = uuid.New().String()
	}
	if logEntry.Status == "" {
		logEntry.Status = "ok"
	}
	if len(logEntry.Metadata) == 0 {
		logEntry.Metadata = json.RawMessage(`{}`)
	}
	_, err := db.ExecContext(ctx, `INSERT INTO audit_logs
(id, actor_type, actor_id, action, resource_type, resource_id, status, ip_address, user_agent, metadata, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now())`,
		logEntry.ID, logEntry.ActorType, logEntry.ActorID, logEntry.Action, logEntry.ResourceType, logEntry.ResourceID,
		logEntry.Status, logEntry.IPAddress, logEntry.UserAgent, logEntry.Metadata)
	return err
}

func (db *DB) ListAuditLogs(ctx context.Context, f AuditLogFilter, limit, offset int) ([]models.AuditLog, int, error) {
	baseQ := `FROM audit_logs WHERE 1=1`
	args := []any{}
	n := 1
	add := func(col, value string) {
		if value == "" {
			return
		}
		baseQ += fmt.Sprintf(" AND %s=$%d", col, n)
		args = append(args, value)
		n++
	}
	add("actor_type", f.ActorType)
	add("actor_id", f.ActorID)
	add("action", f.Action)
	add("resource_type", f.ResourceType)
	add("resource_id", f.ResourceID)
	add("status", f.Status)
	if f.CreatedFrom != nil {
		baseQ += fmt.Sprintf(" AND created_at >= $%d", n)
		args = append(args, *f.CreatedFrom)
		n++
	}
	if f.CreatedTo != nil {
		baseQ += fmt.Sprintf(" AND created_at <= $%d", n)
		args = append(args, *f.CreatedTo)
		n++
	}

	var total int
	if err := db.QueryRowContext(ctx, "SELECT count(*) "+baseQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := `SELECT id, actor_type, actor_id, action, resource_type, resource_id, status, ip_address, user_agent, metadata, created_at ` + baseQ + fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", n, n+1)
	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []models.AuditLog
	for rows.Next() {
		var item models.AuditLog
		if err := rows.Scan(&item.ID, &item.ActorType, &item.ActorID, &item.Action, &item.ResourceType, &item.ResourceID, &item.Status, &item.IPAddress, &item.UserAgent, &item.Metadata, &item.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (db *DB) GetLatestAuditLog(ctx context.Context, f AuditLogFilter, excludedStatuses []string) (*models.AuditLog, error) {
	baseQ := `FROM audit_logs WHERE 1=1`
	args := []any{}
	n := 1
	add := func(col, value string) {
		if value == "" {
			return
		}
		baseQ += fmt.Sprintf(" AND %s=$%d", col, n)
		args = append(args, value)
		n++
	}
	add("actor_type", f.ActorType)
	add("actor_id", f.ActorID)
	add("action", f.Action)
	add("resource_type", f.ResourceType)
	add("resource_id", f.ResourceID)
	add("status", f.Status)
	if f.CreatedFrom != nil {
		baseQ += fmt.Sprintf(" AND created_at >= $%d", n)
		args = append(args, *f.CreatedFrom)
		n++
	}
	if f.CreatedTo != nil {
		baseQ += fmt.Sprintf(" AND created_at <= $%d", n)
		args = append(args, *f.CreatedTo)
		n++
	}
	if len(excludedStatuses) > 0 {
		baseQ += fmt.Sprintf(" AND NOT (status = ANY($%d))", n)
		args = append(args, pq.Array(excludedStatuses))
		n++
	}
	q := `SELECT id, actor_type, actor_id, action, resource_type, resource_id, status, ip_address, user_agent, metadata, created_at ` + baseQ + ` ORDER BY created_at DESC LIMIT 1`
	var item models.AuditLog
	err := db.QueryRowContext(ctx, q, args...).Scan(&item.ID, &item.ActorType, &item.ActorID, &item.Action, &item.ResourceType, &item.ResourceID, &item.Status, &item.IPAddress, &item.UserAgent, &item.Metadata, &item.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

type AccessScope struct {
	All     bool
	HostIDs []string
}

func (s AccessScope) CanReadHost(hostID string) bool {
	if s.All {
		return true
	}
	for _, id := range s.HostIDs {
		if id == hostID {
			return true
		}
	}
	return false
}

func (s AccessScope) Empty() bool {
	return !s.All && len(s.HostIDs) == 0
}

func pqStringArray(v []string) any {
	return pq.Array(v)
}

func ApplyVulnerabilitySLA(v *models.Vulnerability) {
	days := SLADaysForSeverity(v.Severity)
	v.SLADays = days
	if days <= 0 || v.CreatedAt.IsZero() {
		v.DueAt = nil
		v.Overdue = false
		return
	}
	due := v.CreatedAt.Add(time.Duration(days) * 24 * time.Hour)
	v.DueAt = &due
	v.Overdue = time.Now().After(due) && slaAppliesToTriage(v.TriageStatus)
}

func SLADaysForSeverity(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return envInt("BONGSU_SLA_CRITICAL_DAYS", 7)
	case "HIGH":
		return envInt("BONGSU_SLA_HIGH_DAYS", 30)
	case "MEDIUM":
		return envInt("BONGSU_SLA_MEDIUM_DAYS", 90)
	case "LOW":
		return envInt("BONGSU_SLA_LOW_DAYS", 180)
	default:
		return 0
	}
}

func slaAppliesToTriage(status string) bool {
	switch status {
	case "", "open", "in_progress":
		return true
	default:
		return false
	}
}

func overdueSQLCondition() string {
	return fmt.Sprintf(` AND COALESCE(vt.status, 'open') IN ('open', 'in_progress') AND (
		(v.severity='CRITICAL' AND v.created_at < now() - interval '%d days') OR
		(v.severity='HIGH' AND v.created_at < now() - interval '%d days') OR
		(v.severity='MEDIUM' AND v.created_at < now() - interval '%d days') OR
		(v.severity='LOW' AND v.created_at < now() - interval '%d days')
	)`,
		SLADaysForSeverity("CRITICAL"),
		SLADaysForSeverity("HIGH"),
		SLADaysForSeverity("MEDIUM"),
		SLADaysForSeverity("LOW"),
	)
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envPositiveInt(key string, def int) int {
	n := envInt(key, def)
	if n <= 0 {
		return def
	}
	return n
}

func (db *DB) GetAccessScope(ctx context.Context, subjectRef string) (AccessScope, error) {
	return db.getAccessScopeForPermissions(ctx, subjectRef, []string{"read", "admin"})
}

func (db *DB) GetExportScope(ctx context.Context, subjectRef string) (AccessScope, error) {
	return db.getAccessScopeForPermissions(ctx, subjectRef, []string{"export", "admin"})
}

func (db *DB) HasResourcePermission(ctx context.Context, subjectRef, resourceType string, permissions []string) (bool, error) {
	subjectType, externalID := parseAccessSubjectRef(subjectRef)
	if len(permissions) == 0 {
		return false, nil
	}
	args := []any{externalID, resourceType, pqStringArray(permissions)}
	typeFilter := ""
	if subjectType != "" {
		typeFilter = " AND s.subject_type=$4"
		args = append(args, subjectType)
	}
	var ok bool
	err := db.QueryRowContext(ctx, `
SELECT EXISTS (
	SELECT 1
	FROM access_subjects s
	JOIN access_policies p ON p.subject_id = s.id
	WHERE s.external_id=$1`+typeFilter+`
	  AND (p.resource_type=$2 OR p.resource_type='all')
	  AND (p.resource_id='*' OR p.resource_id='')
	  AND p.permission = ANY($3)
)`, args...).Scan(&ok)
	return ok, err
}

func (db *DB) getAccessScopeForPermissions(ctx context.Context, subjectRef string, permissions []string) (AccessScope, error) {
	subjectType, externalID := parseAccessSubjectRef(subjectRef)
	if len(permissions) == 0 {
		return AccessScope{}, nil
	}
	args := []any{externalID, pqStringArray(permissions)}
	typeFilter := ""
	if subjectType != "" {
		typeFilter = " AND s.subject_type=$3"
		args = append(args, subjectType)
	}
	rows, err := db.QueryContext(ctx, `
SELECT p.resource_type, p.resource_id
FROM access_subjects s
JOIN access_policies p ON p.subject_id = s.id
WHERE s.external_id=$1`+typeFilter+` AND p.permission = ANY($2)`, args...)
	if err != nil {
		return AccessScope{}, err
	}
	defer rows.Close()
	scope := AccessScope{}
	containerRefs := []string{}
	imageRefs := []string{}
	assetGroupRefs := []string{}
	containerWildcard := false
	imageWildcard := false
	assetGroupWildcard := false
	for rows.Next() {
		var rt, rid string
		if err := rows.Scan(&rt, &rid); err != nil {
			return AccessScope{}, err
		}
		switch rt {
		case "all":
			scope.All = true
		case "host":
			if rid != "" && rid != "*" {
				scope.HostIDs = appendUnique(scope.HostIDs, rid)
			}
		case "container":
			if rid == "*" {
				containerWildcard = true
			} else if rid != "" {
				containerRefs = append(containerRefs, rid)
			}
		case "image":
			if rid == "*" {
				imageWildcard = true
			} else if rid != "" {
				imageRefs = append(imageRefs, rid)
			}
		case "asset_group":
			if rid == "*" {
				assetGroupWildcard = true
			} else if rid != "" {
				assetGroupRefs = append(assetGroupRefs, rid)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return AccessScope{}, err
	}
	if scope.All {
		return scope, nil
	}
	hostIDs, err := db.hostIDsForContainerPolicies(ctx, containerRefs, containerWildcard)
	if err != nil {
		return AccessScope{}, err
	}
	for _, id := range hostIDs {
		scope.HostIDs = appendUnique(scope.HostIDs, id)
	}
	hostIDs, err = db.hostIDsForImagePolicies(ctx, imageRefs, imageWildcard)
	if err != nil {
		return AccessScope{}, err
	}
	for _, id := range hostIDs {
		scope.HostIDs = appendUnique(scope.HostIDs, id)
	}
	hostIDs, err = db.hostIDsForAssetGroupPolicies(ctx, assetGroupRefs, assetGroupWildcard)
	if err != nil {
		return AccessScope{}, err
	}
	for _, id := range hostIDs {
		scope.HostIDs = appendUnique(scope.HostIDs, id)
	}
	return scope, nil
}

func parseAccessSubjectRef(ref string) (string, string) {
	ref = strings.TrimSpace(ref)
	for _, sep := range []string{":", "/"} {
		left, right, ok := strings.Cut(ref, sep)
		if !ok {
			continue
		}
		left = strings.ToLower(strings.TrimSpace(left))
		right = strings.TrimSpace(right)
		if (left == "user" || left == "group") && right != "" {
			return left, right
		}
	}
	return "", ref
}

func (db *DB) hostIDsForContainerPolicies(ctx context.Context, refs []string, wildcard bool) ([]string, error) {
	if !wildcard && len(refs) == 0 {
		return nil, nil
	}
	q := `SELECT DISTINCT c.host_id FROM container_assets c JOIN ` + latestScansSub + ` ls ON c.scan_id = ls.id`
	args := []any{}
	if !wildcard {
		q += ` WHERE c.container_id = ANY($1) OR c.name = ANY($1)`
		args = append(args, pqStringArray(refs))
	}
	return db.queryStringList(ctx, q, args...)
}

func (db *DB) hostIDsForImagePolicies(ctx context.Context, refs []string, wildcard bool) ([]string, error) {
	if !wildcard && len(refs) == 0 {
		return nil, nil
	}
	q := `SELECT DISTINCT c.host_id FROM container_assets c JOIN ` + latestScansSub + ` ls ON c.scan_id = ls.id`
	args := []any{}
	if !wildcard {
		q += ` WHERE c.image_name = ANY($1) OR c.image_id = ANY($1) OR c.image_digest = ANY($1)`
		args = append(args, pqStringArray(refs))
	}
	return db.queryStringList(ctx, q, args...)
}

func (db *DB) hostIDsForAssetGroupPolicies(ctx context.Context, refs []string, wildcard bool) ([]string, error) {
	if wildcard {
		return db.queryStringList(ctx, `SELECT id FROM hosts`)
	}
	if len(refs) == 0 {
		return nil, nil
	}
	hostIDs := []string{}
	for _, ref := range refs {
		key, value, ok := parseAssetGroupRef(ref)
		if !ok {
			continue
		}
		var (
			ids []string
			err error
		)
		switch key {
		case "owner":
			ids, err = db.queryStringList(ctx, `SELECT id FROM hosts WHERE owner=$1`, value)
		case "team":
			ids, err = db.queryStringList(ctx, `SELECT id FROM hosts WHERE team=$1`, value)
		case "environment":
			ids, err = db.queryStringList(ctx, `SELECT id FROM hosts WHERE environment=$1`, value)
		case "criticality":
			ids, err = db.queryStringList(ctx, `SELECT id FROM hosts WHERE criticality=$1`, value)
		case "tag":
			tagKey, tagValue, ok := strings.Cut(value, "=")
			if !ok || strings.TrimSpace(tagKey) == "" {
				continue
			}
			ids, err = db.queryStringList(ctx, `SELECT id FROM hosts WHERE tags ->> $1 = $2`, strings.TrimSpace(tagKey), strings.TrimSpace(tagValue))
		default:
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			hostIDs = appendUnique(hostIDs, id)
		}
	}
	return hostIDs, nil
}

func parseAssetGroupRef(ref string) (string, string, bool) {
	key, value, ok := strings.Cut(ref, ":")
	if !ok {
		key, value, ok = strings.Cut(ref, "=")
	}
	key = strings.ToLower(strings.TrimSpace(key))
	value = strings.TrimSpace(value)
	if !ok || key == "" || value == "" {
		return "", "", false
	}
	return key, value, true
}

func (db *DB) queryStringList(ctx context.Context, q string, args ...any) ([]string, error) {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = appendUnique(out, v)
	}
	return out, rows.Err()
}

func appendUnique(items []string, item string) []string {
	if item == "" {
		return items
	}
	for _, existing := range items {
		if existing == item {
			return items
		}
	}
	return append(items, item)
}

func (db *DB) UpsertAccessSubject(ctx context.Context, id, subjectType, externalID, displayName string) error {
	if id == "" {
		id = uuid.New().String()
	}
	_, err := db.ExecContext(ctx, `INSERT INTO access_subjects (id, subject_type, external_id, display_name, created_at, updated_at)
VALUES ($1,$2,$3,$4,now(),now())
ON CONFLICT (subject_type, external_id) DO UPDATE SET display_name=EXCLUDED.display_name, updated_at=now()`,
		id, subjectType, externalID, displayName)
	return err
}

func (db *DB) ListAccessSubjects(ctx context.Context) ([]models.AccessSubject, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, subject_type, external_id, display_name, created_at, updated_at
FROM access_subjects
ORDER BY external_id, subject_type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.AccessSubject{}
	for rows.Next() {
		var item models.AccessSubject
		if err := rows.Scan(&item.ID, &item.SubjectType, &item.ExternalID, &item.DisplayName, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (db *DB) ListAccessPolicies(ctx context.Context, subjectExternalID string) ([]models.AccessPolicy, error) {
	q := `SELECT p.id, p.subject_id, s.subject_type, s.external_id, p.resource_type, p.resource_id, p.permission, p.created_at
FROM access_policies p
JOIN access_subjects s ON s.id = p.subject_id`
	args := []any{}
	if subjectExternalID != "" {
		subjectType, externalID := parseAccessSubjectRef(subjectExternalID)
		q += ` WHERE s.external_id=$1`
		args = append(args, externalID)
		if subjectType != "" {
			q += ` AND s.subject_type=$2`
			args = append(args, subjectType)
		}
	}
	q += ` ORDER BY s.external_id, p.resource_type, p.resource_id, p.permission`
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.AccessPolicy{}
	for rows.Next() {
		var item models.AccessPolicy
		if err := rows.Scan(&item.ID, &item.SubjectID, &item.SubjectType, &item.SubjectExternalID, &item.ResourceType, &item.ResourceID, &item.Permission, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (db *DB) DeleteAccessSubject(ctx context.Context, id string) (*models.AccessSubject, int, error) {
	var policyCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM access_policies WHERE subject_id=$1`, id).Scan(&policyCount); err != nil {
		return nil, 0, err
	}
	var item models.AccessSubject
	err := db.QueryRowContext(ctx, `DELETE FROM access_subjects WHERE id=$1
RETURNING id, subject_type, external_id, display_name, created_at, updated_at`, id).
		Scan(&item.ID, &item.SubjectType, &item.ExternalID, &item.DisplayName, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return nil, 0, err
	}
	return &item, policyCount, nil
}

func (db *DB) DeleteAccessPolicy(ctx context.Context, id string) (*models.AccessPolicy, error) {
	var item models.AccessPolicy
	err := db.QueryRowContext(ctx, `WITH deleted AS (
	DELETE FROM access_policies
	WHERE id=$1
	RETURNING id, subject_id, resource_type, resource_id, permission, created_at
)
SELECT d.id, d.subject_id, s.subject_type, s.external_id, d.resource_type, d.resource_id, d.permission, d.created_at
FROM deleted d
JOIN access_subjects s ON s.id = d.subject_id`, id).
		Scan(&item.ID, &item.SubjectID, &item.SubjectType, &item.SubjectExternalID, &item.ResourceType, &item.ResourceID, &item.Permission, &item.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (db *DB) UpsertAccessPolicy(ctx context.Context, id, subjectID, subjectExternalID, resourceType, resourceID, permission string) error {
	if id == "" {
		id = uuid.New().String()
	}
	if resourceID == "" {
		resourceID = "*"
	}
	if subjectID == "" {
		var err error
		subjectID, err = db.resolveAccessSubjectID(ctx, subjectExternalID)
		if err != nil {
			return err
		}
	} else {
		var exists bool
		if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM access_subjects WHERE id=$1)`, subjectID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("access subject id %q not found", subjectID)
		}
	}
	_, err := db.ExecContext(ctx, `INSERT INTO access_policies (id, subject_id, resource_type, resource_id, permission, created_at)
VALUES ($1, $2, $3, $4, $5, now())
ON CONFLICT (subject_id, resource_type, resource_id, permission) DO NOTHING`,
		id, subjectID, resourceType, resourceID, permission)
	return err
}

func (db *DB) resolveAccessSubjectID(ctx context.Context, subjectExternalID string) (string, error) {
	subjectType, externalID := parseAccessSubjectRef(subjectExternalID)
	args := []any{externalID}
	typeFilter := ""
	if subjectType != "" {
		typeFilter = " AND subject_type=$2"
		args = append(args, subjectType)
	}
	rows, err := db.QueryContext(ctx, `SELECT id FROM access_subjects WHERE external_id=$1`+typeFilter+` ORDER BY subject_type`, args...)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return "", err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return "", fmt.Errorf("access subject %q not found", subjectExternalID)
	}
	if len(ids) > 1 {
		return "", fmt.Errorf("access subject %q is ambiguous; use user:%s or group:%s", subjectExternalID, externalID, externalID)
	}
	return ids[0], nil
}

func (db *DB) UpsertVulnerabilityTriage(ctx context.Context, t *models.VulnerabilityTriage) error {
	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	if t.VulnerabilityID == "" {
		return fmt.Errorf("vulnerability_id is required")
	}
	if t.Status == "" {
		t.Status = "open"
	}
	err := db.QueryRowContext(ctx, `INSERT INTO vulnerability_triage
(id, vulnerability_id, host_id, pkg_name, status, reason, comment, expires_at, updated_by, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now(),now())
ON CONFLICT (vulnerability_id, host_id, pkg_name) DO UPDATE SET
	status=EXCLUDED.status,
	reason=EXCLUDED.reason,
	comment=EXCLUDED.comment,
	expires_at=EXCLUDED.expires_at,
	updated_by=EXCLUDED.updated_by,
	updated_at=now()
RETURNING id, created_at, updated_at`,
		t.ID, t.VulnerabilityID, t.HostID, t.PkgName, t.Status, t.Reason, t.Comment, t.ExpiresAt, t.UpdatedBy,
	).Scan(&t.ID, &t.CreatedAt, &t.UpdatedAt)
	return err
}

type VulnerabilityTriageCount struct {
	Status string
	State  string
	Count  int
}

func (db *DB) CountVulnerabilityTriageByStatus(ctx context.Context) ([]VulnerabilityTriageCount, error) {
	rows, err := db.QueryContext(ctx, `SELECT status,
CASE WHEN expires_at IS NOT NULL AND expires_at <= now() THEN 'expired' ELSE 'active' END AS state,
count(*)::int
FROM vulnerability_triage
GROUP BY status, state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VulnerabilityTriageCount
	for rows.Next() {
		var row VulnerabilityTriageCount
		if err := rows.Scan(&row.Status, &row.State, &row.Count); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (db *DB) CountVulnerabilityTriageExpiringSoonByStatus(ctx context.Context, days int) (map[string]int, error) {
	if days <= 0 {
		days = 14
	}
	rows, err := db.QueryContext(ctx, `SELECT status, count(*)::int
FROM vulnerability_triage
WHERE expires_at IS NOT NULL AND expires_at > now() AND expires_at <= now() + ($1::int * interval '1 day')
GROUP BY status`, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		out[status] = count
	}
	return out, rows.Err()
}

const hostCols = `id, hostname, ip_address, os_name, os_version, kernel, arch, cpu_model, cpu_cores, memory_mb, agent_version, agent_token_hash <> '' AS agent_token_set, owner, team, environment, criticality, tags::text, last_seen, created_at`

func scanHost(scanner interface{ Scan(...interface{}) error }, h *models.Host) error {
	return scanner.Scan(&h.ID, &h.Hostname, &h.IPAddress, &h.OSName, &h.OSVersion,
		&h.Kernel, &h.Arch, &h.CPUModel, &h.CPUCores, &h.MemoryMB, &h.AgentVersion,
		&h.AgentTokenSet, &h.Owner, &h.Team, &h.Environment, &h.Criticality, &h.Tags, &h.LastSeen, &h.CreatedAt)
}

func (db *DB) ListHosts(ctx context.Context) ([]models.Host, error) {
	q := `SELECT ` + hostCols + ` FROM hosts ORDER BY hostname`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []models.Host
	for rows.Next() {
		var h models.Host
		if err := scanHost(rows, &h); err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}

type HostInventorySummary struct {
	ScanID         string     `json:"latest_scan_id,omitempty"`
	ScanStatus     string     `json:"latest_scan_status,omitempty"`
	ScannedAt      *time.Time `json:"latest_scan_at,omitempty"`
	PackageCount   int        `json:"latest_package_count"`
	VulnCount      int        `json:"latest_vulnerability_count"`
	ContainerCount int        `json:"latest_container_count"`
}

func (db *DB) GetHostInventorySummaries(ctx context.Context) (map[string]HostInventorySummary, error) {
	q := `SELECT
		s.host_id,
		s.id,
		s.status,
		s.finished_at,
		(SELECT count(*) FROM packages p WHERE p.scan_id=s.id)::int AS package_count,
		(SELECT count(*) FROM vulnerabilities v WHERE v.scan_id=s.id)::int AS vulnerability_count,
		(SELECT count(*) FROM container_assets c WHERE c.scan_id=s.id)::int AS container_count
	FROM scans s
	JOIN ` + latestScansSub + ` ls ON ls.id=s.id`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]HostInventorySummary{}
	for rows.Next() {
		var hostID string
		var s HostInventorySummary
		if err := rows.Scan(&hostID, &s.ScanID, &s.ScanStatus, &s.ScannedAt, &s.PackageCount, &s.VulnCount, &s.ContainerCount); err != nil {
			return nil, err
		}
		out[hostID] = s
	}
	return out, rows.Err()
}

func (db *DB) GetHost(ctx context.Context, id string) (*models.Host, error) {
	q := `SELECT ` + hostCols + ` FROM hosts WHERE id=$1`
	var h models.Host
	err := scanHost(db.QueryRowContext(ctx, q, id), &h)
	if err != nil {
		return nil, err
	}
	return &h, nil
}

func (db *DB) UpdateHostMetadata(ctx context.Context, id, owner, team, environment, criticality, tags string) error {
	if tags == "" {
		tags = "{}"
	}
	res, err := db.ExecContext(ctx, `UPDATE hosts
SET owner=$2, team=$3, environment=$4, criticality=$5, tags=$6::jsonb, updated_at=now()
WHERE id=$1`, id, owner, team, environment, criticality, tags)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

const latestScansSub = `(SELECT DISTINCT ON (host_id) id FROM scans WHERE status IN ('completed','degraded') ORDER BY host_id, created_at DESC)`

type VulnFilter struct {
	HostID        string
	HostIDs       []string
	Severity      string
	TriageStatus  string
	FindingSource string
	RiskLevel     string
	Overdue       bool
	Exploited     bool
	MinEPSS       float64
	MinEPSSPct    float64
	PkgName       string
	Container     string
	Owner         string
	Team          string
	Environment   string
	Criticality   string
	MinCVSS       float64
	SortBy        string
	SortDesc      bool
	HideFixed     bool
	HideNoFix     bool
	HideMismatch  bool
}

func (db *DB) ListVulnerabilities(ctx context.Context, f VulnFilter, limit, offset int) ([]models.Vulnerability, int, error) {
	baseQ := `FROM vulnerabilities v JOIN hosts h ON h.id = v.host_id`
	args := []any{}
	argN := 1

	baseQ += ` JOIN ` + latestScansSub + ` ls ON v.scan_id = ls.id`

	baseQ += vulnTriageJoin
	baseQ += ` WHERE 1=1`

	if f.HostID != "" {
		baseQ += fmt.Sprintf(" AND v.host_id=$%d", argN)
		args = append(args, f.HostID)
		argN++
	} else if len(f.HostIDs) > 0 {
		baseQ += fmt.Sprintf(" AND v.host_id = ANY($%d)", argN)
		args = append(args, pqStringArray(f.HostIDs))
		argN++
	}
	if f.Severity != "" {
		baseQ += fmt.Sprintf(" AND v.severity=$%d", argN)
		args = append(args, f.Severity)
		argN++
	}
	if f.TriageStatus != "" {
		baseQ += fmt.Sprintf(" AND COALESCE(vt.status, 'open')=$%d", argN)
		args = append(args, f.TriageStatus)
		argN++
	}
	if f.FindingSource != "" {
		baseQ += fmt.Sprintf(" AND COALESCE(v.finding_source, 'scanner')=$%d", argN)
		args = append(args, f.FindingSource)
		argN++
	}
	if f.RiskLevel != "" {
		baseQ += fmt.Sprintf(" AND ("+vulnRiskLevelExpr+")=$%d", argN)
		args = append(args, f.RiskLevel)
		argN++
	}
	if f.PkgName != "" {
		baseQ += fmt.Sprintf(" AND v.pkg_name ILIKE $%d", argN)
		args = append(args, "%"+f.PkgName+"%")
		argN++
	}
	if f.Container != "" {
		baseQ += fmt.Sprintf(" AND v.container=$%d", argN)
		args = append(args, f.Container)
		argN++
	}
	if f.Owner != "" {
		baseQ += fmt.Sprintf(" AND h.owner=$%d", argN)
		args = append(args, f.Owner)
		argN++
	}
	if f.Team != "" {
		baseQ += fmt.Sprintf(" AND h.team=$%d", argN)
		args = append(args, f.Team)
		argN++
	}
	if f.Environment != "" {
		baseQ += fmt.Sprintf(" AND h.environment=$%d", argN)
		args = append(args, f.Environment)
		argN++
	}
	if f.Criticality != "" {
		baseQ += fmt.Sprintf(" AND h.criticality=$%d", argN)
		args = append(args, f.Criticality)
		argN++
	}
	if f.MinCVSS > 0 {
		baseQ += fmt.Sprintf(" AND v.cvss_score>=$%d", argN)
		args = append(args, f.MinCVSS)
		argN++
	}
	if f.Overdue {
		baseQ += overdueSQLCondition()
	}
	if f.Exploited {
		baseQ += ` AND EXISTS(SELECT 1 FROM cve_database kev WHERE kev.source = 'cisa-kev' AND kev.vulnerability_id = v.vulnerability_id)`
	}
	if f.MinEPSS > 0 {
		baseQ += fmt.Sprintf(" AND EXISTS(SELECT 1 FROM cve_database cve WHERE cve.vulnerability_id = v.vulnerability_id AND cve.epss_score >= $%d)", argN)
		args = append(args, f.MinEPSS)
		argN++
	}
	if f.MinEPSSPct > 0 {
		baseQ += fmt.Sprintf(" AND EXISTS(SELECT 1 FROM cve_database cve WHERE cve.vulnerability_id = v.vulnerability_id AND cve.epss_percentile >= $%d)", argN)
		args = append(args, f.MinEPSSPct)
		argN++
	}

	if f.HideFixed {
		baseQ += ` AND NOT (` + fixedVersionSQLCondition("v") + `)`
		baseQ += ` AND v.vulnerability_id NOT LIKE 'CGA-%'`
		baseQ += ` AND v.fixed_version !~ '^[0-9a-f]{40}$'`
	}
	if f.HideNoFix {
		baseQ += ` AND (v.fixed_version IS NOT NULL AND v.fixed_version != '')`
	}
	if f.HideMismatch {
		baseQ += defaultVulnMismatchFilterSQL("v")
	}
	var total int
	countArgs := make([]any, len(args))
	copy(countArgs, args)
	if err := db.QueryRowContext(ctx, "SELECT count(*) "+baseQ, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	sortExpr := vulnSortExpr(f.SortBy, f.SortDesc)
	dataQ := fmt.Sprintf(`SELECT %s%s `, vulnSelectCols, vulnTriageCols) + baseQ + fmt.Sprintf(" ORDER BY %s LIMIT $%d OFFSET $%d", sortExpr, argN, argN+1)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, dataQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var vulns []models.Vulnerability
	for rows.Next() {
		var v models.Vulnerability
		if err := scanVuln(rows, &v); err != nil {
			return nil, 0, err
		}
		ApplyVulnerabilitySLA(&v)
		vulns = append(vulns, v)
	}
	return vulns, total, nil
}

func (db *DB) GetHostVulnCounts(ctx context.Context, hostID string) (map[string]int, error) {
	q := `SELECT severity, count(*) FROM vulnerabilities WHERE host_id=$1 GROUP BY severity`
	rows, err := db.QueryContext(ctx, q, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[string]int{}
	for rows.Next() {
		var sev string
		var cnt int
		if err := rows.Scan(&sev, &cnt); err != nil {
			return nil, err
		}
		counts[sev] = cnt
	}
	return counts, nil
}

func (db *DB) GetVulnCountsByHost(ctx context.Context) (map[string]map[string]int, error) {
	q := `SELECT host_id, severity, count(*) FROM vulnerabilities GROUP BY host_id, severity`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := map[string]map[string]int{}
	for rows.Next() {
		var hostID, sev string
		var cnt int
		if err := rows.Scan(&hostID, &sev, &cnt); err != nil {
			return nil, err
		}
		if result[hostID] == nil {
			result[hostID] = map[string]int{}
		}
		result[hostID][sev] = cnt
	}
	return result, nil
}

func (db *DB) GetCurrentActionableVulnCountsByHost(ctx context.Context, hostIDs []string) (map[string]map[string]int, error) {
	baseQ := `FROM vulnerabilities v JOIN ` + latestScansSub + ` ls ON v.scan_id = ls.id` + vulnTriageJoin + ` WHERE ` + currentActionableVulnSQL()
	args := []any{}
	if len(hostIDs) > 0 {
		baseQ += ` AND v.host_id = ANY($1)`
		args = append(args, pqStringArray(hostIDs))
	}
	rows, err := db.QueryContext(ctx, `SELECT v.host_id, v.severity, count(*) `+baseQ+` GROUP BY v.host_id, v.severity`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := map[string]map[string]int{}
	for rows.Next() {
		var hostID, sev string
		var cnt int
		if err := rows.Scan(&hostID, &sev, &cnt); err != nil {
			return nil, err
		}
		if result[hostID] == nil {
			result[hostID] = map[string]int{}
		}
		result[hostID][sev] = cnt
	}
	return result, rows.Err()
}

func currentActionableVulnSQL() string {
	return `COALESCE(vt.status, 'open') IN ('open', 'in_progress')
		AND NOT (` + fixedVersionSQLCondition("v") + `)
		AND v.vulnerability_id NOT LIKE 'CGA-%'
		AND v.fixed_version !~ '^[0-9a-f]{40}$'
		AND (v.fixed_version IS NOT NULL AND v.fixed_version != '')` + defaultVulnMismatchFilterSQL("v")
}

type VulnerabilitySummaryRow struct {
	Group    string         `json:"group"`
	Total    int            `json:"total"`
	Overdue  int            `json:"overdue"`
	Severity map[string]int `json:"severity"`
	Risk     map[string]int `json:"risk"`
}

func (db *DB) GetVulnSummaryByMetadata(ctx context.Context, groupBy string, hostIDs []string) ([]VulnerabilitySummaryRow, error) {
	groupExpr := vulnSummaryGroupExpr(groupBy)
	baseQ := `FROM vulnerabilities v JOIN hosts h ON h.id = v.host_id JOIN ` + latestScansSub + ` ls ON v.scan_id = ls.id` + vulnTriageJoin + ` WHERE ` + currentActionableVulnSQL()
	args := []any{}
	if len(hostIDs) > 0 {
		baseQ += ` AND v.host_id = ANY($1)`
		args = append(args, pqStringArray(hostIDs))
	}
	q := fmt.Sprintf(`SELECT %s AS group_value,
		count(*)::int AS total,
		count(*) FILTER (WHERE v.severity='CRITICAL')::int AS critical,
		count(*) FILTER (WHERE v.severity='HIGH')::int AS high,
		count(*) FILTER (WHERE v.severity='MEDIUM')::int AS medium,
		count(*) FILTER (WHERE v.severity='LOW')::int AS low,
		count(*) FILTER (WHERE (`+vulnRiskLevelExpr+`)='critical')::int AS risk_critical,
		count(*) FILTER (WHERE (`+vulnRiskLevelExpr+`)='high')::int AS risk_high,
		count(*) FILTER (WHERE (`+vulnRiskLevelExpr+`)='medium')::int AS risk_medium,
		count(*) FILTER (WHERE (`+vulnRiskLevelExpr+`)='low')::int AS risk_low,
		count(*) FILTER (WHERE (
			(v.severity='CRITICAL' AND v.created_at < now() - interval '%d days') OR
			(v.severity='HIGH' AND v.created_at < now() - interval '%d days') OR
			(v.severity='MEDIUM' AND v.created_at < now() - interval '%d days') OR
			(v.severity='LOW' AND v.created_at < now() - interval '%d days')
		))::int AS overdue
		%s
		GROUP BY group_value
		ORDER BY risk_critical DESC, risk_high DESC, critical DESC, high DESC, total DESC, group_value`,
		groupExpr,
		SLADaysForSeverity("CRITICAL"),
		SLADaysForSeverity("HIGH"),
		SLADaysForSeverity("MEDIUM"),
		SLADaysForSeverity("LOW"),
		baseQ,
	)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []VulnerabilitySummaryRow{}
	for rows.Next() {
		var row VulnerabilitySummaryRow
		var critical, high, medium, low int
		var riskCritical, riskHigh, riskMedium, riskLow int
		if err := rows.Scan(&row.Group, &row.Total, &critical, &high, &medium, &low, &riskCritical, &riskHigh, &riskMedium, &riskLow, &row.Overdue); err != nil {
			return nil, err
		}
		row.Severity = map[string]int{
			"CRITICAL": critical,
			"HIGH":     high,
			"MEDIUM":   medium,
			"LOW":      low,
		}
		row.Risk = map[string]int{
			"critical": riskCritical,
			"high":     riskHigh,
			"medium":   riskMedium,
			"low":      riskLow,
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (db *DB) GetCurrentActionableVulnRiskCountsByHost(ctx context.Context, hostIDs []string) (map[string]map[string]int, error) {
	baseQ := `FROM vulnerabilities v JOIN hosts h ON h.id = v.host_id JOIN ` + latestScansSub + ` ls ON v.scan_id = ls.id` + vulnTriageJoin + ` WHERE ` + currentActionableVulnSQL()
	args := []any{}
	if len(hostIDs) > 0 {
		baseQ += ` AND v.host_id = ANY($1)`
		args = append(args, pqStringArray(hostIDs))
	}
	rows, err := db.QueryContext(ctx, `SELECT v.host_id, (`+vulnRiskLevelExpr+`) AS risk_level, count(*) `+baseQ+` GROUP BY v.host_id, risk_level`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]int{}
	for rows.Next() {
		var hostID, riskLevel string
		var count int
		if err := rows.Scan(&hostID, &riskLevel, &count); err != nil {
			return nil, err
		}
		if out[hostID] == nil {
			out[hostID] = map[string]int{}
		}
		out[hostID][riskLevel] = count
	}
	return out, rows.Err()
}

func (db *DB) GetCurrentActionableOverdueRiskCountsByHost(ctx context.Context, hostIDs []string) (map[string]map[string]int, error) {
	baseQ := `FROM vulnerabilities v JOIN hosts h ON h.id = v.host_id JOIN ` + latestScansSub + ` ls ON v.scan_id = ls.id` + vulnTriageJoin + ` WHERE ` + currentActionableVulnSQL()
	baseQ += overdueSQLCondition()
	args := []any{}
	if len(hostIDs) > 0 {
		baseQ += ` AND v.host_id = ANY($1)`
		args = append(args, pqStringArray(hostIDs))
	}
	rows, err := db.QueryContext(ctx, `SELECT v.host_id, (`+vulnRiskLevelExpr+`) AS risk_level, count(*) `+baseQ+` GROUP BY v.host_id, risk_level`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]int{}
	for rows.Next() {
		var hostID, riskLevel string
		var count int
		if err := rows.Scan(&hostID, &riskLevel, &count); err != nil {
			return nil, err
		}
		if out[hostID] == nil {
			out[hostID] = map[string]int{}
		}
		out[hostID][riskLevel] = count
	}
	return out, rows.Err()
}

func vulnSummaryGroupExpr(groupBy string) string {
	switch groupBy {
	case "team":
		return "COALESCE(NULLIF(h.team, ''), '(unassigned)')"
	case "environment":
		return "COALESCE(NULLIF(h.environment, ''), '(unassigned)')"
	case "criticality":
		return "COALESCE(NULLIF(h.criticality, ''), '(unassigned)')"
	default:
		return "COALESCE(NULLIF(h.owner, ''), '(unassigned)')"
	}
}

func (db *DB) GetVulnCountsByScan(ctx context.Context, scanID string) (map[string]int, int, error) {
	rows, err := db.QueryContext(ctx, `SELECT severity, count(*) FROM vulnerabilities WHERE scan_id=$1 GROUP BY severity`, scanID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	counts := map[string]int{}
	total := 0
	for rows.Next() {
		var sev string
		var cnt int
		if err := rows.Scan(&sev, &cnt); err != nil {
			return nil, 0, err
		}
		counts[sev] = cnt
		total += cnt
	}
	return counts, total, rows.Err()
}

func (db *DB) GetVulnRiskCountsByScan(ctx context.Context, scanID string) (map[string]int, error) {
	rows, err := db.QueryContext(ctx, `SELECT (`+vulnRiskLevelExpr+`) AS risk_level, count(*) FROM vulnerabilities v JOIN hosts h ON h.id = v.host_id WHERE v.scan_id=$1 GROUP BY risk_level`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var riskLevel string
		var count int
		if err := rows.Scan(&riskLevel, &count); err != nil {
			return nil, err
		}
		counts[riskLevel] = count
	}
	return counts, rows.Err()
}

func (db *DB) GetLatestPackages(ctx context.Context, hostID string, limit, offset int) ([]models.Package, int, error) {
	countQ := fmt.Sprintf(`SELECT count(*) FROM packages p JOIN %s ls ON p.scan_id = ls.id WHERE p.host_id=$1`, latestScansSub)
	dataQ := fmt.Sprintf(`SELECT %s%s FROM packages p JOIN %s ls ON p.scan_id = ls.id%s WHERE p.host_id=$1 ORDER BY p.name LIMIT $2 OFFSET $3`, pkgCols, pkgVulnSelect, latestScansSub, pkgVulnJoin)

	var total int
	if err := db.QueryRowContext(ctx, countQ, hostID).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := db.QueryContext(ctx, dataQ, hostID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var pkgs []models.Package
	for rows.Next() {
		var p models.Package
		if err := scanPkg(rows, &p); err != nil {
			return nil, 0, err
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, total, nil
}

func (db *DB) GetLatestPackagesForSBOM(ctx context.Context, hostID string) ([]models.Package, error) {
	q := fmt.Sprintf(`SELECT %s%s FROM packages p JOIN %s ls ON p.scan_id = ls.id%s WHERE p.host_id=$1 ORDER BY p.asset_type, p.container, p.name, p.version`,
		pkgCols, pkgVulnSelect, latestScansSub, pkgVulnJoin)
	rows, err := db.QueryContext(ctx, q, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var pkgs []models.Package
	for rows.Next() {
		var p models.Package
		if err := scanPkg(rows, &p); err != nil {
			return nil, err
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, rows.Err()
}

type PackageFilter struct {
	HostID     string
	HostIDs    []string
	Container  string
	PkgType    string
	Source     string
	NameSearch string
	SortBy     string
	SortDesc   bool
	Limit      int
	Offset     int
}

func (db *DB) SearchPackages(ctx context.Context, f PackageFilter) ([]models.Package, int, error) {
	baseQ := `FROM packages p` + pkgVulnJoin
	args := []any{}
	n := 1

	baseQ += ` JOIN ` + latestScansSub + ` ls ON p.scan_id = ls.id`

	baseQ += ` WHERE 1=1`

	if f.HostID != "" {
		baseQ += fmt.Sprintf(" AND p.host_id=$%d", n)
		args = append(args, f.HostID)
		n++
	} else if len(f.HostIDs) > 0 {
		baseQ += fmt.Sprintf(" AND p.host_id = ANY($%d)", n)
		args = append(args, pqStringArray(f.HostIDs))
		n++
	}
	if f.Container != "" {
		if f.Container == "(host)" {
			baseQ += " AND (p.container = '' OR p.container IS NULL)"
		} else {
			baseQ += fmt.Sprintf(" AND p.container=$%d", n)
			args = append(args, f.Container)
			n++
		}
	}
	if f.PkgType != "" {
		baseQ += fmt.Sprintf(" AND p.pkg_type=$%d", n)
		args = append(args, f.PkgType)
		n++
	}
	if f.Source != "" {
		baseQ += fmt.Sprintf(" AND p.source=$%d", n)
		args = append(args, f.Source)
		n++
	}
	if f.NameSearch != "" {
		baseQ += fmt.Sprintf(" AND p.name ILIKE $%d", n)
		args = append(args, "%"+f.NameSearch+"%")
		n++
	}

	var total int
	countArgs := make([]any, len(args))
	copy(countArgs, args)
	if err := db.QueryRowContext(ctx, "SELECT count(*) "+baseQ, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	dataQ := fmt.Sprintf(`SELECT %s%s `, pkgCols, pkgVulnSelect) + baseQ + fmt.Sprintf(" ORDER BY %s LIMIT $%d OFFSET $%d", pkgSortExpr(f.SortBy, f.SortDesc), n, n+1)
	args = append(args, f.Limit, f.Offset)

	rows, err := db.QueryContext(ctx, dataQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var pkgs []models.Package
	for rows.Next() {
		var p models.Package
		if err := scanPkg(rows, &p); err != nil {
			return nil, 0, err
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, total, nil
}

type ContainerFilter struct {
	HostID     string
	HostIDs    []string
	Runtime    string
	State      string
	ImageName  string
	NameSearch string
	SortBy     string
	SortDesc   bool
	Limit      int
	Offset     int
}

func (db *DB) SearchContainers(ctx context.Context, f ContainerFilter) ([]models.ContainerAsset, int, error) {
	baseQ := `FROM container_assets c JOIN ` + latestScansSub + ` ls ON c.scan_id = ls.id WHERE 1=1`
	args := []any{}
	n := 1

	if f.HostID != "" {
		baseQ += fmt.Sprintf(" AND c.host_id=$%d", n)
		args = append(args, f.HostID)
		n++
	} else if len(f.HostIDs) > 0 {
		baseQ += fmt.Sprintf(" AND c.host_id = ANY($%d)", n)
		args = append(args, pqStringArray(f.HostIDs))
		n++
	}
	if f.Runtime != "" {
		baseQ += fmt.Sprintf(" AND c.runtime=$%d", n)
		args = append(args, f.Runtime)
		n++
	}
	if f.State != "" {
		baseQ += fmt.Sprintf(" AND c.state=$%d", n)
		args = append(args, f.State)
		n++
	}
	if f.ImageName != "" {
		baseQ += fmt.Sprintf(" AND c.image_name ILIKE $%d", n)
		args = append(args, "%"+f.ImageName+"%")
		n++
	}
	if f.NameSearch != "" {
		baseQ += fmt.Sprintf(" AND (c.name ILIKE $%d OR c.container_id ILIKE $%d OR c.image_id ILIKE $%d)", n, n, n)
		args = append(args, "%"+f.NameSearch+"%")
		n++
	}

	var total int
	countArgs := make([]any, len(args))
	copy(countArgs, args)
	if err := db.QueryRowContext(ctx, "SELECT count(*) "+baseQ, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	q := `SELECT c.id, c.scan_id, c.host_id, c.runtime, c.container_id, c.name, c.image_name, c.image_id, c.image_digest, c.state, c.labels::text, c.started_at,
		(SELECT count(*) FROM packages p WHERE p.scan_id=c.scan_id AND (p.container_id=c.container_id OR p.container=c.name))::int AS package_count,
		(SELECT count(*) FROM vulnerabilities v ` + vulnTriageJoin + ` WHERE v.scan_id=c.scan_id AND v.container=c.name AND ` + currentActionableVulnSQL() + `)::int AS vulnerability_count,
		(SELECT count(*) FROM vulnerabilities v ` + vulnTriageJoin + ` WHERE v.scan_id=c.scan_id AND v.container=c.name AND v.severity='CRITICAL' AND ` + currentActionableVulnSQL() + `)::int AS critical_count,
		(SELECT count(*) FROM vulnerabilities v ` + vulnTriageJoin + ` WHERE v.scan_id=c.scan_id AND v.container=c.name AND v.severity='HIGH' AND ` + currentActionableVulnSQL() + `)::int AS high_count,
		COALESCE((SELECT max(v.cvss_score) FROM vulnerabilities v ` + vulnTriageJoin + ` WHERE v.scan_id=c.scan_id AND v.container=c.name AND ` + currentActionableVulnSQL() + `), 0)::float AS max_cvss,
		c.created_at ` +
		baseQ + fmt.Sprintf(" ORDER BY %s LIMIT $%d OFFSET $%d", containerSortExpr(f.SortBy, f.SortDesc), n, n+1)
	args = append(args, f.Limit, f.Offset)

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []models.ContainerAsset
	for rows.Next() {
		var c models.ContainerAsset
		var started sql.NullTime
		if err := rows.Scan(
			&c.ID, &c.ScanID, &c.HostID, &c.Runtime, &c.ContainerID, &c.Name, &c.ImageName, &c.ImageID, &c.ImageDigest, &c.State, &c.Labels, &started,
			&c.PackageCount, &c.VulnerabilityCount, &c.CriticalCount, &c.HighCount, &c.MaxCVSS, &c.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		if started.Valid {
			c.StartedAt = &started.Time
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (db *DB) GetPackageHostID(ctx context.Context, packageID string) (string, error) {
	var hostID string
	err := db.QueryRowContext(ctx, `SELECT host_id FROM packages WHERE id=$1`, packageID).Scan(&hostID)
	return hostID, err
}

type FilterOptions struct {
	HostIDs        []string `json:"host_ids"`
	Containers     []string `json:"containers"`
	PkgTypes       []string `json:"pkg_types"`
	Sources        []string `json:"sources"`
	FindingSources []string `json:"finding_sources"`
}

func (db *DB) GetVulnFilterOptions(ctx context.Context, hostIDs []string) (*FilterOptions, error) {
	opts := &FilterOptions{}
	args := []any{}
	hostFilter := ""
	if len(hostIDs) > 0 {
		hostFilter = " AND v.host_id = ANY($1)"
		args = append(args, pqStringArray(hostIDs))
	}
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT v.host_id FROM vulnerabilities v JOIN `+latestScansSub+` ls ON v.scan_id = ls.id WHERE 1=1`+hostFilter+` ORDER BY v.host_id`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v string
		rows.Scan(&v)
		opts.HostIDs = append(opts.HostIDs, v)
	}
	rows.Close()

	rows, err = db.QueryContext(ctx, `SELECT DISTINCT COALESCE(NULLIF(v.container, ''), '(host)') FROM vulnerabilities v JOIN `+latestScansSub+` ls ON v.scan_id = ls.id WHERE 1=1`+hostFilter+` ORDER BY 1`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v string
		rows.Scan(&v)
		opts.Containers = append(opts.Containers, v)
	}
	rows.Close()

	rows, err = db.QueryContext(ctx, `SELECT DISTINCT COALESCE(v.finding_source, 'scanner') FROM vulnerabilities v JOIN `+latestScansSub+` ls ON v.scan_id = ls.id WHERE 1=1`+hostFilter+` ORDER BY 1`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v string
		rows.Scan(&v)
		opts.FindingSources = append(opts.FindingSources, v)
	}
	rows.Close()

	return opts, nil
}

type CveSearchFilter struct {
	Query    string
	PkgName  string
	Severity string
	HostIDs  []string
	MinCVSS  float64
	SortBy   string
	SortDesc bool
}

func (db *DB) SearchCVEs(ctx context.Context, f CveSearchFilter, limit, offset int) ([]models.Vulnerability, int, error) {
	baseQ := `FROM vulnerabilities v JOIN hosts h ON h.id = v.host_id JOIN ` + latestScansSub + ` ls ON v.scan_id = ls.id` + vulnTriageJoin + ` WHERE 1=1`
	args := []any{}
	argN := 1

	if f.Query != "" {
		baseQ += fmt.Sprintf(" AND (v.vulnerability_id ILIKE $%d OR v.title ILIKE $%d OR v.description ILIKE $%d)", argN, argN, argN)
		args = append(args, "%"+f.Query+"%")
		argN++
	}
	if f.PkgName != "" {
		baseQ += fmt.Sprintf(" AND v.pkg_name ILIKE $%d", argN)
		args = append(args, "%"+f.PkgName+"%")
		argN++
	}
	if f.Severity != "" {
		baseQ += fmt.Sprintf(" AND v.severity=$%d", argN)
		args = append(args, f.Severity)
		argN++
	}
	if len(f.HostIDs) > 0 {
		baseQ += fmt.Sprintf(" AND v.host_id = ANY($%d)", argN)
		args = append(args, pqStringArray(f.HostIDs))
		argN++
	}
	if f.MinCVSS > 0 {
		baseQ += fmt.Sprintf(" AND v.cvss_score>=$%d", argN)
		args = append(args, f.MinCVSS)
		argN++
	}

	var total int
	countArgs := make([]any, len(args))
	copy(countArgs, args)
	if err := db.QueryRowContext(ctx, "SELECT count(*) "+baseQ, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	sortExpr := vulnSortExpr(f.SortBy, f.SortDesc)
	dataQ := fmt.Sprintf(`SELECT %s%s `, vulnSelectCols, vulnTriageCols) + baseQ + fmt.Sprintf(" ORDER BY %s LIMIT $%d OFFSET $%d", sortExpr, argN, argN+1)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, dataQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var vulns []models.Vulnerability
	for rows.Next() {
		var v models.Vulnerability
		if err := scanVuln(rows, &v); err != nil {
			return nil, 0, err
		}
		ApplyVulnerabilitySLA(&v)
		vulns = append(vulns, v)
	}
	return vulns, total, nil
}

func (db *DB) EnrichVulnerabilities(ctx context.Context) (int, error) {
	fixedExpr := cveEnrichmentFixedVersionSQL("c", "v")
	// Step 1: exact vulnerability_id match — fill severity + fixed_version + title/description
	q1 := fmt.Sprintf(`
	UPDATE vulnerabilities v
	SET severity = COALESCE(c.severity, v.severity),
	    cvss_score = CASE WHEN v.cvss_score = 0 OR c.cvss_score > v.cvss_score THEN c.cvss_score ELSE v.cvss_score END,
	    cvss_vector = COALESCE(NULLIF(c.cvss_vector, ''), v.cvss_vector),
	    fixed_version = COALESCE(NULLIF(v.fixed_version, ''), COALESCE(%s, '')),
	    title = CASE WHEN c.title != '' THEN c.title ELSE v.title END,
	    description = CASE WHEN c.description != '' THEN c.description ELSE v.description END
	FROM cve_database c
	WHERE c.vulnerability_id = v.vulnerability_id
	  AND (v.severity = '' OR v.cvss_score = 0 OR v.fixed_version = '' OR v.title = '' OR v.description = '' OR c.cvss_score > v.cvss_score)
	  AND (c.cvss_score > 0 OR %s IS NOT NULL OR c.title != '')`, fixedExpr, fixedExpr)
	r1, err := db.ExecContext(ctx, q1)
	if err != nil {
		return 0, err
	}
	n1, _ := r1.RowsAffected()

	// Step 2: CVE number extraction match (DEBIAN-CVE-*, ALPINE-CVE-*, etc.)
	fixedExpr = cveSafeFixedVersionSQL("")
	q2 := fmt.Sprintf(`
	WITH v_cves AS (
		SELECT id as vid, SUBSTRING(vulnerability_id FROM 'CVE-\d+-\d+') as cve
		FROM vulnerabilities
		WHERE (severity = '' OR cvss_score = 0 OR fixed_version = '' OR title = '') AND vulnerability_id ~ 'CVE-'
	),
	c_cves AS (
		SELECT DISTINCT ON (cve) severity, cvss_score, cvss_vector,
		    %s as fixed_ver, cve,
		    title as cve_title, description as cve_desc
		FROM (
			SELECT severity, cvss_score, cvss_vector, affected_products,
				   SUBSTRING(vulnerability_id FROM 'CVE-\d+-\d+') as cve,
				   title, description
			FROM cve_database WHERE cvss_score > 0 OR %s IS NOT NULL OR title != ''
		) sub
		ORDER BY cve, cvss_score DESC
	)
	UPDATE vulnerabilities v
	SET severity = COALESCE(c.severity, v.severity),
	    cvss_score = CASE WHEN v.cvss_score = 0 OR c.cvss_score > v.cvss_score THEN c.cvss_score ELSE v.cvss_score END,
	    cvss_vector = COALESCE(NULLIF(c.cvss_vector, ''), v.cvss_vector),
	    fixed_version = COALESCE(NULLIF(v.fixed_version, ''), COALESCE(c.fixed_ver, '')),
	    title = CASE WHEN c.cve_title != '' THEN c.cve_title ELSE v.title END,
	    description = CASE WHEN c.cve_desc != '' THEN c.cve_desc ELSE v.description END
	FROM v_cves vc JOIN c_cves c ON c.cve = vc.cve
	WHERE v.id = vc.vid`, fixedExpr, fixedExpr)
	r2, err := db.ExecContext(ctx, q2)
	if err != nil {
		return int(n1), err
	}
	n2, _ := r2.RowsAffected()
	return int(n1) + int(n2), nil
}

func (db *DB) RemoveStaleRematchedVulnerabilities(ctx context.Context) (int, error) {
	res, err := db.ExecContext(ctx, fmt.Sprintf(`
DELETE FROM vulnerabilities v
USING packages p
WHERE v.package_id = p.id
  AND v.finding_source = 'cve-db'
  AND NOT EXISTS (
	SELECT 1
	FROM cve_database c
	JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(c.affected_products) = 'array' THEN c.affected_products ELSE '[]'::jsonb END) ap ON true
	WHERE c.vulnerability_id = v.vulnerability_id
	  AND COALESCE(ap->>'name', '') != ''
	  AND lower(ap->>'name') = lower(COALESCE(NULLIF(p.name, ''), NULLIF(v.pkg_name, '')))
	  AND COALESCE(NULLIF(ap->>'ecosystem', ''), NULLIF(c.ecosystem, '')) IS NOT NULL
	  AND %s = %s
	  AND (
		%s
	  )
  )`, affectedProductEcosystemSQL("c", "ap"), packageEcosystemSQL("p"), cveSourceFixedPredicateSQL()))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func cveEnrichmentFixedVersionSQL(cveAlias, vulnAlias string) string {
	return fmt.Sprintf(`COALESCE(
		%s,
		%s
	)`, cveContextualFixedVersionSQL(cveAlias, vulnAlias), cveSafeFixedVersionSQL(cveAlias))
}

func cveContextualFixedVersionSQL(cveAlias, vulnAlias string) string {
	cvePrefix := ""
	if cveAlias != "" {
		cvePrefix = cveAlias + "."
	}
	return fmt.Sprintf(`(
		SELECT COALESCE(
			%s,
			NULLIF(jsonb_path_query_first(ap, '$.ranges[*].events[*].fixed ? (@ != "")') #>> '{}', '')
		)
		FROM packages p
		JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(%saffected_products) = 'array' THEN %saffected_products ELSE '[]'::jsonb END) ap ON true
		WHERE p.id = %s.package_id
		  AND lower(ap->>'name') = lower(COALESCE(NULLIF(p.name, ''), NULLIF(%s.pkg_name, '')))
		  AND %s = %s
		  AND (
			%s
		  )
		LIMIT 1
	)`, safeAffectedFixedVersionSQL("ap"), cvePrefix, cvePrefix, vulnAlias, vulnAlias, affectedProductEcosystemSQL(cveAlias, "ap"), packageEcosystemSQL("p"), cveSourceFixedPredicateSQL())
}

func cveSafeFixedVersionSQL(alias string) string {
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	return fmt.Sprintf(`CASE
		WHEN jsonb_typeof(%saffected_products) = 'array'
		  AND jsonb_array_length(%saffected_products) = 1
		THEN %s
		ELSE NULL
	END`, prefix, prefix, cveFixedVersionSQL(alias))
}

func cveFixedVersionSQL(alias string) string {
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	return fmt.Sprintf(`COALESCE(
		%s,
		NULLIF(jsonb_path_query_first(%saffected_products, '$[*].ranges[*].events[*].fixed ? (@ != "")') #>> '{}', '')
	)`, safeAffectedFixedVersionSQL(prefix+"affected_products->0"), prefix)
}

func safeAffectedFixedVersionSQL(affectedExpr string) string {
	return fmt.Sprintf(`CASE
			WHEN jsonb_typeof(%s->'fixed') = 'array'
			  AND jsonb_array_length(%s->'fixed') = 1
			THEN NULLIF(%s->'fixed'->>0, '')
			ELSE NULL
		END`, affectedExpr, affectedExpr, affectedExpr)
}

func cveAffectedPackageFixedVersionSQL(affectedExpr string) string {
	return fmt.Sprintf(`COALESCE(
		%s,
		NULLIF(jsonb_path_query_first(%s, '$.ranges[*].events[*].fixed ? (@ != "")') #>> '{}', '')
	)`, safeAffectedFixedVersionSQL(affectedExpr), affectedExpr)
}

func affectedProductEcosystemSQL(cveAlias, affectedAlias string) string {
	cvePrefix := ""
	if cveAlias != "" {
		cvePrefix = cveAlias + "."
	}
	raw := fmt.Sprintf("lower(COALESCE(NULLIF(%s->>'ecosystem', ''), NULLIF(%secosystem, '')))", affectedAlias, cvePrefix)
	return normalizeEcosystemSQL(raw)
}

func packageEcosystemSQL(alias string) string {
	raw := fmt.Sprintf("lower(COALESCE(NULLIF(%s.ecosystem, ''), NULLIF(%s.pkg_type, '')))", alias, alias)
	return normalizeEcosystemSQL(raw)
}

func cvePackageEcosystemMismatchFilter(vulnAlias string) string {
	affectedProducts := `CASE WHEN jsonb_typeof(c.affected_products) = 'array' THEN c.affected_products ELSE '[]'::jsonb END`
	return fmt.Sprintf(` AND NOT EXISTS (
		SELECT 1
		FROM cve_database c
		JOIN packages p ON p.id = %s.package_id
		WHERE c.vulnerability_id = %s.vulnerability_id
		  AND p.pkg_type IN ('debian','ubuntu','deb','alpine','apk','redhat','centos','rocky','alma','amazon','rpm','suse','wolfi','python-pkg','pip','node-pkg','npm','gomod','go','gobinary','cargo','rustbinary','jar','maven','composer','gem','nuget')
		  AND EXISTS (
			SELECT 1
			FROM jsonb_array_elements(%s) ap
			WHERE COALESCE(NULLIF(ap->>'ecosystem', ''), NULLIF(c.ecosystem, '')) IS NOT NULL
		  )
		  AND NOT EXISTS (
			SELECT 1
			FROM jsonb_array_elements(%s) ap
			WHERE %s = %s
			  AND (
				COALESCE(ap->>'name', '') = ''
				OR lower(ap->>'name') = lower(COALESCE(NULLIF(p.name, ''), NULLIF(%s.pkg_name, '')))
			  )
		  )
	)`, vulnAlias, vulnAlias, affectedProducts, affectedProducts, affectedProductEcosystemSQL("c", "ap"), packageEcosystemSQL("p"), vulnAlias)
}

func defaultVulnMismatchFilterSQL(vulnAlias string) string {
	return fmt.Sprintf(` AND NOT EXISTS (SELECT 1 FROM packages p WHERE p.id = %[1]s.package_id AND p.pkg_type IN ('python-pkg','pip','node-pkg','npm','gomod','go','gobinary','cargo','rustbinary','jar','maven','composer','gem','nuget') AND SUBSTRING(%[1]s.vulnerability_id FROM '^[A-Z]+') IN ('DEBIAN','DSA','DLA','ALPINE','SUSE','ALSA','CGA','UBUNTU','RHSA'))
		AND NOT (EXISTS (SELECT 1 FROM packages p WHERE p.id = %[1]s.package_id AND p.pkg_type = 'debian') AND SUBSTRING(%[1]s.vulnerability_id FROM '^[A-Z]+') IN ('ALPINE','SUSE','ALSA','RHSA','UBUNTU'))
		AND NOT (EXISTS (SELECT 1 FROM packages p WHERE p.id = %[1]s.package_id AND p.pkg_type IN ('apk','alpine')) AND SUBSTRING(%[1]s.vulnerability_id FROM '^[A-Z]+') IN ('DEBIAN','DSA','DLA','SUSE','ALSA','RHSA','UBUNTU'))
		AND NOT (EXISTS (SELECT 1 FROM packages p WHERE p.id = %[1]s.package_id AND p.pkg_type = 'ubuntu') AND SUBSTRING(%[1]s.vulnerability_id FROM '^[A-Z]+') IN ('ALPINE','SUSE','ALSA','RHSA'))
		AND NOT (EXISTS (SELECT 1 FROM packages p WHERE p.id = %[1]s.package_id AND p.pkg_type = 'wolfi') AND SUBSTRING(%[1]s.vulnerability_id FROM '^[A-Z]+') IN ('DEBIAN','DSA','DLA','ALPINE','SUSE','ALSA','RHSA','UBUNTU'))`, vulnAlias) + cvePackageEcosystemMismatchFilter(vulnAlias)
}

func normalizeEcosystemSQL(raw string) string {
	return fmt.Sprintf(`CASE
		WHEN %s IN ('python', 'python-pkg', 'pip', 'poetry', 'pypi') THEN 'pypi'
		WHEN %s IN ('node', 'node-pkg', 'javascript', 'npm', 'yarn', 'pnpm') THEN 'npm'
		WHEN %s IN ('golang', 'gomod', 'gobinary', 'go') THEN 'go'
		WHEN %s IN ('ruby', 'gem', 'rubygems') THEN 'rubygems'
		WHEN %s IN ('rust', 'cargo', 'rustbinary', 'crates.io') THEN 'crates.io'
		WHEN %s IN ('jar', 'maven') THEN 'maven'
		WHEN %s IN ('composer', 'packagist') THEN 'packagist'
		WHEN %s IN ('nuget') THEN 'nuget'
		WHEN %s LIKE 'debian:%%' OR %s IN ('debian', 'deb') THEN 'debian'
		WHEN %s LIKE 'ubuntu:%%' OR %s = 'ubuntu' THEN 'ubuntu'
		WHEN %s IN ('alpine', 'apk') THEN 'alpine'
		WHEN %s IN ('redhat', 'red hat', 'red hat enterprise linux', 'centos', 'rocky', 'almalinux', 'alma', 'amazon', 'amazon linux', 'rpm', 'rhel') THEN 'rhel'
		WHEN %s IN ('suse') THEN 'suse'
		WHEN %s IN ('wolfi', 'chainguard') THEN 'wolfi'
		ELSE %s
	END`, raw, raw, raw, raw, raw, raw, raw, raw, raw, raw, raw, raw, raw, raw, raw, raw, raw)
}

func (db *DB) GetFilterOptions(ctx context.Context, hostIDs []string) (*FilterOptions, error) {
	opts := &FilterOptions{}
	args := []any{}
	hostFilter := ""
	if len(hostIDs) > 0 {
		hostFilter = " AND p.host_id = ANY($1)"
		args = append(args, pqStringArray(hostIDs))
	}

	rows, err := db.QueryContext(ctx, `SELECT DISTINCT p.host_id FROM packages p JOIN `+latestScansSub+` ls ON p.scan_id = ls.id WHERE 1=1`+hostFilter+` ORDER BY p.host_id`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v string
		rows.Scan(&v)
		opts.HostIDs = append(opts.HostIDs, v)
	}
	rows.Close()

	rows, err = db.QueryContext(ctx, `SELECT DISTINCT COALESCE(NULLIF(p.container, ''), '(host)') FROM packages p JOIN `+latestScansSub+` ls ON p.scan_id = ls.id WHERE 1=1`+hostFilter+` ORDER BY 1`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v string
		rows.Scan(&v)
		opts.Containers = append(opts.Containers, v)
	}
	rows.Close()

	rows, err = db.QueryContext(ctx, `SELECT DISTINCT p.pkg_type FROM packages p JOIN `+latestScansSub+` ls ON p.scan_id = ls.id WHERE 1=1`+hostFilter+` ORDER BY p.pkg_type`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v string
		rows.Scan(&v)
		opts.PkgTypes = append(opts.PkgTypes, v)
	}
	rows.Close()

	rows, err = db.QueryContext(ctx, `SELECT DISTINCT p.source FROM packages p JOIN `+latestScansSub+` ls ON p.scan_id = ls.id WHERE 1=1`+hostFilter+` ORDER BY p.source`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v string
		rows.Scan(&v)
		opts.Sources = append(opts.Sources, v)
	}
	rows.Close()

	return opts, nil
}

func pkgSortExpr(col string, desc bool) string {
	allowed := map[string]string{
		"name": "p.name", "version": "p.version", "pkg_type": "p.pkg_type",
		"container": "p.container", "source": "p.source", "file_path": "p.file_path",
		"asset_type": "p.asset_type", "ecosystem": "p.ecosystem", "image_name": "p.image_name",
		"max_cvss": "COALESCE(vx.max_cvss, 0)", "vuln_count": "COALESCE(vx.vuln_count, 0)",
	}
	expr, ok := allowed[col]
	if !ok {
		expr = "p.name"
	}
	dir := "ASC"
	if desc {
		dir = "DESC"
	}
	return expr + " " + dir + " NULLS LAST"
}

func containerSortExpr(col string, desc bool) string {
	allowed := map[string]string{
		"name":                "c.name",
		"image_name":          "c.image_name",
		"state":               "c.state",
		"runtime":             "c.runtime",
		"started_at":          "c.started_at",
		"created_at":          "c.created_at",
		"container_id":        "c.container_id",
		"package_count":       "(SELECT count(*) FROM packages p WHERE p.scan_id=c.scan_id AND (p.container_id=c.container_id OR p.container=c.name))",
		"vulnerability_count": "(SELECT count(*) FROM vulnerabilities v " + vulnTriageJoin + " WHERE v.scan_id=c.scan_id AND v.container=c.name AND " + currentActionableVulnSQL() + ")",
		"critical_count":      "(SELECT count(*) FROM vulnerabilities v " + vulnTriageJoin + " WHERE v.scan_id=c.scan_id AND v.container=c.name AND v.severity='CRITICAL' AND " + currentActionableVulnSQL() + ")",
		"high_count":          "(SELECT count(*) FROM vulnerabilities v " + vulnTriageJoin + " WHERE v.scan_id=c.scan_id AND v.container=c.name AND v.severity='HIGH' AND " + currentActionableVulnSQL() + ")",
		"max_cvss":            "COALESCE((SELECT max(v.cvss_score) FROM vulnerabilities v " + vulnTriageJoin + " WHERE v.scan_id=c.scan_id AND v.container=c.name AND " + currentActionableVulnSQL() + "), 0)",
	}
	expr, ok := allowed[col]
	if !ok {
		expr = "c.created_at"
	}
	dir := "ASC"
	if desc {
		dir = "DESC"
	}
	return expr + " " + dir + " NULLS LAST"
}

func vulnSortExpr(col string, desc bool) string {
	allowed := map[string]string{
		"vulnerability_id": "v.vulnerability_id", "severity": "CASE v.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END",
		"cvss_score": "v.cvss_score", "pkg_name": "v.pkg_name",
		"host_id": "v.host_id", "container": "v.container", "installed_version": "v.installed_version",
		"fixed_version": "v.fixed_version", "created_at": "v.created_at", "due_at": "v.created_at",
		"exploited":       vulnExploitedExpr,
		"epss_score":      vulnEPSSScoreExpr,
		"epss_percentile": vulnEPSSPercentileExpr,
		"risk_score":      vulnRiskScoreExpr,
		"risk_level":      vulnRiskLevelExpr,
		"pkg_type":        "COALESCE((SELECT p.pkg_type FROM packages p WHERE p.id = v.package_id), '')",
		"ecosystem":       "COALESCE((SELECT p.ecosystem FROM packages p WHERE p.id = v.package_id), '')",
		"owner":           "h.owner", "team": "h.team", "environment": "h.environment", "criticality": "h.criticality",
	}
	expr, ok := allowed[col]
	if !ok {
		expr = vulnRiskScoreExpr
	}
	dir := "ASC"
	if desc {
		dir = "DESC"
	}
	return expr + " " + dir + " NULLS LAST"
}

func (db *DB) GetVulnsByPackageID(ctx context.Context, packageID string) ([]models.Vulnerability, error) {
	q := `SELECT ` + vulnSelectCols + vulnTriageCols + ` FROM vulnerabilities v JOIN hosts h ON h.id = v.host_id JOIN ` + latestScansSub + ` ls ON v.scan_id = ls.id` + vulnTriageJoin + ` WHERE v.package_id=$1 AND ` + currentActionableVulnSQL() + ` ORDER BY v.cvss_score DESC`
	rows, err := db.QueryContext(ctx, q, packageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulns []models.Vulnerability
	for rows.Next() {
		var v models.Vulnerability
		if err := scanVuln(rows, &v); err != nil {
			return nil, err
		}
		ApplyVulnerabilitySLA(&v)
		vulns = append(vulns, v)
	}
	return vulns, nil
}

const CveCols = `id, vulnerability_id, source, category, ecosystem, severity, cvss_score, cvss_vector, epss_score, epss_percentile, title, description, published_date, modified_date, affected_products, refs, raw_data, updated_at`

func ScanCveEntry(scanner interface{ Scan(...interface{}) error }, e *models.CveEntry) error {
	return scanner.Scan(&e.ID, &e.VulnerabilityID, &e.Source, &e.Category, &e.Ecosystem, &e.Severity, &e.CVSSScore, &e.CVSSVector,
		&e.EPSSScore, &e.EPSSPercentile, &e.Title, &e.Description, &e.PublishedDate, &e.ModifiedDate,
		&e.AffectedProducts, &e.References, &e.RawData, &e.UpdatedAt)
}

func (db *DB) UpsertCveEntries(ctx context.Context, entries []models.CveEntry) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	count, err := db.UpsertCveEntriesTx(ctx, tx, entries)
	if err != nil {
		return 0, err
	}
	return count, tx.Commit()
}

func (db *DB) UpsertCveEntriesTx(ctx context.Context, tx *sql.Tx, entries []models.CveEntry) (int, error) {
	return db.upsertCveEntriesTx(ctx, tx, entries, true)
}

func (db *DB) UpsertCveEntriesWithoutAffectedIndexTx(ctx context.Context, tx *sql.Tx, entries []models.CveEntry) (int, error) {
	return db.upsertCveEntriesTx(ctx, tx, entries, false)
}

func (db *DB) upsertCveEntriesTx(ctx context.Context, tx *sql.Tx, entries []models.CveEntry, refreshAffectedIndex bool) (int, error) {
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO cve_database (id, vulnerability_id, source, category, ecosystem, severity, cvss_score, cvss_vector, epss_score, epss_percentile, title, description, published_date, modified_date, affected_products, refs, raw_data, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, now())
ON CONFLICT (vulnerability_id, source) DO UPDATE SET
	category=EXCLUDED.category, ecosystem=EXCLUDED.ecosystem,
	severity=EXCLUDED.severity, cvss_score=EXCLUDED.cvss_score, cvss_vector=EXCLUDED.cvss_vector,
	epss_score=EXCLUDED.epss_score, epss_percentile=EXCLUDED.epss_percentile,
	title=EXCLUDED.title, description=EXCLUDED.description,
	published_date=EXCLUDED.published_date, modified_date=EXCLUDED.modified_date,
	affected_products=EXCLUDED.affected_products, refs=EXCLUDED.refs,
	raw_data=EXCLUDED.raw_data, updated_at=now()
RETURNING id`)
	if err != nil {
		return 0, fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	count := 0
	var firstErr error
	for i := range entries {
		e := &entries[i]
		if e.ID == "" {
			e.ID = uuid.New().String()
		}
		// Auto-calculate CVSS score from vector if missing
		if e.CVSSScore == 0 && e.CVSSVector != "" {
			e.CVSSScore = calcCvssScore(e.CVSSVector)
		}
		// Auto-normalize severity from score
		if e.CVSSScore > 0 && (e.Severity == "" || e.Severity == "MODERATE") {
			if e.CVSSScore >= 9.0 {
				e.Severity = "CRITICAL"
			} else if e.CVSSScore >= 7.0 {
				e.Severity = "HIGH"
			} else if e.CVSSScore >= 4.0 {
				e.Severity = "MEDIUM"
			} else {
				e.Severity = "LOW"
			}
		}
		if e.Category == "" || e.Ecosystem == "" {
			e.Category, e.Ecosystem = ClassifySecuritySource(e.Source, e.AffectedProducts)
		}
		var cveID string
		if err := stmt.QueryRowContext(ctx, e.ID, e.VulnerabilityID, e.Source, e.Category, e.Ecosystem, e.Severity,
			e.CVSSScore, e.CVSSVector, e.EPSSScore, e.EPSSPercentile, e.Title, e.Description,
			e.PublishedDate, e.ModifiedDate, e.AffectedProducts, e.References, e.RawData).Scan(&cveID); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("insert %s: %w", e.VulnerabilityID, err)
			}
			log.Printf("rematch scan row: %v", err)
			continue
		}
		if refreshAffectedIndex {
			if _, err := db.RefreshCveAffectedPackagesForCveTx(ctx, tx, cveID); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("refresh affected packages %s: %w", e.VulnerabilityID, err)
				}
				log.Printf("refresh affected package index: %v", err)
				continue
			}
		} else {
			_ = cveID
		}
		if _, err := db.RefreshCveReferenceKeysForCveTx(ctx, tx, cveID, *e); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("refresh reference keys %s: %w", e.VulnerabilityID, err)
			}
			log.Printf("refresh CVE reference key index: %v", err)
			continue
		}
		count++
	}
	if firstErr != nil {
		return 0, firstErr
	}
	return count, nil
}

func (db *DB) RefreshCveAffectedPackagesForSourceTx(ctx context.Context, tx *sql.Tx, source string) (int, error) {
	source = strings.TrimSpace(source)
	if source == "" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM cve_affected_packages`); err != nil {
			return 0, err
		}
		return db.insertCveAffectedPackagesTx(ctx, tx, "")
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM cve_affected_packages cap
USING cve_database c
WHERE cap.cve_id = c.id
  AND c.source = $1`, source); err != nil {
		return 0, err
	}
	return db.insertCveAffectedPackagesTx(ctx, tx, source)
}

func (db *DB) RefreshCveReferenceKeysForCveTx(ctx context.Context, tx *sql.Tx, cveID string, entry models.CveEntry) (int, error) {
	if _, err := tx.ExecContext(ctx, `DELETE FROM cve_reference_keys WHERE cve_id=$1`, cveID); err != nil {
		return 0, err
	}
	keys := cveReferenceKeys(entry)
	if len(keys) == 0 {
		return 0, nil
	}
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO cve_reference_keys (cve_id, reference_key, updated_at)
VALUES ($1, $2, now())
ON CONFLICT (cve_id, reference_key) DO UPDATE SET updated_at=now()`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	count := 0
	for _, key := range keys {
		if _, err := stmt.ExecContext(ctx, cveID, key); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func (db *DB) insertCveAffectedPackagesTx(ctx context.Context, tx *sql.Tx, source string) (int, error) {
	source = strings.TrimSpace(source)
	args := []any{}
	filter := ""
	if source != "" {
		args = append(args, source)
		filter = " AND c.source = $1"
	}
	fixedExpr := cveAffectedPackageFixedVersionSQL("ap")
	ecosystemExpr := affectedProductEcosystemSQL("c", "ap")
	res, err := tx.ExecContext(ctx, fmt.Sprintf(`
INSERT INTO cve_affected_packages (cve_id, vulnerability_id, source, package_name, ecosystem, fixed_version, affected_product, updated_at)
SELECT DISTINCT ON (c.id, lower(ap->>'name'), %s, %s)
       c.id,
       c.vulnerability_id,
       c.source,
       lower(ap->>'name') AS package_name,
       %s AS ecosystem,
       %s AS fixed_version,
       ap AS affected_product,
       now()
FROM cve_database c
JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(c.affected_products) = 'array' THEN c.affected_products ELSE '[]'::jsonb END) ap ON true
WHERE COALESCE(ap->>'name', '') != ''
  AND COALESCE(NULLIF(ap->>'ecosystem', ''), NULLIF(c.ecosystem, '')) IS NOT NULL
  AND %s IS NOT NULL
  AND %s != ''
  %s
ON CONFLICT (cve_id, package_name, ecosystem, fixed_version) DO UPDATE SET
	affected_product=EXCLUDED.affected_product,
	updated_at=now()`, ecosystemExpr, fixedExpr, ecosystemExpr, fixedExpr, fixedExpr, fixedExpr, filter), args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (db *DB) RefreshCveAffectedPackagesForCveTx(ctx context.Context, tx *sql.Tx, cveID string) (int, error) {
	if _, err := tx.ExecContext(ctx, `DELETE FROM cve_affected_packages WHERE cve_id=$1`, cveID); err != nil {
		return 0, err
	}
	fixedExpr := cveAffectedPackageFixedVersionSQL("ap")
	ecosystemExpr := affectedProductEcosystemSQL("c", "ap")
	res, err := tx.ExecContext(ctx, fmt.Sprintf(`
INSERT INTO cve_affected_packages (cve_id, vulnerability_id, source, package_name, ecosystem, fixed_version, affected_product, updated_at)
SELECT DISTINCT ON (c.id, lower(ap->>'name'), %s, %s)
       c.id,
       c.vulnerability_id,
       c.source,
       lower(ap->>'name') AS package_name,
       %s AS ecosystem,
       %s AS fixed_version,
       ap AS affected_product,
       now()
FROM cve_database c
JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(c.affected_products) = 'array' THEN c.affected_products ELSE '[]'::jsonb END) ap ON true
WHERE c.id=$1
  AND COALESCE(ap->>'name', '') != ''
  AND COALESCE(NULLIF(ap->>'ecosystem', ''), NULLIF(c.ecosystem, '')) IS NOT NULL
  AND %s IS NOT NULL
  AND %s != ''
ON CONFLICT (cve_id, package_name, ecosystem, fixed_version) DO UPDATE SET
	affected_product=EXCLUDED.affected_product,
	updated_at=now()`, ecosystemExpr, fixedExpr, ecosystemExpr, fixedExpr, fixedExpr, fixedExpr), cveID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (db *DB) RebuildCveAffectedPackages(ctx context.Context) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM cve_affected_packages`); err != nil {
		return 0, err
	}
	fixedExpr := cveAffectedPackageFixedVersionSQL("ap")
	ecosystemExpr := affectedProductEcosystemSQL("c", "ap")
	res, err := tx.ExecContext(ctx, fmt.Sprintf(`
INSERT INTO cve_affected_packages (cve_id, vulnerability_id, source, package_name, ecosystem, fixed_version, affected_product, updated_at)
SELECT DISTINCT ON (c.id, lower(ap->>'name'), %s, %s)
       c.id,
       c.vulnerability_id,
       c.source,
       lower(ap->>'name') AS package_name,
       %s AS ecosystem,
       %s AS fixed_version,
       ap AS affected_product,
       now()
FROM cve_database c
JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(c.affected_products) = 'array' THEN c.affected_products ELSE '[]'::jsonb END) ap ON true
WHERE COALESCE(ap->>'name', '') != ''
  AND COALESCE(NULLIF(ap->>'ecosystem', ''), NULLIF(c.ecosystem, '')) IS NOT NULL
  AND %s IS NOT NULL
  AND %s != ''
ON CONFLICT (cve_id, package_name, ecosystem, fixed_version) DO UPDATE SET
	affected_product=EXCLUDED.affected_product,
	updated_at=now()`, ecosystemExpr, fixedExpr, ecosystemExpr, fixedExpr, fixedExpr, fixedExpr))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(n), nil
}

func (db *DB) EnsureCveAffectedPackages(ctx context.Context) (int, error) {
	var cveCount, affectedCount int
	if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM cve_database), (SELECT count(*) FROM cve_affected_packages)`).Scan(&cveCount, &affectedCount); err != nil {
		return 0, err
	}
	if cveCount == 0 || affectedCount > 0 {
		return 0, nil
	}
	return db.RebuildCveAffectedPackages(ctx)
}

func (db *DB) RebuildCveReferenceKeys(ctx context.Context) (int, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, vulnerability_id, title, description, refs::text FROM cve_database`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	type indexedEntry struct {
		cveID string
		keys  []string
	}
	entries := []indexedEntry{}
	for rows.Next() {
		var e models.CveEntry
		if err := rows.Scan(&e.ID, &e.VulnerabilityID, &e.Title, &e.Description, &e.References); err != nil {
			return 0, err
		}
		keys := cveReferenceKeys(e)
		if len(keys) == 0 {
			continue
		}
		entries = append(entries, indexedEntry{cveID: e.ID, keys: keys})
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM cve_reference_keys`); err != nil {
		return 0, err
	}
	stmt, err := tx.PrepareContext(ctx, pq.CopyIn("cve_reference_keys", "cve_id", "reference_key", "updated_at"))
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	count := 0
	now := time.Now().UTC()
	for _, entry := range entries {
		for _, key := range entry.keys {
			if _, err := stmt.ExecContext(ctx, entry.cveID, key, now); err != nil {
				return 0, err
			}
			count++
		}
	}
	if _, err := stmt.ExecContext(ctx); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

func (db *DB) EnsureCveReferenceKeys(ctx context.Context) (int, error) {
	var cveCount, keyCount int
	if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM cve_database), (SELECT count(*) FROM cve_reference_keys)`).Scan(&cveCount, &keyCount); err != nil {
		return 0, err
	}
	if cveCount == 0 || keyCount > 0 {
		return 0, nil
	}
	return db.RebuildCveReferenceKeys(ctx)
}

func (db *DB) DeleteCveEntriesBySourceTx(ctx context.Context, tx *sql.Tx, source string) (int, error) {
	res, err := tx.ExecContext(ctx, `DELETE FROM cve_database WHERE source=$1`, source)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (db *DB) DeleteAllCveEntriesTx(ctx context.Context, tx *sql.Tx) (int, error) {
	res, err := tx.ExecContext(ctx, `DELETE FROM cve_database`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (db *DB) SyncEPSSPriorityColumnsTx(ctx context.Context, tx *sql.Tx) (int, error) {
	clearRes, err := tx.ExecContext(ctx, `
		UPDATE cve_database c
		SET epss_score = 0,
		    epss_percentile = 0
		WHERE c.source != 'epss'
		  AND (c.epss_score != 0 OR c.epss_percentile != 0)
		  AND NOT EXISTS (
			SELECT 1
			FROM cve_database epss
			WHERE epss.source = 'epss'
			  AND epss.vulnerability_id = c.vulnerability_id
			  AND (epss.epss_score > 0 OR epss.epss_percentile > 0)
		  )`)
	if err != nil {
		return 0, err
	}
	setRes, err := tx.ExecContext(ctx, `
		WITH latest_epss AS (
			SELECT DISTINCT ON (vulnerability_id)
			       vulnerability_id, epss_score, epss_percentile
			FROM cve_database
			WHERE source = 'epss'
			  AND (epss_score > 0 OR epss_percentile > 0)
			ORDER BY vulnerability_id, updated_at DESC, epss_score DESC, epss_percentile DESC
		)
		UPDATE cve_database c
		SET epss_score = latest_epss.epss_score,
		    epss_percentile = latest_epss.epss_percentile
		FROM latest_epss
		WHERE c.source != 'epss'
		  AND c.vulnerability_id = latest_epss.vulnerability_id
		  AND (c.epss_score IS DISTINCT FROM latest_epss.epss_score
		       OR c.epss_percentile IS DISTINCT FROM latest_epss.epss_percentile)`)
	if err != nil {
		return 0, err
	}
	clearN, _ := clearRes.RowsAffected()
	setN, _ := setRes.RowsAffected()
	return int(clearN + setN), nil
}

func (db *DB) SearchCveDatabase(ctx context.Context, query, referenceKey, severity, source string, minCVSS, minEPSS, minEPSSPercentile float64, matchableOnly, includePrioritySources bool, sortBy, sortOrder string, limit, offset int) ([]models.CveEntry, int, error) {
	baseQ := `FROM cve_database WHERE 1=1`
	args := []any{}
	argN := 1

	if query != "" {
		baseQ += fmt.Sprintf(` AND (
			vulnerability_id ILIKE $%d OR title ILIKE $%d OR description ILIKE $%d
			OR EXISTS (
				SELECT 1
				FROM jsonb_array_elements(CASE WHEN jsonb_typeof(affected_products) = 'array' THEN affected_products ELSE '[]'::jsonb END) ap
				WHERE ap->>'name' ILIKE $%d
				   OR COALESCE(NULLIF(ap->>'ecosystem', ''), ecosystem) ILIKE $%d
				   OR ap::text ILIKE $%d
			)
		)`, argN, argN, argN, argN, argN, argN)
		args = append(args, "%"+query+"%")
		argN++
	}
	if referenceKey != "" {
		filter, vals, ok := cveReferenceKeyWhere(referenceKey, argN)
		if ok {
			baseQ += " AND " + filter
			args = append(args, vals...)
			argN += len(vals)
		}
	}
	if severity != "" {
		baseQ += fmt.Sprintf(" AND severity=$%d", argN)
		args = append(args, severity)
		argN++
	}
	if source != "" {
		baseQ += fmt.Sprintf(" AND source=$%d", argN)
		args = append(args, source)
		argN++
	} else if !includePrioritySources {
		baseQ += " AND source NOT IN ('cisa-kev', 'epss')"
	}
	if minCVSS > 0 {
		baseQ += fmt.Sprintf(" AND cvss_score>=$%d", argN)
		args = append(args, minCVSS)
		argN++
	}
	if minEPSS > 0 {
		baseQ += fmt.Sprintf(" AND epss_score>=$%d", argN)
		args = append(args, minEPSS)
		argN++
	}
	if minEPSSPercentile > 0 {
		baseQ += fmt.Sprintf(" AND epss_percentile>=$%d", argN)
		args = append(args, minEPSSPercentile)
		argN++
	}
	if matchableOnly {
		baseQ += " AND " + cveSourceMatchablePredicateSQL("CASE WHEN jsonb_typeof(affected_products) = 'array' THEN affected_products ELSE '[]'::jsonb END", "ecosystem")
	}

	var total int
	countArgs := make([]any, len(args))
	copy(countArgs, args)
	if err := db.QueryRowContext(ctx, "SELECT count(*) "+baseQ, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	sortCol := "cvss_score"
	switch sortBy {
	case "vulnerability_id", "severity", "cvss_score", "epss_score", "epss_percentile", "source", "title", "published_date":
		sortCol = sortBy
	}
	sortDir := "DESC"
	if sortOrder == "asc" {
		sortDir = "ASC"
	}
	nullHandling := ""
	if sortCol == "cvss_score" || sortCol == "epss_score" || sortCol == "epss_percentile" {
		nullHandling = " NULLS LAST"
	}
	dataQ := fmt.Sprintf("SELECT %s ", CveCols) + baseQ + fmt.Sprintf(" ORDER BY %s %s%s LIMIT $%d OFFSET $%d", sortCol, sortDir, nullHandling, argN, argN+1)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, dataQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []models.CveEntry
	for rows.Next() {
		var e models.CveEntry
		if err := ScanCveEntry(rows, &e); err != nil {
			return nil, 0, err
		}
		e.MatchableAffected = cveEntryMatchableAffectedCount(e.AffectedProducts, e.Ecosystem)
		e.Matchable = e.MatchableAffected > 0
		e.ReferenceKeys = cveReferenceKeys(e)
		entries = append(entries, e)
	}
	if err := db.enrichCveReferenceGroupCounts(ctx, entries); err != nil {
		log.Printf("WARNING: CVE reference group summary enrichment skipped: %v", err)
		markCveReferenceGroupStatus(entries, "unavailable")
	}
	return entries, total, nil
}

type cveReferenceGroupCounts struct {
	Total     int
	Matchable int
	Sources   int
}

func (db *DB) enrichCveReferenceGroupCounts(ctx context.Context, entries []models.CveEntry) error {
	entryKeys := make([]string, len(entries))
	keys := []string{}
	for i := range entries {
		key := preferredReferenceGroupKey(entries[i].ReferenceKeys)
		if key != "" {
			entryKeys[i] = key
			keys = appendUnique(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	timeout := time.Duration(envPositiveInt("BONGSU_CVE_GROUP_SUMMARY_TIMEOUT_MS", 1500)) * time.Millisecond
	groupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	matchablePredicate := cveSourceMatchablePredicateSQL("CASE WHEN jsonb_typeof(c.affected_products) = 'array' THEN c.affected_products ELSE '[]'::jsonb END", "c.ecosystem")
	rows, err := db.QueryContext(groupCtx, fmt.Sprintf(`
WITH keys AS (SELECT unnest($1::text[]) AS reference_key)
SELECT k.reference_key,
	count(c.id),
	count(c.id) FILTER (WHERE %s),
	count(DISTINCT NULLIF(c.source, ''))
FROM keys k
JOIN cve_reference_keys crk ON crk.reference_key = k.reference_key
JOIN cve_database c ON c.id = crk.cve_id
GROUP BY k.reference_key`, matchablePredicate), pq.Array(keys))
	if err != nil {
		return err
	}
	defer rows.Close()
	counts := map[string]cveReferenceGroupCounts{}
	for rows.Next() {
		var key string
		var c cveReferenceGroupCounts
		if err := rows.Scan(&key, &c.Total, &c.Matchable, &c.Sources); err != nil {
			return err
		}
		counts[key] = c
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range entries {
		c, ok := counts[entryKeys[i]]
		if !ok {
			continue
		}
		entries[i].ReferenceGroupKey = entryKeys[i]
		entries[i].ReferenceGroupTotal = c.Total
		entries[i].ReferenceGroupMatchable = c.Matchable
		entries[i].ReferenceGroupSources = c.Sources
		entries[i].ReferenceGroupStatus = "ok"
	}
	return nil
}

func preferredReferenceGroupKey(keys []string) string {
	for _, prefix := range []string{"cve:", "debian:", "ghsa:", "rustsec:", "pysec:", "go:", "repo:", "vendor:"} {
		for _, key := range keys {
			if strings.HasPrefix(key, prefix) {
				return key
			}
		}
	}
	return ""
}

func markCveReferenceGroupStatus(entries []models.CveEntry, status string) {
	for i := range entries {
		if key := preferredReferenceGroupKey(entries[i].ReferenceKeys); key != "" {
			entries[i].ReferenceGroupKey = key
			entries[i].ReferenceGroupStatus = status
		}
	}
}

func (db *DB) GetCveReferenceGroupSummary(ctx context.Context, key string, limit int) (CveReferenceGroupSummary, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	filter, args, ok := cveReferenceKeyWhere(key, 1)
	if !ok {
		return CveReferenceGroupSummary{}, ErrInvalidCveReferenceKey
	}
	summary := CveReferenceGroupSummary{Key: strings.TrimSpace(key)}
	baseQ := "FROM cve_database WHERE " + filter
	if err := db.QueryRowContext(ctx, "SELECT count(*), count(*) FILTER (WHERE "+cveSourceMatchablePredicateSQL("CASE WHEN jsonb_typeof(affected_products) = 'array' THEN affected_products ELSE '[]'::jsonb END", "ecosystem")+") "+baseQ, args...).Scan(&summary.Total, &summary.Matchable); err != nil {
		return summary, err
	}
	var err error
	if summary.Sources, err = db.cveReferenceGroupBuckets(ctx, "source", baseQ, args); err != nil {
		return summary, err
	}
	if summary.Categories, err = db.cveReferenceGroupBuckets(ctx, "COALESCE(NULLIF(category, ''), '(uncategorized)')", baseQ, args); err != nil {
		return summary, err
	}
	if summary.Ecosystems, err = db.cveReferenceGroupBuckets(ctx, "COALESCE(NULLIF(ecosystem, ''), '(unknown)')", baseQ, args); err != nil {
		return summary, err
	}
	if summary.SourceGroups, err = db.cveReferenceGroupBuckets(ctx, "COALESCE(NULLIF(source, ''), '(unknown)') || ' / ' || COALESCE(NULLIF(category, ''), '(uncategorized)') || ' / ' || COALESCE(NULLIF(ecosystem, ''), '(unknown)')", baseQ, args); err != nil {
		return summary, err
	}
	dataArgs := append([]any{}, args...)
	dataArgs = append(dataArgs, limit)
	rows, err := db.QueryContext(ctx, fmt.Sprintf("SELECT %s %s ORDER BY cvss_score DESC NULLS LAST, updated_at DESC LIMIT $%d", CveCols, baseQ, len(dataArgs)), dataArgs...)
	if err != nil {
		return summary, err
	}
	defer rows.Close()
	for rows.Next() {
		var e models.CveEntry
		if err := ScanCveEntry(rows, &e); err != nil {
			return summary, err
		}
		e.MatchableAffected = cveEntryMatchableAffectedCount(e.AffectedProducts, e.Ecosystem)
		e.Matchable = e.MatchableAffected > 0
		e.ReferenceKeys = cveReferenceKeys(e)
		for _, refKey := range e.ReferenceKeys {
			summary.ReferenceKeys = appendUnique(summary.ReferenceKeys, refKey)
		}
		summary.Items = append(summary.Items, e)
	}
	return summary, rows.Err()
}

func (db *DB) cveReferenceGroupBuckets(ctx context.Context, expr, baseQ string, args []any) ([]CveReferenceGroupBucket, error) {
	rows, err := db.QueryContext(ctx, fmt.Sprintf(`SELECT %s AS name, count(*)
		%s
		GROUP BY name
		ORDER BY count(*) DESC, name
		LIMIT 20`, expr, baseQ), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CveReferenceGroupBucket{}
	for rows.Next() {
		var b CveReferenceGroupBucket
		if err := rows.Scan(&b.Name, &b.Count); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func cveReferenceKeys(e models.CveEntry) []string {
	keys := []string{}
	text := strings.Join([]string{e.VulnerabilityID, e.Title, e.Description, e.References, e.RawData}, "\n")
	addRegexKeys := func(prefix string, re *regexp.Regexp, upper bool) {
		for _, match := range re.FindAllString(text, -1) {
			match = strings.TrimSpace(match)
			if upper {
				match = strings.ToUpper(match)
			}
			keys = appendUnique(keys, prefix+match)
		}
	}
	addRegexKeys("cve:", cveReferenceKeyRe, true)
	addRegexKeys("ghsa:", ghsaReferenceKeyRe, false)
	addRegexKeys("rustsec:", rustsecReferenceKeyRe, true)
	addRegexKeys("pysec:", pysecReferenceKeyRe, true)
	addRegexKeys("go:", goReferenceKeyRe, true)
	addRegexKeys("debian:", debianAdvisoryKeyRe, true)
	if isDebianSecurityEntry(e) {
		keys = appendUnique(keys, "vendor:debian")
	}

	for _, raw := range referenceURLs(e.References) {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		host := strings.ToLower(strings.TrimPrefix(u.Host, "www."))
		path := strings.Trim(u.EscapedPath(), "/")
		parts := strings.Split(path, "/")
		if host == "github.com" && len(parts) >= 2 {
			owner := strings.ToLower(parts[0])
			repo := strings.ToLower(strings.TrimSuffix(parts[1], ".git"))
			if owner != "" && repo != "" {
				keys = appendUnique(keys, "repo:github.com/"+owner+"/"+repo)
			}
			continue
		}
		if strings.Contains(host, "debian.org") {
			keys = appendUnique(keys, "vendor:debian")
		} else if strings.Contains(host, "ubuntu.com") {
			keys = appendUnique(keys, "vendor:ubuntu")
		} else if strings.Contains(host, "redhat.com") {
			keys = appendUnique(keys, "vendor:redhat")
		}
	}
	return keys
}

func isDebianSecurityEntry(e models.CveEntry) bool {
	eco := strings.ToLower(strings.TrimSpace(e.Ecosystem))
	if eco == "debian" || strings.HasPrefix(eco, "debian:") {
		return true
	}
	vulnID := strings.ToUpper(strings.TrimSpace(e.VulnerabilityID))
	return strings.HasPrefix(vulnID, "DEBIAN-CVE-") || debianAdvisoryKeyRe.MatchString(vulnID)
}

func cveReferenceKeyFilter(referenceKey string) (string, []string) {
	key := strings.TrimSpace(referenceKey)
	if key == "" {
		return "", nil
	}
	lower := strings.ToLower(key)
	indexFilter := `EXISTS (SELECT 1 FROM cve_reference_keys crk WHERE crk.cve_id = id AND crk.reference_key = $%d)`
	switch {
	case strings.HasPrefix(lower, "cve:"):
		cve := strings.ToUpper(strings.TrimSpace(key[len("cve:"):]))
		if !cveReferenceKeyRe.MatchString(cve) {
			return "", nil
		}
		return indexFilter, []string{"cve:" + cve}
	case strings.HasPrefix(lower, "ghsa:"):
		ghsa := strings.TrimSpace(key[len("ghsa:"):])
		if !ghsaReferenceKeyRe.MatchString(ghsa) {
			return "", nil
		}
		return indexFilter, []string{"ghsa:" + ghsa}
	case strings.HasPrefix(lower, "rustsec:"):
		id := strings.ToUpper(strings.TrimSpace(key[len("rustsec:"):]))
		if !rustsecReferenceKeyRe.MatchString(id) {
			return "", nil
		}
		return indexFilter, []string{"rustsec:" + id}
	case strings.HasPrefix(lower, "pysec:"):
		id := strings.ToUpper(strings.TrimSpace(key[len("pysec:"):]))
		if !pysecReferenceKeyRe.MatchString(id) {
			return "", nil
		}
		return indexFilter, []string{"pysec:" + id}
	case strings.HasPrefix(lower, "go:"):
		id := strings.ToUpper(strings.TrimSpace(key[len("go:"):]))
		if !goReferenceKeyRe.MatchString(id) {
			return "", nil
		}
		return indexFilter, []string{"go:" + id}
	case strings.HasPrefix(lower, "debian:"):
		id := strings.ToUpper(strings.TrimSpace(key[len("debian:"):]))
		if !debianAdvisoryKeyRe.MatchString(id) {
			return "", nil
		}
		return indexFilter, []string{"debian:" + id}
	case strings.HasPrefix(lower, "repo:"):
		repo := strings.TrimSpace(strings.TrimPrefix(lower, "repo:"))
		if !strings.HasPrefix(repo, "github.com/") || strings.Count(repo, "/") < 2 {
			return "", nil
		}
		return indexFilter, []string{"repo:" + repo}
	case lower == "vendor:debian":
		return indexFilter, []string{"vendor:debian"}
	case lower == "vendor:ubuntu":
		return indexFilter, []string{"vendor:ubuntu"}
	case lower == "vendor:redhat":
		return indexFilter, []string{"vendor:redhat"}
	default:
		return "", nil
	}
}

func cveReferenceKeyWhere(referenceKey string, start int) (string, []any, bool) {
	filter, vals := cveReferenceKeyFilter(referenceKey)
	if filter == "" {
		return "", nil, false
	}
	args := make([]any, 0, len(vals))
	for _, val := range vals {
		args = append(args, val)
	}
	return fmt.Sprintf(filter, placeholderRange(start, len(args))...), args, true
}

func placeholderRange(start, count int) []any {
	out := make([]any, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, start+i)
	}
	return out
}

func referenceURLs(refs string) []string {
	type refEntry struct {
		URL string `json:"url"`
	}
	out := []string{}
	var entries []refEntry
	if refs != "" && json.Unmarshal([]byte(refs), &entries) == nil {
		for _, entry := range entries {
			if strings.TrimSpace(entry.URL) != "" {
				out = append(out, strings.TrimSpace(entry.URL))
			}
		}
		return out
	}
	if strings.TrimSpace(refs) != "" {
		out = append(out, strings.Fields(refs)...)
	}
	return out
}

func calcCvssScore(vector string) float64 {
	if vector == "" {
		return 0
	}
	prefix := ""
	if strings.HasPrefix(vector, "CVSS:") {
		idx := strings.Index(vector, "/")
		if idx <= 0 {
			return 0
		}
		prefix = vector[:idx+1]
		vector = vector[idx+1:]
	}

	parts := strings.Split(vector, "/")
	kv := make(map[string]string)
	for _, p := range parts {
		if sep := strings.Index(p, ":"); sep > 0 {
			kv[p[:sep]] = p[sep+1:]
		}
	}

	if strings.HasPrefix(prefix, "CVSS:4.0") {
		return calcCvss40(kv)
	}
	if strings.HasPrefix(prefix, "CVSS:3") {
		return calcCvss3x(kv)
	}
	if strings.HasPrefix(prefix, "CVSS:2") || kv["Au"] != "" {
		return calcCvss2(kv)
	}
	return 0
}

func calcCvss2(kv map[string]string) float64 {
	av := map[string]float64{"L": 0.395, "A": 0.646, "N": 1.0}
	ac := map[string]float64{"H": 0.35, "M": 0.61, "L": 0.71}
	au := map[string]float64{"M": 0.45, "S": 0.56, "N": 0.704}
	cia := map[string]float64{"N": 0.0, "P": 0.275, "C": 0.66}
	avVal, ok := av[kv["AV"]]
	if !ok {
		return 0
	}
	acVal, ok := ac[kv["AC"]]
	if !ok {
		return 0
	}
	auVal, ok := au[kv["Au"]]
	if !ok {
		return 0
	}
	cVal, ok := cia[kv["C"]]
	if !ok {
		return 0
	}
	iVal, ok := cia[kv["I"]]
	if !ok {
		return 0
	}
	aVal, ok := cia[kv["A"]]
	if !ok {
		return 0
	}
	impact := 10.41 * (1 - (1-cVal)*(1-iVal)*(1-aVal))
	exploit := 20 * avVal * acVal * auVal
	if impact == 0 {
		return 0
	}
	fImpact := 1.176
	return roundup1(((0.6 * impact) + (0.4 * exploit) - 1.5) * fImpact)
}

func calcCvss3x(kv map[string]string) float64 {
	avW := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	acW := map[string]float64{"L": 0.77, "H": 0.44}
	prWU := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	prWC := map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	uiW := map[string]float64{"N": 0.85, "R": 0.62}
	cW := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	iW := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	aW := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}

	scopeChanged := kv["S"] == "C"

	pr := prWU[kv["PR"]]
	if scopeChanged {
		pr = prWC[kv["PR"]]
	}

	iss := 1 - (1-cW[kv["C"]])*(1-iW[kv["I"]])*(1-aW[kv["A"]])
	if iss <= 0 {
		return 0
	}

	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = iss * 6.42
	}
	if impact <= 0 {
		return 0
	}

	exploitability := 8.22 * avW[kv["AV"]] * acW[kv["AC"]] * pr * uiW[kv["UI"]]

	var base float64
	if scopeChanged {
		base = math.Min(1.08*(impact+exploitability), 10)
	} else {
		base = math.Min(impact+exploitability, 10)
	}
	return math.Round(base*10) / 10
}

var cvss40Lookup = map[string]float64{
	// EQ1=0, EQ2=0
	"000000": 10, "000001": 9.9, "000010": 9.8, "000011": 9.5, "000020": 9.5, "000021": 9.2,
	"000100": 10, "000101": 9.6, "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1,
	"000200": 9.3, "000201": 9, "000210": 8.9, "000211": 8, "000220": 8.1, "000221": 6.8,
	"001000": 9.8, "001001": 9.5, "001010": 9.5, "001011": 9.2, "001020": 9, "001021": 8.4,
	"001100": 9.3, "001101": 9.2, "001110": 8.9, "001111": 8.1, "001120": 8.1, "001121": 6.5,
	"001200": 8.8, "001201": 8, "001210": 7.8, "001211": 7, "001220": 6.9, "001221": 4.8,
	"002001": 9.2, "002011": 8.2, "002021": 7.2,
	"002101": 7.9, "002111": 6.9, "002121": 5,
	"002201": 6.9, "002211": 5.5, "002221": 2.7,
	// EQ1=0, EQ2=1
	"010000": 9.9, "010001": 9.7, "010010": 9.5, "010011": 9.2, "010020": 9.2, "010021": 8.5,
	"010100": 9.5, "010101": 9.1, "010110": 9, "010111": 8.3, "010120": 8.4, "010121": 7.1,
	"010200": 9.2, "010201": 8.1, "010210": 8.2, "010211": 7.1, "010220": 7.2, "010221": 5.3,
	"011000": 9.5, "011001": 9.3, "011010": 9.2, "011011": 8.5, "011020": 8.5, "011021": 7.3,
	"011100": 9.2, "011101": 8.2, "011110": 8, "011111": 7.2, "011120": 7, "011121": 5.9,
	"011200": 8.4, "011201": 7, "011210": 7.1, "011211": 5.2, "011220": 5, "011221": 3,
	"012001": 8.6, "012011": 7.5, "012021": 5.2,
	"012101": 7.1, "012111": 5.2, "012121": 2.9,
	"012201": 6.3, "012211": 2.9, "012221": 1.7,
	// EQ1=1, EQ2=0
	"100000": 9.8, "100001": 9.5, "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1,
	"100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4, "100120": 7.7, "100121": 6.4,
	"100200": 8.7, "100201": 7.5, "100210": 7.4, "100211": 6.3, "100220": 6.3, "100221": 4.9,
	"101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7, "101020": 7.6, "101021": 6.7,
	"101100": 8.6, "101101": 7.6, "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5,
	"101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2, "101220": 5.2, "101221": 2.5,
	"102001": 8.3, "102011": 7, "102021": 5.4,
	"102101": 6.5, "102111": 5.8, "102121": 2.6,
	"102201": 5.3, "102211": 2.1, "102221": 1.3,
	// EQ1=1, EQ2=1
	"110000": 9.5, "110001": 9, "110010": 8.8, "110011": 7.6, "110020": 7.6, "110021": 7,
	"110100": 9, "110101": 7.7, "110110": 7.5, "110111": 6.2, "110120": 6.1, "110121": 5.3,
	"110200": 7.7, "110201": 6.6, "110210": 6.8, "110211": 5.9, "110220": 5.2, "110221": 3,
	"111000": 8.9, "111001": 7.8, "111010": 7.6, "111011": 6.7, "111020": 6.2, "111021": 5.8,
	"111100": 7.4, "111101": 5.9, "111110": 5.7, "111111": 5.7, "111120": 4.7, "111121": 2.3,
	"111200": 6.1, "111201": 5.2, "111210": 5.7, "111211": 2.9, "111220": 2.4, "111221": 1.6,
	"112001": 7.1, "112011": 5.9, "112021": 3,
	"112101": 5.8, "112111": 2.6, "112121": 1.5,
	"112201": 2.3, "112211": 1.3, "112221": 0.6,
	// EQ1=2, EQ2=0
	"200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2, "200020": 7.5, "200021": 5.8,
	"200100": 8.6, "200101": 7.4, "200110": 7.4, "200111": 6.1, "200120": 5.6, "200121": 3.4,
	"200200": 7, "200201": 5.4, "200210": 5.2, "200211": 4, "200220": 4, "200221": 2.2,
	"201000": 8.5, "201001": 7.5, "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1,
	"201100": 7.2, "201101": 5.7, "201110": 5.5, "201111": 4.1, "201120": 4.6, "201121": 1.9,
	"201200": 5.3, "201201": 3.6, "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8,
	"202001": 6.4, "202011": 5.1, "202021": 2,
	"202101": 4.7, "202111": 2.1, "202121": 1.1,
	"202201": 2.4, "202211": 0.9, "202221": 0.4,
	// EQ1=2, EQ2=1
	"210000": 8.8, "210001": 7.5, "210010": 7.3, "210011": 5.3, "210020": 6, "210021": 5,
	"210100": 7.3, "210101": 5.5, "210110": 5.9, "210111": 4, "210120": 4.1, "210121": 2,
	"210200": 5.4, "210201": 4.3, "210210": 4.5, "210211": 2.2, "210220": 2, "210221": 1.1,
	"211000": 7.5, "211001": 5.5, "211010": 5.8, "211011": 4.5, "211020": 4, "211021": 2.1,
	"211100": 6.1, "211101": 5.1, "211110": 4.8, "211111": 1.8, "211120": 2, "211121": 0.9,
	"211200": 4.6, "211201": 1.8, "211210": 1.7, "211211": 0.7, "211220": 0.8, "211221": 0.2,
	"212001": 5.3, "212011": 2.4, "212021": 1.4,
	"212101": 2.4, "212111": 1.2, "212121": 0.5,
	"212201": 1, "212211": 0.3, "212221": 0.1,
}

func calcCvss40(kv map[string]string) float64 {
	// EQ1: AV/PR/UI (Table 24)
	avN := kv["AV"] == "N"
	prN := kv["PR"] == "N"
	uiN := kv["UI"] == "N"
	var eq1 int
	if avN && prN && uiN {
		eq1 = 0
	} else if (avN && prN && (kv["UI"] == "A" || kv["UI"] == "P")) ||
		(avN && kv["PR"] == "L" && uiN) ||
		(kv["AV"] == "A" && prN && uiN) {
		eq1 = 1
	} else {
		eq1 = 2
	}

	// EQ2: AC/AT (Table 25)
	var eq2 int
	if kv["AC"] == "L" && kv["AT"] == "N" {
		eq2 = 0
	} else {
		eq2 = 1
	}

	// EQ3: VC/VI/VA (Table 26)
	var eq3 int
	if kv["VC"] == "H" || kv["VI"] == "H" || kv["VA"] == "H" {
		eq3 = 0
	} else if kv["VC"] == "L" || kv["VI"] == "L" || kv["VA"] == "L" {
		eq3 = 1
	} else {
		eq3 = 2
	}

	// EQ4: SC/SI/SA (Table 27)
	var eq4 int
	if kv["SC"] == "H" || kv["SI"] == "H" || kv["SA"] == "H" {
		eq4 = 0
	} else if kv["SC"] == "L" || kv["SI"] == "L" || kv["SA"] == "L" {
		eq4 = 1
	} else {
		eq4 = 2
	}

	// EQ5: E (Table 28)
	e := kv["E"]
	if e == "" {
		e = "X"
	}
	var eq5 int
	switch e {
	case "A":
		eq5 = 0
	case "P":
		eq5 = 1
	default: // U or X
		eq5 = 2
	}

	// EQ6: VC+CR / VI+IR / VA+AR (Table 29)
	// CR/IR/AR default to X (Not Defined), treated as H for EQ6
	cr := kv["CR"]
	if cr == "" {
		cr = "X"
	}
	ir := kv["IR"]
	if ir == "" {
		ir = "X"
	}
	ar := kv["AR"]
	if ar == "" {
		ar = "X"
	}
	eq6 := 1
	if (kv["VC"] == "H" && (cr == "H" || cr == "X")) ||
		(kv["VI"] == "H" && (ir == "H" || ir == "X")) ||
		(kv["VA"] == "H" && (ar == "H" || ar == "X")) {
		eq6 = 0
	}

	key := fmt.Sprintf("%d%d%d%d%d%d", eq1, eq2, eq3, eq4, eq5, eq6)
	if score, ok := cvss40Lookup[key]; ok {
		return score
	}
	return 0
}

func severityFromScore(score float64) string {
	if score >= 9.0 {
		return "CRITICAL"
	} else if score >= 7.0 {
		return "HIGH"
	} else if score >= 4.0 {
		return "MEDIUM"
	} else if score >= 0.1 {
		return "LOW"
	}
	return ""
}

func (db *DB) NormalizeVulnSeverity(ctx context.Context) (int, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE vulnerabilities
		SET severity = CASE
			WHEN cvss_score >= 9.0 THEN 'CRITICAL'
			WHEN cvss_score >= 7.0 THEN 'HIGH'
			WHEN cvss_score >= 4.0 THEN 'MEDIUM'
			WHEN cvss_score >= 0.1 THEN 'LOW'
			ELSE severity
		END
		WHERE cvss_score > 0 AND severity != CASE
			WHEN cvss_score >= 9.0 THEN 'CRITICAL'
			WHEN cvss_score >= 7.0 THEN 'HIGH'
			WHEN cvss_score >= 4.0 THEN 'MEDIUM'
			WHEN cvss_score >= 0.1 THEN 'LOW'
			ELSE ''
		END`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (db *DB) CalcCvssScores(ctx context.Context) (int, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, cvss_vector FROM cve_database WHERE cvss_vector LIKE 'CVSS:4%' OR (cvss_vector != '' AND cvss_score = 0)`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	type update struct {
		id       string
		score    float64
		severity string
	}
	var updates []update

	for rows.Next() {
		var id, vector string
		if err := rows.Scan(&id, &vector); err != nil {
			continue
		}
		score := calcCvssScore(vector)
		severity := severityFromScore(score)
		updates = append(updates, update{id: id, score: score, severity: severity})
	}

	if len(updates) == 0 {
		return 0, nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `UPDATE cve_database SET cvss_score=$1, severity=CASE WHEN $2 != '' THEN $2 ELSE severity END WHERE id=$3`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	for _, u := range updates {
		if _, err := stmt.ExecContext(ctx, u.score, u.severity, u.id); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(updates), nil
}

func (db *DB) GetCveSources(ctx context.Context) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT source FROM cve_database WHERE source != '' ORDER BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sources []string
	for rows.Next() {
		var s string
		rows.Scan(&s)
		sources = append(sources, s)
	}
	return sources, nil
}

type CveSourceStats struct {
	Source           string     `json:"source"`
	Count            int        `json:"count"`
	Matchable        int        `json:"matchable"`
	MatchablePercent float64    `json:"matchable_percent"`
	WithEcosystem    int        `json:"with_ecosystem"`
	WithFixed        int        `json:"with_fixed"`
	WithRanges       int        `json:"with_ranges"`
	WithCVSS         int        `json:"with_cvss"`
	LastUpdate       *time.Time `json:"last_update"`
}

type CveSourceFreshnessStats struct {
	Source     string     `json:"source"`
	Count      int        `json:"count"`
	LastUpdate *time.Time `json:"last_update"`
}

type CveReferenceGroupBucket struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type CveReferenceGroupSummary struct {
	Key           string                    `json:"key"`
	Total         int                       `json:"total"`
	Matchable     int                       `json:"matchable"`
	Sources       []CveReferenceGroupBucket `json:"sources"`
	Categories    []CveReferenceGroupBucket `json:"categories"`
	Ecosystems    []CveReferenceGroupBucket `json:"ecosystems"`
	SourceGroups  []CveReferenceGroupBucket `json:"source_groups"`
	ReferenceKeys []string                  `json:"reference_keys"`
	Items         []models.CveEntry         `json:"items"`
}

type CveAffectedPackageIndexStats struct {
	Count                   int        `json:"count"`
	SourceCount             int        `json:"source_count"`
	IndexedCVEs             int        `json:"indexed_cves"`
	MatchableCVEs           int        `json:"matchable_cves"`
	CoveragePercent         float64    `json:"coverage_percent"`
	MissingMatchableSources []string   `json:"missing_matchable_sources"`
	LastUpdate              *time.Time `json:"last_update"`
	LatestMatchableUpdate   *time.Time `json:"latest_matchable_update"`
	Stale                   bool       `json:"stale"`
	Orphans                 int        `json:"orphans"`
}

type CveReferenceKeyIndexStats struct {
	Count           int        `json:"count"`
	IndexedCVEs     int        `json:"indexed_cves"`
	TotalCVEs       int        `json:"total_cves"`
	CanonicalCVEs   int        `json:"canonical_cves"`
	VendorKeys      int        `json:"vendor_keys"`
	RepositoryKeys  int        `json:"repository_keys"`
	CoveragePercent float64    `json:"coverage_percent"`
	LastUpdate      *time.Time `json:"last_update"`
	LatestCVEUpdate *time.Time `json:"latest_cve_update"`
	Stale           bool       `json:"stale"`
	Orphans         int        `json:"orphans"`
}

type CveAffectedPackage struct {
	CveID           string    `json:"cve_id"`
	VulnerabilityID string    `json:"vulnerability_id"`
	Source          string    `json:"source"`
	PackageName     string    `json:"package_name"`
	Ecosystem       string    `json:"ecosystem"`
	FixedVersion    string    `json:"fixed_version"`
	AffectedProduct string    `json:"affected_product"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type CveEPSSMergeStats struct {
	EPSSRecords          int     `json:"epss_records"`
	EPSSCVEs             int     `json:"epss_cves"`
	MatchedCVEs          int     `json:"matched_cves"`
	UnmatchedCVEs        int     `json:"unmatched_cves"`
	EnrichedRecords      int     `json:"enriched_records"`
	EnrichedCVEs         int     `json:"enriched_cves"`
	EnrichedSourceCount  int     `json:"enriched_source_count"`
	MergeCoveragePercent float64 `json:"merge_coverage_percent"`
}

func (db *DB) GetCveAffectedPackageIndexStats(ctx context.Context) (*CveAffectedPackageIndexStats, error) {
	var stats CveAffectedPackageIndexStats
	matchablePredicate := cveSourceMatchablePredicateSQL("CASE WHEN jsonb_typeof(c.affected_products) = 'array' THEN c.affected_products ELSE '[]'::jsonb END", "c.ecosystem")
	err := db.QueryRowContext(ctx, fmt.Sprintf(`
WITH affected_index AS (
	SELECT
		count(*) AS count,
		count(DISTINCT source) FILTER (WHERE source != '') AS source_count,
		count(DISTINCT cve_id) AS indexed_cves,
		max(updated_at) AS last_update
	FROM cve_affected_packages
),
matchable_sources AS (
	SELECT
		c.source,
		count(*) AS matchable_cves,
		max(c.updated_at) AS latest_matchable_update
	FROM cve_database c
	WHERE c.source != ''
	  AND %s
	GROUP BY c.source
)
SELECT
	COALESCE(ai.count, 0),
	COALESCE(ai.source_count, 0),
	COALESCE(ai.indexed_cves, 0),
	COALESCE((SELECT sum(matchable_cves) FROM matchable_sources), 0),
	ai.last_update,
	(SELECT max(latest_matchable_update) FROM matchable_sources),
	(SELECT count(*) FROM cve_affected_packages cap WHERE NOT EXISTS (SELECT 1 FROM cve_database c WHERE c.id = cap.cve_id)),
	COALESCE((
		SELECT array_agg(ms.source ORDER BY ms.source)
		FROM matchable_sources ms
		WHERE NOT EXISTS (SELECT 1 FROM cve_affected_packages cap WHERE cap.source = ms.source)
	), ARRAY[]::text[])
FROM affected_index ai`, matchablePredicate)).Scan(
		&stats.Count, &stats.SourceCount, &stats.IndexedCVEs, &stats.MatchableCVEs, &stats.LastUpdate, &stats.LatestMatchableUpdate, &stats.Orphans, pq.Array(&stats.MissingMatchableSources))
	if err != nil {
		return nil, err
	}
	if stats.MatchableCVEs > 0 {
		stats.CoveragePercent = math.Round(float64(stats.IndexedCVEs)*1000/float64(stats.MatchableCVEs)) / 10
	}
	stats.Stale = stats.MatchableCVEs > 0 && (stats.LastUpdate == nil || stats.LatestMatchableUpdate == nil || stats.LastUpdate.Before(*stats.LatestMatchableUpdate))
	if stats.MissingMatchableSources == nil {
		stats.MissingMatchableSources = []string{}
	}
	return &stats, nil
}

func (db *DB) GetCveAffectedPackageIndexHealthStats(ctx context.Context) (map[string]any, error) {
	var count, sourceCount, indexedCVEs, orphans int
	var lastUpdate *time.Time
	err := db.QueryRowContext(ctx, `
SELECT
	(SELECT count(*) FROM cve_affected_packages),
	(SELECT count(DISTINCT source) FROM cve_affected_packages WHERE source != ''),
	(SELECT count(DISTINCT cve_id) FROM cve_affected_packages),
	(SELECT max(updated_at) FROM cve_affected_packages),
	(SELECT count(*) FROM cve_affected_packages cap WHERE NOT EXISTS (SELECT 1 FROM cve_database c WHERE c.id = cap.cve_id))`).Scan(
		&count, &sourceCount, &indexedCVEs, &lastUpdate, &orphans)
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"summary_mode": "indexed-only",
		"count":        count,
		"source_count": sourceCount,
		"indexed_cves": indexedCVEs,
		"orphans":      orphans,
	}
	if lastUpdate != nil {
		out["last_update"] = lastUpdate
	}
	return out, nil
}

func (db *DB) GetCveReferenceKeyIndexStats(ctx context.Context) (*CveReferenceKeyIndexStats, error) {
	var stats CveReferenceKeyIndexStats
	err := db.QueryRowContext(ctx, `
SELECT
	(SELECT count(*) FROM cve_reference_keys),
	(SELECT count(DISTINCT cve_id) FROM cve_reference_keys),
	(SELECT count(*) FROM cve_database),
	(SELECT count(DISTINCT cve_id) FROM cve_reference_keys WHERE reference_key LIKE 'cve:%'),
	(SELECT count(*) FROM cve_reference_keys WHERE reference_key LIKE 'vendor:%'),
	(SELECT count(*) FROM cve_reference_keys WHERE reference_key LIKE 'repo:%'),
	(SELECT max(updated_at) FROM cve_reference_keys),
	(SELECT max(updated_at) FROM cve_database),
	(SELECT count(*) FROM cve_reference_keys crk WHERE NOT EXISTS (SELECT 1 FROM cve_database c WHERE c.id = crk.cve_id))`).Scan(
		&stats.Count, &stats.IndexedCVEs, &stats.TotalCVEs, &stats.CanonicalCVEs, &stats.VendorKeys, &stats.RepositoryKeys,
		&stats.LastUpdate, &stats.LatestCVEUpdate, &stats.Orphans)
	if err != nil {
		return nil, err
	}
	if stats.TotalCVEs > 0 {
		stats.CoveragePercent = math.Round(float64(stats.IndexedCVEs)*1000/float64(stats.TotalCVEs)) / 10
	}
	stats.Stale = stats.TotalCVEs > 0 && (stats.LastUpdate == nil || stats.LatestCVEUpdate == nil || stats.LastUpdate.Before(*stats.LatestCVEUpdate))
	return &stats, nil
}

func (db *DB) ListCveAffectedPackages(ctx context.Context, cveID string, limit, offset int) ([]CveAffectedPackage, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	var total int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM cve_affected_packages WHERE cve_id=$1`, cveID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.QueryContext(ctx, `
SELECT cve_id, vulnerability_id, source, package_name, ecosystem, fixed_version, affected_product::text, updated_at
FROM cve_affected_packages
WHERE cve_id=$1
ORDER BY package_name, ecosystem, fixed_version
LIMIT $2 OFFSET $3`, cveID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []CveAffectedPackage{}
	for rows.Next() {
		var item CveAffectedPackage
		if err := rows.Scan(&item.CveID, &item.VulnerabilityID, &item.Source, &item.PackageName, &item.Ecosystem, &item.FixedVersion, &item.AffectedProduct, &item.UpdatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (db *DB) GetCveEPSSMergeStats(ctx context.Context) (*CveEPSSMergeStats, error) {
	var stats CveEPSSMergeStats
	err := db.QueryRowContext(ctx, `
WITH epss AS (
	SELECT DISTINCT vulnerability_id
	FROM cve_database
	WHERE source = 'epss'
	  AND vulnerability_id != ''
	  AND (epss_score > 0 OR epss_percentile > 0)
),
non_epss AS (
	SELECT vulnerability_id, source, epss_score, epss_percentile
	FROM cve_database
	WHERE source != 'epss'
	  AND vulnerability_id != ''
)
SELECT
	(SELECT count(*) FROM cve_database WHERE source = 'epss' AND (epss_score > 0 OR epss_percentile > 0)),
	(SELECT count(*) FROM epss),
	(SELECT count(*) FROM epss e WHERE EXISTS (SELECT 1 FROM non_epss n WHERE n.vulnerability_id = e.vulnerability_id)),
	(SELECT count(*) FROM epss e WHERE NOT EXISTS (SELECT 1 FROM non_epss n WHERE n.vulnerability_id = e.vulnerability_id)),
	(SELECT count(*) FROM non_epss WHERE epss_score > 0 OR epss_percentile > 0),
	(SELECT count(DISTINCT vulnerability_id) FROM non_epss WHERE epss_score > 0 OR epss_percentile > 0),
	(SELECT count(DISTINCT source) FROM non_epss WHERE epss_score > 0 OR epss_percentile > 0)`).Scan(
		&stats.EPSSRecords, &stats.EPSSCVEs, &stats.MatchedCVEs, &stats.UnmatchedCVEs,
		&stats.EnrichedRecords, &stats.EnrichedCVEs, &stats.EnrichedSourceCount)
	if err != nil {
		return nil, err
	}
	if stats.EPSSCVEs > 0 {
		stats.MergeCoveragePercent = math.Round(float64(stats.MatchedCVEs)*1000/float64(stats.EPSSCVEs)) / 10
	}
	return &stats, nil
}

func (db *DB) GetCveSourceStats(ctx context.Context) ([]CveSourceStats, error) {
	rows, err := db.QueryContext(ctx, fmt.Sprintf(`
WITH normalized AS (
	SELECT
		source,
		updated_at,
		COALESCE(category, '') AS category,
		COALESCE(ecosystem, '') AS ecosystem,
		cvss_score,
		COALESCE(cvss_vector, '') AS cvss_vector,
		CASE
			WHEN jsonb_typeof(affected_products) = 'array' THEN affected_products
			ELSE '[]'::jsonb
		END AS affected_products
	FROM cve_database
	WHERE source != ''
)
SELECT
	source,
	COUNT(*) AS count,
	COUNT(*) FILTER (
		WHERE %s
	) AS matchable,
	COUNT(*) FILTER (
		WHERE ecosystem != '' OR EXISTS (
			SELECT 1 FROM jsonb_array_elements(affected_products) ap
			WHERE COALESCE(ap->>'ecosystem', '') != ''
		)
	) AS with_ecosystem,
	COUNT(*) FILTER (
		WHERE EXISTS (SELECT 1 FROM jsonb_array_elements(affected_products) ap WHERE %s)
	) AS with_fixed,
	COUNT(*) FILTER (
		WHERE EXISTS (
			SELECT 1 FROM jsonb_array_elements(affected_products) ap
			WHERE jsonb_typeof(ap->'ranges') = 'array' AND jsonb_array_length(ap->'ranges') > 0
		)
	) AS with_ranges,
	COUNT(*) FILTER (WHERE cvss_score > 0 OR cvss_vector != '') AS with_cvss,
	MAX(updated_at) AS last_update
FROM normalized
GROUP BY source
ORDER BY source`, cveSourceMatchablePredicateSQL("affected_products", "ecosystem"), cveSourceFixedPredicateSQL()))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var stats []CveSourceStats
	for rows.Next() {
		var s CveSourceStats
		if err := rows.Scan(&s.Source, &s.Count, &s.Matchable, &s.WithEcosystem, &s.WithFixed, &s.WithRanges, &s.WithCVSS, &s.LastUpdate); err != nil {
			return nil, err
		}
		if s.Count > 0 {
			s.MatchablePercent = math.Round(float64(s.Matchable)*1000/float64(s.Count)) / 10
		}
		stats = append(stats, s)
	}
	return stats, nil
}

func (db *DB) GetCveSourceFreshnessStats(ctx context.Context) ([]CveSourceFreshnessStats, error) {
	rows, err := db.QueryContext(ctx, `
SELECT source, count(*) AS count, MAX(updated_at) AS last_update
FROM cve_database
WHERE source != ''
GROUP BY source
ORDER BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	stats := []CveSourceFreshnessStats{}
	for rows.Next() {
		var s CveSourceFreshnessStats
		if err := rows.Scan(&s.Source, &s.Count, &s.LastUpdate); err != nil {
			return nil, err
		}
		stats = append(stats, s)
	}
	return stats, rows.Err()
}

func (db *DB) GetSecurityDBRevision(ctx context.Context) (string, error) {
	rows, err := db.QueryContext(ctx, `
WITH indexed AS (
	SELECT source, count(DISTINCT cve_id) AS matchable
	FROM cve_affected_packages
	GROUP BY source
)
SELECT c.source, count(*) AS records, COALESCE(i.matchable, 0) AS matchable, MAX(c.updated_at) AS last_update
FROM cve_database c
LEFT JOIN indexed i ON i.source = c.source
WHERE c.source != ''
GROUP BY c.source, i.matchable
ORDER BY c.source`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	type revisionSource struct {
		source     string
		count      int
		matchable  int
		lastUpdate *time.Time
	}
	stats := []revisionSource{}
	for rows.Next() {
		var s revisionSource
		if err := rows.Scan(&s.source, &s.count, &s.matchable, &s.lastUpdate); err != nil {
			return "", err
		}
		stats = append(stats, s)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if len(stats) == 0 {
		return "empty", nil
	}
	h := sha256.New()
	for _, s := range stats {
		lastUpdate := ""
		if s.lastUpdate != nil {
			lastUpdate = s.lastUpdate.UTC().Format(time.RFC3339Nano)
		}
		fmt.Fprintf(h, "%s\t%d\t%d\t%s\n", s.source, s.count, s.matchable, lastUpdate)
	}
	return hex.EncodeToString(h.Sum(nil))[:16], nil
}

type RematchResult struct {
	Matched                 int                       `json:"matched"`
	NewVulns                int                       `json:"new_vulns"`
	Updated                 int                       `json:"updated"`
	Skipped                 int                       `json:"skipped"`
	ScannedCandidates       int                       `json:"scanned_candidates"`
	CandidateLimit          int                       `json:"candidate_limit"`
	Limited                 bool                      `json:"limited"`
	SecurityDBRevision      string                    `json:"security_db_revision,omitempty"`
	SecurityDBRevisionError string                    `json:"security_db_revision_error,omitempty"`
	EligibleSources         int                       `json:"eligible_sources,omitempty"`
	ExcludedSources         int                       `json:"excluded_sources,omitempty"`
	SourcePolicy            map[string]map[string]any `json:"source_policy,omitempty"`
}

type RematchOptions struct {
	Sources                   []string
	MinSourceMatchablePercent float64
	ScanID                    string
	CandidateLimit            int
}

const (
	DefaultRematchCandidateLimit = 50000
	MaxRematchCandidateLimit     = 1000000
)

func cveSourceFixedPredicateSQL() string {
	return `(jsonb_typeof(ap->'fixed') = 'array' AND jsonb_array_length(ap->'fixed') = 1 AND COALESCE(ap->'fixed'->>0, '') != '')
		OR jsonb_path_exists(ap, '$.ranges[*].events[*].fixed ? (@ != "")')`
}

func cveSourceMatchablePredicateSQL(affectedProductsExpr, ecosystemExpr string) string {
	return fmt.Sprintf(`EXISTS (
		SELECT 1
		FROM jsonb_array_elements(%s) ap
		WHERE COALESCE(ap->>'name', '') != ''
		  AND COALESCE(NULLIF(ap->>'ecosystem', ''), NULLIF(%s, '')) IS NOT NULL
		  AND (%s)
		)`, affectedProductsExpr, ecosystemExpr, cveSourceFixedPredicateSQL())
}

func cvePackageMatchablePredicateSQL(affectedProductsExpr, ecosystemExpr, packageNameExpr, packageEcosystemExpr string) string {
	effectiveEcosystem := normalizeEcosystemSQL(fmt.Sprintf("lower(COALESCE(NULLIF(ap->>'ecosystem', ''), NULLIF(%s, '')))", ecosystemExpr))
	packageEcosystem := normalizeEcosystemSQL(fmt.Sprintf("lower(%s)", packageEcosystemExpr))
	return fmt.Sprintf(`EXISTS (
		SELECT 1
		FROM jsonb_array_elements(%s) ap
		WHERE lower(COALESCE(ap->>'name', '')) = lower(%s)
		  AND COALESCE(NULLIF(ap->>'ecosystem', ''), NULLIF(%s, '')) IS NOT NULL
		  AND %s = %s
		  AND (%s)
	)`, affectedProductsExpr, packageNameExpr, ecosystemExpr, effectiveEcosystem, packageEcosystem, cveSourceFixedPredicateSQL())
}

func cveEntryHasMatchableAffectedProduct(affectedProducts, ecosystem string) bool {
	return cveEntryMatchableAffectedCount(affectedProducts, ecosystem) > 0
}

func cveEntryMatchableAffectedCount(affectedProducts, ecosystem string) int {
	var products []affectedProduct
	if affectedProducts == "" || json.Unmarshal([]byte(affectedProducts), &products) != nil {
		return 0
	}
	cveEco := normalizeEcosystem(ecosystem)
	count := 0
	for _, p := range products {
		if strings.TrimSpace(p.Name) == "" {
			continue
		}
		effectiveEco := normalizeEcosystem(p.Ecosystem)
		if effectiveEco == "" {
			effectiveEco = cveEco
		}
		if effectiveEco == "" {
			continue
		}
		if !hasSafeFixedEvidence(p) {
			continue
		}
		count++
	}
	return count
}

func (db *DB) RematchCVEs(ctx context.Context, opts RematchOptions) (*RematchResult, error) {
	if opts.CandidateLimit <= 0 {
		opts.CandidateLimit = DefaultRematchCandidateLimit
	}
	if opts.CandidateLimit > MaxRematchCandidateLimit {
		opts.CandidateLimit = MaxRematchCandidateLimit
	}
	args := []any{}
	filters := ""
	qualityCTE := ""
	qualityJoin := ""
	if len(opts.Sources) > 0 {
		args = append(args, pq.Array(opts.Sources))
		filters += fmt.Sprintf(" AND c.source = ANY($%d)", len(args))
	}
	if opts.MinSourceMatchablePercent > 0 {
		affectedProducts := `CASE WHEN jsonb_typeof(affected_products) = 'array' THEN affected_products ELSE '[]'::jsonb END`
		qualityCTE = fmt.Sprintf(`WITH source_quality AS (
			SELECT
				source,
				COUNT(*) AS total,
				COUNT(*) FILTER (
					WHERE %s
				) AS matchable
			FROM cve_database
			WHERE source != ''
			GROUP BY source
		)`, cveSourceMatchablePredicateSQL(affectedProducts, "ecosystem"))
		qualityJoin = "JOIN source_quality sq ON sq.source = c.source"
		args = append(args, opts.MinSourceMatchablePercent)
		filters += fmt.Sprintf(" AND (100.0 * sq.matchable / NULLIF(sq.total, 0)) >= $%d", len(args))
	}
	scanJoin := fmt.Sprintf("JOIN (%s) ls ON p.scan_id = ls.id", latestScansSub)
	if opts.ScanID != "" {
		args = append(args, opts.ScanID)
		filters += fmt.Sprintf(" AND p.scan_id = $%d", len(args))
		scanJoin = ""
	}
	rowLimit := opts.CandidateLimit * 100
	if rowLimit < opts.CandidateLimit+1 {
		rowLimit = opts.CandidateLimit + 1
	}
	if rowLimit > MaxRematchCandidateLimit+1 {
		rowLimit = MaxRematchCandidateLimit + 1
	}
	args = append(args, rowLimit)
	limitPlaceholder := fmt.Sprintf("$%d", len(args))

	query := fmt.Sprintf(`
		%s
		SELECT p.id, p.name, p.version, p.host_id, p.scan_id, p.container, p.file_path,
		       p.pkg_type, p.ecosystem,
		       c.vulnerability_id, c.severity, c.cvss_score, c.cvss_vector,
		       c.title, c.description, c.refs, c.category, c.ecosystem, c.affected_products
		FROM packages p
		%s
		JOIN cve_affected_packages cap
		  ON cap.package_name = lower(p.name)
		 AND cap.ecosystem = %s
		JOIN cve_database c ON c.id = cap.cve_id
		%s
		WHERE 1=1%s
		LIMIT %s
	`, qualityCTE, scanJoin, packageEcosystemSQL("p"), qualityJoin, filters, limitPlaceholder)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("match query: %w", err)
	}
	defer rows.Close()

	type match struct {
		pkgID, pkgName, version, hostID, scanID, container, filePath string
		pkgType, pkgEco                                              string
		vulnID, severity, title, description, refs                   string
		category, cveEco, affectedProducts                           string
		cvssScore                                                    float64
		cvssVector                                                   string
	}
	var matches []match

	for rows.Next() {
		var m match
		if err := rows.Scan(&m.pkgID, &m.pkgName, &m.version, &m.hostID, &m.scanID,
			&m.container, &m.filePath, &m.pkgType, &m.pkgEco,
			&m.vulnID, &m.severity, &m.cvssScore, &m.cvssVector,
			&m.title, &m.description, &m.refs, &m.category, &m.cveEco, &m.affectedProducts); err != nil {
			continue
		}
		matches = append(matches, m)
	}

	result := &RematchResult{ScannedCandidates: len(matches), CandidateLimit: opts.CandidateLimit}
	if len(matches) >= rowLimit {
		result.Limited = true
	}
	var newVulns []models.Vulnerability
	pending := map[string]int{}
	compatible := 0

	for _, m := range matches {
		affected, ok := compatibleSecurityCandidate(m.pkgName, m.pkgType, m.pkgEco, m.version, m.category, m.cveEco, m.affectedProducts)
		if !ok {
			result.Skipped++
			continue
		}
		compatible++
		if compatible > opts.CandidateLimit {
			result.Limited = true
			break
		}
		result.Matched++
		var exists bool
		if err := db.QueryRowContext(ctx,
			"SELECT EXISTS(SELECT 1 FROM vulnerabilities WHERE package_id=$1 AND vulnerability_id=$2 AND scan_id=$3)",
			m.pkgID, m.vulnID, m.scanID).Scan(&exists); err != nil || exists {
			result.Skipped++
			continue
		}

		primaryURL := ""
		var refList []struct {
			URL string `json:"url"`
		}
		if json.Unmarshal([]byte(m.refs), &refList) == nil {
			for _, r := range refList {
				if r.URL != "" {
					primaryURL = r.URL
					break
				}
			}
		}

		sev := m.severity
		if m.cvssScore >= 9.0 {
			sev = "CRITICAL"
		} else if m.cvssScore >= 7.0 {
			sev = "HIGH"
		} else if m.cvssScore >= 4.0 {
			sev = "MEDIUM"
		} else if m.cvssScore > 0 {
			sev = "LOW"
		}

		v := models.Vulnerability{
			ID: uuid.New().String(), PackageID: m.pkgID, ScanID: m.scanID, HostID: m.hostID,
			VulnerabilityID: m.vulnID, Severity: sev, Title: truncate(m.title, 500),
			Description: truncate(m.description, 2000), PkgName: m.pkgName, PkgPath: m.filePath,
			InstalledVer: m.version, FixedVersion: fixedVersions(affected)[0], CVSSScore: m.cvssScore, CVSSVector: m.cvssVector,
			PrimaryURL: primaryURL, Container: m.container, FindingSource: "cve-db",
		}
		key := rematchVulnerabilityKey(v)
		if idx, ok := pending[key]; ok {
			if betterRematchVulnerability(v, newVulns[idx]) {
				newVulns[idx] = v
			}
			result.Skipped++
			continue
		}
		pending[key] = len(newVulns)
		newVulns = append(newVulns, v)
	}

	if len(newVulns) > 0 {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()

		stmt, err := tx.PrepareContext(ctx, `INSERT INTO vulnerabilities
(id, package_id, scan_id, host_id, vulnerability_id, severity, title, description,
 pkg_name, pkg_path, installed_version, fixed_version, cvss_score, cvss_vector,
 primary_url, container, layer_id, finding_source, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,now())
ON CONFLICT (package_id, scan_id, vulnerability_id) DO NOTHING`)
		if err != nil {
			return nil, fmt.Errorf("prepare: %w", err)
		}
		defer stmt.Close()

		for _, v := range newVulns {
			res, err := stmt.ExecContext(ctx, v.ID, v.PackageID, v.ScanID, v.HostID,
				v.VulnerabilityID, v.Severity, v.Title, v.Description,
				v.PkgName, v.PkgPath, v.InstalledVer, v.FixedVersion,
				v.CVSSScore, v.CVSSVector, v.PrimaryURL, v.Container, "", v.FindingSource)
			if err != nil {
				continue
			}
			if affected, _ := res.RowsAffected(); affected > 0 {
				result.NewVulns++
			} else {
				result.Skipped++
			}
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func rematchVulnerabilityKey(v models.Vulnerability) string {
	return v.PackageID + "\x00" + v.ScanID + "\x00" + v.VulnerabilityID
}

func betterRematchVulnerability(candidate, current models.Vulnerability) bool {
	if candidate.CVSSScore != current.CVSSScore {
		return candidate.CVSSScore > current.CVSSScore
	}
	if severityRank(candidate.Severity) != severityRank(current.Severity) {
		return severityRank(candidate.Severity) > severityRank(current.Severity)
	}
	if (candidate.FixedVersion != "") != (current.FixedVersion != "") {
		return candidate.FixedVersion != ""
	}
	if (candidate.Title != "") != (current.Title != "") {
		return candidate.Title != ""
	}
	return candidate.PrimaryURL != "" && current.PrimaryURL == ""
}

func severityRank(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// CVSS 3.x base score calculator
func calcCVSS3BaseScore(vector string) float64 {
	parts := map[string]string{}
	for _, seg := range splitCVSS(vector) {
		kv := splitCVSSKV(seg)
		if len(kv) == 2 {
			parts[kv[0]] = kv[1]
		}
	}

	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	ac := map[string]float64{"L": 0.77, "H": 0.44}
	ui := map[string]float64{"N": 0.85, "R": 0.62}
	cia := map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}

	avVal, ok := av[parts["AV"]]
	if !ok {
		return 0
	}
	acVal, ok := ac[parts["AC"]]
	if !ok {
		return 0
	}
	uiVal, ok := ui[parts["UI"]]
	if !ok {
		return 0
	}
	cVal := cia[parts["C"]]
	iVal := cia[parts["I"]]
	aVal := cia[parts["A"]]

	scopeChanged := parts["S"] == "C"

	prVal := 0.0
	switch parts["PR"] {
	case "N":
		prVal = 0.85
	case "L":
		if scopeChanged {
			prVal = 0.68
		} else {
			prVal = 0.62
		}
	case "H":
		if scopeChanged {
			prVal = 0.50
		} else {
			prVal = 0.27
		}
	default:
		return 0
	}

	iss := 1 - ((1 - cVal) * (1 - iVal) * (1 - aVal))
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*pow15(iss-0.02)
	} else {
		impact = 6.42 * iss
	}

	if impact <= 0 {
		return 0
	}

	exploit := 8.22 * avVal * acVal * prVal * uiVal

	var base float64
	if scopeChanged {
		base = 1.08 * (impact + exploit)
	} else {
		base = impact + exploit
	}
	if base > 10 {
		base = 10
	}
	return roundup1(base)
}

func pow15(x float64) float64 { y := x * x; y = y * y; return y * y * x }

func roundup1(x float64) float64 { return float64(int(x*10+0.95)) / 10 }

func splitCVSS(v string) []string {
	var res []string
	for _, s := range stringsSplit(v, "/") {
		if len(s) >= 5 && s[:5] == "CVSS:" {
			continue
		}
		res = append(res, s)
	}
	return res
}

func splitCVSSKV(s string) []string {
	for i, c := range s {
		if c == ':' {
			return []string{s[:i], s[i+1:]}
		}
	}
	return nil
}

func stringsSplit(s, sep string) []string {
	var res []string
	for {
		i := indexOfStr(s, sep)
		if i < 0 {
			res = append(res, s)
			break
		}
		res = append(res, s[:i])
		s = s[i+len(sep):]
	}
	return res
}

func indexOfStr(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func (db *DB) RecalcCVSSFromVectors(ctx context.Context) (int, error) {
	return db.CalcCvssScores(ctx)
}
