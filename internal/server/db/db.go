package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
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
	cveReferenceKeyRe         = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)
	ghsaReferenceKeyRe        = regexp.MustCompile(`(?i)\bGHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}\b`)
	rustsecReferenceKeyRe     = regexp.MustCompile(`(?i)\bRUSTSEC-\d{4}-\d{4,}\b`)
	pysecReferenceKeyRe       = regexp.MustCompile(`(?i)\bPYSEC-\d{4}-\d{1,}\b`)
	goReferenceKeyRe          = regexp.MustCompile(`(?i)\bGO-\d{4}-\d{4,}\b`)
	debianAdvisoryKeyRe       = regexp.MustCompile(`(?i)\bD(?:SA|LA)-\d{1,6}(?:-\d+)?\b`)
	malwareAdvisoryKeyRe      = regexp.MustCompile(`(?i)\bMAL-\d{4}-\d{1,}\b`)
	almaAdvisoryKeyRe         = regexp.MustCompile(`(?i)\bAL(?:BA|EA|SA)-\d{4}:\d{1,}\b`)
	suseAdvisoryKeyRe         = regexp.MustCompile(`(?i)\b(?:openSUSE|SUSE)-[A-Z]{2}-\d{4}:\d{1,}-\d+\b`)
	drupalAdvisoryKeyRe       = regexp.MustCompile(`(?i)\bDRUPAL-[A-Z]+-\d{4}-\d{3,}\b`)
	dtsaAdvisoryKeyRe         = regexp.MustCompile(`(?i)\bDTSA-\d{1,}-\d+\b`)
	osvAdvisoryKeyRe          = regexp.MustCompile(`(?i)\bOSV-\d{4}-\d{1,}\b`)
	gsdAdvisoryKeyRe          = regexp.MustCompile(`(?i)\bGSD-\d{4}-\d{1,}\b`)
	hashOnlyFixedVersionRe    = regexp.MustCompile(`(?i)^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$`)
	versionLikeFixedVersionRe = regexp.MustCompile(`[0-9]`)
	urlLikeFixedVersionRe     = regexp.MustCompile(`(?i)^(?:https?|git|ssh)://|^git\+|^pkg:|/`)
	branchLikeFixedVersionRe  = regexp.MustCompile(`(?i)^(?:main|master|trunk|head|latest|stable|unstable|develop|development)$`)
	githubRepoPartRe          = regexp.MustCompile(`^[a-z0-9_.-]+$`)
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

func defaultString(v, def string) string {
	if v == "" {
		return def
	}
	return v
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

func envString(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// quoteSQLLiteral wraps a string as a single-quoted SQL literal, doubling any
// embedded quotes. Used for the rare GUC value (work_mem) that cannot be passed
// as a bind parameter.
func quoteSQLLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

const latestScansSub = `(SELECT DISTINCT ON (host_id) id FROM scans WHERE status IN ('completed','degraded') ORDER BY host_id, created_at DESC)`
