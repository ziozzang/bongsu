//go:build integration

package db

import (
	"context"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// seedRematchHostScan creates a host + completed scan for the rematch limit/dedup
// tests and returns the scan ID.
func seedRematchHostScan(t *testing.T, ctx context.Context, database *DB, hostID, scanID string) {
	t.Helper()
	host := &models.Host{ID: hostID, Hostname: "limit-dedup-host", OSName: "debian", LastSeen: time.Now()}
	if err := database.UpsertHost(ctx, host); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	scan := &models.Scan{ID: scanID, HostID: hostID, ScanType: "manual", Status: "completed"}
	if err := database.CreateScan(ctx, scan); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
}

// TestRematchCVEsCandidateLimitIntegration pins the flood guard: with
// opts.CandidateLimit=1 and three independent compatible (package, CVE) pairs,
// the rematch must stop after the first compatible candidate — exactly one
// finding inserted and Limited==true. Raising the limit above the match count
// inserts all three with Limited==false. This guards against one over-broad
// advisory set burying a scan in findings, while confirming the limit is not
// applied when it isn't needed.
func TestRematchCVEsCandidateLimitIntegration(t *testing.T) {
	database := openIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const hostID = "eeee4444eeee4444eeee4444eeee4444"
	const scanID = "eeee-scan-0000-0000-000000000001"
	seedRematchHostScan(t, ctx, database, hostID, scanID)

	// Three distinct npm packages, each below the single fixed version of its
	// own advisory => three independent compatible (package, CVE) pairs.
	pkgs := []models.Package{
		{ID: "limit-pkg-a", ScanID: scanID, HostID: hostID, Name: "alpha-lib", Version: "1.0.0", PkgType: "npm", Ecosystem: "npm", Source: "lockfile", FilePath: "/app/package-lock.json"},
		{ID: "limit-pkg-b", ScanID: scanID, HostID: hostID, Name: "beta-lib", Version: "1.0.0", PkgType: "npm", Ecosystem: "npm", Source: "lockfile", FilePath: "/app/package-lock.json"},
		{ID: "limit-pkg-c", ScanID: scanID, HostID: hostID, Name: "gamma-lib", Version: "1.0.0", PkgType: "npm", Ecosystem: "npm", Source: "lockfile", FilePath: "/app/package-lock.json"},
	}
	if err := database.InsertPackages(ctx, pkgs); err != nil {
		t.Fatalf("seed packages: %v", err)
	}

	entries := []models.CveEntry{
		{VulnerabilityID: "CVE-9991-0001", Source: "osv", Severity: "HIGH", CVSSScore: 7.5, Ecosystem: "npm", Description: "alpha", AffectedProducts: `[{"name":"alpha-lib","ecosystem":"npm","fixed":["1.1.0"]}]`, References: `[]`, RawData: `{}`, Category: "code-library"},
		{VulnerabilityID: "CVE-9991-0002", Source: "osv", Severity: "HIGH", CVSSScore: 7.5, Ecosystem: "npm", Description: "beta", AffectedProducts: `[{"name":"beta-lib","ecosystem":"npm","fixed":["1.1.0"]}]`, References: `[]`, RawData: `{}`, Category: "code-library"},
		{VulnerabilityID: "CVE-9991-0003", Source: "osv", Severity: "HIGH", CVSSScore: 7.5, Ecosystem: "npm", Description: "gamma", AffectedProducts: `[{"name":"gamma-lib","ecosystem":"npm","fixed":["1.1.0"]}]`, References: `[]`, RawData: `{}`, Category: "code-library"},
	}
	if _, err := database.UpsertCveEntries(ctx, entries); err != nil {
		t.Fatalf("seed cve entries: %v", err)
	}

	// CandidateLimit=1: the loop breaks once the second compatible candidate is
	// seen, so only one finding is inserted and the result is flagged Limited.
	limited, err := database.RematchCVEs(ctx, RematchOptions{ScanID: scanID, CandidateLimit: 1})
	if err != nil {
		t.Fatalf("RematchCVEs (limit=1): %v", err)
	}
	if limited.NewVulns != 1 {
		t.Fatalf("limit=1 inserted %d findings, want exactly 1", limited.NewVulns)
	}
	if !limited.Limited {
		t.Fatalf("limit=1 result.Limited = false, want true (the cap was hit)")
	}
	var stored int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM vulnerabilities WHERE scan_id=$1`, scanID).Scan(&stored); err != nil {
		t.Fatalf("count findings: %v", err)
	}
	if stored != 1 {
		t.Fatalf("stored findings = %d, want 1 (cap enforced in the DB)", stored)
	}

	// Reset findings and rerun with a limit larger than the match count: all
	// three insert and Limited must be false.
	if _, err := database.ExecContext(ctx, `DELETE FROM vulnerabilities WHERE scan_id=$1`, scanID); err != nil {
		t.Fatalf("reset findings: %v", err)
	}
	all, err := database.RematchCVEs(ctx, RematchOptions{ScanID: scanID, CandidateLimit: 10})
	if err != nil {
		t.Fatalf("RematchCVEs (limit=10): %v", err)
	}
	if all.NewVulns != 3 {
		t.Fatalf("limit=10 inserted %d findings, want 3 (all matches)", all.NewVulns)
	}
	if all.Limited {
		t.Fatalf("limit=10 result.Limited = true, want false (limit not reached)")
	}
}

// TestRematchCVEsDedupPicksBetterCandidateIntegration exercises the dedup branch
// in RematchCVEs: two cve_database rows that share the SAME vulnerability_id but
// differ by source (the unique key is (vulnerability_id, source)) both index into
// cve_affected_packages and both match the same package. The match loop therefore
// produces two candidates with the same dedup key
// (package_id, scan_id, vulnerability_id) but different severity/CVSS/fixed
// metadata. betterRematchVulnerability ranks by CVSS first, so the higher-CVSS
// candidate must win regardless of which match row was seen first, and exactly
// one row is stored.
func TestRematchCVEsDedupPicksBetterCandidateIntegration(t *testing.T) {
	database := openIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const hostID = "ffff5555ffff5555ffff5555ffff5555"
	const scanID = "ffff-scan-0000-0000-000000000001"
	const vulnID = "CVE-9992-0001"
	seedRematchHostScan(t, ctx, database, hostID, scanID)

	pkgs := []models.Package{{
		ID: "dedup-pkg", ScanID: scanID, HostID: hostID,
		Name: "dup-lib", Version: "1.0.0", PkgType: "npm", Ecosystem: "npm",
		Source: "lockfile", FilePath: "/app/package-lock.json",
	}}
	if err := database.InsertPackages(ctx, pkgs); err != nil {
		t.Fatalf("seed package: %v", err)
	}

	// Same vulnerability_id, two sources. The "ghsa" row carries the higher CVSS
	// (9.8 -> CRITICAL) and a distinct fixed version; it is the better candidate.
	// The "osv" row is lower (5.0 -> MEDIUM). Both name dup-lib@npm and the
	// installed 1.0.0 sits below each fixed version, so both are compatible.
	entries := []models.CveEntry{
		{VulnerabilityID: vulnID, Source: "osv", Severity: "MEDIUM", CVSSScore: 5.0, Ecosystem: "npm", Title: "low row", Description: "lower-severity duplicate", AffectedProducts: `[{"name":"dup-lib","ecosystem":"npm","fixed":["1.0.1"]}]`, References: `[]`, RawData: `{}`, Category: "code-library"},
		{VulnerabilityID: vulnID, Source: "ghsa", Severity: "CRITICAL", CVSSScore: 9.8, Ecosystem: "npm", Title: "high row", Description: "higher-severity duplicate", AffectedProducts: `[{"name":"dup-lib","ecosystem":"npm","fixed":["1.2.0"]}]`, References: `[]`, RawData: `{}`, Category: "code-library"},
	}
	if _, err := database.UpsertCveEntries(ctx, entries); err != nil {
		t.Fatalf("seed cve entries: %v", err)
	}

	// Sanity: both sources indexed into cve_affected_packages so the match loop
	// genuinely sees the duplicate. If this is 1, the dedup branch is not exercised.
	var capRows int
	if err := database.QueryRowContext(ctx,
		`SELECT count(*) FROM cve_affected_packages WHERE vulnerability_id=$1 AND package_name='dup-lib'`, vulnID).Scan(&capRows); err != nil {
		t.Fatalf("count cve_affected_packages: %v", err)
	}
	if capRows != 2 {
		t.Fatalf("cve_affected_packages rows for the duplicate = %d, want 2 (both sources indexed; dedup branch not exercised otherwise)", capRows)
	}

	result, err := database.RematchCVEs(ctx, RematchOptions{ScanID: scanID})
	if err != nil {
		t.Fatalf("RematchCVEs: %v", err)
	}
	if result.NewVulns != 1 {
		t.Fatalf("inserted %d findings, want exactly 1 (deduped on package+scan+vulnerability_id)", result.NewVulns)
	}

	rows, err := database.QueryContext(ctx,
		`SELECT severity, cvss_score, fixed_version, title FROM vulnerabilities WHERE scan_id=$1 AND vulnerability_id=$2`, scanID, vulnID)
	if err != nil {
		t.Fatalf("query finding: %v", err)
	}
	defer rows.Close()
	var got []struct {
		sev, fixed, title string
		cvss              float64
	}
	for rows.Next() {
		var r struct {
			sev, fixed, title string
			cvss              float64
		}
		if err := rows.Scan(&r.sev, &r.cvss, &r.fixed, &r.title); err != nil {
			t.Fatalf("scan row: %v", err)
		}
		got = append(got, r)
	}
	if len(got) != 1 {
		t.Fatalf("stored findings = %+v, want exactly one (deduped)", got)
	}
	f := got[0]
	// betterRematchVulnerability ranks CVSS first: the 9.8 candidate must win.
	if f.cvss != 9.8 {
		t.Fatalf("stored cvss_score = %v, want 9.8 (the better/higher candidate)", f.cvss)
	}
	if f.sev != "CRITICAL" {
		t.Fatalf("stored severity = %q, want CRITICAL (recomputed from the better CVSS)", f.sev)
	}
	if f.fixed != "1.2.0" {
		t.Fatalf("stored fixed_version = %q, want 1.2.0 (from the better candidate)", f.fixed)
	}
	if f.title != "high row" {
		t.Fatalf("stored title = %q, want \"high row\" (from the better candidate)", f.title)
	}
}
