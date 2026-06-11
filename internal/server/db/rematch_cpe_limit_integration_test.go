//go:build integration

package db

import (
	"context"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// TestRematchCPECandidateCapIntegration guards the RematchCPE flood guard: a
// single runtime package paired with two in-range NVD CPE advisories under
// opts.CandidateLimit=1 must produce at most one new finding and set
// Limited==true. The CPE matcher caps on result.Matched >= CandidateLimit, so
// one over-broad NVD product cannot bury a scan in findings.
func TestRematchCPECandidateCapIntegration(t *testing.T) {
	database := openIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	host := &models.Host{ID: "99998888777766665555444433332222", Hostname: "cpe-cap-host", OSName: "debian", LastSeen: time.Now()}
	if err := database.UpsertHost(ctx, host); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	scan := &models.Scan{ID: "9999-scan-0000-0000-000000000001", HostID: host.ID, ScanType: "manual", Status: "completed"}
	if err := database.CreateScan(ctx, scan); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	pkgs := []models.Package{{
		ID: "pkg-python-cap", ScanID: scan.ID, HostID: host.ID,
		Name: "python", Version: "3.11.4", PkgType: "runtime", Ecosystem: "python",
		Source: "native-runtime", FilePath: "/opt/py/bin/python3",
	}}
	if err := database.InsertPackages(ctx, pkgs); err != nil {
		t.Fatalf("seed package: %v", err)
	}

	// Two distinct advisories, both with 3.11.4 inside their range => two
	// compatible candidates for the single runtime package.
	entries := []models.CveEntry{
		{VulnerabilityID: "CVE-9100-0001", Source: "nvd", Severity: "HIGH", CVSSScore: 7.5, Description: "in-range A", AffectedProducts: `[{"vendor":"python","product":"python","version_start_including":"3.11.0","version_end_excluding":"3.11.9"}]`, References: `[]`, RawData: `{}`, Category: "general-cve"},
		{VulnerabilityID: "CVE-9100-0002", Source: "nvd", Severity: "HIGH", CVSSScore: 8.0, Description: "in-range B", AffectedProducts: `[{"vendor":"python","product":"python","version_start_including":"3.11.0","version_end_excluding":"3.12.0"}]`, References: `[]`, RawData: `{}`, Category: "general-cve"},
	}
	if _, err := database.UpsertCveEntries(ctx, entries); err != nil {
		t.Fatalf("seed cve entries: %v", err)
	}

	result, err := database.RematchCPE(ctx, RematchOptions{ScanID: scan.ID, CandidateLimit: 1})
	if err != nil {
		t.Fatalf("RematchCPE: %v", err)
	}
	if result.NewVulns != 1 {
		t.Fatalf("RematchCPE inserted %d findings, want at most 1 under CandidateLimit=1", result.NewVulns)
	}
	if !result.Limited {
		t.Fatalf("result.Limited = false, want true (the cap was hit with two in-range advisories)")
	}

	var stored int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM vulnerabilities WHERE scan_id=$1`, scan.ID).Scan(&stored); err != nil {
		t.Fatalf("count findings: %v", err)
	}
	if stored != 1 {
		t.Fatalf("stored findings = %d, want exactly 1 (cap enforced)", stored)
	}
}
