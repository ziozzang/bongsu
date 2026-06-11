//go:build integration

package db

import (
	"context"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// TestRematchCPEIntegration seeds a real Postgres with a runtime package and
// NVD CPE advisories and asserts the version-gated matching outcome — the
// invariant the fake-driver tests cannot express: an in-range runtime version
// produces exactly one finding, while out-of-range and unbounded advisories
// produce none.
func TestRematchCPEIntegration(t *testing.T) {
	database := openIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	host := &models.Host{ID: "11111111222233334444555566667777", Hostname: "itest-host", OSName: "debian", LastSeen: time.Now()}
	if err := database.UpsertHost(ctx, host); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	scan := &models.Scan{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeffff0001", HostID: host.ID, ScanType: "manual", Status: "completed"}
	if err := database.CreateScan(ctx, scan); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	pkgs := []models.Package{{
		ID: "pkg-python-itest", ScanID: scan.ID, HostID: host.ID,
		Name: "python", Version: "3.11.4", PkgType: "runtime", Ecosystem: "python",
		Source: "native-runtime", FilePath: "/opt/py/bin/python3",
	}}
	if err := database.InsertPackages(ctx, pkgs); err != nil {
		t.Fatalf("seed package: %v", err)
	}

	entries := []models.CveEntry{
		{
			VulnerabilityID: "CVE-9000-0001", Source: "nvd", Severity: "HIGH", CVSSScore: 7.5,
			Description: "in-range: 3.11.0 <= v < 3.11.9",
			AffectedProducts: `[{"vendor":"python","product":"python","version_start_including":"3.11.0","version_end_excluding":"3.11.9"}]`,
			References:       `[]`, RawData: `{}`, Category: "general-cve",
		},
		{
			VulnerabilityID: "CVE-9000-0002", Source: "nvd", Severity: "HIGH", CVSSScore: 9.0,
			Description: "out-of-range: v < 3.10.0",
			AffectedProducts: `[{"vendor":"python","product":"python","version_end_excluding":"3.10.0"}]`,
			References:       `[]`, RawData: `{}`, Category: "general-cve",
		},
		{
			VulnerabilityID: "CVE-9000-0003", Source: "nvd", Severity: "CRITICAL", CVSSScore: 9.8,
			Description: "unbounded product entry must never match (FP guard)",
			AffectedProducts: `[{"vendor":"python","product":"python"}]`,
			References:       `[]`, RawData: `{}`, Category: "general-cve",
		},
	}
	if _, err := database.UpsertCveEntries(ctx, entries); err != nil {
		t.Fatalf("seed cve entries: %v", err)
	}

	result, err := database.RematchCPE(ctx, RematchOptions{ScanID: scan.ID})
	if err != nil {
		t.Fatalf("RematchCPE: %v", err)
	}
	if result.NewVulns != 1 {
		t.Fatalf("RematchCPE inserted %d findings, want exactly 1 (in-range only)", result.NewVulns)
	}

	rows, err := database.QueryContext(ctx,
		`SELECT vulnerability_id, fixed_version FROM vulnerabilities WHERE scan_id=$1 ORDER BY vulnerability_id`, scan.ID)
	if err != nil {
		t.Fatalf("query findings: %v", err)
	}
	defer rows.Close()
	var got []struct{ id, fixed string }
	for rows.Next() {
		var id, fixed string
		if err := rows.Scan(&id, &fixed); err != nil {
			t.Fatalf("scan row: %v", err)
		}
		got = append(got, struct{ id, fixed string }{id, fixed})
	}
	if len(got) != 1 || got[0].id != "CVE-9000-0001" {
		t.Fatalf("findings = %+v, want exactly CVE-9000-0001", got)
	}
	if got[0].fixed != "3.11.9" {
		t.Fatalf("fixed_version = %q, want 3.11.9 (the exclusive upper bound)", got[0].fixed)
	}

	// Idempotency: a second rematch must not duplicate the finding.
	again, err := database.RematchCPE(ctx, RematchOptions{ScanID: scan.ID})
	if err != nil {
		t.Fatalf("second RematchCPE: %v", err)
	}
	if again.NewVulns != 0 {
		t.Fatalf("second RematchCPE inserted %d findings, want 0 (idempotent)", again.NewVulns)
	}
}
