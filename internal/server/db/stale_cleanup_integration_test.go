//go:build integration

package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// TestRemoveStaleRematchedVulnerabilitiesIntegration seeds a mix of cve-db
// findings — some still backed by a matching CVE row, some referencing a CVE
// that no longer matches the package — across more than one keyset page (batch
// size forced to 5) and asserts that cleanup removes exactly the stale findings
// while the scan walked every page (Scanned covers all rows).
func TestRemoveStaleRematchedVulnerabilitiesIntegration(t *testing.T) {
	t.Setenv("BONGSU_STALE_REMATCH_CLEANUP_BATCH_SIZE", "5")

	database := openIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	host := &models.Host{ID: "cccc2222cccc2222cccc2222cccc2222", Hostname: "stale-host", OSName: "debian", LastSeen: time.Now()}
	if err := database.UpsertHost(ctx, host); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	scan := &models.Scan{ID: "cccc-scan-0000-0000-000000000001", HostID: host.ID, ScanType: "manual", Status: "completed"}
	if err := database.CreateScan(ctx, scan); err != nil {
		t.Fatalf("seed scan: %v", err)
	}

	// The matching CVE: a code-library (npm) advisory with a single safe fixed
	// version. A finding whose package + installed version sit below the fix and
	// whose CVE row resolves here stays "compatible" and is NOT removed.
	matchVulnID := "CVE-8888-MATCH"
	entries := []models.CveEntry{{
		VulnerabilityID: matchVulnID, Source: "osv", Severity: "HIGH", CVSSScore: 7.5,
		Ecosystem:        "npm",
		Description:      "matching npm advisory",
		AffectedProducts: `[{"name":"left-pad","ecosystem":"npm","fixed":["1.1.0"]}]`,
		References:       `[]`, RawData: `{}`, Category: "code-library",
	}}
	if _, err := database.UpsertCveEntries(ctx, entries); err != nil {
		t.Fatalf("seed cve entry: %v", err)
	}

	// Seed 12 findings: indices 0,3,6,9 are "kept" (reference matchVulnID with a
	// compatible package), the rest are "stale" (reference a CVE row that does
	// not exist, so the LEFT JOIN yields empty advisory data -> incompatible).
	const total = 12
	keptIDs := map[string]bool{}
	staleIDs := map[string]bool{}
	for i := 0; i < total; i++ {
		pkgID := fmt.Sprintf("stale-pkg-%02d", i)
		vulnRowID := fmt.Sprintf("stale-vuln-%02d", i)
		kept := i%3 == 0
		var vulnID string
		var pkgName, eco, installed string
		if kept {
			vulnID = matchVulnID
			pkgName, eco, installed = "left-pad", "npm", "1.0.0"
			keptIDs[vulnRowID] = true
		} else {
			vulnID = fmt.Sprintf("CVE-8888-GONE-%02d", i)
			pkgName, eco, installed = "left-pad", "npm", "1.0.0"
			staleIDs[vulnRowID] = true
		}
		pkgs := []models.Package{{
			ID: pkgID, ScanID: scan.ID, HostID: host.ID,
			Name: pkgName, Version: installed, PkgType: "npm", Ecosystem: eco,
			Source: "lockfile", FilePath: "/app/package-lock.json",
		}}
		if err := database.InsertPackages(ctx, pkgs); err != nil {
			t.Fatalf("seed package %d: %v", i, err)
		}
		vulns := []models.Vulnerability{{
			ID: vulnRowID, PackageID: pkgID, ScanID: scan.ID, HostID: host.ID,
			VulnerabilityID: vulnID, Severity: "HIGH", PkgName: pkgName,
			InstalledVer: installed, FixedVersion: "1.1.0", CVSSScore: 7.5,
			Ecosystem: eco, FindingSource: "cve-db",
		}}
		if _, err := database.InsertVulnerabilities(ctx, vulns); err != nil {
			t.Fatalf("seed vuln %d: %v", i, err)
		}
	}

	result, err := database.RemoveStaleRematchedVulnerabilities(ctx)
	if err != nil {
		t.Fatalf("RemoveStaleRematchedVulnerabilities: %v", err)
	}

	if result.BatchSize != 5 {
		t.Fatalf("batch size = %d, want 5 (from env)", result.BatchSize)
	}
	// Keyset pagination must walk every cve-db finding across all pages.
	if result.Scanned != total {
		t.Fatalf("scanned = %d, want %d (all cve-db findings across pages)", result.Scanned, total)
	}
	// 12 rows at batch size 5 => pages of 5, 5, 2.
	if result.Batches != 3 {
		t.Fatalf("batches = %d, want 3 (5+5+2)", result.Batches)
	}
	if result.Removed != len(staleIDs) {
		t.Fatalf("removed = %d, want %d (the stale findings only)", result.Removed, len(staleIDs))
	}

	// Verify the exact survivors: every kept finding remains, every stale one is gone.
	rows, err := database.QueryContext(ctx, `SELECT id FROM vulnerabilities WHERE finding_source='cve-db'`)
	if err != nil {
		t.Fatalf("query survivors: %v", err)
	}
	defer rows.Close()
	survivors := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan survivor: %v", err)
		}
		survivors[id] = true
	}
	if len(survivors) != len(keptIDs) {
		t.Fatalf("survivors = %d, want %d kept findings", len(survivors), len(keptIDs))
	}
	for id := range keptIDs {
		if !survivors[id] {
			t.Fatalf("kept finding %s was wrongly removed", id)
		}
	}
	for id := range staleIDs {
		if survivors[id] {
			t.Fatalf("stale finding %s was not removed", id)
		}
	}
}
