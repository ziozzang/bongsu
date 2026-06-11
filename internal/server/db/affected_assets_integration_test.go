//go:build integration

package db

import (
	"context"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// TestAffectedAssetsForVulnerabilityIntegration seeds two hosts that both carry
// a finding for the same CVE and asserts the CVE→assets reverse lookup:
//   - hostIDs=nil returns both occurrences,
//   - scoping to one host ID returns exactly that one,
//   - production hosts sort ahead of non-production,
//   - the limit caps the result set.
func TestAffectedAssetsForVulnerabilityIntegration(t *testing.T) {
	database := openIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const vulnID = "CVE-7777-0001"

	// hostA is staging, hostB is production. Production must sort first.
	hostA := &models.Host{ID: "aaaa0000aaaa0000aaaa0000aaaa0000", Hostname: "staging-web", OSName: "debian", Environment: "staging", LastSeen: time.Now()}
	hostB := &models.Host{ID: "bbbb1111bbbb1111bbbb1111bbbb1111", Hostname: "prod-web", OSName: "debian", Environment: "production", LastSeen: time.Now()}
	for _, h := range []*models.Host{hostA, hostB} {
		if err := database.UpsertHost(ctx, h); err != nil {
			t.Fatalf("seed host %s: %v", h.Hostname, err)
		}
		// UpsertHost does not persist environment/owner/team; set it explicitly
		// so the production-first ordering can be exercised.
		if err := database.UpdateHostMetadata(ctx, h.ID, "", "", h.Environment, "", ""); err != nil {
			t.Fatalf("set host metadata %s: %v", h.Hostname, err)
		}
	}

	seedFinding := func(host *models.Host, scanID, pkgID, vulnRowID string, cvss float64) {
		scan := &models.Scan{ID: scanID, HostID: host.ID, ScanType: "manual", Status: "completed"}
		if err := database.CreateScan(ctx, scan); err != nil {
			t.Fatalf("seed scan for %s: %v", host.Hostname, err)
		}
		pkgs := []models.Package{{
			ID: pkgID, ScanID: scanID, HostID: host.ID,
			Name: "openssl", Version: "3.0.0", PkgType: "debian", Ecosystem: "Debian",
			Source: "os", FilePath: "/usr/bin/openssl",
		}}
		if err := database.InsertPackages(ctx, pkgs); err != nil {
			t.Fatalf("seed package for %s: %v", host.Hostname, err)
		}
		vulns := []models.Vulnerability{{
			ID: vulnRowID, PackageID: pkgID, ScanID: scanID, HostID: host.ID,
			VulnerabilityID: vulnID, Severity: "HIGH", PkgName: "openssl",
			InstalledVer: "3.0.0", FixedVersion: "3.0.1", CVSSScore: cvss,
			FindingSource: "scanner",
		}}
		if _, err := database.InsertVulnerabilities(ctx, vulns); err != nil {
			t.Fatalf("seed vuln for %s: %v", host.Hostname, err)
		}
	}

	seedFinding(hostA, "aaaa-scan-0000-0000-000000000001", "pkg-a-openssl", "vuln-a-0001", 7.5)
	seedFinding(hostB, "bbbb-scan-0000-0000-000000000001", "pkg-b-openssl", "vuln-b-0001", 9.1)

	// nil scope returns both, production first.
	all, err := database.AffectedAssetsForVulnerability(ctx, vulnID, nil, 100)
	if err != nil {
		t.Fatalf("AffectedAssetsForVulnerability (all): %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("got %d affected assets, want 2", len(all))
	}
	if all[0].HostID != hostB.ID {
		t.Fatalf("first asset host = %q (env %q), want production host %q first", all[0].HostID, all[0].Environment, hostB.ID)
	}
	if all[0].Environment != "production" {
		t.Fatalf("first asset environment = %q, want production", all[0].Environment)
	}

	// Scope to staging host only -> exactly one row.
	scoped, err := database.AffectedAssetsForVulnerability(ctx, vulnID, []string{hostA.ID}, 100)
	if err != nil {
		t.Fatalf("AffectedAssetsForVulnerability (scoped): %v", err)
	}
	if len(scoped) != 1 || scoped[0].HostID != hostA.ID {
		t.Fatalf("scoped result = %+v, want exactly hostA", scoped)
	}

	// Limit caps the result set.
	limited, err := database.AffectedAssetsForVulnerability(ctx, vulnID, nil, 1)
	if err != nil {
		t.Fatalf("AffectedAssetsForVulnerability (limit): %v", err)
	}
	if len(limited) != 1 {
		t.Fatalf("limited result len = %d, want 1", len(limited))
	}
	if limited[0].HostID != hostB.ID {
		t.Fatalf("limit=1 returned host %q, want production host %q (sorted first)", limited[0].HostID, hostB.ID)
	}
}
