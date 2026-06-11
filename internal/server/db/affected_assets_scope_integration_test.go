//go:build integration

package db

import (
	"context"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// TestAffectedAssetsForVulnerabilityScopeNilVsEmptyIntegration pins the
// RBAC-relevant scoping semantics of AffectedAssetsForVulnerability:
//
//   - hostIDs == nil          -> no scope filter; ALL hosts' rows returned.
//   - hostIDs == []string{}   -> scope filter applied with an empty array;
//     host_id = ANY('{}') matches nothing, so ZERO
//     rows are returned.
//
// The empty-but-non-nil slice is the "scoped to no hosts" case (e.g. a subject
// with read access to nothing): it must NOT leak every host's findings. This
// distinction is easy to regress if the code ever treats len==0 like nil.
func TestAffectedAssetsForVulnerabilityScopeNilVsEmptyIntegration(t *testing.T) {
	database := openIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const vulnID = "CVE-7788-0001"

	seedFinding := func(hostID, hostname, scanID, pkgID, vulnRowID string) {
		host := &models.Host{ID: hostID, Hostname: hostname, OSName: "debian", LastSeen: time.Now()}
		if err := database.UpsertHost(ctx, host); err != nil {
			t.Fatalf("seed host %s: %v", hostname, err)
		}
		scan := &models.Scan{ID: scanID, HostID: hostID, ScanType: "manual", Status: "completed"}
		if err := database.CreateScan(ctx, scan); err != nil {
			t.Fatalf("seed scan for %s: %v", hostname, err)
		}
		pkgs := []models.Package{{
			ID: pkgID, ScanID: scanID, HostID: hostID,
			Name: "openssl", Version: "3.0.0", PkgType: "debian", Ecosystem: "Debian",
			Source: "os", FilePath: "/usr/bin/openssl",
		}}
		if err := database.InsertPackages(ctx, pkgs); err != nil {
			t.Fatalf("seed package for %s: %v", hostname, err)
		}
		vulns := []models.Vulnerability{{
			ID: vulnRowID, PackageID: pkgID, ScanID: scanID, HostID: hostID,
			VulnerabilityID: vulnID, Severity: "HIGH", PkgName: "openssl",
			InstalledVer: "3.0.0", FixedVersion: "3.0.1", CVSSScore: 7.5,
			FindingSource: "scanner",
		}}
		if _, err := database.InsertVulnerabilities(ctx, vulns); err != nil {
			t.Fatalf("seed vuln for %s: %v", hostname, err)
		}
	}

	seedFinding("7788aaaa7788aaaa7788aaaa7788aaaa", "scope-host-a", "7788-scan-a-0000-000000000001", "scope-pkg-a", "scope-vuln-a")
	seedFinding("7788bbbb7788bbbb7788bbbb7788bbbb", "scope-host-b", "7788-scan-b-0000-000000000001", "scope-pkg-b", "scope-vuln-b")

	// nil scope -> all rows.
	all, err := database.AffectedAssetsForVulnerability(ctx, vulnID, nil, 100)
	if err != nil {
		t.Fatalf("AffectedAssetsForVulnerability (nil scope): %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("nil scope returned %d rows, want 2 (all hosts)", len(all))
	}

	// empty non-nil scope -> zero rows (host_id = ANY('{}') matches nothing).
	empty, err := database.AffectedAssetsForVulnerability(ctx, vulnID, []string{}, 100)
	if err != nil {
		t.Fatalf("AffectedAssetsForVulnerability (empty scope): %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("empty non-nil scope returned %d rows, want 0 (scoped to no hosts must not leak all rows)", len(empty))
	}
}
