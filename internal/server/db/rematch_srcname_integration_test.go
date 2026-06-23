//go:build integration

package db

import (
	"context"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// TestRematchCVEsMatchesBySourcePackage verifies the Debian/Ubuntu fix from the
// detailed scanning review: distro advisories are keyed by SOURCE package name,
// while the installed package is a BINARY built from it (e.g. libssl3 from
// openssl). RematchCVEs must match the binary against its source advisory via
// src_name; without src_name the binary name alone must not match.
func TestRematchCVEsMatchesBySourcePackage(t *testing.T) {
	database := openIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	host := &models.Host{ID: "5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c", Hostname: "src-host", OSName: "debian", LastSeen: time.Now()}
	if err := database.UpsertHost(ctx, host); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	scan := &models.Scan{ID: "5c5c-scan-0000-0000-000000000001", HostID: host.ID, ScanType: "manual", Status: "completed"}
	if err := database.CreateScan(ctx, scan); err != nil {
		t.Fatalf("seed scan: %v", err)
	}

	pkgs := []models.Package{
		// Binary package libssl3, built from source openssl, below the fix.
		{
			ID: "src-pkg-libssl3", ScanID: scan.ID, HostID: host.ID,
			Name: "libssl3", SrcName: "openssl", Version: "3.0.11-1",
			PkgType: "deb", Ecosystem: "debian", Source: "dpkg",
		},
		// A binary with no source name and a name the advisory doesn't list -> no match.
		{
			ID: "src-pkg-other", ScanID: scan.ID, HostID: host.ID,
			Name: "libfoo1", Version: "3.0.11-1",
			PkgType: "deb", Ecosystem: "debian", Source: "dpkg",
		},
	}
	if err := database.InsertPackages(ctx, pkgs); err != nil {
		t.Fatalf("seed packages: %v", err)
	}

	entries := []models.CveEntry{{
		VulnerabilityID: "CVE-9999-7777", Source: "osv", Severity: "HIGH", CVSSScore: 7.5,
		Ecosystem:        "Debian:12",
		Description:      "openssl source advisory",
		AffectedProducts: `[{"name":"openssl","ecosystem":"Debian:12","fixed":["3.0.14-1"]}]`,
		References:       `[]`, RawData: `{}`, Category: "os-package",
	}}
	if _, err := database.UpsertCveEntries(ctx, entries); err != nil {
		t.Fatalf("seed cve entries: %v", err)
	}

	result, err := database.RematchCVEs(ctx, RematchOptions{ScanID: scan.ID})
	if err != nil {
		t.Fatalf("RematchCVEs: %v", err)
	}
	if result.NewVulns != 1 {
		t.Fatalf("RematchCVEs created %d findings, want exactly 1 (libssl3 via source openssl)", result.NewVulns)
	}

	var pkgID string
	if err := database.QueryRowContext(ctx,
		`SELECT package_id FROM vulnerabilities WHERE scan_id=$1 AND vulnerability_id=$2`,
		scan.ID, "CVE-9999-7777").Scan(&pkgID); err != nil {
		t.Fatalf("read finding: %v", err)
	}
	if pkgID != "src-pkg-libssl3" {
		t.Fatalf("finding must attach to the installed binary libssl3, got %s", pkgID)
	}
}
