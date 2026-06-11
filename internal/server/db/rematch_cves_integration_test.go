//go:build integration

package db

import (
	"context"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// TestRematchCVEsIntegration seeds an OSV-style cve_database row (with an
// affected_products entry carrying an ecosystem + single fixed version, which
// UpsertCveEntries indexes into cve_affected_packages) plus a matching package
// in that ecosystem, and asserts RematchCVEs(ScanID) creates the finding. A
// second package in the wrong ecosystem must NOT produce a finding — the
// ecosystem gate is the false-positive guard for name-collision advisories.
func TestRematchCVEsIntegration(t *testing.T) {
	database := openIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	host := &models.Host{ID: "dddd3333dddd3333dddd3333dddd3333", Hostname: "rematch-host", OSName: "debian", LastSeen: time.Now()}
	if err := database.UpsertHost(ctx, host); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	scan := &models.Scan{ID: "dddd-scan-0000-0000-000000000001", HostID: host.ID, ScanType: "manual", Status: "completed"}
	if err := database.CreateScan(ctx, scan); err != nil {
		t.Fatalf("seed scan: %v", err)
	}

	// A matching npm package below the fix, and a same-name PyPI package that
	// must not be flagged by the npm advisory.
	pkgs := []models.Package{
		{
			ID: "rematch-pkg-npm", ScanID: scan.ID, HostID: host.ID,
			Name: "left-pad", Version: "1.0.0", PkgType: "npm", Ecosystem: "npm",
			Source: "lockfile", FilePath: "/app/package-lock.json",
		},
		{
			ID: "rematch-pkg-pypi", ScanID: scan.ID, HostID: host.ID,
			Name: "left-pad", Version: "1.0.0", PkgType: "python-pkg", Ecosystem: "PyPI",
			Source: "lockfile", FilePath: "/app/requirements.txt",
		},
	}
	if err := database.InsertPackages(ctx, pkgs); err != nil {
		t.Fatalf("seed packages: %v", err)
	}

	entries := []models.CveEntry{{
		VulnerabilityID: "CVE-9999-0001", Source: "osv", Severity: "HIGH", CVSSScore: 7.5,
		Ecosystem:        "npm",
		Description:      "npm advisory with single fixed version",
		AffectedProducts: `[{"name":"left-pad","ecosystem":"npm","fixed":["1.1.0"]}]`,
		References:       `[]`, RawData: `{}`, Category: "code-library",
	}}
	if _, err := database.UpsertCveEntries(ctx, entries); err != nil {
		t.Fatalf("seed cve entries: %v", err)
	}

	result, err := database.RematchCVEs(ctx, RematchOptions{ScanID: scan.ID})
	if err != nil {
		t.Fatalf("RematchCVEs: %v", err)
	}
	if result.NewVulns != 1 {
		t.Fatalf("RematchCVEs created %d findings, want exactly 1 (npm match only)", result.NewVulns)
	}

	rows, err := database.QueryContext(ctx,
		`SELECT vulnerability_id, package_id, fixed_version, finding_source FROM vulnerabilities WHERE scan_id=$1`, scan.ID)
	if err != nil {
		t.Fatalf("query findings: %v", err)
	}
	defer rows.Close()
	var got []struct{ vulnID, pkgID, fixed, source string }
	for rows.Next() {
		var r struct{ vulnID, pkgID, fixed, source string }
		if err := rows.Scan(&r.vulnID, &r.pkgID, &r.fixed, &r.source); err != nil {
			t.Fatalf("scan row: %v", err)
		}
		got = append(got, r)
	}
	if len(got) != 1 {
		t.Fatalf("findings = %+v, want exactly one", got)
	}
	f := got[0]
	if f.vulnID != "CVE-9999-0001" {
		t.Fatalf("finding vulnerability_id = %q, want CVE-9999-0001", f.vulnID)
	}
	if f.pkgID != "rematch-pkg-npm" {
		t.Fatalf("finding matched package %q, want the npm package (not the PyPI same-name package)", f.pkgID)
	}
	if f.fixed != "1.1.0" {
		t.Fatalf("finding fixed_version = %q, want 1.1.0", f.fixed)
	}
	if f.source != "cve-db" {
		t.Fatalf("finding finding_source = %q, want cve-db", f.source)
	}
}
