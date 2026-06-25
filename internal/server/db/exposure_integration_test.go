//go:build integration

package db

import (
	"context"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// TestNormalizePkgNameMatchesSQL asserts the Go normalizePkgName and the SQL
// bongsu_normalize_pkg_name function (migration 071) agree — they MUST, or the
// exposure match silently misses.
func TestNormalizePkgNameMatchesSQL(t *testing.T) {
	database := openIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cases := []struct{ eco, name string }{
		{"pypi", "Pillow"}, {"pypi", "ruamel.yaml"}, {"pypi", "Zope_Interface"},
		{"npm", "@Angular/Core"}, {"maven", "com.x:Art"}, {"go", "Ex.com/Foo"}, {"rubygems", "Rails"},
	}
	for _, c := range cases {
		var sqlOut string
		if err := database.QueryRowContext(ctx, `SELECT bongsu_normalize_pkg_name($1,$2)`, c.eco, c.name).Scan(&sqlOut); err != nil {
			t.Fatalf("sql normalize(%q,%q): %v", c.eco, c.name, err)
		}
		if goOut := normalizePkgName(c.eco, c.name); goOut != sqlOut {
			t.Errorf("normalize(%q,%q): Go=%q SQL=%q (must agree)", c.eco, c.name, goOut, sqlOut)
		}
	}
}

// TestExposureCatalogMatch covers upload (flatten + normalize), exact match,
// normalization-aware match, and the negative case.
func TestExposureCatalogMatch(t *testing.T) {
	database := openIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	host := &models.Host{ID: "8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f", Hostname: "expo-host", OSName: "ubuntu", LastSeen: time.Now()}
	if err := database.UpsertHost(ctx, host); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	scan := &models.Scan{ID: "8f8f-scan-0000-0000-000000000001", HostID: host.ID, ScanType: "manual", Status: "running"}
	if err := database.CreateScan(ctx, scan); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	pkgs := []models.Package{
		{ID: "expo-pkg-lodash", ScanID: scan.ID, HostID: host.ID, Name: "lodash", Version: "4.17.21", PkgType: "node-pkg", Ecosystem: "npm", Source: "native-lang"},
		{ID: "expo-pkg-pillow", ScanID: scan.ID, HostID: host.ID, Name: "Pillow", Version: "9.0.0", PkgType: "python-pkg", Ecosystem: "PyPI", Source: "native-lang"},
		{ID: "expo-pkg-safe", ScanID: scan.ID, HostID: host.ID, Name: "express", Version: "4.18.2", PkgType: "node-pkg", Ecosystem: "npm", Source: "native-lang"},
	}
	if err := database.InsertPackages(ctx, pkgs); err != nil {
		t.Fatalf("seed packages: %v", err)
	}

	// Catalog: lodash@4.17.21 (exact), pillow@9.0.0 (normalization: Pillow->pillow),
	// express@4.18.1 (wrong version -> must NOT match).
	cat := `{"schema_version":"0.1.0","entries":[
	  {"id":"MAL-X-1","name":"lodash poisoned","ecosystem":"npm","package":"lodash","versions":["4.17.21"],"severity":"critical"},
	  {"id":"MAL-X-2","name":"pillow poisoned","ecosystem":"PyPI","package":"pillow","versions":["9.0.0"],"severity":"critical"},
	  {"id":"MAL-X-3","name":"express other","ecosystem":"npm","package":"express","versions":["4.18.1"],"severity":"critical"}
	]}`
	_, entries, err := ParseBumblebeeCatalog([]byte(cat))
	if err != nil {
		t.Fatalf("parse catalog: %v", err)
	}
	stored, err := database.UpsertExposureCatalog(ctx, "test-campaign", "Test Campaign", "tester", "0.1.0", []byte(cat), entries)
	if err != nil {
		t.Fatalf("upsert catalog: %v", err)
	}
	if stored != 3 {
		t.Fatalf("stored entries = %d, want 3", stored)
	}

	created, err := database.MatchExposureCatalog(ctx, scan.ID, host.ID)
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if created != 2 {
		t.Fatalf("exposure matches = %d, want 2 (lodash exact + Pillow normalized; express wrong-version excluded)", created)
	}

	// Verify the findings: critical, exposure-catalog source, catalog_id set.
	var sev, src, catalogID string
	if err := database.QueryRowContext(ctx,
		`SELECT severity, finding_source, catalog_id FROM vulnerabilities WHERE scan_id=$1 AND package_id=$2`,
		scan.ID, "expo-pkg-lodash").Scan(&sev, &src, &catalogID); err != nil {
		t.Fatalf("read lodash finding: %v", err)
	}
	if sev != "CRITICAL" || src != "exposure-catalog" || catalogID != "MAL-X-1" {
		t.Fatalf("lodash finding wrong: sev=%s src=%s catalog=%s", sev, src, catalogID)
	}

	// Idempotent: a second match creates no new findings.
	again, err := database.MatchExposureCatalog(ctx, scan.ID, host.ID)
	if err != nil {
		t.Fatalf("re-match: %v", err)
	}
	if again != 0 {
		t.Fatalf("re-match must be idempotent, created %d", again)
	}

	// Atomic re-upload replaces entries (no accumulation).
	stored2, err := database.UpsertExposureCatalog(ctx, "test-campaign", "Test Campaign", "tester", "0.1.0", []byte(cat), entries)
	if err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	if stored2 != 3 {
		t.Fatalf("re-upsert stored = %d, want 3", stored2)
	}
	var srcCount int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM exposure_catalog_sources WHERE source_name='test-campaign'`).Scan(&srcCount); err != nil {
		t.Fatalf("count sources: %v", err)
	}
	if srcCount != 1 {
		t.Fatalf("re-upload must replace, got %d source rows", srcCount)
	}
}
