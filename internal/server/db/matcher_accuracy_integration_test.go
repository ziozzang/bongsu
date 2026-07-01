//go:build integration

package db

import (
	"context"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

func countFindings(t *testing.T, database *DB, ctx context.Context, scanID, vulnID string) int {
	t.Helper()
	var n int
	if err := database.QueryRowContext(ctx,
		`SELECT count(*) FROM vulnerabilities WHERE scan_id=$1 AND vulnerability_id=$2`, scanID, vulnID).Scan(&n); err != nil {
		t.Fatalf("count findings: %v", err)
	}
	return n
}

// TestRematchCVEsWithdrawn verifies an OSV advisory marked `withdrawn` is
// excluded from matching (no new finding), while an otherwise-identical active
// advisory still matches — and that re-importing an active finding's advisory as
// withdrawn makes the existing finding stale (triage-safe cleanup path).
func TestRematchCVEsWithdrawn(t *testing.T) {
	database := openIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	host := &models.Host{ID: "acc11111acc11111acc11111acc11111", Hostname: "acc-host", OSName: "debian", LastSeen: time.Now()}
	if err := database.UpsertHost(ctx, host); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	scan := &models.Scan{ID: "acc1-scan-0000-0000-000000000001", HostID: host.ID, ScanType: "manual", Status: "completed"}
	if err := database.CreateScan(ctx, scan); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	pkgs := []models.Package{
		{ID: "acc-pkg-active", ScanID: scan.ID, HostID: host.ID, Name: "left-pad", Version: "1.0.0", PkgType: "npm", Ecosystem: "npm", Source: "lockfile", FilePath: "/app/a"},
		{ID: "acc-pkg-wd", ScanID: scan.ID, HostID: host.ID, Name: "right-pad", Version: "1.0.0", PkgType: "npm", Ecosystem: "npm", Source: "lockfile", FilePath: "/app/b"},
	}
	if err := database.InsertPackages(ctx, pkgs); err != nil {
		t.Fatalf("seed packages: %v", err)
	}

	withdrawnAt := time.Now().Add(-24 * time.Hour)
	entries := []models.CveEntry{
		{VulnerabilityID: "CVE-ACC-ACTIVE", Source: "osv", Severity: "HIGH", CVSSScore: 7.5, Ecosystem: "npm",
			AffectedProducts: `[{"name":"left-pad","ecosystem":"npm","fixed":["1.1.0"]}]`, References: `[]`, RawData: `{}`, Category: "code-library"},
		{VulnerabilityID: "CVE-ACC-WITHDRAWN", Source: "osv", Severity: "HIGH", CVSSScore: 7.5, Ecosystem: "npm", Withdrawn: &withdrawnAt,
			AffectedProducts: `[{"name":"right-pad","ecosystem":"npm","fixed":["1.1.0"]}]`, References: `[]`, RawData: `{}`, Category: "code-library"},
	}
	if _, err := database.UpsertCveEntries(ctx, entries); err != nil {
		t.Fatalf("seed cve entries: %v", err)
	}

	if _, err := database.RematchCVEs(ctx, RematchOptions{ScanID: scan.ID}); err != nil {
		t.Fatalf("RematchCVEs: %v", err)
	}
	if got := countFindings(t, database, ctx, scan.ID, "CVE-ACC-ACTIVE"); got != 1 {
		t.Fatalf("active advisory should match: got %d findings, want 1", got)
	}
	if got := countFindings(t, database, ctx, scan.ID, "CVE-ACC-WITHDRAWN"); got != 0 {
		t.Fatalf("withdrawn advisory must NOT match: got %d findings, want 0", got)
	}

	// Now retract the active advisory (re-import with withdrawn set) and confirm
	// the existing finding is cleaned up as stale.
	entries[0].Withdrawn = &withdrawnAt
	if _, err := database.UpsertCveEntries(ctx, entries[:1]); err != nil {
		t.Fatalf("re-import withdrawn: %v", err)
	}
	if _, err := database.RemoveStaleRematchedVulnerabilities(ctx); err != nil {
		t.Fatalf("stale cleanup: %v", err)
	}
	if got := countFindings(t, database, ctx, scan.ID, "CVE-ACC-ACTIVE"); got != 0 {
		t.Fatalf("retracted advisory's finding must be pruned as stale: got %d, want 0", got)
	}
}

// TestRematchCPEVulnerableFalse verifies the NVD per-CPE `vulnerable:false` flag
// is honored: a runtime whose only matching CPE node is vulnerable:false gets no
// finding, while a true/absent node still matches.
func TestRematchCPEVulnerableFalse(t *testing.T) {
	database := openIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	host := &models.Host{ID: "acc22222acc22222acc22222acc22222", Hostname: "acc-cpe-host", OSName: "debian", LastSeen: time.Now()}
	if err := database.UpsertHost(ctx, host); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	scan := &models.Scan{ID: "acc2-scan-0000-0000-000000000001", HostID: host.ID, ScanType: "manual", Status: "completed"}
	if err := database.CreateScan(ctx, scan); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	pkgs := []models.Package{
		{ID: "acc-rt-py", ScanID: scan.ID, HostID: host.ID, Name: "python", Version: "3.9.5", PkgType: "runtime", Ecosystem: "python", Source: "runtime", FilePath: "/usr/bin/python3"},
		{ID: "acc-rt-node", ScanID: scan.ID, HostID: host.ID, Name: "node", Version: "18.16.0", PkgType: "runtime", Ecosystem: "nodejs", Source: "runtime", FilePath: "/usr/bin/node"},
	}
	if err := database.InsertPackages(ctx, pkgs); err != nil {
		t.Fatalf("seed packages: %v", err)
	}

	entries := []models.CveEntry{
		{VulnerabilityID: "CVE-CPE-FALSE", Source: "nvd", Severity: "HIGH", CVSSScore: 7.5,
			AffectedProducts: `[{"vendor":"python","product":"python","version_start_including":"3.9.0","version_end_excluding":"3.9.17","vulnerable":false}]`,
			References:       `[]`, RawData: `{}`},
		{VulnerabilityID: "CVE-CPE-TRUE", Source: "nvd", Severity: "HIGH", CVSSScore: 7.5,
			AffectedProducts: `[{"vendor":"nodejs","product":"node.js","version":"18.16.0","vulnerable":true}]`,
			References:       `[]`, RawData: `{}`},
	}
	if _, err := database.UpsertCveEntries(ctx, entries); err != nil {
		t.Fatalf("seed cve entries: %v", err)
	}

	if _, err := database.RematchCPE(ctx, RematchOptions{ScanID: scan.ID}); err != nil {
		t.Fatalf("RematchCPE: %v", err)
	}
	if got := countFindings(t, database, ctx, scan.ID, "CVE-CPE-FALSE"); got != 0 {
		t.Fatalf("vulnerable:false CPE must NOT match: got %d findings, want 0", got)
	}
	if got := countFindings(t, database, ctx, scan.ID, "CVE-CPE-TRUE"); got != 1 {
		t.Fatalf("vulnerable:true CPE must match: got %d findings, want 1", got)
	}
}
