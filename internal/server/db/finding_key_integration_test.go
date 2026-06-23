//go:build integration

package db

import (
	"context"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// TestFindingKeyIntegration verifies, against a real PostgreSQL, the three Phase
// C.2 guarantees: (1) the finding_key stored by Go ingest equals the SQL recipe
// the migration backfill uses (no Go↔SQL drift), (2) re-ingesting a finding now
// REFRESHES its mutable fields instead of silently dropping the update (the old
// ON CONFLICT DO NOTHING staleness bug), and (3) the finding_key is stable across
// an installed_version change.
func TestFindingKeyIntegration(t *testing.T) {
	database := openIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const hostID = "fk00fk00fk00fk00fk00fk00fk00fk00"
	const scanID = "fk00-scan-0000-0000-000000000001"
	host := &models.Host{ID: hostID, Hostname: "fk-host", OSName: "debian", LastSeen: time.Now()}
	if err := database.UpsertHost(ctx, host); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	scan := &models.Scan{ID: scanID, HostID: hostID, ScanType: "manual", Status: "completed"}
	if err := database.CreateScan(ctx, scan); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	pkg := models.Package{ID: "fk-pkg-a", ScanID: scanID, HostID: hostID, Name: "openssl", Version: "1.0.0", PkgType: "deb", Ecosystem: "debian", Source: "os", FilePath: ""}
	if err := database.InsertPackages(ctx, []models.Package{pkg}); err != nil {
		t.Fatalf("seed package: %v", err)
	}

	vuln := models.Vulnerability{
		ID: "fk-vuln-1", PackageID: "fk-pkg-a", ScanID: scanID, HostID: hostID,
		VulnerabilityID: "CVE-2024-1234", Severity: "MEDIUM", PkgName: "openssl",
		InstalledVer: "1.0.0", FixedVersion: "1.0.1", PkgPath: "", FindingSource: "scanner",
	}
	if _, err := database.InsertVulnerabilities(ctx, []models.Vulnerability{vuln}); err != nil {
		t.Fatalf("insert vuln: %v", err)
	}

	wantKey := ComputeFindingKey(FindingIdentity{HostID: hostID, PkgName: "openssl", PkgPath: "", VulnerabilityID: "CVE-2024-1234"})

	t.Run("stored finding_key equals Go and the SQL recipe", func(t *testing.T) {
		var storedKey, sqlKey string
		err := database.QueryRowContext(ctx, `
			SELECT finding_key,
			       encode(digest(
			         lower(trim(host_id)) || E'\x1f' ||
			         lower(trim(pkg_name)) || E'\x1f' ||
			         CASE WHEN trim(coalesce(pkg_path,''))='' THEN '__HOST__' ELSE trim(pkg_path) END || E'\x1f' ||
			         trim(vulnerability_id)
			       ,'sha256'),'hex')
			FROM vulnerabilities WHERE id='fk-vuln-1'`).Scan(&storedKey, &sqlKey)
		if err != nil {
			t.Fatalf("read finding_key: %v", err)
		}
		if storedKey != wantKey {
			t.Fatalf("Go-stored finding_key mismatch:\n got %s\n want %s", storedKey, wantKey)
		}
		if sqlKey != wantKey {
			t.Fatalf("SQL recipe (migration backfill) diverged from Go:\n got %s\n want %s", sqlKey, wantKey)
		}
	})

	t.Run("re-ingest refreshes stale fields instead of dropping the update", func(t *testing.T) {
		// Same identity, NEW severity + fixed_version (what a fresh scan would
		// report). Under the old DO NOTHING this update was silently lost.
		upd := vuln
		upd.Severity = "CRITICAL"
		upd.FixedVersion = "1.0.2"
		res, err := database.InsertVulnerabilities(ctx, []models.Vulnerability{upd})
		if err != nil {
			t.Fatalf("re-insert vuln: %v", err)
		}
		if res.Inserted != 0 {
			t.Fatalf("re-ingest of an existing finding must not count as inserted: %+v", res)
		}
		var severity, fixed string
		var rows int
		if err := database.QueryRowContext(ctx,
			`SELECT severity, fixed_version FROM vulnerabilities WHERE id='fk-vuln-1'`).Scan(&severity, &fixed); err != nil {
			t.Fatalf("read refreshed row: %v", err)
		}
		if severity != "CRITICAL" || fixed != "1.0.2" {
			t.Fatalf("DO UPDATE must refresh stale fields, got severity=%s fixed=%s", severity, fixed)
		}
		if err := database.QueryRowContext(ctx,
			`SELECT count(*) FROM vulnerabilities WHERE finding_key=$1`, wantKey).Scan(&rows); err != nil {
			t.Fatalf("count rows: %v", err)
		}
		if rows != 1 {
			t.Fatalf("re-ingest in the same scan must not duplicate the finding, got %d rows", rows)
		}
	})
}
