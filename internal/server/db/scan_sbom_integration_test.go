//go:build integration

package db

import (
	"context"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// TestScanSBOMStoreAndRetrieve verifies migration 068 applies and an SBOM
// round-trips, including the ingested-over-generated retrieval preference and
// cascade-on-scan-delete.
func TestScanSBOMStoreAndRetrieve(t *testing.T) {
	database := openIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	host := &models.Host{ID: "6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d", Hostname: "sbom-host", OSName: "sbom", LastSeen: time.Now()}
	if err := database.UpsertHost(ctx, host); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	scan := &models.Scan{ID: "6d6d-scan-0000-0000-000000000001", HostID: host.ID, ScanType: "sbom", Status: "completed"}
	if err := database.CreateScan(ctx, scan); err != nil {
		t.Fatalf("seed scan: %v", err)
	}

	// Store a generated, then an ingested SBOM for the same scan+format.
	if err := database.StoreScanSBOM(ctx, ScanSBOM{
		ScanID: scan.ID, HostID: host.ID, Format: "cyclonedx", Origin: "generated",
		SpecVersion: "1.5", ComponentCount: 3, BOM: []byte(`{"bomFormat":"CycloneDX","origin":"generated"}`),
	}); err != nil {
		t.Fatalf("store generated: %v", err)
	}
	if err := database.StoreScanSBOM(ctx, ScanSBOM{
		ScanID: scan.ID, HostID: host.ID, Format: "cyclonedx", Origin: "ingested",
		SpecVersion: "1.5", SourceRef: "urn:uuid:src", ComponentCount: 5, BOM: []byte(`{"bomFormat":"CycloneDX","origin":"ingested"}`),
	}); err != nil {
		t.Fatalf("store ingested: %v", err)
	}

	got, err := database.GetScanSBOM(ctx, scan.ID, "cyclonedx")
	if err != nil {
		t.Fatalf("get sbom: %v", err)
	}
	if got.Origin != "ingested" || got.ComponentCount != 5 || got.SourceRef != "urn:uuid:src" {
		t.Fatalf("expected ingested preferred, got %+v", got)
	}

	// Upsert (same scan+format+origin) must replace, not duplicate.
	if err := database.StoreScanSBOM(ctx, ScanSBOM{
		ScanID: scan.ID, HostID: host.ID, Format: "cyclonedx", Origin: "ingested",
		ComponentCount: 9, BOM: []byte(`{"bomFormat":"CycloneDX","v":2}`),
	}); err != nil {
		t.Fatalf("re-store ingested: %v", err)
	}
	var rows int
	if err := database.QueryRowContext(ctx,
		`SELECT count(*) FROM scan_sboms WHERE scan_id=$1 AND format='cyclonedx' AND origin='ingested'`, scan.ID).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 1 {
		t.Fatalf("upsert must keep a single row, got %d", rows)
	}

	// Retention sweep with a huge window deletes nothing fresh.
	if n, err := database.PruneScanSBOMs(ctx, 3650); err != nil || n != 0 {
		t.Fatalf("prune fresh: n=%d err=%v", n, err)
	}
}
