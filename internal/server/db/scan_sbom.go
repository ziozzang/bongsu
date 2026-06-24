package db

import (
	"context"
	"fmt"
	"time"
)

// ScanSBOM is a stored SBOM document pinned to a scan (see migrations/068).
type ScanSBOM struct {
	ScanID         string
	HostID         string
	Format         string // "cyclonedx" | "spdx"
	Origin         string // "ingested" | "generated"
	SpecVersion    string
	SourceRef      string
	ComponentCount int
	BOM            []byte
	CreatedAt      time.Time
}

const scanSBOMUpsertSQL = `INSERT INTO scan_sboms
(scan_id, host_id, format, origin, spec_version, source_ref, component_count, bom)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (scan_id, format, origin) DO UPDATE SET
  host_id=EXCLUDED.host_id, spec_version=EXCLUDED.spec_version, source_ref=EXCLUDED.source_ref,
  component_count=EXCLUDED.component_count, bom=EXCLUDED.bom, created_at=now()`

// StoreScanSBOM persists (or replaces) an SBOM for a scan. bom must be valid JSON.
func (db *DB) StoreScanSBOM(ctx context.Context, s ScanSBOM) error {
	if s.Origin == "" {
		s.Origin = "ingested"
	}
	if len(s.BOM) == 0 {
		return fmt.Errorf("empty SBOM document")
	}
	_, err := db.ExecContext(ctx, scanSBOMUpsertSQL,
		s.ScanID, s.HostID, s.Format, s.Origin, s.SpecVersion, s.SourceRef, s.ComponentCount, s.BOM)
	if err != nil {
		return fmt.Errorf("store scan sbom: %w", err)
	}
	return nil
}

// GetScanSBOM returns the stored SBOM for a scan in the requested format,
// preferring an ingested document over a generated one.
func (db *DB) GetScanSBOM(ctx context.Context, scanID, format string) (ScanSBOM, error) {
	var s ScanSBOM
	err := db.QueryRowContext(ctx,
		`SELECT scan_id, host_id, format, origin, spec_version, source_ref, component_count, bom, created_at
		   FROM scan_sboms WHERE scan_id=$1 AND format=$2
		   ORDER BY CASE origin WHEN 'ingested' THEN 0 ELSE 1 END LIMIT 1`,
		scanID, format).
		Scan(&s.ScanID, &s.HostID, &s.Format, &s.Origin, &s.SpecVersion, &s.SourceRef, &s.ComponentCount, &s.BOM, &s.CreatedAt)
	if err != nil {
		return ScanSBOM{}, err
	}
	return s, nil
}

// PruneScanSBOMs deletes stored SBOMs older than the retention window. A
// non-positive retention disables the sweep.
func (db *DB) PruneScanSBOMs(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	res, err := db.ExecContext(ctx,
		fmt.Sprintf(`DELETE FROM scan_sboms WHERE created_at < now() - interval '%d days'`, retentionDays))
	if err != nil {
		return 0, fmt.Errorf("prune scan sboms: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
