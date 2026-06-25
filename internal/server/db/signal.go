package db

import (
	"context"
	"database/sql"
	"fmt"
)

// RefreshSignalTables rebuilds the signal-plane tables (cve_kev, cve_epss) from
// the current cve_database signal rows. It is idempotent and runs alongside the
// EPSS column sync at every secdb refresh (see SyncEPSSPriorityColumnsTx).
// Phase 1 keeps cve_database as the producer-facing landing zone; once the
// destructive cleanup migration lands, ingest will write these tables directly.
func (db *DB) RefreshSignalTables(ctx context.Context) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := db.RefreshSignalTablesTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// RefreshSignalTablesTx is the transactional form. KEV: every cisa-kev
// vulnerability_id becomes (or stays) a cve_kev row, and rows whose source
// disappeared are pruned. EPSS: the authoritative source='epss' score/percentile
// per CVE is upserted, and stale rows pruned.
func (db *DB) RefreshSignalTablesTx(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cve_kev (vulnerability_id, source, raw_data, updated_at)
		SELECT DISTINCT ON (vulnerability_id)
		       vulnerability_id, 'cisa-kev', COALESCE(raw_data, '{}'::jsonb), now()
		FROM cve_database
		WHERE source = 'cisa-kev' AND vulnerability_id <> ''
		ORDER BY vulnerability_id, updated_at DESC
		ON CONFLICT (vulnerability_id) DO UPDATE
		   SET raw_data = EXCLUDED.raw_data, updated_at = now()`); err != nil {
		return fmt.Errorf("refresh cve_kev: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM cve_kev k
		WHERE NOT EXISTS (
			SELECT 1 FROM cve_database c
			WHERE c.source = 'cisa-kev' AND c.vulnerability_id = k.vulnerability_id)`); err != nil {
		return fmt.Errorf("prune cve_kev: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cve_epss (vulnerability_id, score, percentile, updated_at)
		SELECT DISTINCT ON (vulnerability_id)
		       vulnerability_id, epss_score, epss_percentile, now()
		FROM cve_database
		WHERE source = 'epss' AND vulnerability_id <> '' AND (epss_score > 0 OR epss_percentile > 0)
		ORDER BY vulnerability_id, updated_at DESC, epss_score DESC, epss_percentile DESC
		ON CONFLICT (vulnerability_id) DO UPDATE
		   SET score = EXCLUDED.score, percentile = EXCLUDED.percentile, updated_at = now()`); err != nil {
		return fmt.Errorf("refresh cve_epss: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM cve_epss e
		WHERE NOT EXISTS (
			SELECT 1 FROM cve_database c
			WHERE c.source = 'epss' AND c.vulnerability_id = e.vulnerability_id
			  AND (c.epss_score > 0 OR c.epss_percentile > 0))`); err != nil {
		return fmt.Errorf("prune cve_epss: %w", err)
	}
	return nil
}
