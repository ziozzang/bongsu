package db

import (
	"context"
	"fmt"
	"time"
)

func (db *DB) PruneOperationalData(ctx context.Context, scanDays, requestDays, auditDays int, dryRun bool) (*RetentionPruneResult, error) {
	result := &RetentionPruneResult{
		DryRun:      dryRun,
		ScanDays:    scanDays,
		RequestDays: requestDays,
		AuditDays:   auditDays,
	}
	now := time.Now()
	scanCutoff := now.Add(-time.Duration(scanDays) * 24 * time.Hour)
	requestCutoff := now.Add(-time.Duration(requestDays) * 24 * time.Hour)
	auditCutoff := now.Add(-time.Duration(auditDays) * 24 * time.Hour)
	result.ScanCutoff = scanCutoff.UTC().Format(time.RFC3339)
	result.RequestCutoff = requestCutoff.UTC().Format(time.RFC3339)
	result.AuditCutoff = auditCutoff.UTC().Format(time.RFC3339)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	oldScans := pruneOldScansCTE()
	countFor := func(table string) (int, error) {
		var n int
		err := tx.QueryRowContext(ctx, oldScans+fmt.Sprintf(` SELECT count(*) FROM %s WHERE scan_id IN (SELECT id FROM old_scans)`, table), scanCutoff).Scan(&n)
		return n, err
	}
	result.Vulns, err = countFor("vulnerabilities")
	if err != nil {
		return nil, err
	}
	result.Packages, err = countFor("packages")
	if err != nil {
		return nil, err
	}
	result.Containers, err = countFor("container_assets")
	if err != nil {
		return nil, err
	}
	result.Users, err = countFor("user_accounts")
	if err != nil {
		return nil, err
	}
	result.Processes, err = countFor("process_snapshots")
	if err != nil {
		return nil, err
	}
	result.Ports, err = countFor("port_info")
	if err != nil {
		return nil, err
	}
	if err := tx.QueryRowContext(ctx, oldScans+` SELECT count(*) FROM old_scans`, scanCutoff).Scan(&result.Scans); err != nil {
		return nil, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM scan_requests WHERE created_at < $1 AND status IN ('completed','degraded','failed','cancelled')`, requestCutoff).Scan(&result.Requests); err != nil {
		return nil, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE created_at < $1`, auditCutoff).Scan(&result.AuditLogs); err != nil {
		return nil, err
	}
	if dryRun {
		return result, tx.Commit()
	}

	deleteFrom := func(table string) error {
		_, err := tx.ExecContext(ctx, oldScans+fmt.Sprintf(` DELETE FROM %s WHERE scan_id IN (SELECT id FROM old_scans)`, table), scanCutoff)
		return err
	}
	for _, table := range []string{"vulnerabilities", "packages", "container_assets", "user_accounts", "process_snapshots", "port_info"} {
		if err := deleteFrom(table); err != nil {
			return nil, fmt.Errorf("delete old %s: %w", table, err)
		}
	}
	if _, err := tx.ExecContext(ctx, oldScans+` DELETE FROM scans WHERE id IN (SELECT id FROM old_scans)`, scanCutoff); err != nil {
		return nil, fmt.Errorf("delete old scans: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM scan_requests WHERE created_at < $1 AND status IN ('completed','degraded','failed','cancelled')`, requestCutoff); err != nil {
		return nil, fmt.Errorf("delete old scan requests: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM audit_logs WHERE created_at < $1`, auditCutoff); err != nil {
		return nil, fmt.Errorf("delete old audit logs: %w", err)
	}
	return result, tx.Commit()
}

func pruneOldScansCTE() string {
	return `WITH old_scans AS (
		SELECT id FROM scans
		WHERE created_at < $1
		  AND status IN ('completed','degraded','failed')
		  AND id NOT IN (SELECT DISTINCT ON (host_id) id FROM scans WHERE status IN ('completed','degraded') ORDER BY host_id, created_at DESC)
	)`
}

