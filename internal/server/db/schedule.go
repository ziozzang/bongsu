package db

import (
	"context"
	"fmt"
	"time"
)

type ScheduledScan struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	CronExpr     string     `json:"cron_expr"`
	ScanType     string     `json:"scan_type"`
	HostFilter   string     `json:"host_filter"`
	PackagesOnly bool       `json:"packages_only"`
	Enabled      bool       `json:"enabled"`
	LastRun      *time.Time `json:"last_run,omitempty"`
	NextRun      *time.Time `json:"next_run,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

const scheduledScanCols = `id, name, cron_expr, scan_type, host_filter, packages_only, enabled, last_run, next_run, created_at, updated_at`

func (db *DB) scanScheduledScanRow(row interface{ Scan(...interface{}) error }) (*ScheduledScan, error) {
	var s ScheduledScan
	err := row.Scan(&s.ID, &s.Name, &s.CronExpr, &s.ScanType, &s.HostFilter, &s.PackagesOnly, &s.Enabled, &s.LastRun, &s.NextRun, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (db *DB) CreateScheduledScan(ctx context.Context, s *ScheduledScan) error {
	q := `INSERT INTO scheduled_scans (id, name, cron_expr, scan_type, host_filter, packages_only, enabled, next_run, created_at, updated_at)
	      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), now())`
	_, err := db.ExecContext(ctx, q, s.ID, s.Name, s.CronExpr, s.ScanType, s.HostFilter, s.PackagesOnly, s.Enabled, s.NextRun)
	if err != nil {
		return fmt.Errorf("create scheduled scan: %w", err)
	}
	return nil
}

func (db *DB) GetScheduledScan(ctx context.Context, id string) (*ScheduledScan, error) {
	s, err := db.scanScheduledScanRow(db.QueryRowContext(ctx,
		`SELECT `+scheduledScanCols+` FROM scheduled_scans WHERE id = $1`, id))
	if err != nil {
		return nil, fmt.Errorf("get scheduled scan: %w", err)
	}
	return s, nil
}

func (db *DB) ListScheduledScans(ctx context.Context) ([]ScheduledScan, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+scheduledScanCols+` FROM scheduled_scans ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list scheduled scans: %w", err)
	}
	defer rows.Close()
	var out []ScheduledScan
	for rows.Next() {
		s, err := db.scanScheduledScanRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

func (db *DB) UpdateScheduledScan(ctx context.Context, s *ScheduledScan) error {
	q := `UPDATE scheduled_scans SET name=$2, cron_expr=$3, scan_type=$4, host_filter=$5, packages_only=$6, enabled=$7, next_run=$8, updated_at=now() WHERE id=$1`
	res, err := db.ExecContext(ctx, q, s.ID, s.Name, s.CronExpr, s.ScanType, s.HostFilter, s.PackagesOnly, s.Enabled, s.NextRun)
	if err != nil {
		return fmt.Errorf("update scheduled scan: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("scheduled scan not found")
	}
	return nil
}

func (db *DB) DeleteScheduledScan(ctx context.Context, id string) error {
	res, err := db.ExecContext(ctx, `DELETE FROM scheduled_scans WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete scheduled scan: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("scheduled scan not found")
	}
	return nil
}

func (db *DB) UpdateScheduledScanRunTimes(ctx context.Context, id string, lastRun, nextRun time.Time) error {
	_, err := db.ExecContext(ctx,
		`UPDATE scheduled_scans SET last_run=$2, next_run=$3, updated_at=now() WHERE id=$1`,
		id, lastRun, nextRun)
	return err
}

func (db *DB) GetDueScheduledScans(ctx context.Context, now time.Time) ([]ScheduledScan, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT `+scheduledScanCols+` FROM scheduled_scans WHERE enabled = true AND next_run IS NOT NULL AND next_run <= $1 ORDER BY next_run`,
		now)
	if err != nil {
		return nil, fmt.Errorf("get due scheduled scans: %w", err)
	}
	defer rows.Close()
	var out []ScheduledScan
	for rows.Next() {
		s, err := db.scanScheduledScanRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}
