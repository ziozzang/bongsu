package db

import (
	"context"
	"fmt"
	"time"
)

type VulnTrendSnapshot struct {
	ID             string    `json:"id"`
	SnapshotDate   string    `json:"snapshot_date"`
	HostID         string    `json:"host_id"`
	TotalVulns     int       `json:"total_vulns"`
	CriticalCount  int       `json:"critical_count"`
	HighCount      int       `json:"high_count"`
	MediumCount    int       `json:"medium_count"`
	LowCount       int       `json:"low_count"`
	ExploitedCount int       `json:"exploited_count"`
	OverdueCount   int       `json:"overdue_count"`
	NewCount       int       `json:"new_count"`
	FixedCount     int       `json:"fixed_count"`
	ScanID         string    `json:"scan_id"`
	CreatedAt      time.Time `json:"created_at"`
}

type VulnTrendRow struct {
	Date           string `json:"date"`
	TotalVulns     int    `json:"total_vulns"`
	CriticalCount  int    `json:"critical_count"`
	HighCount      int    `json:"high_count"`
	MediumCount    int    `json:"medium_count"`
	LowCount       int    `json:"low_count"`
	ExploitedCount int    `json:"exploited_count"`
	OverdueCount   int    `json:"overdue_count"`
	NewCount       int    `json:"new_count"`
	FixedCount     int    `json:"fixed_count"`
	HostCount      int    `json:"host_count"`
}

type VulnTrendSummary struct {
	Current           VulnTrendRow `json:"current"`
	Previous          VulnTrendRow `json:"previous"`
	TrendDirection    string       `json:"trend_direction"`
	TotalHosts        int          `json:"total_hosts"`
	SnapshotHostCount int          `json:"snapshot_host_count"`
}

func (db *DB) RecordVulnTrendSnapshot(ctx context.Context, hostID, scanID string) error {
	baseQ := `FROM vulnerabilities v JOIN hosts h ON h.id = v.host_id JOIN ` + latestScansSub + ` ls ON v.scan_id = ls.id` + vulnTriageJoin +
		` WHERE ` + currentActionableVulnSQL() + ` AND v.host_id = $1`
	countQ := fmt.Sprintf(`SELECT count(*)::int,
		count(*) FILTER (WHERE v.severity='CRITICAL')::int,
		count(*) FILTER (WHERE v.severity='HIGH')::int,
		count(*) FILTER (WHERE v.severity='MEDIUM')::int,
		count(*) FILTER (WHERE v.severity='LOW')::int,
		count(*) FILTER (WHERE %s)::int,
		count(*) FILTER (WHERE (
			COALESCE(vt.status, 'open') IN ('open', 'in_progress') AND (
				(v.severity='CRITICAL' AND v.created_at < now() - interval '%d days') OR
				(v.severity='HIGH' AND v.created_at < now() - interval '%d days') OR
				(v.severity='MEDIUM' AND v.created_at < now() - interval '%d days') OR
				(v.severity='LOW' AND v.created_at < now() - interval '%d days')
			)
		))::int
		%s`,
		vulnExploitedExpr,
		SLADaysForSeverity("CRITICAL"),
		SLADaysForSeverity("HIGH"),
		SLADaysForSeverity("MEDIUM"),
		SLADaysForSeverity("LOW"),
		baseQ,
	)
	var total, critical, high, medium, low, exploited, overdue int
	if err := db.QueryRowContext(ctx, countQ, hostID).Scan(&total, &critical, &high, &medium, &low, &exploited, &overdue); err != nil {
		return fmt.Errorf("count vulns for trend snapshot: %w", err)
	}
	var prevTotal int
	db.QueryRowContext(ctx,
		`SELECT total_vulns FROM vuln_trend_snapshots WHERE host_id = $1 ORDER BY snapshot_date DESC LIMIT 1`,
		hostID).Scan(&prevTotal)
	newCount := total - prevTotal
	fixedCount := 0
	if prevTotal > total {
		newCount = 0
		fixedCount = prevTotal - total
	}
	today := time.Now().UTC().Format("2006-01-02")
	_, err := db.ExecContext(ctx, `
		INSERT INTO vuln_trend_snapshots (id, snapshot_date, host_id, total_vulns, critical_count, high_count, medium_count, low_count, exploited_count, overdue_count, new_count, fixed_count, scan_id, created_at)
		VALUES (gen_random_uuid()::text, $1::date, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now())
		ON CONFLICT (snapshot_date, host_id) DO UPDATE SET
			total_vulns = EXCLUDED.total_vulns,
			critical_count = EXCLUDED.critical_count,
			high_count = EXCLUDED.high_count,
			medium_count = EXCLUDED.medium_count,
			low_count = EXCLUDED.low_count,
			exploited_count = EXCLUDED.exploited_count,
			overdue_count = EXCLUDED.overdue_count,
			new_count = EXCLUDED.new_count,
			fixed_count = EXCLUDED.fixed_count,
			scan_id = EXCLUDED.scan_id`,
		today, hostID, total, critical, high, medium, low, exploited, overdue, newCount, fixedCount, scanID)
	if err != nil {
		return fmt.Errorf("insert vuln trend snapshot: %w", err)
	}
	return nil
}

func (db *DB) GetVulnTrends(ctx context.Context, days int, hostID string) ([]VulnTrendRow, error) {
	if days <= 0 || days > 365 {
		days = 30
	}
	q := `SELECT snapshot_date::text,
		sum(total_vulns)::int, sum(critical_count)::int, sum(high_count)::int,
		sum(medium_count)::int, sum(low_count)::int, sum(exploited_count)::int,
		sum(overdue_count)::int, sum(new_count)::int, sum(fixed_count)::int,
		count(DISTINCT host_id)::int
		FROM vuln_trend_snapshots
		WHERE snapshot_date >= (CURRENT_DATE - $1 * interval '1 day')::date`
	args := []any{days}
	if hostID != "" {
		q += ` AND host_id = $2`
		args = append(args, hostID)
	}
	q += ` GROUP BY snapshot_date ORDER BY snapshot_date`
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("get vuln trends: %w", err)
	}
	defer rows.Close()
	var out []VulnTrendRow
	for rows.Next() {
		var r VulnTrendRow
		if err := rows.Scan(&r.Date, &r.TotalVulns, &r.CriticalCount, &r.HighCount, &r.MediumCount, &r.LowCount, &r.ExploitedCount, &r.OverdueCount, &r.NewCount, &r.FixedCount, &r.HostCount); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) GetVulnTrendSummary(ctx context.Context) (*VulnTrendSummary, error) {
	var summary VulnTrendSummary
	currentQ := `SELECT COALESCE(sum(total_vulns),0)::int, COALESCE(sum(critical_count),0)::int,
		COALESCE(sum(high_count),0)::int, COALESCE(sum(medium_count),0)::int, COALESCE(sum(low_count),0)::int,
		COALESCE(sum(exploited_count),0)::int, COALESCE(sum(overdue_count),0)::int,
		COALESCE(sum(new_count),0)::int, COALESCE(sum(fixed_count),0)::int,
		count(DISTINCT host_id)::int
		FROM vuln_trend_snapshots WHERE snapshot_date = CURRENT_DATE`
	if err := db.QueryRowContext(ctx, currentQ).Scan(
		&summary.Current.TotalVulns, &summary.Current.CriticalCount, &summary.Current.HighCount,
		&summary.Current.MediumCount, &summary.Current.LowCount, &summary.Current.ExploitedCount,
		&summary.Current.OverdueCount, &summary.Current.NewCount, &summary.Current.FixedCount,
		&summary.Current.HostCount); err != nil {
		return nil, fmt.Errorf("get current trend: %w", err)
	}
	prevQ := `SELECT COALESCE(sum(total_vulns),0)::int, COALESCE(sum(critical_count),0)::int,
		COALESCE(sum(high_count),0)::int, COALESCE(sum(medium_count),0)::int, COALESCE(sum(low_count),0)::int,
		COALESCE(sum(exploited_count),0)::int, COALESCE(sum(overdue_count),0)::int,
		COALESCE(sum(new_count),0)::int, COALESCE(sum(fixed_count),0)::int,
		count(DISTINCT host_id)::int
		FROM vuln_trend_snapshots WHERE snapshot_date = CURRENT_DATE - interval '7 days'`
	if err := db.QueryRowContext(ctx, prevQ).Scan(
		&summary.Previous.TotalVulns, &summary.Previous.CriticalCount, &summary.Previous.HighCount,
		&summary.Previous.MediumCount, &summary.Previous.LowCount, &summary.Previous.ExploitedCount,
		&summary.Previous.OverdueCount, &summary.Previous.NewCount, &summary.Previous.FixedCount,
		&summary.Previous.HostCount); err != nil {
		return nil, fmt.Errorf("get previous trend: %w", err)
	}
	summary.TrendDirection = "stable"
	if summary.Previous.TotalVulns > 0 {
		delta := float64(summary.Current.TotalVulns-summary.Previous.TotalVulns) / float64(summary.Previous.TotalVulns) * 100
		if delta > 5 {
			summary.TrendDirection = "degrading"
		} else if delta < -5 {
			summary.TrendDirection = "improving"
		}
	}
	db.QueryRowContext(ctx, `SELECT count(*)::int FROM hosts`).Scan(&summary.TotalHosts)
	summary.SnapshotHostCount = summary.Current.HostCount
	return &summary, nil
}

func (db *DB) CleanupOldTrendSnapshots(ctx context.Context) error {
	days := envInt("BONGSU_VULN_TREND_RETENTION_DAYS", 365)
	if days < 30 {
		days = 30
	}
	_, err := db.ExecContext(ctx, `DELETE FROM vuln_trend_snapshots WHERE snapshot_date < CURRENT_DATE - $1 * interval '1 day'`, days)
	return err
}
