package db

import (
	"context"
	"fmt"
)

type AtRiskHost struct {
	HostID        string `json:"host_id"`
	Hostname      string `json:"hostname"`
	TotalVulns    int    `json:"total_vulns"`
	CriticalCount int    `json:"critical_count"`
	HighCount     int    `json:"high_count"`
	Exploited     int    `json:"exploited_count"`
	Overdue       int    `json:"overdue_count"`
	MaxRiskScore  int    `json:"max_risk_score"`
}

type Recommendation struct {
	Priority    string   `json:"priority"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	HostIDs     []string `json:"host_ids"`
}

type PostureComparison struct {
	CurrentTotal   int     `json:"current_total"`
	PreviousTotal  int     `json:"previous_total"`
	Delta          int     `json:"delta"`
	DeltaPercent   float64 `json:"delta_percent"`
	TrendDirection string  `json:"trend_direction"`
	CurrentDate    string  `json:"current_date"`
	PreviousDate   string  `json:"previous_date"`
}

func (db *DB) GetTopAtRiskHosts(ctx context.Context, limit int) ([]AtRiskHost, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	q := fmt.Sprintf(`SELECT h.id, h.hostname,
		count(*)::int AS total,
		count(*) FILTER (WHERE v.severity='CRITICAL')::int AS critical,
		count(*) FILTER (WHERE v.severity='HIGH')::int AS high,
		count(*) FILTER (WHERE %s)::int AS exploited,
		count(*) FILTER (WHERE
			COALESCE(vt.status, 'open') IN ('open', 'in_progress') AND (
				(v.severity='CRITICAL' AND v.created_at < now() - interval '%d days') OR
				(v.severity='HIGH' AND v.created_at < now() - interval '%d days') OR
				(v.severity='MEDIUM' AND v.created_at < now() - interval '%d days') OR
				(v.severity='LOW' AND v.created_at < now() - interval '%d days')
			)
		)::int AS overdue,
		MAX(%s)::int AS max_risk
		FROM vulnerabilities v JOIN hosts h ON h.id = v.host_id
		JOIN %s ls ON v.scan_id = ls.id%s
		WHERE %s
		GROUP BY h.id, h.hostname
		ORDER BY critical DESC, high DESC, max_risk DESC, total DESC
		LIMIT %d`,
		vulnExploitedExpr,
		SLADaysForSeverity("CRITICAL"),
		SLADaysForSeverity("HIGH"),
		SLADaysForSeverity("MEDIUM"),
		SLADaysForSeverity("LOW"),
		vulnRiskScoreExpr,
		latestScansSub,
		vulnTriageJoin,
		currentActionableVulnSQL(),
		limit,
	)
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("get top at risk hosts: %w", err)
	}
	defer rows.Close()
	var out []AtRiskHost
	for rows.Next() {
		var h AtRiskHost
		if err := rows.Scan(&h.HostID, &h.Hostname, &h.TotalVulns, &h.CriticalCount, &h.HighCount, &h.Exploited, &h.Overdue, &h.MaxRiskScore); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (db *DB) GetRecommendations(ctx context.Context) ([]Recommendation, error) {
	var recs []Recommendation
	rows, err := db.QueryContext(ctx, fmt.Sprintf(`
		SELECT h.id, h.hostname, count(*)::int,
			count(*) FILTER (WHERE v.severity='CRITICAL')::int,
			count(*) FILTER (WHERE %s)::int
		FROM vulnerabilities v JOIN hosts h ON h.id = v.host_id
		JOIN %s ls ON v.scan_id = ls.id%s
		WHERE %s
		AND COALESCE(vt.status, 'open') IN ('open', 'in_progress')
		AND (
			(v.severity='CRITICAL' AND v.created_at < now() - interval '%d days') OR
			(v.severity='HIGH' AND v.created_at < now() - interval '%d days')
		)
		GROUP BY h.id, h.hostname
		HAVING count(*) FILTER (WHERE v.severity IN ('CRITICAL','HIGH')) > 0
		ORDER BY count(*) FILTER (WHERE v.severity='CRITICAL') DESC
		LIMIT 10`,
		vulnExploitedExpr,
		latestScansSub,
		vulnTriageJoin,
		currentActionableVulnSQL(),
		SLADaysForSeverity("CRITICAL"),
		SLADaysForSeverity("HIGH"),
	))
	if err != nil {
		return nil, fmt.Errorf("get overdue recommendations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var hostID, hostname string
		var total, critical, exploited int
		if err := rows.Scan(&hostID, &hostname, &total, &critical, &exploited); err != nil {
			return nil, err
		}
		recs = append(recs, Recommendation{
			Priority:    "critical",
			Category:    "patching",
			Title:       fmt.Sprintf("Patch %s: %d overdue critical/high vulnerabilities", hostname, total),
			Description: fmt.Sprintf("Host %s has %d critical and %d total overdue vulnerabilities (%d exploited)", hostname, critical, total, exploited),
			HostIDs:     []string{hostID},
		})
	}
	exploitedRows, err := db.QueryContext(ctx, fmt.Sprintf(`
		SELECT h.id, h.hostname, count(*)::int
		FROM vulnerabilities v JOIN hosts h ON h.id = v.host_id
		JOIN %s ls ON v.scan_id = ls.id%s
		WHERE %s AND %s
		GROUP BY h.id, h.hostname
		ORDER BY count(*) DESC LIMIT 5`,
		latestScansSub,
		vulnTriageJoin,
		currentActionableVulnSQL(),
		vulnExploitedExpr,
	))
	if err == nil {
		defer exploitedRows.Close()
		for exploitedRows.Next() {
			var hostID, hostname string
			var count int
			if err := exploitedRows.Scan(&hostID, &hostname, &count); err != nil {
				break
			}
			recs = append(recs, Recommendation{
				Priority:    "critical",
				Category:    "exploitation_risk",
				Title:       fmt.Sprintf("Host %s has %d exploited-in-the-wild vulnerabilities", hostname, count),
				Description: fmt.Sprintf("Active exploitation detected for %d vulnerabilities on host %s", count, hostname),
				HostIDs:     []string{hostID},
			})
		}
	}
	return recs, nil
}

func (db *DB) GetVulnPostureComparison(ctx context.Context, days int) (*PostureComparison, error) {
	if days <= 0 {
		days = 7
	}
	var current, previous int
	var currentDate, previousDate string
	db.QueryRowContext(ctx, `SELECT COALESCE(sum(total_vulns),0)::int, max(snapshot_date)::text FROM vuln_trend_snapshots WHERE snapshot_date = CURRENT_DATE`).Scan(&current, &currentDate)
	db.QueryRowContext(ctx, fmt.Sprintf(`SELECT COALESCE(sum(total_vulns),0)::int, max(snapshot_date)::text FROM vuln_trend_snapshots WHERE snapshot_date = CURRENT_DATE - interval '%d days'`, days)).Scan(&previous, &previousDate)
	pc := &PostureComparison{
		CurrentTotal:  current,
		PreviousTotal: previous,
		Delta:         current - previous,
		CurrentDate:   currentDate,
		PreviousDate:  previousDate,
	}
	if previous > 0 {
		pc.DeltaPercent = float64(current-previous) / float64(previous) * 100
	}
	pc.TrendDirection = "stable"
	if pc.DeltaPercent > 5 {
		pc.TrendDirection = "degrading"
	} else if pc.DeltaPercent < -5 {
		pc.TrendDirection = "improving"
	}
	return pc, nil
}
