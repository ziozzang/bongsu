package db

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type ExecutiveSummary struct {
	GeneratedAt    time.Time      `json:"generated_at"`
	TotalHosts     int            `json:"total_hosts"`
	HostCoverage   float64        `json:"host_coverage_percent"`
	ActiveVulns    int            `json:"active_vulnerabilities"`
	SeverityCounts map[string]int `json:"severity_counts"`
	RiskCounts     map[string]int `json:"risk_level_counts"`
	ExploitedCount int            `json:"exploited_count"`
	OverdueCount   int            `json:"overdue_sla_count"`
	SLACompliance  float64        `json:"sla_compliance_percent"`
	TrendDirection string         `json:"trend_direction"`
	TrendDelta     int            `json:"trend_delta"`
	TopRiskHosts   []AtRiskHost   `json:"top_risk_hosts"`
}

type SLAComplianceReport struct {
	GeneratedAt    time.Time              `json:"generated_at"`
	OverallRate    float64                `json:"overall_compliance_percent"`
	BySeverity     map[string]SLASevStats `json:"by_severity"`
	OverdueByOwner []SLAOwnerRow          `json:"overdue_by_owner"`
}

type SLASevStats struct {
	Total   int     `json:"total"`
	Overdue int     `json:"overdue"`
	Rate    float64 `json:"compliance_percent"`
}

type SLAOwnerRow struct {
	Owner   string `json:"owner"`
	Overdue int    `json:"overdue"`
	Total   int    `json:"total"`
}

type RiskBreakdownRow struct {
	Group          string         `json:"group"`
	Total          int            `json:"total"`
	SeverityCounts map[string]int `json:"severity_counts"`
	RiskCounts     map[string]int `json:"risk_level_counts"`
}

func reportHostFilter(hostIDs []string, alias string, param int) (string, []any) {
	if hostIDs == nil {
		return "", nil
	}
	return fmt.Sprintf(" AND %s.id = ANY($%d)", alias, param), []any{pqStringArray(hostIDs)}
}

func (db *DB) GetExecutiveSummary(ctx context.Context, hostIDs []string) (*ExecutiveSummary, error) {
	summary := &ExecutiveSummary{
		GeneratedAt:    time.Now().UTC(),
		SeverityCounts: map[string]int{},
		RiskCounts:     map[string]int{},
	}
	hostFilter, hostArgs := reportHostFilter(hostIDs, "h", 1)
	db.QueryRowContext(ctx, `SELECT count(*)::int FROM hosts h WHERE 1=1`+hostFilter, hostArgs...).Scan(&summary.TotalHosts)
	baseQ := `FROM vulnerabilities v JOIN hosts h ON h.id = v.host_id JOIN ` + latestScansSub + ` ls ON v.scan_id = ls.id` + vulnTriageJoin + ` WHERE ` + currentActionableVulnSQL() + hostFilter
	// Materialize the per-row risk level and exploited flag once; otherwise the
	// KEV/EPSS correlated subqueries inside vulnRiskLevelExpr are re-evaluated for
	// every one of the four risk FILTER buckets (plus the exploited count).
	q := fmt.Sprintf(`WITH actionable AS MATERIALIZED (
		SELECT v.severity, v.created_at,
			COALESCE(vt.status, 'open') AS triage_status,
			(%s) AS risk_level,
			(%s) AS exploited
		%s
	)
	SELECT count(*)::int,
		count(*) FILTER (WHERE severity='CRITICAL')::int,
		count(*) FILTER (WHERE severity='HIGH')::int,
		count(*) FILTER (WHERE severity='MEDIUM')::int,
		count(*) FILTER (WHERE severity='LOW')::int,
		count(*) FILTER (WHERE risk_level='critical')::int,
		count(*) FILTER (WHERE risk_level='high')::int,
		count(*) FILTER (WHERE risk_level='medium')::int,
		count(*) FILTER (WHERE risk_level='low')::int,
		count(*) FILTER (WHERE exploited)::int,
		count(*) FILTER (WHERE
			triage_status IN ('open', 'in_progress') AND (
				(severity='CRITICAL' AND created_at < now() - interval '%d days') OR
				(severity='HIGH' AND created_at < now() - interval '%d days') OR
				(severity='MEDIUM' AND created_at < now() - interval '%d days') OR
				(severity='LOW' AND created_at < now() - interval '%d days')
			)
		)::int
		FROM actionable`,
		vulnRiskLevelExpr,
		vulnExploitedExpr,
		baseQ,
		SLADaysForSeverity("CRITICAL"), SLADaysForSeverity("HIGH"), SLADaysForSeverity("MEDIUM"), SLADaysForSeverity("LOW"))
	var riskCritical, riskHigh, riskMedium, riskLow int
	var sevCritical, sevHigh, sevMedium, sevLow int
	db.QueryRowContext(ctx, q, hostArgs...).Scan(
		&summary.ActiveVulns,
		&sevCritical, &sevHigh, &sevMedium, &sevLow,
		&riskCritical, &riskHigh, &riskMedium, &riskLow,
		&summary.ExploitedCount, &summary.OverdueCount)
	summary.SeverityCounts["CRITICAL"] = sevCritical
	summary.SeverityCounts["HIGH"] = sevHigh
	summary.SeverityCounts["MEDIUM"] = sevMedium
	summary.SeverityCounts["LOW"] = sevLow
	summary.RiskCounts["critical"] = riskCritical
	summary.RiskCounts["high"] = riskHigh
	summary.RiskCounts["medium"] = riskMedium
	summary.RiskCounts["low"] = riskLow
	if summary.ActiveVulns > 0 {
		summary.SLACompliance = float64(summary.ActiveVulns-summary.OverdueCount) / float64(summary.ActiveVulns) * 100
	} else {
		summary.SLACompliance = 100
	}
	var snapHosts int
	snapFilter := ""
	if hostIDs != nil {
		snapFilter = " WHERE host_id = ANY($1)"
	}
	db.QueryRowContext(ctx, `SELECT count(DISTINCT host_id)::int FROM vuln_trend_snapshots`+snapFilter, hostArgs...).Scan(&snapHosts)
	if summary.TotalHosts > 0 {
		summary.HostCoverage = float64(snapHosts) / float64(summary.TotalHosts) * 100
	}
	var prevTotal int
	prevFilter := ` WHERE snapshot_date = CURRENT_DATE - interval '7 days'`
	if hostIDs != nil {
		prevFilter += " AND host_id = ANY($1)"
	}
	db.QueryRowContext(ctx, `SELECT COALESCE(sum(total_vulns),0)::int FROM vuln_trend_snapshots`+prevFilter, hostArgs...).Scan(&prevTotal)
	summary.TrendDelta = summary.ActiveVulns - prevTotal
	summary.TrendDirection = "stable"
	if prevTotal > 0 {
		pct := float64(summary.TrendDelta) / float64(prevTotal) * 100
		if pct > 5 {
			summary.TrendDirection = "degrading"
		} else if pct < -5 {
			summary.TrendDirection = "improving"
		}
	}
	topHosts, _ := db.GetTopAtRiskHosts(ctx, 5, hostIDs)
	if topHosts != nil {
		summary.TopRiskHosts = topHosts
	} else {
		summary.TopRiskHosts = []AtRiskHost{}
	}
	return summary, nil
}

func (db *DB) GetSLAComplianceReport(ctx context.Context, hostIDs []string) (*SLAComplianceReport, error) {
	report := &SLAComplianceReport{
		GeneratedAt:    time.Now().UTC(),
		BySeverity:     map[string]SLASevStats{},
		OverdueByOwner: []SLAOwnerRow{},
	}
	hostFilter, hostArgs := reportHostFilter(hostIDs, "h", 2)
	baseQ := `FROM vulnerabilities v JOIN hosts h ON h.id = v.host_id JOIN ` + latestScansSub + ` ls ON v.scan_id = ls.id` + vulnTriageJoin + ` WHERE ` + currentActionableVulnSQL() +
		` AND COALESCE(vt.status, 'open') IN ('open', 'in_progress')` + hostFilter
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		slaDays := SLADaysForSeverity(sev)
		var total, overdue int
		args := append([]any{sev}, hostArgs...)
		db.QueryRowContext(ctx, fmt.Sprintf(`SELECT count(*)::int, count(*) FILTER (WHERE v.created_at < now() - interval '%d days')::int %s AND v.severity = $1`, slaDays, baseQ), args...).Scan(&total, &overdue)
		rate := 100.0
		if total > 0 {
			rate = float64(total-overdue) / float64(total) * 100
		}
		report.BySeverity[sev] = SLASevStats{Total: total, Overdue: overdue, Rate: rate}
	}
	var totalAll, overdueAll int
	for _, s := range report.BySeverity {
		totalAll += s.Total
		overdueAll += s.Overdue
	}
	if totalAll > 0 {
		report.OverallRate = float64(totalAll-overdueAll) / float64(totalAll) * 100
	} else {
		report.OverallRate = 100
	}
	ownerHostFilter, ownerHostArgs := reportHostFilter(hostIDs, "h", 1)
	ownerBaseQ := `FROM vulnerabilities v JOIN hosts h ON h.id = v.host_id JOIN ` + latestScansSub + ` ls ON v.scan_id = ls.id` + vulnTriageJoin + ` WHERE ` + currentActionableVulnSQL() +
		` AND COALESCE(vt.status, 'open') IN ('open', 'in_progress')` + ownerHostFilter
	ownerRows, err := db.QueryContext(ctx, fmt.Sprintf(`SELECT COALESCE(h.owner, '(unassigned)'), count(*)::int,
		count(*) FILTER (WHERE
			(v.severity='CRITICAL' AND v.created_at < now() - interval '%d days') OR
			(v.severity='HIGH' AND v.created_at < now() - interval '%d days') OR
			(v.severity='MEDIUM' AND v.created_at < now() - interval '%d days') OR
			(v.severity='LOW' AND v.created_at < now() - interval '%d days')
		)::int AS overdue
		%s GROUP BY COALESCE(h.owner, '(unassigned)') ORDER BY overdue DESC LIMIT 10`,
		SLADaysForSeverity("CRITICAL"), SLADaysForSeverity("HIGH"), SLADaysForSeverity("MEDIUM"), SLADaysForSeverity("LOW"),
		ownerBaseQ), ownerHostArgs...)
	if err == nil {
		defer ownerRows.Close()
		for ownerRows.Next() {
			var r SLAOwnerRow
			if err := ownerRows.Scan(&r.Owner, &r.Total, &r.Overdue); err != nil {
				break
			}
			report.OverdueByOwner = append(report.OverdueByOwner, r)
		}
	}
	return report, nil
}

func (db *DB) GetRiskBreakdown(ctx context.Context, groupBy string, hostIDs []string) ([]RiskBreakdownRow, error) {
	groupExpr := `COALESCE(h.owner, '')`
	switch strings.ToLower(groupBy) {
	case "team":
		groupExpr = `COALESCE(h.team, '')`
	case "environment":
		groupExpr = `COALESCE(h.environment, '')`
	case "criticality":
		groupExpr = `COALESCE(h.criticality, '')`
	}
	hostFilter, hostArgs := reportHostFilter(hostIDs, "h", 1)
	baseQ := `FROM vulnerabilities v JOIN hosts h ON h.id = v.host_id JOIN ` + latestScansSub + ` ls ON v.scan_id = ls.id` + vulnTriageJoin + ` WHERE ` + currentActionableVulnSQL() + hostFilter
	// Compute the per-row risk level once in a MATERIALIZED CTE so the KEV/EPSS
	// correlated subqueries don't run four times per row (once per risk bucket).
	q := fmt.Sprintf(`WITH actionable AS MATERIALIZED (
		SELECT %s AS group_value, v.severity, (%s) AS risk_level
		%s
	)
	SELECT group_value,
		count(*)::int,
		count(*) FILTER (WHERE severity='CRITICAL')::int,
		count(*) FILTER (WHERE severity='HIGH')::int,
		count(*) FILTER (WHERE severity='MEDIUM')::int,
		count(*) FILTER (WHERE severity='LOW')::int,
		count(*) FILTER (WHERE risk_level='critical')::int,
		count(*) FILTER (WHERE risk_level='high')::int,
		count(*) FILTER (WHERE risk_level='medium')::int,
		count(*) FILTER (WHERE risk_level='low')::int
		FROM actionable GROUP BY group_value ORDER BY count(*) DESC`,
		groupExpr,
		vulnRiskLevelExpr,
		baseQ)
	rows, err := db.QueryContext(ctx, q, hostArgs...)
	if err != nil {
		return nil, fmt.Errorf("get risk breakdown: %w", err)
	}
	defer rows.Close()
	var out []RiskBreakdownRow
	for rows.Next() {
		var r RiskBreakdownRow
		var rc, rh, rm, rl int
		var sc, sh, sm, sl int
		if err := rows.Scan(&r.Group, &r.Total, &sc, &sh, &sm, &sl, &rc, &rh, &rm, &rl); err != nil {
			return nil, err
		}
		r.SeverityCounts = map[string]int{"CRITICAL": sc, "HIGH": sh, "MEDIUM": sm, "LOW": sl}
		r.RiskCounts = map[string]int{"critical": rc, "high": rh, "medium": rm, "low": rl}
		out = append(out, r)
	}
	return out, rows.Err()
}
