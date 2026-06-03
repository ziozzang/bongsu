-- Performance indexes for common query patterns
-- Targets: SLA overdue queries, host lookups, latestScansSub, retention pruning, trend snapshots

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity_created_at
    ON vulnerabilities(severity, created_at);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_host_id
    ON vulnerabilities(host_id);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id
    ON vulnerabilities(scan_id);

CREATE INDEX IF NOT EXISTS idx_scans_host_created_desc
    ON scans(host_id, created_at DESC)
    WHERE status IN ('completed', 'degraded');

CREATE INDEX IF NOT EXISTS idx_scans_created_at
    ON scans(created_at);

CREATE INDEX IF NOT EXISTS idx_vuln_trend_snapshots_date_host
    ON vuln_trend_snapshots(snapshot_date, host_id);

CREATE INDEX IF NOT EXISTS idx_vulnerability_triage_vuln_id
    ON vulnerability_triage(vulnerability_id);
