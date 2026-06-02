CREATE TABLE IF NOT EXISTS vuln_trend_snapshots (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    snapshot_date DATE NOT NULL,
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    total_vulns INT NOT NULL DEFAULT 0,
    critical_count INT NOT NULL DEFAULT 0,
    high_count INT NOT NULL DEFAULT 0,
    medium_count INT NOT NULL DEFAULT 0,
    low_count INT NOT NULL DEFAULT 0,
    exploited_count INT NOT NULL DEFAULT 0,
    overdue_count INT NOT NULL DEFAULT 0,
    new_count INT NOT NULL DEFAULT 0,
    fixed_count INT NOT NULL DEFAULT 0,
    scan_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (snapshot_date, host_id)
);
CREATE INDEX IF NOT EXISTS idx_vuln_trend_date ON vuln_trend_snapshots(snapshot_date DESC);
CREATE INDEX IF NOT EXISTS idx_vuln_trend_host_date ON vuln_trend_snapshots(host_id, snapshot_date DESC);
