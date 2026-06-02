CREATE TABLE IF NOT EXISTS scheduled_scans (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    name TEXT NOT NULL,
    cron_expr TEXT NOT NULL,
    scan_type TEXT NOT NULL DEFAULT 'manual' CHECK (scan_type IN ('manual', 'daily', 'security-db-update')),
    host_filter TEXT NOT NULL DEFAULT '',
    packages_only BOOLEAN NOT NULL DEFAULT true,
    enabled BOOLEAN NOT NULL DEFAULT true,
    last_run TIMESTAMPTZ,
    next_run TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scheduled_scans_enabled ON scheduled_scans(enabled) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_scheduled_scans_next_run ON scheduled_scans(next_run) WHERE enabled = true AND next_run IS NOT NULL;
