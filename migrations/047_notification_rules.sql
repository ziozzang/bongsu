CREATE TABLE IF NOT EXISTS notification_rules (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    name TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    trigger_event TEXT NOT NULL DEFAULT '' CHECK (trigger_event IN ('', 'vuln.new_critical', 'vuln.new_high', 'sla.breach', 'scan.completed', 'security_db.updated', 'schedule.daily')),
    min_severity TEXT NOT NULL DEFAULT '' CHECK (min_severity IN ('', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    min_risk_level TEXT NOT NULL DEFAULT '' CHECK (min_risk_level IN ('', 'critical', 'high', 'medium', 'low')),
    exploited_only BOOLEAN NOT NULL DEFAULT false,
    host_filter TEXT NOT NULL DEFAULT '',
    channel_type TEXT NOT NULL DEFAULT 'webhook' CHECK (channel_type IN ('webhook', 'log')),
    channel_config JSONB NOT NULL DEFAULT '{}',
    last_triggered TIMESTAMPTZ,
    trigger_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notification_rules_enabled ON notification_rules(enabled) WHERE enabled = true;
