CREATE TABLE IF NOT EXISTS notification_log (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    rule_id TEXT NOT NULL REFERENCES notification_rules(id) ON DELETE CASCADE,
    trigger_event TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'sent' CHECK (status IN ('sent', 'failed')),
    payload JSONB NOT NULL DEFAULT '{}',
    error_message TEXT NOT NULL DEFAULT '',
    attempts INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notification_log_rule ON notification_log(rule_id, created_at DESC);
