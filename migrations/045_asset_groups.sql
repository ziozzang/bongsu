CREATE TABLE IF NOT EXISTS asset_groups (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    rule_type TEXT NOT NULL DEFAULT 'static' CHECK (rule_type IN ('static', 'dynamic')),
    rule_expr TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS asset_group_members (
    group_id TEXT NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, host_id)
);
CREATE INDEX IF NOT EXISTS idx_asset_group_members_host ON asset_group_members(host_id);
