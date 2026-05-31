-- Operator-owned host metadata for prioritization, routing, and reporting.

ALTER TABLE hosts ADD COLUMN IF NOT EXISTS owner TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS team TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS environment TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS criticality TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS tags JSONB NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_hosts_owner ON hosts(owner);
CREATE INDEX IF NOT EXISTS idx_hosts_team ON hosts(team);
CREATE INDEX IF NOT EXISTS idx_hosts_environment ON hosts(environment);
CREATE INDEX IF NOT EXISTS idx_hosts_criticality ON hosts(criticality);
