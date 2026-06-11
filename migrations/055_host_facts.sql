-- Flexible, unstructured host facts collected by the agent (cpu, memory, os,
-- dmi/hardware, network, kernel, virtualization, etc.). Stored as JSONB so the
-- schema can evolve without migrations.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS facts JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS facts_collected_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_hosts_facts ON hosts USING gin (facts);
