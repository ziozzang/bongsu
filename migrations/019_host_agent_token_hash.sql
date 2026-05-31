ALTER TABLE hosts ADD COLUMN IF NOT EXISTS agent_token_hash TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_hosts_agent_token_hash ON hosts(agent_token_hash) WHERE agent_token_hash <> '';
