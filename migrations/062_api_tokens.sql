-- DB-backed, rotatable API tokens. Complements the static env keys
-- (BONGSU_API_KEY / BONGSU_VIEWER_API_KEYS): these can be created, scoped,
-- expired, and revoked at runtime without a server restart. Only the SHA-256
-- hash of the secret is stored; the plaintext is shown to the operator once at
-- creation time.
CREATE TABLE IF NOT EXISTS api_tokens (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,         -- sha256 hex of the secret
    prefix TEXT NOT NULL DEFAULT '',         -- first chars of the secret, for display only
    role TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
    subject TEXT NOT NULL DEFAULT '',        -- RBAC subject for viewer tokens (e.g. user:alice)
    created_by TEXT NOT NULL DEFAULT '',     -- actor that created the token
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,                  -- NULL = never expires
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_token_hash ON api_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_api_tokens_active
    ON api_tokens(token_hash)
    WHERE revoked_at IS NULL;
