-- Human-approval queue for AI-proposed actions that the policy engine ruled as
-- "ask" (assisted mode). An admin approves (the action is then executed) or
-- rejects. Generic across action types so future autonomous actions reuse it.
CREATE TABLE IF NOT EXISTS ai_action_approvals (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    action_type TEXT NOT NULL,                 -- e.g. triage.suppress
    subject TEXT NOT NULL DEFAULT '',          -- e.g. the vulnerability_id
    proposed JSONB NOT NULL DEFAULT '{}',       -- the concrete action payload to execute on approval
    context JSONB NOT NULL DEFAULT '{}',         -- supporting facts / model reasoning
    confidence REAL NOT NULL DEFAULT 0,
    rule TEXT NOT NULL DEFAULT '',               -- policy rule that produced the ask
    reason TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at TIMESTAMPTZ,
    decided_by TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_ai_action_approvals_status ON ai_action_approvals(status, created_at DESC);
-- Avoid duplicate pending approvals for the same proposed action.
CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_action_approvals_pending
    ON ai_action_approvals(action_type, subject)
    WHERE status = 'pending';
