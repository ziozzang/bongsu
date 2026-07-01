-- Interactive-audit sessions for the intelligence layer: a run may carry the
-- backbone session id so a follow-up run builds on the earlier conversation
-- (the "continue questioning the finding" workflow). The id is jikji's session
-- id, stored per run so an operator can chain related runs and trace a session.

ALTER TABLE intel_runs ADD COLUMN IF NOT EXISTS session_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_intel_runs_session ON intel_runs (session_id, started_at) WHERE session_id <> '';
