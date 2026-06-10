-- Per-finding assignee for vulnerability triage (담당자 할당).
ALTER TABLE vulnerability_triage ADD COLUMN IF NOT EXISTS assignee TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_vulnerability_triage_assignee
    ON vulnerability_triage(assignee) WHERE assignee <> '';
