-- Security-intelligence backbone persistence (design:
-- docs/redesign-intel-backbone-trinity.md). An "intel run" is one agentic
-- reasoning pass the jikji backbone performs over Bongsu's security data for a
-- scenario (triage, correlation, remediation, ...). Every run and every tool the
-- agent invokes is recorded: the run snapshots the caller's RBAC scope at start
-- (forensics + reproducibility), and tool calls are audited 100% so an operator
-- can see exactly what data the intelligence layer read and produced.
--
-- These tables are the ONLY writes the intelligence layer performs (tools
-- themselves are read-only); they are isolated from the scan/match pipeline,
-- which never references them.

CREATE TABLE IF NOT EXISTS intel_runs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scenario        TEXT NOT NULL,
    goal            TEXT NOT NULL DEFAULT '',
    principal_id    TEXT NOT NULL DEFAULT '',
    principal_scope JSONB NOT NULL DEFAULT '{}',   -- RBAC snapshot at run start
    status          TEXT NOT NULL DEFAULT 'pending', -- pending|running|completed|failed|timeout|cancelled
    tools_injected  TEXT[] NOT NULL DEFAULT '{}',
    output          JSONB,
    error           TEXT NOT NULL DEFAULT '',
    token_usage     JSONB NOT NULL DEFAULT '{}',
    dropped_audits  INTEGER NOT NULL DEFAULT 0,     -- audit-channel overflow counter
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at        TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_intel_runs_scenario_status ON intel_runs (scenario, status);
CREATE INDEX IF NOT EXISTS idx_intel_runs_principal_time ON intel_runs (principal_id, started_at DESC);

CREATE TABLE IF NOT EXISTS intel_tool_calls (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id           UUID NOT NULL REFERENCES intel_runs(id) ON DELETE CASCADE,
    seq              INTEGER NOT NULL DEFAULT 0,
    tool_name        TEXT NOT NULL,
    input_args       JSONB NOT NULL DEFAULT '{}',
    output_result    JSONB,
    output_truncated BOOLEAN NOT NULL DEFAULT false,
    duration_ms      INTEGER NOT NULL DEFAULT 0,
    error            TEXT NOT NULL DEFAULT '',
    called_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_intel_tool_calls_run ON intel_tool_calls (run_id, seq);
