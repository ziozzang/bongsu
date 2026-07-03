-- Pipeline stage isolation (design: docs/redesign-pipeline-isolation-trinity.md).
-- Pipeline stages now run in INDEPENDENT backbone sessions (session-threading
-- polluted later stages into echoing raw tool output). A pipeline run is instead
-- correlated by a shared pipeline_run_id stamped on each stage's intel_runs row;
-- session_id keeps its original meaning (a single run's backbone session).

ALTER TABLE intel_runs
    ADD COLUMN IF NOT EXISTS pipeline_run_id UUID;

CREATE INDEX IF NOT EXISTS idx_intel_runs_pipeline_run_id
    ON intel_runs (pipeline_run_id) WHERE pipeline_run_id IS NOT NULL;
