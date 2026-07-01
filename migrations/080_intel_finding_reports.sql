-- Finding-report persistence (design: docs/redesign-finding-reports-trinity.md).
-- The `report` scenario produces a CVE-grade structured report with a stable
-- dedup_key. Persisting it here — keyed UNIQUE by dedup_key — turns ephemeral
-- per-run outputs into an accumulating, deduplicated asset: re-reporting the same
-- finding collapses onto one row and bumps seen_count/last_seen.

CREATE TABLE IF NOT EXISTS intel_finding_reports (
    id            BIGSERIAL PRIMARY KEY,
    dedup_key     TEXT NOT NULL,
    finding       TEXT NOT NULL,
    summary       TEXT NOT NULL DEFAULT '',
    severity      TEXT NOT NULL DEFAULT 'unknown'
                  CHECK (severity IN ('critical','high','medium','low','info','unknown')),
    cvss          NUMERIC(3,1) CHECK (cvss IS NULL OR (cvss >= 0 AND cvss <= 10)),
    report        JSONB NOT NULL DEFAULT '{}'::jsonb,
    run_id        UUID REFERENCES intel_runs(id) ON DELETE SET NULL,
    principal_id  TEXT NOT NULL DEFAULT '',
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    seen_count    INTEGER NOT NULL DEFAULT 1,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT intel_finding_reports_dedup_key_nonempty CHECK (length(trim(dedup_key)) > 0),
    CONSTRAINT intel_finding_reports_seen_count_positive CHECK (seen_count > 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS intel_finding_reports_dedup_key_uq
    ON intel_finding_reports (dedup_key);
CREATE INDEX IF NOT EXISTS intel_finding_reports_last_seen_idx
    ON intel_finding_reports (last_seen DESC);
CREATE INDEX IF NOT EXISTS intel_finding_reports_severity_idx
    ON intel_finding_reports (severity);
