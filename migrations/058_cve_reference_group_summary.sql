-- Materialized per-reference-key group counts so CVE search reads summaries
-- with a primary-key lookup instead of joining cve_reference_keys (1.7M+ rows)
-- live on every page. Refreshed by the reference-index rebuild and the
-- security recalculation job.
CREATE TABLE IF NOT EXISTS cve_reference_group_summary (
    reference_key TEXT PRIMARY KEY,
    total INT NOT NULL DEFAULT 0,
    matchable INT NOT NULL DEFAULT 0,
    sources INT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
