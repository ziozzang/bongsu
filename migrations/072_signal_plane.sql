-- secdb plane separation, phase 1 (signal plane). KEV (exploited-in-the-wild
-- boolean signal) and EPSS (exploit-probability score) are conceptually NOT
-- advisories — they are CVE-id-keyed enrichment signals — but were stored inside
-- cve_database (source='cisa-kev' rows; source='epss' rows + epss_score/
-- epss_percentile columns double-stored). That forced `WHERE source != 'epss'` /
-- `NOT IN ('cisa-kev','epss')` filters across nearly every advisory query.
--
-- This migration is NON-DESTRUCTIVE: it creates dedicated signal tables and
-- backfills them from the current data. The Go read path cuts over to these
-- tables in the same change; the cve_database signal rows/columns are removed in
-- a later migration only after the cutover is proven (rollback safety).

CREATE TABLE IF NOT EXISTS cve_kev (
    vulnerability_id TEXT PRIMARY KEY,
    source           TEXT NOT NULL DEFAULT 'cisa-kev',
    known_ransomware BOOLEAN NOT NULL DEFAULT false,
    date_added       TIMESTAMPTZ,
    due_date         TIMESTAMPTZ,
    raw_data         JSONB NOT NULL DEFAULT '{}',
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cve_epss (
    vulnerability_id TEXT PRIMARY KEY,
    score            REAL NOT NULL DEFAULT 0,
    percentile       REAL NOT NULL DEFAULT 0,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cve_epss_score ON cve_epss (score DESC);

-- Backfill KEV from existing cisa-kev advisory rows.
INSERT INTO cve_kev (vulnerability_id, source, raw_data, updated_at)
SELECT DISTINCT ON (vulnerability_id)
       vulnerability_id, 'cisa-kev', COALESCE(raw_data, '{}'::jsonb), now()
FROM cve_database
WHERE source = 'cisa-kev' AND vulnerability_id <> ''
ORDER BY vulnerability_id, updated_at DESC
ON CONFLICT (vulnerability_id) DO NOTHING;

-- Backfill EPSS from the authoritative source='epss' rows.
INSERT INTO cve_epss (vulnerability_id, score, percentile, updated_at)
SELECT DISTINCT ON (vulnerability_id)
       vulnerability_id, epss_score, epss_percentile, now()
FROM cve_database
WHERE source = 'epss' AND vulnerability_id <> '' AND (epss_score > 0 OR epss_percentile > 0)
ORDER BY vulnerability_id, updated_at DESC, epss_score DESC, epss_percentile DESC
ON CONFLICT (vulnerability_id) DO NOTHING;
