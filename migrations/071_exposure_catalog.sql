-- Exposure catalog (absorbed from perplexityai/bumblebee, Apache-2.0): a curated
-- list of KNOWN-COMPROMISED package releases matched by EXACT
-- (ecosystem, name, version) — supply-chain IOC detection, a distinct axis from
-- Bongsu's version-range CVE matching. A CVE says "this version range is
-- vulnerable"; an exposure entry says "this exact release is a known-malicious
-- artifact" (e.g. a poisoned npm/PyPI release from a supply-chain attack).

-- One row per uploaded catalog file (provenance + atomic replace unit).
CREATE TABLE IF NOT EXISTS exposure_catalog_sources (
    id              BIGSERIAL PRIMARY KEY,
    source_name     TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL DEFAULT '',
    schema_version  TEXT NOT NULL DEFAULT '0.1.0',
    entry_count     INTEGER NOT NULL DEFAULT 0,
    checksum_sha256 TEXT NOT NULL DEFAULT '',
    uploaded_by     TEXT NOT NULL DEFAULT '',
    active          BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Flattened one row per (entry, version): the bumblebee entries[].versions[]
-- array is exploded so each affected release is a single matchable tuple.
-- ecosystem + normalized_name are stored already normalized (Bongsu's
-- normalizeEcosystem + normalizePkgName), so the match is a plain equi-join.
CREATE TABLE IF NOT EXISTS exposure_catalog_entries (
    id              BIGSERIAL PRIMARY KEY,
    source_id       BIGINT NOT NULL REFERENCES exposure_catalog_sources(id) ON DELETE CASCADE,
    catalog_id      TEXT NOT NULL,
    catalog_name    TEXT NOT NULL DEFAULT '',
    ecosystem       TEXT NOT NULL,
    package_name    TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    version         TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'critical',
    confidence      TEXT NOT NULL DEFAULT 'high',
    evidence        TEXT NOT NULL DEFAULT 'exact name+version match',
    raw_entry       JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source_id, catalog_id, ecosystem, normalized_name, version)
);

-- Match index is intentionally NON-unique: two catalogs may list the same
-- compromised release (e.g. overlapping campaign reports). Finding-level dedup is
-- handled by finding_key, not by forbidding the second catalog row.
CREATE INDEX IF NOT EXISTS idx_exposure_match
    ON exposure_catalog_entries (ecosystem, normalized_name, version);
CREATE INDEX IF NOT EXISTS idx_exposure_source ON exposure_catalog_entries (source_id);

-- Exposure findings reuse the vulnerabilities table (triage/VEX/notify/risk
-- machinery). Two non-destructive columns carry the exposure-specific provenance.
ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS catalog_id TEXT,
    ADD COLUMN IF NOT EXISTS exposure_confidence TEXT;

-- Admit the new finding source (see migration 032).
ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS vulnerabilities_finding_source_check;
ALTER TABLE vulnerabilities ADD CONSTRAINT vulnerabilities_finding_source_check
    CHECK (finding_source IN ('scanner', 'cve-db', 'exposure-catalog'));

-- SQL twin of Go normalizePkgName: must stay in sync (asserted by tests). The
-- ecosystem argument is the already-normalized family (pypi/npm/maven/...).
CREATE OR REPLACE FUNCTION bongsu_normalize_pkg_name(eco TEXT, name TEXT)
RETURNS TEXT AS $$
    SELECT CASE
        WHEN eco = 'pypi'  THEN lower(regexp_replace(btrim(name), '[-_.]+', '-', 'g'))
        WHEN eco = 'maven' THEN btrim(name)
        ELSE lower(btrim(name))
    END
$$ LANGUAGE sql IMMUTABLE;
