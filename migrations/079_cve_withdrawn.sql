-- Core matcher accuracy (design: docs/redesign-matcher-accuracy-trinity.md).
-- Record the OSV `withdrawn` timestamp so retracted advisories can be excluded
-- from matching. NULL = active (backward compatible: every existing row stays
-- matchable). The per-CPE `vulnerable:false` flag needs no schema change — it
-- rides inside affected_products JSONB elements and is honored at match time.

ALTER TABLE cve_database
    ADD COLUMN IF NOT EXISTS withdrawn TIMESTAMPTZ;

-- Most advisories are active; a partial index keeps the common "active only"
-- match scans cheap without indexing the rare withdrawn rows.
CREATE INDEX IF NOT EXISTS idx_cve_database_active
    ON cve_database (source, vulnerability_id) WHERE withdrawn IS NULL;

COMMENT ON COLUMN cve_database.withdrawn IS
    'OSV withdrawn timestamp; NULL = active advisory (backward compatible).';
