CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS idx_cve_db_vulnerability_id_trgm
ON cve_database USING gin (vulnerability_id gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_cve_db_title_trgm
ON cve_database USING gin (title gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_cve_db_description_trgm
ON cve_database USING gin (description gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_cve_affected_pkg_name_trgm
ON cve_affected_packages USING gin (package_name gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_cve_affected_ecosystem_trgm
ON cve_affected_packages USING gin (ecosystem gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_cve_affected_fixed_version_trgm
ON cve_affected_packages USING gin (fixed_version gin_trgm_ops);
