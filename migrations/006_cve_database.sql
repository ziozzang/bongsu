-- Unified CVE database from multiple sources (NVD, OSV, Trivy, etc.)
CREATE TABLE IF NOT EXISTS cve_database (
    id TEXT PRIMARY KEY,
    vulnerability_id TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT '',
    cvss_score REAL NOT NULL DEFAULT 0,
    cvss_vector TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    published_date TIMESTAMPTZ,
    modified_date TIMESTAMPTZ,
    affected_products JSONB DEFAULT '[]',
    refs JSONB DEFAULT '[]',
    raw_data JSONB DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_cve_db_vulnerability_id_source ON cve_database(vulnerability_id, source);
CREATE INDEX IF NOT EXISTS idx_cve_db_severity ON cve_database(severity);
CREATE INDEX IF NOT EXISTS idx_cve_db_cvss_score ON cve_database(cvss_score);
CREATE INDEX IF NOT EXISTS idx_cve_db_source ON cve_database(source);
CREATE INDEX IF NOT EXISTS idx_cve_db_published ON cve_database(published_date);
CREATE INDEX IF NOT EXISTS idx_cve_db_description ON cve_database USING gin(to_tsvector('english', description));
CREATE INDEX IF NOT EXISTS idx_cve_db_title ON cve_database USING gin(to_tsvector('english', title));
