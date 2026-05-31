ALTER TABLE cve_database ADD COLUMN IF NOT EXISTS epss_score REAL NOT NULL DEFAULT 0;
ALTER TABLE cve_database ADD COLUMN IF NOT EXISTS epss_percentile REAL NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_cve_db_epss_score ON cve_database(epss_score DESC);
CREATE INDEX IF NOT EXISTS idx_cve_db_epss_percentile ON cve_database(epss_percentile DESC);
