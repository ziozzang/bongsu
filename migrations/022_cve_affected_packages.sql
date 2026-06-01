CREATE TABLE IF NOT EXISTS cve_affected_packages (
    cve_id TEXT NOT NULL REFERENCES cve_database(id) ON DELETE CASCADE,
    vulnerability_id TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    package_name TEXT NOT NULL DEFAULT '',
    ecosystem TEXT NOT NULL DEFAULT '',
    fixed_version TEXT NOT NULL DEFAULT '',
    affected_product JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (cve_id, package_name, ecosystem, fixed_version)
);

CREATE INDEX IF NOT EXISTS idx_cve_affected_pkg_name_ecosystem
    ON cve_affected_packages(package_name, ecosystem);
CREATE INDEX IF NOT EXISTS idx_cve_affected_vulnerability
    ON cve_affected_packages(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_cve_affected_source
    ON cve_affected_packages(source);
