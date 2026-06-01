CREATE INDEX IF NOT EXISTS idx_cve_affected_vuln_pkg_ecosystem
ON cve_affected_packages(vulnerability_id, package_name, ecosystem);
