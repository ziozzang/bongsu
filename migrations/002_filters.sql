CREATE INDEX IF NOT EXISTS idx_packages_pkg_type ON packages(pkg_type);
CREATE INDEX IF NOT EXISTS idx_packages_container ON packages(container);
CREATE INDEX IF NOT EXISTS idx_packages_source ON packages(source);
CREATE INDEX IF NOT EXISTS idx_packages_host_container ON packages(host_id, container);
