ALTER TABLE hosts
DROP CONSTRAINT IF EXISTS hosts_identity_nonempty_check;

ALTER TABLE hosts
ADD CONSTRAINT hosts_identity_nonempty_check
CHECK (trim(id) <> '' AND trim(hostname) <> '');

ALTER TABLE scans
DROP CONSTRAINT IF EXISTS scans_identity_nonempty_check;

ALTER TABLE scans
ADD CONSTRAINT scans_identity_nonempty_check
CHECK (trim(id) <> '' AND trim(host_id) <> '' AND trim(scan_type) <> '' AND trim(status) <> '');

ALTER TABLE packages
DROP CONSTRAINT IF EXISTS packages_identity_nonempty_check;

ALTER TABLE packages
ADD CONSTRAINT packages_identity_nonempty_check
CHECK (trim(id) <> '' AND trim(scan_id) <> '' AND trim(host_id) <> '' AND trim(name) <> '' AND trim(source) <> '' AND trim(pkg_type) <> '');

ALTER TABLE vulnerabilities
DROP CONSTRAINT IF EXISTS vulnerabilities_identity_nonempty_check;

ALTER TABLE vulnerabilities
ADD CONSTRAINT vulnerabilities_identity_nonempty_check
CHECK (trim(id) <> '' AND trim(package_id) <> '' AND trim(scan_id) <> '' AND trim(host_id) <> '' AND trim(vulnerability_id) <> '' AND trim(pkg_name) <> '');

ALTER TABLE cve_database
DROP CONSTRAINT IF EXISTS cve_database_identity_nonempty_check;

ALTER TABLE cve_database
ADD CONSTRAINT cve_database_identity_nonempty_check
CHECK (trim(id) <> '' AND trim(vulnerability_id) <> '' AND trim(source) <> '');
