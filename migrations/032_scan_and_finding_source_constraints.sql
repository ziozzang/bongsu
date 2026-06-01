UPDATE vulnerabilities
SET finding_source='scanner'
WHERE trim(finding_source) = ''
   OR finding_source NOT IN ('scanner', 'cve-db');

UPDATE scans
SET scan_type='inventory'
WHERE trim(scan_type) = ''
   OR scan_type NOT IN ('inventory', 'daily', 'manual', 'security-db-update');

UPDATE scans
SET status='failed'
WHERE trim(status) = ''
   OR status NOT IN ('running', 'completed', 'degraded', 'failed');

ALTER TABLE vulnerabilities
DROP CONSTRAINT IF EXISTS vulnerabilities_finding_source_check;

ALTER TABLE vulnerabilities
ADD CONSTRAINT vulnerabilities_finding_source_check
CHECK (finding_source IN ('scanner', 'cve-db'));

ALTER TABLE scans
DROP CONSTRAINT IF EXISTS scans_status_check;

ALTER TABLE scans
ADD CONSTRAINT scans_status_check
CHECK (status IN ('running', 'completed', 'degraded', 'failed'));

ALTER TABLE scans
DROP CONSTRAINT IF EXISTS scans_scan_type_check;

ALTER TABLE scans
ADD CONSTRAINT scans_scan_type_check
CHECK (scan_type IN ('inventory', 'daily', 'manual', 'security-db-update'));
