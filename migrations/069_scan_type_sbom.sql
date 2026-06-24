-- SBOM ingest (POST /api/sbom) creates scans with scan_type 'sbom' so that
-- externally-submitted SBOM scans are distinguishable from agent inventory/daily
-- /manual scans and the internal security-db-update sweep. Extend the existing
-- scan_type check (see 032) to admit it.

ALTER TABLE scans
DROP CONSTRAINT IF EXISTS scans_scan_type_check;

ALTER TABLE scans
ADD CONSTRAINT scans_scan_type_check
CHECK (scan_type IN ('inventory', 'daily', 'manual', 'security-db-update', 'sbom'));
