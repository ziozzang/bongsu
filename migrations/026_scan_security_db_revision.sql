ALTER TABLE scans
ADD COLUMN IF NOT EXISTS security_db_revision TEXT NOT NULL DEFAULT '';

ALTER TABLE scans
ADD COLUMN IF NOT EXISTS scan_request_id TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_scans_security_db_revision
ON scans(security_db_revision)
WHERE security_db_revision <> '';

CREATE INDEX IF NOT EXISTS idx_scans_scan_request_id
ON scans(scan_request_id)
WHERE scan_request_id <> '';
