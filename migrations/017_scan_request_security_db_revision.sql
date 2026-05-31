ALTER TABLE scan_requests
ADD COLUMN IF NOT EXISTS security_db_revision TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_scan_requests_security_db_revision
ON scan_requests(security_db_revision)
WHERE security_db_revision <> '';
