-- Prevent concurrent security DB update hooks from creating duplicate active
-- package-only rescan work for the same host.

WITH ranked AS (
    SELECT
        id,
        row_number() OVER (PARTITION BY host_id ORDER BY created_at ASC, id ASC) AS rn
    FROM scan_requests
    WHERE host_id <> ''
      AND scan_type = 'security-db-update'
      AND status IN ('pending', 'claimed')
)
UPDATE scan_requests sr
SET status = 'cancelled',
    completed_at = now(),
    error_message = 'cancelled duplicate active security-db-update request during migration'
FROM ranked
WHERE sr.id = ranked.id
  AND ranked.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_requests_active_security_db_host
    ON scan_requests(host_id)
    WHERE host_id <> ''
      AND scan_type = 'security-db-update'
      AND status IN ('pending', 'claimed');
