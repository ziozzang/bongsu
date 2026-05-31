-- A CVE DB update that arrives while an earlier automatic rescan is already
-- claimed must leave a follow-up pending request. Only pending auto-rescans are
-- unique per host; claimed requests are allowed to finish independently.

DROP INDEX IF EXISTS idx_scan_requests_active_security_db_host;

WITH ranked AS (
    SELECT
        id,
        row_number() OVER (PARTITION BY host_id ORDER BY created_at ASC, id ASC) AS rn
    FROM scan_requests
    WHERE host_id <> ''
      AND scan_type = 'security-db-update'
      AND status = 'pending'
)
UPDATE scan_requests sr
SET status = 'cancelled',
    completed_at = now(),
    error_message = 'cancelled duplicate pending security-db-update request during migration'
FROM ranked
WHERE sr.id = ranked.id
  AND ranked.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_requests_pending_security_db_host
    ON scan_requests(host_id)
    WHERE host_id <> ''
      AND scan_type = 'security-db-update'
      AND status = 'pending';
