ALTER TABLE scan_requests
ADD COLUMN IF NOT EXISTS claimed_by_host_id TEXT NOT NULL DEFAULT '';

UPDATE scan_requests
SET claimed_by_host_id = host_id
WHERE status = 'claimed'
  AND claimed_by_host_id = ''
  AND host_id <> '';

UPDATE scan_requests
SET status = 'pending',
    claimed_at = NULL,
    error_message = 'requeued during claimed host ownership migration'
WHERE status = 'claimed'
  AND claimed_by_host_id = ''
  AND host_id = '';

CREATE INDEX IF NOT EXISTS idx_scan_requests_claimed_by_host
ON scan_requests(claimed_by_host_id)
WHERE claimed_by_host_id <> '';
