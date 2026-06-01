ALTER TABLE scan_requests
DROP CONSTRAINT IF EXISTS scan_requests_status_check;

ALTER TABLE scan_requests
ADD CONSTRAINT scan_requests_status_check
CHECK (status IN ('pending', 'claimed', 'completed', 'degraded', 'failed', 'cancelled'));
