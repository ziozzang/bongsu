-- Queue-backed rescans after vulnerability database updates.

CREATE INDEX IF NOT EXISTS idx_scan_requests_active_host
    ON scan_requests(host_id)
    WHERE status IN ('pending', 'claimed');

CREATE INDEX IF NOT EXISTS idx_hosts_last_seen ON hosts(last_seen);
