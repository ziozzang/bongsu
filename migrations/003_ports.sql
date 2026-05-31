CREATE TABLE IF NOT EXISTS port_info (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name TEXT NOT NULL DEFAULT '',
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT '',
    address TEXT NOT NULL DEFAULT '',
    pid INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_port_info_scan_id ON port_info(scan_id);
CREATE INDEX IF NOT EXISTS idx_port_info_host_id ON port_info(host_id);
