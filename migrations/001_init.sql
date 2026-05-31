CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    hostname TEXT NOT NULL,
    ip_address TEXT NOT NULL DEFAULT '',
    os_name TEXT NOT NULL DEFAULT '',
    os_version TEXT NOT NULL DEFAULT '',
    kernel TEXT NOT NULL DEFAULT '',
    arch TEXT NOT NULL DEFAULT '',
    cpu_model TEXT NOT NULL DEFAULT '',
    cpu_cores INTEGER NOT NULL DEFAULT 0,
    memory_mb BIGINT NOT NULL DEFAULT 0,
    agent_version TEXT NOT NULL DEFAULT '',
    api_key_hash TEXT NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    scan_type TEXT NOT NULL DEFAULT 'daily',
    status TEXT NOT NULL DEFAULT 'running',
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS packages (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    container TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    arch TEXT NOT NULL DEFAULT '',
    pkg_type TEXT NOT NULL DEFAULT 'os',
    src_name TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    package_id TEXT NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    vulnerability_id TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'UNKNOWN',
    title TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    pkg_name TEXT NOT NULL,
    installed_version TEXT NOT NULL DEFAULT '',
    fixed_version TEXT NOT NULL DEFAULT '',
    cvss_score REAL NOT NULL DEFAULT 0,
    cvss_vector TEXT NOT NULL DEFAULT '',
    primary_url TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_accounts (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    uid INTEGER NOT NULL DEFAULT 0,
    gid INTEGER NOT NULL DEFAULT 0,
    home_dir TEXT NOT NULL DEFAULT '',
    shell TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS process_snapshots (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    pid INTEGER NOT NULL,
    name TEXT NOT NULL,
    cmdline TEXT NOT NULL DEFAULT '',
    user_name TEXT NOT NULL DEFAULT '',
    cpu_usage REAL NOT NULL DEFAULT 0,
    mem_usage REAL NOT NULL DEFAULT 0
);

-- Indexes for dashboard queries
CREATE INDEX IF NOT EXISTS idx_scans_host_id ON scans(host_id);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_packages_host_id ON packages(host_id);
CREATE INDEX IF NOT EXISTS idx_packages_scan_id ON packages(scan_id);
CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(name);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_host_id ON vulnerabilities(host_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_vulnerability_id ON vulnerabilities(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cvss_score ON vulnerabilities(cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_user_accounts_scan_id ON user_accounts(scan_id);
CREATE INDEX IF NOT EXISTS idx_process_snapshots_scan_id ON process_snapshots(scan_id);
