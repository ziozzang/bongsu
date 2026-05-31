-- Asset ontology, security source sync state, and RBAC foundations.

CREATE TABLE IF NOT EXISTS security_sources (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'vulnerability',
    category TEXT NOT NULL DEFAULT '',
    ecosystems TEXT[] NOT NULL DEFAULT '{}',
    update_url TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT true,
    update_interval_seconds INTEGER NOT NULL DEFAULT 21600,
    last_sync_started_at TIMESTAMPTZ,
    last_sync_finished_at TIMESTAMPTZ,
    last_exported_at TIMESTAMPTZ,
    last_status TEXT NOT NULL DEFAULT 'never',
    last_error TEXT NOT NULL DEFAULT '',
    record_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO security_sources (id, name, category, ecosystems, update_interval_seconds)
VALUES
    ('osv', 'OSV.dev', 'code-library', ARRAY['PyPI','npm','Go','Maven','crates.io','NuGet','RubyGems','Packagist','Alpine','Debian'], 21600),
    ('nvd', 'NVD CVE 2.0', 'general-cve', ARRAY[]::TEXT[], 21600),
    ('trivy', 'Trivy vulnerability DB', 'os-package', ARRAY['Debian','Ubuntu','Alpine','RHEL','SUSE','Amazon Linux','Wolfi'], 21600)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS container_assets (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    runtime TEXT NOT NULL DEFAULT 'docker',
    container_id TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    image_name TEXT NOT NULL DEFAULT '',
    image_id TEXT NOT NULL DEFAULT '',
    image_digest TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT '',
    labels JSONB NOT NULL DEFAULT '{}',
    started_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE packages ADD COLUMN IF NOT EXISTS asset_type TEXT NOT NULL DEFAULT 'host';
ALTER TABLE packages ADD COLUMN IF NOT EXISTS asset_id TEXT NOT NULL DEFAULT '';
ALTER TABLE packages ADD COLUMN IF NOT EXISTS container_id TEXT NOT NULL DEFAULT '';
ALTER TABLE packages ADD COLUMN IF NOT EXISTS image_name TEXT NOT NULL DEFAULT '';
ALTER TABLE packages ADD COLUMN IF NOT EXISTS image_id TEXT NOT NULL DEFAULT '';
ALTER TABLE packages ADD COLUMN IF NOT EXISTS ecosystem TEXT NOT NULL DEFAULT '';
ALTER TABLE packages ADD COLUMN IF NOT EXISTS purl TEXT NOT NULL DEFAULT '';

ALTER TABLE cve_database ADD COLUMN IF NOT EXISTS category TEXT NOT NULL DEFAULT '';
ALTER TABLE cve_database ADD COLUMN IF NOT EXISTS ecosystem TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS access_subjects (
    id TEXT PRIMARY KEY,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('user', 'group')),
    external_id TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (subject_type, external_id)
);

CREATE TABLE IF NOT EXISTS access_policies (
    id TEXT PRIMARY KEY,
    subject_id TEXT NOT NULL REFERENCES access_subjects(id) ON DELETE CASCADE,
    resource_type TEXT NOT NULL CHECK (resource_type IN ('host', 'container', 'image', 'asset_group', 'all')),
    resource_id TEXT NOT NULL DEFAULT '*',
    permission TEXT NOT NULL CHECK (permission IN ('read', 'write', 'admin')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (subject_id, resource_type, resource_id, permission)
);

CREATE TABLE IF NOT EXISTS scan_requests (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL DEFAULT '',
    requested_by TEXT NOT NULL DEFAULT '',
    scan_type TEXT NOT NULL DEFAULT 'manual',
    packages_only BOOLEAN NOT NULL DEFAULT true,
    reason TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'claimed', 'completed', 'failed', 'cancelled')),
    error_message TEXT NOT NULL DEFAULT '',
    claimed_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE scan_requests ADD COLUMN IF NOT EXISTS error_message TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_security_sources_status ON security_sources(last_status);
CREATE INDEX IF NOT EXISTS idx_container_assets_scan_id ON container_assets(scan_id);
CREATE INDEX IF NOT EXISTS idx_container_assets_host_id ON container_assets(host_id);
CREATE INDEX IF NOT EXISTS idx_container_assets_container_id ON container_assets(container_id);
CREATE INDEX IF NOT EXISTS idx_container_assets_image_name ON container_assets(image_name);
CREATE INDEX IF NOT EXISTS idx_packages_asset ON packages(asset_type, asset_id);
CREATE INDEX IF NOT EXISTS idx_packages_ecosystem ON packages(ecosystem);
CREATE INDEX IF NOT EXISTS idx_packages_purl ON packages(purl);
CREATE INDEX IF NOT EXISTS idx_cve_db_category ON cve_database(category);
CREATE INDEX IF NOT EXISTS idx_cve_db_ecosystem ON cve_database(ecosystem);
CREATE INDEX IF NOT EXISTS idx_access_policies_subject ON access_policies(subject_id);
CREATE INDEX IF NOT EXISTS idx_access_policies_resource ON access_policies(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_scan_requests_host_status ON scan_requests(host_id, status);
CREATE INDEX IF NOT EXISTS idx_scan_requests_status ON scan_requests(status);
