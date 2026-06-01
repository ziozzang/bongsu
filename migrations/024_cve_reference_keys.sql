CREATE TABLE IF NOT EXISTS cve_reference_keys (
    cve_id TEXT NOT NULL REFERENCES cve_database(id) ON DELETE CASCADE,
    reference_key TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (cve_id, reference_key)
);

CREATE INDEX IF NOT EXISTS idx_cve_reference_keys_key
    ON cve_reference_keys(reference_key);

CREATE INDEX IF NOT EXISTS idx_cve_reference_keys_cve_id
    ON cve_reference_keys(cve_id);
