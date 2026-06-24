-- SBOM provenance: store the CycloneDX/SPDX BOM produced or ingested for a scan,
-- pinned to the scan (and thus to a point in time), so an operator can answer
-- "exactly what was installed on this asset at scan time" during incident
-- response — the practice of retaining a commit-pinned SBOM, applied to Bongsu's
-- continuous scans.
--
-- One row per (scan, format): the generated CycloneDX/SPDX export and any
-- ingested source SBOM are stored side by side. `bom` is the verbatim document;
-- `source_ref` records provenance (e.g. an ingested SBOM's serialNumber or the
-- subject the CI submitted). Rows cascade-delete with their scan, and a
-- retention sweep (BONGSU_SBOM_RETENTION_DAYS) trims old documents.

CREATE TABLE IF NOT EXISTS scan_sboms (
    id           BIGSERIAL PRIMARY KEY,
    scan_id      TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host_id      TEXT NOT NULL DEFAULT '',
    format       TEXT NOT NULL,                 -- 'cyclonedx' | 'spdx'
    origin       TEXT NOT NULL DEFAULT 'ingested', -- 'ingested' | 'generated'
    spec_version TEXT NOT NULL DEFAULT '',
    source_ref   TEXT NOT NULL DEFAULT '',
    component_count INT NOT NULL DEFAULT 0,
    bom          JSONB NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scan_id, format, origin)
);

CREATE INDEX IF NOT EXISTS idx_scan_sboms_scan ON scan_sboms (scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_sboms_host_created ON scan_sboms (host_id, created_at DESC);
