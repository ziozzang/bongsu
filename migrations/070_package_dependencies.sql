-- Dependency graph: the parent->child edges of a scan's package set, so Bongsu
-- can answer "what (transitively) pulls in this vulnerable package" rather than
-- only "is it present". CycloneDX/SPDX SBOMs carry this graph directly
-- (dependencies / DEPENDS_ON); npm lockfiles carry it per package.
--
-- Edges are keyed by a stable component key (the PURL when known, else the
-- lowercased package name) rather than package ids, so an edge survives even
-- when one endpoint wasn't separately inventoried, and both ingest paths
-- (agent report, SBOM upload) populate the same shape. Edges are per-scan (the
-- graph is a point-in-time snapshot) and cascade-delete with the scan.

CREATE TABLE IF NOT EXISTS package_dependencies (
    id         BIGSERIAL PRIMARY KEY,
    scan_id    TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    parent_key TEXT NOT NULL,
    child_key  TEXT NOT NULL,
    UNIQUE (scan_id, parent_key, child_key)
);

CREATE INDEX IF NOT EXISTS idx_package_dependencies_scan_child ON package_dependencies (scan_id, child_key);
CREATE INDEX IF NOT EXISTS idx_package_dependencies_scan_parent ON package_dependencies (scan_id, parent_key);
