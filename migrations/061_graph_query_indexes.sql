-- Supporting indexes for the asset knowledge graph queries (internal/server/db/
-- graph.go, graph_ext.go). These back the joins/predicates that the graph
-- endpoints run at scale; without them the planner falls back to sequential
-- scans on large inventories.

-- ExposedServices: the LATERAL process lookup joins process_snapshots by
-- (host_id, pid) within the latest scan. Only scan_id was indexed before.
CREATE INDEX IF NOT EXISTS idx_process_snapshots_host_pid
    ON process_snapshots(host_id, pid);

-- ExposedServices: scoped, latest-scan port lookup filters by (host_id, scan_id);
-- the address predicate is evaluated after, but this composite avoids scanning
-- all ports for a host's scan history.
CREATE INDEX IF NOT EXISTS idx_port_info_host_scan
    ON port_info(host_id, scan_id);

-- Images: container packages are joined by (host_id, scan_id, container_id) for
-- asset_type='container'. A partial composite keeps it an index probe.
CREATE INDEX IF NOT EXISTS idx_packages_container_link
    ON packages(host_id, scan_id, container_id)
    WHERE asset_type = 'container';

-- Images: containers are grouped by image_digest (fallback image_name); index the
-- digest so the grouping/scan join is index-driven.
CREATE INDEX IF NOT EXISTS idx_container_assets_image_digest
    ON container_assets(image_digest);

-- KEV semijoin: the graph builds a `WITH kev AS (SELECT DISTINCT vulnerability_id
-- FROM cve_database WHERE source='cisa-kev')` CTE. A partial index on the KEV
-- subset makes that an index-only scan over ~1-2k rows instead of touching the
-- full ~1M-row cve_database via the source index.
CREATE INDEX IF NOT EXISTS idx_cve_database_kev_vuln
    ON cve_database(vulnerability_id)
    WHERE source = 'cisa-kev';
