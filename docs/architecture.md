# Bongsu Architecture

Bongsu means "봉수대": a watchtower network that sends signals from the edge back to a central point. The system follows that model.

## Goals

- Collect host and running-container package inventories with Trivy and optional osquery.
- Send SBOM-like package data to the central server with host, OS, container, image, and runtime context.
- Build and maintain a merged security database from public sources such as OSV, NVD, and Trivy DB.
- Support connected and air-gapped deployments. Connected sites update every 6 hours; air-gapped sites import exported data.
- Separate OS package advisories from code library advisories.
- Provide a web dashboard, one-line agent install, force scan requests, and an RBAC-ready data model.

## Current Implementation

- Server: Go static binary, PostgreSQL, Vite dashboard, Docker Compose deployment.
- Agent: Go static binary. It collects host metadata, users, processes, listening ports, host packages, and running Docker container packages.
- Auth: admin APIs use `BONGSU_API_KEY`; agent report and force-scan polling use `BONGSU_AGENT_API_KEY`; installer and binary downloads can be protected by `BONGSU_INSTALL_TOKEN`; viewer keys from `BONGSU_VIEWER_API_KEYS` are scoped through RBAC policies.
- Matching: packages-only mode sends packages to the server, then the server runs Trivy SBOM matching with the local Trivy DB.
- Security DB: JSONL import/export for `cve_database`, Trivy DB upload/update, source sync command hook via `BONGSU_SECURITY_DB_SYNC_CMD`.
- Airgap: server can import CVE JSONL and Trivy DB archives. The one-line installer downloads the agent and Trivy binaries from the management server.
- Data model: host, scan, package, vulnerability, container asset, security source, scan request, and RBAC policy tables.

## Security Sources

Security sources are classified into:

- `os-package`: Debian, Ubuntu, Alpine, RHEL-family, SUSE, Wolfi/Chainguard, and similar distribution advisories.
- `code-library`: PyPI, npm, Go, Maven, crates.io, NuGet, RubyGems, Packagist, and similar language ecosystems.
- `general-cve`: NVD/CPE-oriented records that may enrich either category.
- `custom`: locally imported or future proprietary feeds.

The merge strategy is:

1. Normalize source records into `cve_database`.
2. Keep source provenance in `source`, `category`, `ecosystem`, `raw_data`, and timestamps.
3. Prefer stronger CVSS scores/vectors and fixed-version data when enriching scan findings.
4. Match by ecosystem-aware identity first. Name-only candidates are discarded unless `affected_products` contains the same package name, compatible ecosystem/category, fixed-version data, and an affected range that contains the installed version.
5. CVSS vectors are recalculated after import for supported CVSS v2, v3.x, and v4.0 formats.

## Connected Update Flow

1. Server has `BONGSU_SECURITY_DB_SYNC_CMD` configured, usually:
   `scripts/sync-all-cvedb.sh http://localhost:8080 $BONGSU_API_KEY`
2. The server runs the command every `BONGSU_SECURITY_DB_INTERVAL_HOURS`, default 6.
3. Scripts download OSV, NVD, and Trivy-derived metadata, then import JSONL through `/api/admin/cve-db/import`.
4. Each successful DB change starts background CVSS recalculation, vulnerability enrichment, CVE rematching, and automatic package-only rescan requests for hosts seen within `BONGSU_AUTO_RESCAN_LAST_SEEN_HOURS` (default 720).
5. Operators export `/api/admin/security-db/export` for air-gapped transfer. The bundle contains a manifest, CVE JSONL, source stats, and optionally the current Trivy DB archive.

## Air-Gapped Flow

1. In a connected environment, build Docker images and static binaries.
2. Download/update Trivy DB and CVE JSONL exports.
3. Transfer images, binaries, Trivy DB archive, and CVE JSONL into the air-gapped network.
4. Start Docker Compose without online DB updates.
5. Import Trivy DB through `/api/admin/trivy-db`.
6. Import CVE JSONL through `/api/admin/cve-db/import`.

The implemented bundle is a versioned `tar.gz` archive containing `manifest.json`, `cve-database.jsonl`, checksums, source stats, and optional `trivy-db.tar.gz`. Importing the bundle loads CVE records in batches, loads Trivy DB when present, and triggers background CVSS/enrichment/rematch recalculation plus automatic package-only rescans.

## Force Scan Model

The server stores force scan requests in `scan_requests`. The intended lifecycle is:

- `pending`: a user or automation requested a scan.
- `claimed`: an agent picked up the request.
- `completed` or `failed`: the agent submitted a result or reported failure.

Current implementation exposes request creation/listing plus agent claim/complete endpoints. Agents can run with `--daemon --poll-interval 60s` to claim pending requests, execute a scan, upload the report, and mark the request completed or failed. Security DB updates enqueue `security-db-update` scan requests automatically, deduplicated against existing pending or claimed work per host.

## RBAC Model

RBAC tables are present:

- `access_subjects`: future users and groups from company identity systems.
- `access_policies`: permissions on `host`, `container`, `image`, `asset_group`, or `all`.

Runtime RBAC supports viewer API keys mapped to external subjects through `BONGSU_VIEWER_API_KEYS=key:subject`. Admins create `access_subjects` and `access_policies`; viewer queries are scoped to allowed hosts across host, package, vulnerability, scan, and stats views. Future SSO integration should replace static viewer keys with identity-provider subjects.

## Audit Trail

Administration and agent events are written to append-only `audit_logs` rows. The current audit surface includes agent report submissions, force-scan request lifecycle events, scan deletion, Trivy DB upload/update, security DB import/export/update, CVE DB import/export/rematch/CVSS recalculation, RBAC subject/policy changes, and periodic security DB change hooks. Admins can query `/api/admin/audit-logs` with `actor_type`, `actor_id`, `action`, `resource_type`, `resource_id`, `status`, `limit`, and `offset`.

## Test Expectations

Required test surface:

- CVE JSONL import/export and malformed input handling.
- Security source classification and CVSS recalculation.
- Ecosystem-aware matching for OS package vs code library advisories.
- Agent report shape for host and container inventories.
- Installer rendering and shell syntax.
- Docker Compose smoke test.
- Web dashboard build and key management actions.
