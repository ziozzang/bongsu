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
4. Operators export `/api/admin/cve-db/export` for air-gapped transfer.

## Air-Gapped Flow

1. In a connected environment, build Docker images and static binaries.
2. Download/update Trivy DB and CVE JSONL exports.
3. Transfer images, binaries, Trivy DB archive, and CVE JSONL into the air-gapped network.
4. Start Docker Compose without online DB updates.
5. Import Trivy DB through `/api/admin/trivy-db`.
6. Import CVE JSONL through `/api/admin/cve-db/import`.

The durable bundle target is a single versioned archive containing manifest, checksums, source snapshots, `cve_database` rows, `security_sources` state, and Trivy DB.

## Force Scan Model

The server stores force scan requests in `scan_requests`. The intended lifecycle is:

- `pending`: a user or automation requested a scan.
- `claimed`: an agent picked up the request.
- `completed` or `failed`: the agent submitted a result or reported failure.

Current implementation exposes request creation/listing plus agent claim/complete endpoints. Agents can run with `--daemon --poll-interval 60s` to claim pending requests, execute a scan, upload the report, and mark the request completed or failed.

## RBAC Model

RBAC tables are present:

- `access_subjects`: future users and groups from company identity systems.
- `access_policies`: permissions on `host`, `container`, `image`, `asset_group`, or `all`.

Current runtime auth still uses a shared API key. Production RBAC requires user identity, policy CRUD, middleware authorization, and query scoping.

## Test Expectations

Required test surface:

- CVE JSONL import/export and malformed input handling.
- Security source classification and CVSS recalculation.
- Ecosystem-aware matching for OS package vs code library advisories.
- Agent report shape for host and container inventories.
- Installer rendering and shell syntax.
- Docker Compose smoke test.
- Web dashboard build and key management actions.
