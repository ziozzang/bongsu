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
- Auth: admin APIs use `BONGSU_API_KEY`; agent report and force-scan polling use `BONGSU_AGENT_API_KEY`; installer generation requires `BONGSU_INSTALL_TOKEN`; binary downloads accept that token or an admin API key header; viewer keys from `BONGSU_VIEWER_API_KEYS` are scoped through RBAC policies. The generated one-line installer renders embedded credentials as shell-safe literals, uses fail-fast binary downloads, and returns `Cache-Control: no-store`.
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
3. Prefer stronger CVSS scores/vectors and fixed-version data when enriching scan findings; fixed-version enrichment reads both top-level fixed lists and fixed events inside affected ranges.
4. Match by ecosystem-aware identity first. Name-only candidates are discarded unless `affected_products` contains the same package name, compatible ecosystem/category, fixed-version data, and an affected range that contains the installed version. Fixed versions can come from either the advisory's top-level `fixed` list or fixed events inside range data, and multiple introduced/fixed intervals in one range are evaluated independently.
5. CVSS vectors are recalculated after import for supported CVSS v2, v3.x, and v4.0 formats.
6. `/api/cve-db/stats` reports source quality counters for ecosystem metadata, fixed versions, affected ranges, CVSS data, and matchable records so operators can reject weak feeds before they create noisy matches. `matchable` requires package name, ecosystem context, and fixed-version data, counting fixed events inside affected ranges but not range metadata that lacks a fixed event.
7. Rematch can be constrained by source allowlist and minimum matchable percentage through `BONGSU_CVE_MATCH_SOURCES`, `BONGSU_CVE_MATCH_MIN_SOURCE_MATCHABLE_PERCENT`, or the dashboard rematch control.

Scanner package ecosystems are kept distro-specific for OS advisories. For example, Trivy `ubuntu` packages are stored as `Ubuntu` rather than collapsed into `Debian`, so Ubuntu advisories can match without weakening Debian/Ubuntu separation.
Version comparisons treat pre-release markers such as `alpha`, `beta`, and `rc` as lower than the corresponding final release so release candidates are not incorrectly considered fixed.
Scanner-imported vulnerabilities are bound back to packages by scanner target and package name, with name-only fallback only when the package name is unique in the scan. This avoids linking same-named packages from different ecosystems or manifests to the wrong package row.
Vulnerability inserts drop dangling scanner rows that have no package, scan, host, or vulnerability identity instead of letting one malformed row discard the whole batch. Trivy vulnerability rows are bound to package rows by target, package name, and installed version before falling back to unambiguous package-name matches, so duplicate package names in one lockfile/image do not attach findings to the wrong version. Report audit metadata records inserted and skipped vulnerability counts plus table-level ingest errors. Scans with skipped vulnerability rows or partial inventory persistence failures are stored, audited, and webhooked with `degraded` status so operators can filter for scanner output quality issues while still using the scan as the latest inventory. `/api/report` rejects oversized JSON bodies before decode with a `413` response; `BONGSU_AGENT_REPORT_MAX_BYTES` controls the limit and defaults to 536870912 bytes.

## Connected Update Flow

1. Server has `BONGSU_SECURITY_DB_SYNC_CMD` configured, usually:
   `scripts/sync-all-cvedb.sh http://localhost:8080 $BONGSU_API_KEY`
2. The server runs the command every `BONGSU_SECURITY_DB_INTERVAL_HOURS`, default 6.
3. Scripts download OSV, NVD, and Trivy-derived metadata, then import JSONL through `/api/admin/cve-db/import`.
4. Each successful DB change, including periodic security DB sync, starts background CVSS recalculation, vulnerability enrichment, CVE rematching, and automatic package-only rescan requests for hosts seen within `BONGSU_AUTO_RESCAN_LAST_SEEN_HOURS` (default 720). Recalculation runs as a serialized background worker: if OSV, NVD, and Trivy imports arrive while a pass is still running, bongsu queues one follow-up pass instead of running overlapping recalculations.
5. Operators export `/api/admin/security-db/export` for air-gapped transfer. The bundle contains a manifest, CVE JSONL, source stats, and optionally the current Trivy DB archive.

Database migrations are tracked in `schema_migrations` with per-file SHA-256 checksums. Startup applies each SQL migration once, records the checksum transactionally with the migration, skips already-applied files on later restarts, and refuses to start if an applied migration file is modified in place. When upgrading a legacy database that already has the current schema markers but no migration ledger, startup baselines the bundled migration files into `schema_migrations` without rerunning their SQL; older partial schemas continue through the normal idempotent migration path. This keeps cleanup and requeue migrations from repeating on every container restart and gives operators a deterministic upgrade trail.

## Air-Gapped Flow

1. In a connected environment, build Docker images and static binaries.
2. Download/update Trivy DB and CVE JSONL exports.
3. Transfer images, binaries, Trivy DB archive, and CVE JSONL into the air-gapped network.
4. Start Docker Compose without online DB updates.
5. Import Trivy DB through `/api/admin/trivy-db`.
6. Import CVE JSONL through `/api/admin/cve-db/import`.

The implemented bundle is a versioned `tar.gz` archive containing `manifest.json`, `cve-database.jsonl`, checksums, source stats, and optional `trivy-db.tar.gz`. Import stages payloads to temporary files and verifies manifest SHA-256 checksums before mutating the CVE database or Trivy cache. After validation, importing the bundle loads the full CVE payload inside one database transaction, stages Trivy DB extraction before replacing the active cache, and triggers background CVSS/enrichment/rematch recalculation plus automatic package-only rescans. Direct CVE JSONL imports through `/api/admin/cve-db/import` use the same all-or-nothing transaction boundary, reject malformed JSONL as a client error, and audit failed attempts. Any CVE row insert error rejects the entire CVE payload instead of committing a partially corrupt source update, and an invalid Trivy archive does not overwrite the existing Trivy cache.

## Force Scan Model

The server stores force scan requests in `scan_requests`. The intended lifecycle is:

- `pending`: a user or automation requested a scan.
- `claimed`: an agent picked up the request.
- `completed` or `failed`: the agent submitted a result or reported failure.

Current implementation exposes request creation/listing/cancel plus agent claim/complete endpoints. Agents can run with `--daemon --poll-interval 60s` to claim pending requests, execute a scan, upload the report, and mark the request completed or failed. Claiming a request records `claimed_by_host_id`; agent completion must include the same host ID and is rejected if a different host tries to complete the request. Admin cancellation still works for pending or claimed rows, while missing requests return `404`, and already terminal requests return `409` instead of creating misleading success audit rows. Claimed requests older than `BONGSU_SCAN_REQUEST_CLAIM_TIMEOUT_MINUTES` are requeued automatically during agent claim and can also be requeued by admins from the Scan History view; requeue clears the claimed host ownership. Security DB updates enqueue `security-db-update` scan requests automatically, deduplicated against existing pending or claimed security-db-update work per host; manual or unrelated active scan requests no longer suppress the follow-up security DB rescan. A partial unique index also prevents concurrent DB update hooks from creating duplicate active auto-rescan work for the same host. Auto-rescan queue results are written to audit logs as `security_db.auto_rescan`, including disabled and error cases. Viewer access to scan request queues is host-scoped through RBAC; global all-host requests remain visible only to admins.

## Container Inventory

Running container metadata is stored separately from package rows in `container_assets`. The inventory preserves host ID, runtime, container instance ID/name, image name, image ID/digest, state, labels, and start time. `/api/containers` returns the latest completed or degraded scan per host and supports host, runtime, state, image, name, container ID, and image ID filters. Viewer RBAC is applied before returning rows and before returning package/vulnerability filter options, so container names, package sources, package types, and host IDs are not exposed outside the viewer's allowed host scope.

## Scan Inventory Drift

`/api/scans` includes package, vulnerability, and container counts for each scan plus package inventory delta against the previous completed or degraded scan for the same host. Delta identity uses asset/source/container/package metadata without the version field, so version movement is reported as `packages_changed`, while new or missing identities are reported as added/removed. The Scan History dashboard exposes these counters to help operators spot broken collectors, unexpected package churn, or container image drift.

## Asset Metadata

Hosts preserve operator-owned metadata independently from agent reports: owner, team, environment, criticality, and JSON tags. Agent check-ins update technical facts such as OS, IP, CPU, and memory without overwriting this metadata. Agents normally send a stable host ID derived from machine-id or hostname; if an older or malformed report omits it, the server derives a stable fallback from hostname or IP before using a random ID as the last resort. Admins can update metadata through `/api/hosts/{id}/metadata`, the dashboard shows it on host inventory/detail pages, and CycloneDX SBOM exports include it as `bongsu:*` root component properties.

Agent status is derived from each host's `last_seen` timestamp at read time. The dashboard and `/api/hosts?agent_status=...` expose `online`, `stale`, `offline`, or `unknown`; defaults mark agents online for 26 hours and offline after 72 hours, controlled by `BONGSU_AGENT_ONLINE_MINUTES` and `BONGSU_AGENT_OFFLINE_MINUTES`.

Host list responses include `latest_inventory`, summarizing the latest completed or degraded scan ID, scan status, finish time, package count, vulnerability count, and container count. They also include `active_vuln_counts`, the same latest-scan remediation finding counts used by the dashboard. This gives operators a quick signal for stale agents that are checking in but producing empty or incomplete SBOM data. `/api/hosts?inventory_status=...` supports `healthy`, `degraded`, `stale`, `empty`, and `none`; `stale` is controlled by `BONGSU_INVENTORY_STALE_HOURS` and defaults to 48 hours. The dashboard uses the same filtered API to show RBAC-scoped SBOM health counts. `/api/stats` also includes RBAC-scoped active finding counts from each host's latest completed or degraded scan, excluding terminal triage states, fixed rows, no-fix rows, CGA rows, hash-only fixed versions, and ecosystem mismatches. Scan request status counts are included so operators can see pending, claimed, and failed force-scan or automatic rescan backlog from the first dashboard view.

Dashboard summary views can group active remediation findings by `owner`, `team`, `environment`, or `criticality` through `/api/vuln-summary?group_by=...`. The summary is RBAC-scoped and uses the same latest-scan active finding filter as `/api/stats` and `/api/hosts`, including total, severity, and SLA-overdue counts so remediation queues can be routed by operational ownership.

## RBAC Model

RBAC tables are present:

- `access_subjects`: future users and groups from company identity systems.
- `access_policies`: permissions on `host`, `container`, `image`, `asset_group`, or `all`.

Runtime RBAC supports viewer API keys mapped to external subjects through `BONGSU_VIEWER_API_KEYS=key:subject`. Admins create, list, and delete `access_subjects` and `access_policies` through `/api/admin/rbac/*` or the dashboard RBAC view; viewer queries are scoped to allowed hosts across host, package, vulnerability, scan, filter-option, and stats views. Deleting a subject revokes all attached policies through database cascade. Policy creation accepts a subject UUID or external ID, and the dashboard uses UUIDs to avoid ambiguity when a user and group share the same external ID. Policy creation requires a known subject so typos do not silently create ineffective access grants. Future SSO integration should replace static viewer keys with identity-provider subjects.

RBAC resource matching supports:

- `all:*`: read every resource.
- `host:<host_id>`: read one host and its packages, vulnerabilities, scans, SBOM, and containers.
- `container:<container_id_or_name>`: resolve the latest matching container asset to its host scope.
- `image:<image_name_or_id_or_digest>`: resolve the latest matching image asset to its host scope.
- `asset_group:<selector>`: resolve hosts by operator metadata. Supported selectors are `owner:<value>`, `team:<value>`, `environment:<value>`, `criticality:<value>`, and `tag:<key>=<value>`.

Container and image policies are resolved from the latest completed or degraded scan per host so access follows the current runtime inventory instead of stale historical scans. Asset group policies are resolved from current host metadata so ownership transfers or environment changes immediately affect viewer scope.

## Audit Trail

Administration and agent events are written to append-only `audit_logs` rows. The current audit surface includes installer generation and binary downloads, agent report submissions, force-scan request lifecycle events, scan deletion, SBOM export, vulnerability report export, Trivy DB upload/update, security DB import/export/update, CVE DB import/export/rematch/CVSS recalculation, serialized security recalculation worker events, auto-rescan queue results, vulnerability triage changes, RBAC subject/policy changes and deletions, webhook delivery results, and periodic security DB change hooks. Security DB bundle import failures are audited with `status=error` and a stage name, so corrupt, tampered, or operationally incompatible airgap bundles remain traceable. Recalculation audit metadata includes CVSS, enrichment, rematch, and severity-normalization counts; partial worker failures are recorded with `status=error` and step-level error messages instead of being reported as successful. Manual scan deletion protects each host's latest completed or degraded inventory scan unless admins explicitly use `force=true`; forced deletes are recorded in audit metadata, and missing scan IDs return `404` instead of creating misleading success audit rows. Admins can query `/api/admin/audit-logs` with `actor_type`, `actor_id`, `action`, `resource_type`, `resource_id`, `status`, `limit`, and `offset`; the dashboard exposes the same data in the Audit Log view for operational review.

## Retention

Admins can dry-run or execute `/api/admin/retention/prune` from the dashboard to remove old operational history. The prune action deletes terminal scans older than `BONGSU_RETENTION_SCAN_DAYS` while preserving each host's latest completed or degraded scan; running scans are not pruning targets. It also removes completed/failed/cancelled scan requests older than `BONGSU_RETENTION_SCAN_REQUEST_DAYS`, and removes audit events older than `BONGSU_RETENTION_AUDIT_DAYS`. Retention responses and audit metadata include deleted scan, package, vulnerability, container, user, process, port, scan-request, and audit-log counts so operators can review the full blast radius. Triage decisions and the current host inventory are not pruned by this action.

## Vulnerability Triage

Triage decisions are stored separately from scan-result rows in `vulnerability_triage`, so they survive rescans and security DB updates. A decision can target one CVE globally, one CVE on a host, or one CVE/package pair on a host. Current statuses are `open`, `in_progress`, `accepted_risk`, `false_positive`, `fixed`, and `ignored`; expired decisions stop applying automatically. The dashboard exposes an expiry date for time-bound exceptions, exports include `triage_expires_at`, and triage changes are audited through `vulnerability.triage`.

## Remediation SLA

Findings expose computed SLA fields from first-seen time and severity: `sla_days`, `due_at`, and `overdue`. Defaults are 7 days for critical, 30 for high, 90 for medium, and 180 for low, controlled by `BONGSU_SLA_*_DAYS`. SLA overdue filtering excludes triaged `accepted_risk`, `false_positive`, `fixed`, and `ignored` findings so accepted exceptions do not pollute operational breach queues.

## SBOM Export

Each host can export its latest completed or degraded package inventory as CycloneDX 1.5 JSON through `/api/hosts/{id}/sbom` or SPDX 2.3 JSON through `/api/hosts/{id}/sbom?format=spdx`. Exports include bongsu host/package context such as host ID, OS, asset type, container/image identifiers, source, package type, ecosystem, file path, and target. CycloneDX component `bom-ref` values are stable bongsu identities based on package placement context instead of raw purl strings, so the same package/version appearing in multiple containers remains reference-safe; the host root component also lists package components through CycloneDX `dependencies`. SPDX packages include purl external references, deterministic package verification codes based on stable package identity rather than database row IDs, sanitized document names/namespaces derived from host identity, and explicit `NOASSERTION` license/copyright/supplier fields when the scanner did not collect authoritative values. Viewer RBAC is enforced before export, and successful exports are audited as `sbom.export`.

## Vulnerability Report Export

Filtered vulnerability and package views are always scoped to each host's latest completed or degraded scan, including when a specific `host_id` filter is used. Package `max_cvss`, `vuln_count`, and package vulnerability details use the same active finding filter as the remediation dashboard. Vulnerability findings are unique per package, scan, and vulnerability ID; migrations deduplicate older rows by keeping the strongest CVSS/fixed-version candidate, and scanner/rematch inserts ignore duplicate conflicts. During CVE rematch, duplicate source candidates for the same package finding are collapsed before insert, preferring higher CVSS, stronger severity, fixed-version data, richer titles, and primary references. Paginated API list endpoints clamp negative or excessive `limit`/`offset` values through `BONGSU_API_MAX_PAGE_LIMIT` and `BONGSU_API_MAX_PAGE_OFFSET` before reaching SQL. Filtered vulnerability views can be exported through `/api/vulnerabilities/export` as CSV by default or JSON with `format=json`. The export reuses the same host, severity, triage status, package, container, owner, team, environment, criticality, sorting, fixed-version, ecosystem-mismatch, and RBAC filters as the interactive vulnerability list. CSV and JSON rows include the host metadata fields so exported remediation queues can be routed outside bongsu. `BONGSU_VULN_EXPORT_MAX_ROWS` limits export size and defaults to 100000 rows. Successful exports are audited as `vulnerability.export`.

## Webhook Notifications

Operators can configure `BONGSU_WEBHOOK_URL` to receive outbound JSON webhooks for `scan.completed` and `security_db.updated`. `scan.completed` includes host identity, scan status, inventory status, package/container counts, inserted/skipped vulnerability row counts, ingest errors, vulnerability totals, and severity counts; `BONGSU_WEBHOOK_MIN_SEVERITY` controls the minimum severity that triggers scan notifications, and `BONGSU_WEBHOOK_INVENTORY_STATUSES` triggers notifications for selected SBOM health states such as `empty` or `degraded`. `BONGSU_WEBHOOK_SECRET` signs payloads with `X-Bongsu-Signature-256: sha256=<hex hmac>` for receiver verification.

## Test Expectations

Required test surface:

- CVE JSONL import/export and malformed input handling.
- Security source classification and CVSS recalculation.
- Ecosystem-aware matching for OS package vs code library advisories.
- Agent report shape for host and container inventories.
- Installer rendering and shell syntax.
- Docker Compose smoke test.
- Web dashboard build and key management actions.
