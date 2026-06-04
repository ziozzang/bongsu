# Bongsu Requirements Audit

Updated: 2026-06-04 14:05:00 KST

This audit keeps the original product requirements tied to implementation evidence, verification commands, and remaining gaps. It is not a completion claim; the goal remains open until every item has authoritative evidence from code, tests, deployment, and live behavior.

## Status Legend

- `Verified`: covered by committed implementation and an automated verification command.
- `Implemented`: code exists, but the evidence is narrower than the full commercial requirement.
- `Partial`: useful implementation exists, but known product or verification gaps remain.
- `Open`: no sufficient current evidence.

## Requirement Matrix

| ID | Requirement | Current Status | Evidence | Verification |
| --- | --- | --- | --- | --- |
| R1 | Build and continuously update a security database every 6 hours, with import/export for air-gapped transfer. | Verified | `scripts/sync-all-cvedb.sh`, `scripts/export-security-db-bundle.sh`, `scripts/import-security-db-bundle.sh`, `deploy/docker-compose.yml`, `deploy/docker-compose.airgap.yml`, `docs/architecture.md` | `./scripts/verify-deploy-config.sh`, compose config checks |
| R2 | Classify security sources by OS package vs code package/library and match to compatible sources only. | Verified | `docs/vulnerability-matching-rules.md`, `internal/server/db`, `migrations/022_cve_affected_packages.sql`, package ecosystem fields in API models, focused CVE matching invariant verifier for same-name OS/library collisions and ecosystem aliases | `go test ./...`, `./scripts/verify-cve-matching-invariants.sh` |
| R3 | Collect installed OS/library packages, host metadata, running containers, images, and relationship context, then send SBOM to the server. | Implemented | `internal/agent/collector`, `cmd/agent`, `internal/agent/reporter`, `internal/shared/models`, DB package/container persistence, SBOM export paths in server API, source-level ontology preservation tests, live verifier agent report ingestion tied to scan request completion, real agent binary workflow verifier with fixture Trivy/osquery/docker collection for two logical hosts and container inventories, live host-token binding verifier, live RBAC fixture ingestion of distinct allowed/denied hosts and containers | `go test ./...`, `./scripts/verify-operator-workflow.sh`, `./scripts/verify-agent-binary-workflow.sh`, `./scripts/verify-live-agent-token-binding.sh`, `./scripts/verify-live-rbac-scope.sh`; real fleet deployment fixture remains useful |
| R4 | RBAC by UserID/GroupID for host/container/system access. | Verified | access subject/policy migrations, local sessions, viewer-key flow, `/api/admin/rbac-*` handlers, dashboard RBAC view, dynamic asset-group scope expansion, source-level scope enforcement tests for host/container/image/asset-group policies, live RBAC scope verifier for two-host/two-container viewer-key filtering across hosts, packages, containers, scans, and scan requests via an `asset_group` policy plus fail-closed denied-host filters | `go test ./...`, `npm --prefix web run test:e2e`, `./scripts/verify-live-rbac-scope.sh`; broader multi-tenant staging fixtures remain useful |
| R5 | Provide a sufficiently good web interface. | Verified | Vite dashboard, first-screen `bongsu`/`봉수대` product intro, CVE DB status card, CVE Search, vulnerability/host/RBAC/audit/admin views, schedules, asset groups, trends, reports, notifications, optional-widget failure tolerance, browser workflow coverage for schedules, asset groups, reports, and notifications; fixed schedule and asset-group UI/API contract mismatches; live browser verifier for dashboard, CVE Search, Hosts, Packages, Containers, Scan History, Vulnerabilities, RBAC, Audit Log, Schedules, Asset Groups, Trends, Reports, and Notifications routes plus product intro text | `npm --prefix web run build`, `npm --prefix web run test:e2e`, `./scripts/verify-live-web-smoke.sh` |
| R6 | Deploy fully in air-gapped environments; update externally, export, import internally. | Verified | airgap compose file, bundle import/export, package script, packaged docs, static binary verification, trivy archive validation, package contents verifier, package smoke verifier, offline package rehearsal, generated release archive verifier for outer/inner checksums, required contents, executable/static binaries, Docker image archives, loader, and airgap compose invariants | `./scripts/verify-deploy-config.sh`, `./scripts/verify-package-contents.sh`, `./scripts/verify-airgap-package-smoke.sh`, `./scripts/verify-airgap-release-archive.sh <archive>`, `./scripts/verify-airgap-offline-rehearsal.sh <archive>`, `./scripts/verify-static-binaries.sh`, compose config checks |
| R7 | Provide force scan and rematch functions. | Implemented | scan request APIs, dashboard force-scan buttons, asset-group scan trigger, scheduled scans, agent daemon polling/retry, CVE rematch endpoints, auto-rescan on security DB changes, executable DB test for security DB update queue accounting/dedupe/revision propagation, live operator workflow verifier for schedule CRUD, asset-group scan trigger, agent claim, agent report, and scan-request completion, real agent binary daemon verifier for host-id-specific claim/report/complete, live token-binding verifier proving another token cannot claim or complete a bound host's request | `go test ./...`, `go test ./internal/server/db`, `npm --prefix web run test:e2e`, `./scripts/verify-operator-workflow.sh`, `./scripts/verify-agent-binary-workflow.sh`, `./scripts/verify-live-agent-token-binding.sh`; full production installed-agent rollout remains environment-specific |
| R8 | Calculate CVSS and match vulnerabilities while distinguishing OS package vulnerabilities from library vulnerabilities. | Verified | CVSS recalculation support, ecosystem-aware affected package index, package type/ecosystem fields on findings, fixed/range evidence checks, inclusive `last_affected`, exclusive `limit`, pre-release handling, and numeric epoch version comparison tests | `go test ./...`, `./scripts/verify-cve-matching-invariants.sh` |
| R9 | Collect from diverse public DBs and merge carefully, preserving only records with sufficient fixed/range evidence for matching. | Implemented | CISA KEV, FIRST EPSS, OSV, NVD, Trivy scripts; matchability policy; affected/reference indexes; placeholder rejection; live CVE DB quality verifier for source count, matchability, EPSS enrichment, direct DB index invariants, placeholder rejection, affected package evidence, reference grouping, and API responsiveness | `go test ./...`, `./scripts/verify-migrations.sh`, `./scripts/verify-live-cvedb-quality.sh` |
| R10 | Provide one-line installer that downloads required binaries, can deploy as service, and uploads scan results. | Verified for installer paths | `/api/install.sh`, `scripts/install-agent.sh`, installer readiness metrics, cron/download/systemd smoke verification, optional `BONGSU_HOST_ID` host identity override, real agent binary workflow verifier proving the packaged-style binary can upload inventory and service-style polling can complete requests, live agent token binding verifier for upload/claim/complete authorization | `./scripts/verify-installer-smoke.sh`, `./scripts/verify-agent-binary-workflow.sh`, `./scripts/verify-live-agent-token-binding.sh`, `go test ./...` |
| R11 | Everything must be sufficiently tested. | Partial | Go unit/source tests, executable DB test for automatic security DB rescan queueing, Playwright E2E for CVE DB, dashboard partial-failure behavior, force scan, RBAC admin flows, schedules, asset groups, reports, trends, notifications with API payload assertions, rate limiting, OpenAPI coverage; live operator workflow verifier for sessions, schedules, asset groups, reports, notifications, OpenAPI, backup dry-run, restore dry-run, agent claim/report/complete; backup/restore archive verifier for safe tar entries, required members, duplicates, and manifest checksums; real agent binary workflow verifier for two logical hosts, host/container inventory, host-id override, and daemon polling; live RBAC scope verifier for dynamic asset-group policy expansion; live agent token binding verifier for report, claim, and completion authorization; deployment/static/installer/migration/runbook/archive/package-smoke verifiers; GitHub Actions CI | CI and local verifier suite; broader real multi-host/container fixtures remain useful |
| R12 | Use parallel worktrees/sub-agents where useful; static binaries by default. | Partial | static binary verifier, package script, CI static build gate | `./scripts/verify-static-binaries.sh`; sub-agent usage is process evidence, not repository evidence |
| R13 | Management server deploys with Docker Compose. | Verified | `deploy/docker-compose.yml`, `deploy/docker-compose.airgap.yml`, safe default verifier | compose config checks, `./scripts/verify-deploy-config.sh` |
| R14 | Product name is `bongsu`, dashboard introduces the name and meaning, and pushes go to `github.com/ziozzang/bongsu` main. | Verified | README, dashboard first-screen `bongsu` heading and `봉수대` meaning text, git remote push history | `npm --prefix web run test:e2e`, `./scripts/verify-live-web-smoke.sh`, `git remote -v`, `git log` |
| R15 | Reject `TEMP-*` and `CVD-*` placeholder vulnerabilities from CVE DB and matching paths. | Verified | migrations `027`, `030`, `035`, `041`, placeholder filters, CVE search API guards, live CVE DB quality verifier with optional direct table checks across CVE rows, affected-package index, and reference keys | `go test ./...`, `./scripts/verify-migrations.sh`, `BONGSU_DB_DSN=... ./scripts/verify-live-cvedb-quality.sh` |
| R16 | EPSS should be columns on matching CVE/advisory rows, not only standalone rows. | Verified | `epss_score`, `epss_percentile` fields, EPSS synchronization and merge stats, live CVE DB quality verifier checking EPSS source rows plus EPSS-enriched non-EPSS CVE/advisory rows through API and direct DB invariants | `go test ./...`, `BONGSU_DB_DSN=... ./scripts/verify-live-cvedb-quality.sh` |
| R17 | Group related advisory records by references such as CVE, Debian, GHSA, vendor keys. | Verified | `cve_reference_keys`, reference-group API, dashboard expansion behavior, live CVE DB quality verifier checking reference group API structure and direct DB multi-source canonical CVE plus vendor/advisory key materialization when `BONGSU_DB_DSN` is set | `go test ./...`, `npm --prefix web run test:e2e`, `BONGSU_DB_DSN=... ./scripts/verify-live-cvedb-quality.sh` |
| R18 | Keep API on 5677 and web on 5678; do not depend on or modify Caddy. | Verified | compose defaults, deploy verifier, local runtime handoff | `./scripts/verify-deploy-config.sh` |

| R19 | Maintain documented, operator-usable API and recovery surfaces as the product grows. | Implemented | embedded and docs OpenAPI 3.0 specs, OpenAPI verifier, backup/restore scripts with archive member validation and manifest checksums, live backup/restore dry-run verifier, backup archive safety verifier, CHANGELOG, report/trend/notification/admin endpoints | `./scripts/verify-openapi.sh`, `./scripts/verify-backup-restore-archive.sh`, `./scripts/verify-operator-workflow.sh`, `go test ./...` |

## Required Verification Suite

Run this suite before claiming a handoff state is healthy:

```bash
git status --short --branch
./scripts/verify-release-readiness.sh
go test ./...
./scripts/verify-migrations.sh
./scripts/verify-deploy-config.sh
./scripts/verify-requirements-audit.sh
./scripts/verify-cve-matching-invariants.sh
./scripts/verify-openapi.sh
./scripts/verify-backup-restore-archive.sh
./scripts/verify-operator-workflow.sh
./scripts/verify-agent-binary-workflow.sh
./scripts/verify-live-agent-token-binding.sh
./scripts/verify-live-cvedb-quality.sh
./scripts/verify-live-rbac-scope.sh
./scripts/verify-live-web-smoke.sh
./scripts/verify-package-contents.sh
./scripts/verify-airgap-package-smoke.sh
./scripts/verify-airgap-release-archive.sh <generated-bongsu-archive.tar.gz>
./scripts/verify-airgap-offline-rehearsal.sh <generated-bongsu-archive.tar.gz>
./scripts/verify-installer-smoke.sh
./scripts/verify-static-binaries.sh
npm --prefix web run build
npm --prefix web run test:e2e
BONGSU_DB_PASSWORD=bongsu BONGSU_API_KEY=test-admin-key-0123456789 BONGSU_AGENT_API_KEY=test-agent-key-0123456789 BONGSU_INSTALL_TOKEN=test-install-token-0123456789 docker compose -f deploy/docker-compose.yml config >/tmp/bongsu-compose.out
BONGSU_DB_PASSWORD=bongsu BONGSU_API_KEY=test-admin-key-0123456789 BONGSU_AGENT_API_KEY=test-agent-key-0123456789 BONGSU_INSTALL_TOKEN=test-install-token-0123456789 docker compose -f deploy/docker-compose.airgap.yml config >/tmp/bongsu-airgap-compose.out
git diff --check
```

## Remaining Commercial-Readiness Gaps

- Live browser smoke is automated through `./scripts/verify-live-web-smoke.sh` and currently covers first-screen `bongsu`/`봉수대` product intro, dashboard CVE DB status plus CVE Search, Hosts, Packages, Containers, Scan History, Vulnerabilities, RBAC, Audit Log, Schedules, Asset Groups, Trends, Reports, and Notifications on the deployed `5678` web UI while failing on any `/api/` 5xx response; repeat it after larger UI changes and still do a staging visual pass before commercial release.
- Multi-host/container RBAC enforcement now has source-level coverage and a live two-host/two-container viewer-key scope verifier across host, package, container, scan, and scan-request APIs using a dynamic `asset_group` policy such as `team:rbac-allowed`; broader multi-tenant staging fixtures with real installed agents should still be exercised before a commercial release.
- Large imported CVE DB performance and quality are now measured by `./scripts/verify-live-cvedb-quality.sh` against current production-scale snapshots, including direct DB invariant checks when `BONGSU_DB_DSN` is provided for placeholder rejection, affected-package evidence, EPSS column enrichment, multi-source canonical CVE reference groups, and vendor/advisory key materialization; keep tightening thresholds as larger imports are exercised.
- CVE rematch false-positive controls now have a focused `./scripts/verify-cve-matching-invariants.sh` gate for same-name OS/library collisions, fixed/range evidence, range boundaries, pre-release ordering, and numeric epoch version comparison; extend this suite when new ecosystems or source formats are added.
- Airgap package contents are verified statically, the package script has an end-to-end smoke verifier, and generated archives can now be unpacked, verified, and run through an offline-like loader/compose rehearsal; a full real offline deployment with Docker image loading and security DB import should still be exercised before commercial release.
- Release and handoff verification is consolidated as a release readiness gate in `./scripts/verify-release-readiness.sh`; the operations runbook still should be validated by an operator against a real connected and air-gapped deployment before a commercial release.
- Schedules, asset groups, reports, notification rules, local session login, OpenAPI docs, backup dry-run, restore dry-run, agent claim, agent report ingestion, and scan-request completion now have live API workflow coverage through `./scripts/verify-operator-workflow.sh`; backup archive safety and checksum handling are covered by `./scripts/verify-backup-restore-archive.sh`; repeat both against staging and release candidates before a commercial release.
- The real agent binary now has fixture-backed live coverage for two logical host identities, Trivy host packages, Trivy container packages, osquery packages, container identity, daemon claim, report, and request completion through `./scripts/verify-agent-binary-workflow.sh`; a broader real multi-host/container deployment rehearsal remains useful before commercial release.
- Host-token binding now has live API coverage through `./scripts/verify-live-agent-token-binding.sh`; keep it in release-candidate runs with `BONGSU_AGENT_HOST_BINDING=true` so stolen or stale tokens cannot report, claim, or complete work for another bound host.
