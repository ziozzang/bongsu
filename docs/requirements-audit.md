# Bongsu Requirements Audit

Updated: 2026-06-01 19:57:17 KST

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
| R2 | Classify security sources by OS package vs code package/library and match to compatible sources only. | Implemented | `docs/vulnerability-matching-rules.md`, `internal/server/db`, `migrations/022_cve_affected_packages.sql`, package ecosystem fields in API models | `go test ./...` |
| R3 | Collect installed OS/library packages, host metadata, running containers, images, and relationship context, then send SBOM to the server. | Implemented | `internal/agent/collector`, `internal/agent/reporter`, `internal/shared/models`, SBOM export paths in server API | `go test ./...`; live agent enrollment still needs environment-specific validation |
| R4 | RBAC by UserID/GroupID for host/container/system access. | Implemented | access subject/policy migrations, `/api/admin/rbac-*` handlers, dashboard RBAC view, viewer-key flow, browser smoke for subject/policy creation | `go test ./...`, `npm --prefix web run test:e2e`; multi-tenant enforcement examples need broader scenario tests |
| R5 | Provide a sufficiently good web interface. | Partial | Vite dashboard, CVE DB status card, CVE Search, vulnerability/host/RBAC/audit/admin views | `npm --prefix web run build`, `npm --prefix web run test:e2e`; visual live audit at `http://10.2.2.10:5678/` remains required |
| R6 | Deploy fully in air-gapped environments; update externally, export, import internally. | Verified | airgap compose file, bundle import/export, package script, packaged docs, static binary verification, trivy archive validation | `./scripts/verify-deploy-config.sh`, `./scripts/verify-static-binaries.sh`, compose config checks |
| R7 | Provide force scan and rematch functions. | Implemented | scan request APIs, dashboard force-scan buttons, agent daemon polling, CVE rematch endpoints, auto-rescan on security DB changes | `go test ./...`, `npm --prefix web run test:e2e`; live force-scan against enrolled agents remains environment-specific |
| R8 | Calculate CVSS and match vulnerabilities while distinguishing OS package vulnerabilities from library vulnerabilities. | Implemented | CVSS recalculation support, ecosystem-aware affected package index, package type/ecosystem fields on findings | `go test ./...` |
| R9 | Collect from diverse public DBs and merge carefully, preserving only records with sufficient fixed/range evidence for matching. | Implemented | CISA KEV, FIRST EPSS, OSV, NVD, Trivy scripts; matchability policy; affected/reference indexes; placeholder rejection | `go test ./...`, `./scripts/verify-migrations.sh` |
| R10 | Provide one-line installer that downloads required binaries, can deploy as service, and uploads scan results. | Verified for installer paths | `/api/install.sh`, `scripts/install-agent.sh`, installer readiness metrics, cron/download/systemd smoke verification | `./scripts/verify-installer-smoke.sh`, `go test ./...` |
| R11 | Everything must be sufficiently tested. | Partial | Go unit/source tests, Playwright E2E for CVE DB, force scan, and RBAC admin flows; deployment/static/installer/migration/runbook verifiers; GitHub Actions CI | CI and local verifier suite; broader live multi-host/container fixtures remain useful |
| R12 | Use parallel worktrees/sub-agents where useful; static binaries by default. | Partial | static binary verifier, package script, CI static build gate | `./scripts/verify-static-binaries.sh`; sub-agent usage is process evidence, not repository evidence |
| R13 | Management server deploys with Docker Compose. | Verified | `deploy/docker-compose.yml`, `deploy/docker-compose.airgap.yml`, safe default verifier | compose config checks, `./scripts/verify-deploy-config.sh` |
| R14 | Product name is `bongsu`, dashboard introduces the name and meaning, and pushes go to `github.com/ziozzang/bongsu` main. | Implemented | README, dashboard branding, git remote push history | `git remote -v`, `git log`; live dashboard visual check remains useful |
| R15 | Reject `TEMP-*` and `CVD-*` placeholder vulnerabilities from CVE DB and matching paths. | Verified | migrations `027`, `030`, `035`, `041`, placeholder filters, CVE search API guards | `go test ./...`, `./scripts/verify-migrations.sh`; live DB direct query recommended after imports |
| R16 | EPSS should be columns on matching CVE/advisory rows, not only standalone rows. | Implemented | `epss_score`, `epss_percentile` fields, EPSS synchronization and merge stats | `go test ./...`; live `/api/cve-db/stats` coverage check recommended |
| R17 | Group related advisory records by references such as CVE, Debian, GHSA, vendor keys. | Implemented | `cve_reference_keys`, reference-group API, dashboard expansion behavior | `go test ./...`, `npm --prefix web run test:e2e` |
| R18 | Keep API on 5677 and web on 5678; do not depend on or modify Caddy. | Verified | compose defaults, deploy verifier, local runtime handoff | `./scripts/verify-deploy-config.sh` |

## Required Verification Suite

Run this suite before claiming a handoff state is healthy:

```bash
git status --short --branch
go test ./...
./scripts/verify-migrations.sh
./scripts/verify-deploy-config.sh
./scripts/verify-requirements-audit.sh
./scripts/verify-installer-smoke.sh
./scripts/verify-static-binaries.sh
npm --prefix web run build
npm --prefix web run test:e2e
BONGSU_DB_PASSWORD=bongsu BONGSU_API_KEY=test-admin-key-0123456789 BONGSU_AGENT_API_KEY=test-agent-key-0123456789 BONGSU_INSTALL_TOKEN=test-install-token-0123456789 docker compose -f deploy/docker-compose.yml config >/tmp/bongsu-compose.out
BONGSU_DB_PASSWORD=bongsu BONGSU_API_KEY=test-admin-key-0123456789 BONGSU_AGENT_API_KEY=test-agent-key-0123456789 BONGSU_INSTALL_TOKEN=test-install-token-0123456789 docker compose -f deploy/docker-compose.airgap.yml config >/tmp/bongsu-airgap-compose.out
git diff --check
```

## Remaining Commercial-Readiness Gaps

- Live browser review is still required on `http://10.2.2.10:5678/` after each larger UI change.
- Multi-host/container RBAC enforcement scenarios need stronger end-to-end fixtures beyond admin UI smoke coverage.
- Large imported CVE DB performance should keep being measured with current production-scale snapshots.
- Airgap transfer should be exercised with a full generated release package, not only compose rendering and unit tests.
- Operations runbook exists, but should be validated by an operator against a real connected and air-gapped deployment before a commercial release.
