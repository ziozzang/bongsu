# Bongsu Agent Handoff

Updated: 2026-06-04 14:00:12 KST

This document is the handoff point for the next agent session. Continue from the repository state after this file is committed and pushed.

## Non-Negotiable Constraints

- Product name: `bongsu`, meaning "봉수대".
- Repository: `/home/ziozzang/bongsu`.
- Remote target: push local `master` to `origin/main`.
- Web UI must listen on `http://10.2.2.10:5678/`.
- API must listen on port `5677`.
- Do not touch or reconfigure Caddy.
- Docker Compose deployment must remain available for the management server.
- Air-gapped deployment is required: update outside, export bundle, import inside.
- Air-gapped release archives must include static server/agent binaries, source sync scripts, import/export scripts, Docker images, migrations, web assets, and a package `SHA256SUMS` manifest.
- CVE matching must use only matchable affected package evidence: package name, ecosystem/target such as `Packagist`, and fixed-version/range data. Name-only or priority-only records must remain searchable but must not create rematch/rescan findings.
- `TEMP-*` and `CVD-*` placeholder vulnerabilities are invalid for the CVE DB and should not appear in `cve_database`, `cve_affected_packages`, reference keys, or rematch candidates.
- EPSS belongs on matching CVE/advisory rows as columns, not only as separate EPSS source records.

## Current Git State

Expected committed head at this handoff:

```text
master / origin/main latest commit: Verify live observability surfaces
```

Important recent commits:

```text
<latest> Verify live observability surfaces
e93f242 Defer OSV chunk import finalization
4cbd557 Fix OSV chunk imports and admin sessions
32652bf Reject non-regular backup archive entries
8d312c4 Verify OpenAPI operation security
190ff69 Harden generated installer systemd path
477177c Verify static server build metadata
d6f2f27 Verify latest SBOM package ontology
c90c4df Verify stale CVE rematch cleanup
a8db21a Verify matchable CVE rematch insertion
ba171bf Verify security DB rescan queue
699020d Verify dashboard product identity
c2298c9 Verify dynamic asset-group RBAC scope
5bb05ac Harden CVE matching invariants
0229dd2 Verify CVE reference grouping quality
a22626c Expand live web smoke coverage
1183cfb Harden backup restore archives
651f783 Verify CVE DB direct invariants
e25c19a Verify live agent token binding
b0d4cd7 Verify multi-host agent identity
39ce162 Run release readiness gate in CI
c4237f3 Add release readiness gate
8d58410 Document live multi-host RBAC coverage
265cba9 Verify live web smoke workflow
f4be3fd Verify airgap release archive
fa030f8 Verify live agent scan request completion
f6e99ac Add live operator workflow verification
c86ada7 Expand operator workflow browser coverage
cced8c1 Sync OpenAPI docs and audit handoff
6627f13 Allow short admin password when BONGSU_ALLOW_WEAK_SECRETS is set
4f13d45 Add admin credentials to .env.example
0c110c7 Add Phase 5 polish: performance indexes, frontend integration, error consistency
78397ff Add actionable intelligence: trending, recommendations, notifications, reports
049735b Add fleet management: agent retry, scan scheduling, asset groups
fca7b5d Add local user accounts, session auth, and OIDC interface
5bdb43d Add Phase 1 operational safety features
fc827a5 Decompose api.go and db.go into domain-specific files
13da542 Harden live dashboard and summary queries
82972fb Preserve container SBOM relationships
7a9762a Verify airgap package contents
c3fa8e0 Add RBAC scope enforcement tests
```

This handoff commit should include:

- `docs/agent-handoff.md`
- `docs/requirements-audit.md`
- `docs/operations-runbook.md`
- `scripts/verify-requirements-audit.sh`
- `scripts/verify-package-contents.sh`
- `scripts/verify-airgap-package-smoke.sh`
- `scripts/verify-release-readiness.sh`
- `scripts/package.sh`
- `.github/workflows/ci.yml`
- `README.md`
- `web/tests/e2e/cve-db.spec.ts`
- `internal/server/api/auth_test.go`
- `internal/server/db/classify_test.go`
- `scripts/verify-installer-smoke.sh`
- A cron-mode one-line installer smoke verification that installs local packaged agent/Trivy binaries into a temporary work directory, generates and reuses a persistent agent token, writes `0600` config/token files, replaces the bongsu cron entry on reinstall, and runs the first agent scan without requiring root, systemd, network access, or Caddy changes.
- Download-path installer verification that fetches agent and Trivy binaries through header-authenticated `curl`, rejects token-bearing URLs, requires the `X-Bongsu-SHA256` header, and fails closed while removing a checksum-mismatched binary.
- Systemd-mode installer verification that writes service/timer/daemon unit files into a test systemd directory, validates hardening directives and daemon polling command, calls `systemctl daemon-reload` plus timer/daemon enablement, and runs the first scan without touching `/etc/systemd` during tests.
- Requirements audit coverage that maps the original product requirements to evidence, verification commands, and remaining commercial-readiness gaps without declaring the overall goal complete.
- Browser smoke coverage for Hosts force-scan requests and RBAC subject/policy creation, including POST body verification.
- Browser workflow coverage for scheduled scan creation, dynamic asset-group creation, asset-group scan trigger, report rendering/export, notification rule creation/test delivery, and notification-log loading, including request payload verification.
- Live API operator workflow verifier covering liveness/readiness, OpenAPI docs, optional local session login, scheduled scan CRUD, dynamic asset-group creation and scan trigger, report surfaces, notification rule test delivery, notification log shape, backup dry-run, and restore dry-run.
- Live operator workflow verifier now also checks `/api/health` and `/api/admin/metrics` for security DB revision, recalculation state, usable affected/reference index status, EPSS enrichment, and security DB rescan progress observability.
- Backup/restore archive verifier covers safe tar entries, regular-file enforcement, required members, duplicate member rejection, symlink member rejection, and manifest checksum rejection without requiring a live database.
- Live API agent workflow verification now creates a verifier host report, creates a host-specific scan request, claims it through `/api/agent/scan-requests/claim`, posts a scan report tied to that request, completes it through `/api/agent/scan-requests/{id}/complete`, and verifies both scan-request and scan list state.
- Real agent binary workflow verifier builds `cmd/agent`, runs it against fixture Trivy/osquery/docker tools for two logical host IDs, verifies host/container package ontology and host-id isolation through the live API, then runs daemon polling to claim and complete a host-specific scan request.
- Live agent token binding verifier binds a host to one token, then proves a different token cannot report inventory, claim scan requests, or complete requests for the bound host when `BONGSU_AGENT_HOST_BINDING=true`.
- Live CVE DB quality verifier checks production-scale source count, matchability, EPSS enrichment, affected/reference index health, placeholder rejection, affected package evidence, reference grouping, endpoint responsiveness, and optional direct PostgreSQL invariants when `BONGSU_DB_DSN` is set; direct checks use local `psql` or `docker exec` against `BONGSU_DB_PSQL_CONTAINER`.
- OSV CVE/source upserts now merge `affected_products` and `refs` instead of overwriting the previous row when different ecosystem chunks share a CVE alias. This fixed the live Packagist loss where `phenx/php-svg-lib` was absent after later distro chunks overwrote the same CVE rows. After reimporting the Packagist chunk, live OSV had 330843 rows, 6299 top-level Packagist rows, 282765 affected-package rows, 99597 indexed/matchable CVEs, and CVE Search returned three matchable `phenx/php-svg-lib` rows with `Packagist` ecosystem and fixed versions `0.5.1`/`0.5.2`.
- Live RBAC scope verifier ingests allowed and denied host/container fixtures, creates a viewer subject and dynamic `asset_group` policy (`team:rbac-allowed`), then verifies viewer-key access filters hosts, packages, containers, scans, and scan requests.
- Airgap package smoke verifier runs `scripts/package.sh` end-to-end with lightweight `go`/`npm`/`docker` stubs, then validates the generated `bongsu-*.tar.gz`.
- Airgap offline rehearsal verifier extracts a generated package, checks checksums, rehearses `load-images.sh` with a Docker-load stub, renders packaged airgap compose with real `docker compose config`, and checks import/export script targets.
- Airgap release archive verifier unpacks a generated `bongsu-*.tar.gz`, checks outer and inner SHA256 manifests, required files, executable/static binaries, Docker image tarballs, loader script, runbook/audit references, and airgap compose invariants.
- Frontend API contract fixes for schedules (`{items}` response plus `packages_only`) and asset groups (`rule_type` instead of stale `group_type`).
- Operations runbook covering production readiness, install, upgrade, backup/restore, security DB operations, monitoring/alerting, incident response, and routine maintenance. Air-gapped packages now include `docs/` and top-level `README.md`.
- RBAC enforcement regression coverage for package/container/scan/scan-request endpoint scoping and container/image/asset-group policy expansion through latest container assets and host metadata.
- Airgap package contents verifier that checks the release package script includes static binaries, Docker images, deploy files, migrations, docs, web assets, source sync/import/export tools, loader script, and SHA256 manifests.
- Agent package annotation, DB persistence, and CycloneDX/SPDX export tests that preserve host/container/image/package target relationship context for SBOM and inventory data.
- Live dashboard hardening: optional admin/summary widget failures no longer log out the no-auth dashboard, package/vulnerability summary SQL no longer references a package alias outside scope, and the dashboard action bar wraps instead of clipping controls.
- API and DB decomposition into domain-specific files, preserving previous behavior while reducing the monolithic `api.go`/`db.go` maintenance risk.
- Operational safety additions: per-IP rate limiting, `/api/live`, `/api/ready`, embedded OpenAPI 3.0, `scripts/backup.sh`, `scripts/restore.sh`, `scripts/verify-openapi.sh`, `scripts/verify-operator-workflow.sh`, `scripts/verify-agent-binary-workflow.sh`, and `scripts/verify-airgap-release-archive.sh`.
- Local user/session authentication, initial admin bootstrap, secure session cookies, `Authorization: Bearer` support for the web client, and an OIDC authenticator interface placeholder.
- Fleet management additions: scheduled scans, asset groups, asset-group force scans, agent report retry configuration, and frontend views for schedules and asset groups.
- Actionable intelligence additions: vulnerability trends, top-risk hosts, remediation recommendations, notification rules/logs, executive/risk/SLA reports, report export, and corresponding frontend views.

## Live Runtime

The current live target is:

- Web: `http://10.2.2.10:5678/`
- API: `http://10.2.2.10:5677/`

Last known listener state:

```text
0.0.0.0:5678  web static server
*:5677        bongsu API server
```

API was last started with a fresh build from the current checkout:

```bash
go build -o /tmp/bongsu-server-current ./cmd/server
setsid env BONGSU_DB_DSN="postgres://bongsu:bongsu@localhost:5432/bongsu?sslmode=disable" \
BONGSU_API_KEY=test-admin-key-0123456789 BONGSU_AGENT_API_KEY=test-agent-key-0123456789 BONGSU_INSTALL_TOKEN=test-install-token-0123456789 \
BONGSU_ADMIN_USERNAME=admin BONGSU_ADMIN_PASSWORD=password \
BONGSU_ALLOW_WEAK_SECRETS=true BONGSU_WEB_AUTH=true \
BONGSU_SECURITY_DB_SYNC_ON_START=false BONGSU_SECURITY_DB_SYNC_CMD="" \
BONGSU_TRIVY_DB_INTERVAL_HOURS=0 BONGSU_AGENT_BIN=/home/ziozzang/bongsu/bin/bongsu-agent \
BONGSU_CVE_AFFECTED_INDEX_REBUILD_TIMEOUT_SECONDS=30 \
BONGSU_STARTUP_RECALC_TIMEOUT_SECONDS=1 \
BONGSU_STALE_REMATCH_CLEANUP_BATCH_SIZE=10000 \
BONGSU_CVE_SEARCH_TIMEOUT_SECONDS=15 \
BONGSU_CVE_REFERENCE_GROUP_TIMEOUT_SECONDS=10 \
BONGSU_CVE_AFFECTED_PACKAGES_TIMEOUT_SECONDS=10 \
BONGSU_VULNERABILITY_LIST_TIMEOUT_SECONDS=15 \
BONGSU_PORT=5677 /tmp/bongsu-server-current >/tmp/bongsu-api-5677.log 2>&1 < /dev/null &
```

Do not change this to `8080`. Keep API and web split as `5677` and `5678`. If `http://10.2.2.10:5678/api/auth/login` returns HTTP 500, check that `5677` is listening and that the running API binary was rebuilt from the current checkout. A stale `/tmp/bongsu-server-live` binary previously lacked the current login routes.

Latest login check passed through both the API and the web proxy:

```text
POST http://127.0.0.1:5677/api/auth/login admin/password -> 200
POST http://127.0.0.1:5678/api/auth/login admin/password -> 200
```

## Current CVE DB Status

OSV sync bugs fixed in recent handoffs:

- First root cause: `scripts/sync-all-cvedb.sh` imported each OSV ecosystem chunk with the same `source=osv`, while `/api/admin/cve-db/import` replaced all rows for that source on every import. The final ecosystem chunk overwrote earlier chunks.
- First fix: the import API accepts `replace=false`, OSV ecosystem chunks use append/upsert mode, and OSV chunks use `finalize=false` so affected/reference indexes plus security recalculation run once after all OSV chunks finish instead of once per ecosystem.
- Second root cause: after append mode was fixed, rows sharing the same OSV source and CVE alias still conflicted on `(vulnerability_id, source)`. Later distro chunks could overwrite earlier Packagist/PyPI/npm `affected_products`.
- Second fix: CVE/source upserts now merge existing and incoming `affected_products`/`refs` arrays. The live verifier includes a Packagist sentinel for `phenx/php-svg-lib` when the DB contains a production-scale OSV Packagist feed.

Latest OSV live snapshot:

```text
osv cve_database rows:       330843
osv Packagist top rows:      6299
osv affected index rows:     282765
osv indexed/matchable CVEs:  99597
phenx/php-svg-lib matches:   3 Packagist rows with fixed 0.5.1/0.5.2
```

Last verified operational metrics:

```text
/api/cve-db/stats miss: ~2.32s, X-Bongsu-Cache: miss
/api/cve-db/stats hit:  ~0.0006s, X-Bongsu-Cache: hit
stale stats path:       ~0.0005s, X-Bongsu-Cache: stale
/api/vulnerabilities?limit=50: ~0.69-0.71s
/api/cve-db/search?q=openssl&limit=20: ~0.25s
```

Last quality snapshot:

```json
{
  "temporary_placeholders": 0,
  "total_records": 372310,
  "total_matchable": 39,
  "affected_index_coverage": 100,
  "affected_index_orphans": 0,
  "reference_index_coverage": 100,
  "reference_index_orphans": 0,
  "epss_non_epss_coverage": 95.9
}
```

Last direct DB check found zero `TEMP-*` and zero `CVD-*` rows in `cve_database`, `cve_affected_packages`, and `cve_reference_keys`; affected-package rows all had package/ecosystem/fixed evidence; canonical CVE reference groups merged multiple non-priority sources; vendor/advisory reference keys were materialized beside canonical CVE keys.

## What Has Been Completed

- Management server and dashboard are deployed locally with web on `5678` and API on `5677`.
- Server-side scan report normalization now backfills host/container asset context for package and vulnerability rows from reported containers, and rejects invalid package/vulnerability `asset_type` values before persistence.
- Security DB ingest/import/export exists for connected and air-gapped flows.
- CVE DB quality and status are visible on the dashboard.
- CVE search is backed by indexes and bounded request timeouts.
- Affected packages lookup and reference grouping are bounded.
- Live CVE DB quality verification now checks reference-group API structure, and direct DB mode verifies canonical CVE groups merge multiple non-priority sources while vendor/advisory keys are materialized beside canonical CVE keys.
- Matchable CVE evidence is materialized into `cve_affected_packages`.
- Vulnerability evidence/listing now uses matchable affected package rows instead of raw JSON name matches.
- CVE DB rematch filters require compatible package name, ecosystem, fixed version/range, and affected range semantics.
- CVE rematch false-positive controls now have `./scripts/verify-cve-matching-invariants.sh`, covering same-name OS/library collisions, fixed/range evidence, inclusive `last_affected`, exclusive `limit`, pre-release ordering, and numeric Debian/RPM-style epoch comparison.
- EPSS data is merged into matching non-EPSS CVE/advisory rows.
- TEMP placeholder identifiers are blocked/removed from CVE DB matching paths.
- CVSS v2/v3.x/v4 recalculation support exists and startup recalculation is timeout-bounded.
- Background stale-while-revalidate cache for `/api/cve-db/stats` is implemented.
- The dashboard API client now reads `X-Bongsu-Cache` for CVE DB stats and the dashboard card exposes cache state, generated timestamp, and stats duration.
- `scripts/verify-openapi.sh` now verifies not only route/spec sync but also that non-public operations declare security, admin operations include `AdminKey`, agent operations include `AgentKey`, installer/download operations include `InstallToken`/`AdminKey`, and export/SBOM operations are not documented as public.
- `scripts/restore.sh` now rejects allowed-name backup archive members unless they are regular files, and `scripts/verify-backup-restore-archive.sh` covers symlink `database.dump` rejection.
- The generated `/api/install.sh` one-line installer now supports `BONGSU_SYSTEMD_DIR` and `BONGSU_SYSTEMCTL_BIN`, matching the packaged installer test hooks so systemd service/timer generation can be verified without touching `/etc/systemd/system` or real `systemctl`.
- Static release verification now executes both `bongsu-agent --version` and `bongsu-server --version`, checking injected version/commit/build-date metadata after confirming both linux/amd64 binaries are statically linked; `scripts/package.sh` now builds release binaries with `-trimpath`.
- `scripts/install-agent.sh` supports `BONGSU_SYSTEMD_DIR` and `BONGSU_SYSTEMCTL_BIN` for controlled systemd installation testing while preserving `/etc/systemd/system` and `systemctl` defaults.
- `./scripts/verify-live-rbac-scope.sh` now validates dynamic `asset_group` policy expansion instead of relying only on a direct host policy.
- `internal/server/db/package_sbom_exec_test.go` now executes `GetLatestPackagesForSBOM` through a fake `database/sql` driver and verifies the latest-inventory query preserves container/image/package target ontology fields before CycloneDX/SPDX generation.
- `internal/server/db/stale_rematch_cleanup_exec_test.go` now executes `RemoveStaleRematchedVulnerabilities` through a fake `database/sql` driver and verifies cleanup candidates are restricted to `finding_source='cve-db'`, compatible findings are kept, and missing-fixed/wrong-ecosystem rematch findings are deleted.
- `internal/server/db/cve_rematch_exec_test.go` now executes `RematchCVEs` through a fake `database/sql` driver and verifies that only a compatible, fixed-version-backed, affected npm candidate inserts a `cve-db` finding; missing fixed evidence, non-affected installed versions, and same-name Debian/package ecosystem mismatches are skipped.
- `internal/server/db/scan_rescan_test.go` now executes `QueueSecurityDBRescans` through a fake `database/sql` driver, verifying host eligibility filtering, transaction commit, pending dedupe accounting, requested_by/reason propagation, and `security_db_revision` stamping without requiring a live PostgreSQL instance.
- Playwright coverage now verifies dashboard CVE DB status, CVE Search fixed-version evidence, Hosts force-scan POST bodies, RBAC subject/policy POST bodies, scheduled scan creation payloads, dynamic asset-group creation and scan trigger payloads, report export query parameters, notification rule creation/test payloads, and notification-log rendering.
- Dashboard E2E and live web smoke now verify first-screen `bongsu` branding plus the `봉수대` meaning/product intro text.
- `docs/operations-runbook.md` is available and `scripts/package.sh` includes documentation in release archives.
- Real airgap package generation was exercised with `scripts/package.sh 0.1.0-real-20260604051738` after fixing server/agent Dockerfiles from `golang:1.24-alpine` to `golang:1.25-alpine` to match `go.mod`. The generated archive was `bongsu-0.1.0-real-20260604051738.tar.gz`, size 87M, SHA256 `622d4706b7d31242ae26340d90700480362d1a25f92879ec35d9388e1eece929`; both `scripts/verify-airgap-release-archive.sh` and `scripts/verify-airgap-offline-rehearsal.sh` passed against it.
- Go tests now assert RBAC access scope expansion for host, container, image, and asset-group policies and verify inventory/scan list endpoints apply those scopes.
- CI runs `scripts/verify-package-contents.sh` and `scripts/verify-airgap-package-smoke.sh` to keep air-gapped release archives from silently losing required files or breaking package generation.
- Container package rows are annotated with container name, container ID, image name, and image ID before upload. Source-level regression tests now check that package persistence, container asset persistence, CycloneDX properties, and SPDX package comments keep this runtime identity and package target context.
- Live Playwright smoke is now scripted by `./scripts/verify-live-web-smoke.sh` and passed against `http://127.0.0.1:5678` using `BONGSU_API_KEY=test-admin-key`. It covers dashboard product identity, CVE DB status, CVE Search, Hosts, Packages, Containers, Scan History, Vulnerabilities, RBAC, Audit Log, Schedules, Asset Groups, Trends, Reports, and Notifications routes, while asserting that live `/api/` responses do not return 5xx.
- Other agents added domain file decomposition, sessions/local admin auth, rate limiting, OpenAPI verification, scheduled scans, asset groups, trend/intelligence/report/notification APIs, backup/restore scripts, migration `049`, and frontend integration. Current automated verification has been rerun on this state, the newest browser suite now covers the added schedule/asset-group/report/notification views with mocked API contract assertions, and the live operator verifier passed against `127.0.0.1:5677` using the running API and agent credentials, including agent claim/report/complete.

## Verification Commands

Run these after pulling this handoff state:

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
BONGSU_DB_PASSWORD=bongsu docker compose -f deploy/docker-compose.yml config >/tmp/bongsu-compose.out
BONGSU_DB_PASSWORD=bongsu docker compose -f deploy/docker-compose.airgap.yml config >/tmp/bongsu-airgap-compose.out
git diff --check
```

Useful live checks:

```bash
curl -sS -H 'X-API-Key: test-admin' http://127.0.0.1:5677/api/cve-db/stats -o /tmp/cve-stats.json -D /tmp/cve-stats.headers
cat /tmp/cve-stats.headers
curl -sS -H 'X-API-Key: test-admin' 'http://127.0.0.1:5677/api/cve-db/search?q=openssl&limit=20' >/tmp/cve-search.json
curl -sS http://127.0.0.1:5678/ >/tmp/bongsu-web.html
BONGSU_API_KEY=test-admin-key BONGSU_ADMIN_USERNAME=admin BONGSU_ADMIN_PASSWORD=password ./scripts/verify-operator-workflow.sh
BONGSU_API_KEY=test-admin-key BONGSU_AGENT_API_KEY=test-agent-key ./scripts/verify-agent-binary-workflow.sh
BONGSU_API_KEY=test-admin-key BONGSU_AGENT_API_KEY=test-agent-key ./scripts/verify-live-agent-token-binding.sh
BONGSU_API_KEY=test-admin-key BONGSU_DB_DSN='postgres://bongsu:bongsu@localhost:5432/bongsu?sslmode=disable' ./scripts/verify-live-cvedb-quality.sh
BONGSU_API_KEY=test-admin-key BONGSU_AGENT_API_KEY=test-agent-key BONGSU_VIEWER_API_KEY=viewer-test-key BONGSU_VIEWER_SUBJECT=rbac-live-viewer ./scripts/verify-live-rbac-scope.sh
BONGSU_WEB_BASE=http://127.0.0.1:5678 BONGSU_API_KEY=test-admin-key ./scripts/verify-live-web-smoke.sh
./scripts/verify-airgap-release-archive.sh bongsu-0.1.0.tar.gz
```

TEMP/CVD direct DB check:

```bash
psql 'postgres://bongsu:bongsu@localhost:5432/bongsu?sslmode=disable' -c "
select 'cve_database' as table_name, count(*) from cve_database
where vulnerability_id like 'TEMP-%' or vulnerability_id like 'CVD-%'
union all
select 'cve_affected_packages', count(*) from cve_affected_packages
where vulnerability_id like 'TEMP-%' or vulnerability_id like 'CVD-%'
union all
select 'cve_reference_keys', count(*) from cve_reference_keys
where cve_id like 'TEMP-%' or cve_id like 'CVD-%'
   or reference_key like '%TEMP-%' or reference_key like '%CVD-%';
"
```

## Next Work

1. Confirm this handoff commit is pushed to `origin/main`.
2. Re-run full verification after the next session starts; do not assume long-running local processes survived.
3. Re-run `BONGSU_WEB_BASE=http://127.0.0.1:5678 BONGSU_API_KEY=test-admin-key ./scripts/verify-live-web-smoke.sh` after any UI change, then visually verify dashboard, CVE Search, vulnerability list, RBAC/admin pages, schedules, asset groups, reports, notifications, and force scan controls on `http://10.2.2.10:5678/`.
4. Keep extending browser coverage beyond the current dashboard/CVE Search/Hosts/Vulnerabilities/RBAC smoke paths.
5. Continue requirement audit against the original product list. The system is not yet declared complete.
6. Continue requirement audit against the original product list and fill the next strongest commercial-readiness gap.
7. Keep optimizing CVE DB quality/statistics paths if the imported DB grows beyond the current snapshot.
8. Run a real isolated/offline deployment rehearsal with Docker image loading and security DB bundle import. A real release archive has now been generated and verified locally, but the final commercial gate should still exercise transfer into an offline network or disposable air-gapped host.

## Matching Rules Reminder

Use `docs/vulnerability-matching-rules.md` as the detailed source of truth. The short rule is:

- Affected package row such as `phenx/php-svg-lib / Packagist / Fixed: 0.5.2` is valid and matchable.
- Rows without package name, ecosystem target, or fixed-version/range evidence are reference/enrichment data only.
- Priority sources such as EPSS and CISA KEV can enrich risk, but must not create package-name findings by themselves.
- Multiple source records for the same CVE can be grouped by CVE/reference key, but matching must still be package/ecosystem/range safe.
