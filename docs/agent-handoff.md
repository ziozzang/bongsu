# Bongsu Agent Handoff

Updated: 2026-06-04 11:06:55 KST

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

Expected committed head before this continuation:

```text
fa030f8 (master, origin/main) Verify live agent scan request completion
```

Important recent commits:

```text
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
- Live API agent workflow verification now creates a verifier host report, creates a host-specific scan request, claims it through `/api/agent/scan-requests/claim`, posts a scan report tied to that request, completes it through `/api/agent/scan-requests/{id}/complete`, and verifies both scan-request and scan list state.
- Real agent binary workflow verifier builds `cmd/agent`, runs it against fixture Trivy/osquery/docker tools, verifies host/container package ontology through the live API, then runs daemon polling to claim and complete a host-specific scan request.
- Live CVE DB quality verifier checks production-scale source count, matchability, EPSS enrichment, affected/reference index health, placeholder rejection, affected package evidence, reference grouping, and endpoint responsiveness.
- Live RBAC scope verifier ingests allowed and denied host/container fixtures, creates a viewer subject and host-scoped policy, then verifies viewer-key access filters hosts, packages, containers, scans, and scan requests.
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

API was last started with:

```bash
go build -o /tmp/bongsu-server-live ./cmd/server
setsid env BONGSU_DB_DSN="postgres://bongsu:bongsu@localhost:5432/bongsu?sslmode=disable" \
BONGSU_API_KEY=test-admin BONGSU_AGENT_API_KEY=test-agent BONGSU_INSTALL_TOKEN=test-install \
BONGSU_ALLOW_WEAK_SECRETS=true BONGSU_WEB_AUTH=false \
BONGSU_SECURITY_DB_SYNC_ON_START=false BONGSU_SECURITY_DB_SYNC_CMD="" \
BONGSU_TRIVY_DB_INTERVAL_HOURS=0 BONGSU_AGENT_BIN=/home/ziozzang/bongsu/bin/bongsu-agent \
BONGSU_CVE_AFFECTED_INDEX_REBUILD_TIMEOUT_SECONDS=30 \
BONGSU_STARTUP_RECALC_TIMEOUT_SECONDS=1 \
BONGSU_STALE_REMATCH_CLEANUP_BATCH_SIZE=10000 \
BONGSU_CVE_SEARCH_TIMEOUT_SECONDS=15 \
BONGSU_CVE_REFERENCE_GROUP_TIMEOUT_SECONDS=10 \
BONGSU_CVE_AFFECTED_PACKAGES_TIMEOUT_SECONDS=10 \
BONGSU_VULNERABILITY_LIST_TIMEOUT_SECONDS=15 \
BONGSU_PORT=5677 /tmp/bongsu-server-live >/tmp/bongsu-api-5677.log 2>&1 < /dev/null &
```

Do not change this to `8080`. Keep API and web split as `5677` and `5678`.

## Current CVE DB Status

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
  "total_records": 760499,
  "total_matchable": 111300,
  "affected_index_coverage": 100,
  "affected_index_orphans": 0,
  "reference_index_coverage": 100,
  "reference_index_orphans": 0,
  "epss_non_epss_coverage": 96.5
}
```

Last direct DB check found zero `TEMP-*` and zero `CVD-*` rows in both `cve_database` and `cve_affected_packages`.

## What Has Been Completed

- Management server and dashboard are deployed locally with web on `5678` and API on `5677`.
- Security DB ingest/import/export exists for connected and air-gapped flows.
- CVE DB quality and status are visible on the dashboard.
- CVE search is backed by indexes and bounded request timeouts.
- Affected packages lookup and reference grouping are bounded.
- Matchable CVE evidence is materialized into `cve_affected_packages`.
- Vulnerability evidence/listing now uses matchable affected package rows instead of raw JSON name matches.
- CVE DB rematch filters require compatible package name, ecosystem, fixed version/range, and affected range semantics.
- EPSS data is merged into matching non-EPSS CVE/advisory rows.
- TEMP placeholder identifiers are blocked/removed from CVE DB matching paths.
- CVSS v2/v3.x/v4 recalculation support exists and startup recalculation is timeout-bounded.
- Background stale-while-revalidate cache for `/api/cve-db/stats` is implemented.
- The dashboard API client now reads `X-Bongsu-Cache` for CVE DB stats and the dashboard card exposes cache state, generated timestamp, and stats duration.
- `scripts/install-agent.sh` supports `BONGSU_SYSTEMD_DIR` and `BONGSU_SYSTEMCTL_BIN` for controlled systemd installation testing while preserving `/etc/systemd/system` and `systemctl` defaults.
- Playwright coverage now verifies dashboard CVE DB status, CVE Search fixed-version evidence, Hosts force-scan POST bodies, RBAC subject/policy POST bodies, scheduled scan creation payloads, dynamic asset-group creation and scan trigger payloads, report export query parameters, notification rule creation/test payloads, and notification-log rendering.
- `docs/operations-runbook.md` is available and `scripts/package.sh` includes documentation in release archives.
- Go tests now assert RBAC access scope expansion for host, container, image, and asset-group policies and verify inventory/scan list endpoints apply those scopes.
- CI runs `scripts/verify-package-contents.sh` and `scripts/verify-airgap-package-smoke.sh` to keep air-gapped release archives from silently losing required files or breaking package generation.
- Container package rows are annotated with container name, container ID, image name, and image ID before upload. Source-level regression tests now check that package persistence, container asset persistence, CycloneDX properties, and SPDX package comments keep this runtime identity and package target context.
- Live Playwright smoke is now scripted by `./scripts/verify-live-web-smoke.sh` and passed against `http://127.0.0.1:5678` using `BONGSU_API_KEY=test-admin-key`. It covers dashboard CVE DB status, CVE Search, Hosts, Vulnerabilities, and RBAC routes, while asserting that live `/api/` responses do not return 5xx.
- Other agents added domain file decomposition, sessions/local admin auth, rate limiting, OpenAPI verification, scheduled scans, asset groups, trend/intelligence/report/notification APIs, backup/restore scripts, migration `049`, and frontend integration. Current automated verification has been rerun on this state, the newest browser suite now covers the added schedule/asset-group/report/notification views with mocked API contract assertions, and the live operator verifier passed against `127.0.0.1:5677` using the running API and agent credentials, including agent claim/report/complete.

## Verification Commands

Run these after pulling this handoff state:

```bash
git status --short --branch
go test ./...
./scripts/verify-migrations.sh
./scripts/verify-deploy-config.sh
./scripts/verify-requirements-audit.sh
./scripts/verify-openapi.sh
./scripts/verify-operator-workflow.sh
./scripts/verify-agent-binary-workflow.sh
./scripts/verify-live-cvedb-quality.sh
./scripts/verify-live-rbac-scope.sh
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
BONGSU_API_KEY=test-admin-key ./scripts/verify-live-cvedb-quality.sh
BONGSU_API_KEY=test-admin-key BONGSU_AGENT_API_KEY=test-agent-key BONGSU_VIEWER_API_KEY=viewer-test-key BONGSU_VIEWER_SUBJECT=rbac-live-viewer ./scripts/verify-live-rbac-scope.sh
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
3. Re-run `BONGSU_WEB_BASE=http://127.0.0.1:5678 BONGSU_API_KEY=test-admin-key ./scripts/verify-live-web-smoke.sh` after any UI change, then visually verify dashboard, CVE Search, vulnerability list, RBAC/admin pages, and force scan controls on `http://10.2.2.10:5678/`.
4. Keep extending browser coverage beyond the current dashboard/CVE Search/Hosts/Vulnerabilities/RBAC smoke paths.
5. Continue requirement audit against the original product list. The system is not yet declared complete.
6. Continue requirement audit against the original product list and fill the next strongest commercial-readiness gap.
7. Keep optimizing CVE DB quality/statistics paths if the imported DB grows beyond the current snapshot.
8. Generate a real release archive with `scripts/package.sh`, run `scripts/verify-airgap-release-archive.sh` against it, and then rehearse loading/importing it in an offline-like environment. The lightweight package smoke verifier now covers the package script path, but it intentionally stubs heavy Docker/npm work.

## Matching Rules Reminder

Use `docs/vulnerability-matching-rules.md` as the detailed source of truth. The short rule is:

- Affected package row such as `phenx/php-svg-lib / Packagist / Fixed: 0.5.2` is valid and matchable.
- Rows without package name, ecosystem target, or fixed-version/range evidence are reference/enrichment data only.
- Priority sources such as EPSS and CISA KEV can enrich risk, but must not create package-name findings by themselves.
- Multiple source records for the same CVE can be grouped by CVE/reference key, but matching must still be package/ecosystem/range safe.
