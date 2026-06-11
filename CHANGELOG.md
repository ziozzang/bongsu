# Changelog

All notable changes to Bongsu are documented in this file.

## [0.2.0] - 2026-06-11

### Release Hardening

- Login brute-force throttling: 5 failures per client IP or username within a 15-minute window return HTTP 429 (`BONGSU_LOGIN_MAX_FAILURES`, `BONGSU_LOGIN_LOCKOUT_MINUTES`); unknown-username denials are audited and a constant-cost bcrypt comparison removes the username-existence timing oracle.
- Migrations take a cluster-wide Postgres advisory lock so concurrently starting server instances cannot race schema changes.
- The agent spools unsent scan reports to `<work-dir>/spool/` and replays them on the next run, so a server outage no longer loses completed scans (`BONGSU_AGENT_SPOOL_MAX`, default 20).
- Legacy webhook deliveries are bounded (`BONGSU_WEBHOOK_MAX_CONCURRENT`, default 16) and `notification_log` is pruned by the hourly housekeeping loop.
- The `has_vulns`/`min_cvss` package filters count only current actionable findings; `RematchCPE` gains the same candidate-limit flood guard as `RematchCVEs`.
- Dashboard design system unified across all 14 views (filter bars, buttons, modals, empty/loading/error states).
- CI runs gofmt/vet, the unit suite, a live-Postgres DB integration job, web build + Playwright smoke, compose validation, and all doc/spec verifiers in parallel; the Python e2e suite covers 66 scenarios and the Go integration suite pins matching invariants against a real database.

### Native Scanner GA

- Dependency-free native package scanner (`internal/agent/scanner/`) is now the default, replacing Trivy as the primary inventory path. Agent `-scanner native|trivy` flag (`BONGSU_AGENT_SCANNER`) selects the engine; `native` requires no external binary.
- Pure-Go dpkg reader: parses `var/lib/dpkg/status`, resolves Debian vs Ubuntu from `os-release`. Pure-Go apk reader: parses `lib/apk/db/installed`. rpm via host/container `rpm` exec (RHEL-family base OS ships `rpm`, no extra scanner needed).
- The same `ScanRoot` entry point serves the host (`/`) and each container's merged overlay rootfs so host and container inventory share one code path.
- Container rootfs scanned natively per-container through `GraphDriver.Data.MergedDir`; per-container distro-identity facts collected alongside the package inventory.
- Multi-runtime container enumeration across docker, podman, nerdctl, and crictl with container-ID dedup.

### Language Dependency Scanning

- `ScanLanguagePackages` walks configurable roots for lockfiles and manifests: `package-lock.json` (npm v1/v2/v3), `package.json`, `requirements.txt` (pinned `==`), `go.mod`, `Cargo.lock`, `Gemfile.lock`, PEP 503 `.dist-info/METADATA`.
- Bounded walk with configurable depth (default 12); prunes `/proc`, `/sys`, `.git`, `__pycache__`, `.gradle`, `.m2`, etc.
- `-lang-scan-roots` (`BONGSU_AGENT_LANG_SCAN_ROOTS`): `none` to disable, `all` for full scan-root. `-lang-scan-depth` (`BONGSU_AGENT_LANG_SCAN_DEPTH`).

### Runtime Detection

- `ScanRuntimes` detects language interpreter/VM installations outside the OS package manager from filesystem layout only — no binary execution: pyenv-built Python, Node tarballs, JDK (Oracle/OpenJDK/Temurin from `release` file), Ruby (`lib/ruby/<X.Y.Z>/`), PHP, Go SDK (`VERSION` file).
- Detected runtimes carry `PkgType=runtime` and a CPE-style ecosystem key (python/nodejs/jdk/go/ruby/php) for downstream CPE matching.
- Runtime CPE matching (`RematchCPE`) matches detected runtimes against NVD CPE advisories, version-gated via `compatibleCPECandidate` to suppress false positives from product-name-only matches. Runtime findings are kept out of the OSV stale-rematch cleanup path.
- Runtime CPE findings refreshed on CVE DB recalculation.

### Ecosystem-aware Version Comparison Engine (vercmp)

- New `internal/server/vercmp/` package replaces ad-hoc version heuristics with real per-ecosystem algorithms: Debian `verrevcmp` (dpkg/deb-version(5)), RPM `rpmvercmp` (epoch:version-release, tilde/caret), Alpine apk version algorithm, generic semver fallback for language packages.
- Covers: debian/ubuntu, alpine/wolfi, rhel/centos/rocky/almalinux/amazon/suse/opensuse/azurelinux, and all language ecosystems.
- Cross-ecosystem policy: epoch-loss tolerance — when the installed version has no epoch but the advisory version does, the epoch is stripped before comparison, eliminating the dominant false-positive source from distro epoch bumps.
- Distro backport version suffixes (`+debNuM`, `+ubuntu`) ordered correctly.

### False Positive Reductions

- Version-gated CPE matching: NVD entries with no version constraint never match on product name alone.
- `compatibleCPECandidate` in `internal/server/db/classify.go` requires at least one explicit version bound or an exact pinned version.
- Epoch-loss tolerance in `compareVersions` reduces false positives from administrative distro epoch bumps.

### Host and Container Facts

- `CollectFacts()` (`internal/agent/system/facts.go`): comprehensive host facts from `/proc`, `/sys`, `/etc` (os_release, kernel, cpu, memory, dmi, virtualization, network, filesystems, system) stored in `hosts.facts` JSONB (migration 055). Schema evolves without future migrations.
- `CollectContainerFacts(root)`: distro-identity facts (os-release, lsb-release, release files) from inside the container rootfs stored in `container_assets.facts` JSONB (migration 056). Host-level facts intentionally excluded.
- Facts surfaced in the dashboard: host detail "System Facts" card and container row expansion.

### Triage and Auto-Assignment

- Per-finding triage assignee column added to `vulnerability_triage` (migration 053). `?assignee=` filter on vulnerability list; `unassigned` sentinel returns only unassigned findings.
- Owner auto-assign: after scan ingestion the server resolves the host's authoritative owner from the DB and sets it as the assignee on all new (un-triaged) findings. Existing triage rows are never overwritten. Controlled by `BONGSU_AUTO_ASSIGN_BY_OWNER` (default `true`).
- Assignee column and bulk triage exposed in the vulnerability dashboard.

### Email and scan.failed Alerting

- SMTP email notification channel (migration 054): `BONGSU_SMTP_HOST/PORT/USERNAME/PASSWORD/FROM/ENCRYPTION` (starttls/tls/none). Per-rule recipients via `channel_config: {"to": "a@x,b@y", "subject_prefix"?: "..."}`. Delivery retried with bounded backoff.
- `scan.failed` notification trigger (migration 057): fires when a scan finishes degraded/failed or with ingest errors. Added to the trigger event allowlist alongside `scan.completed`, `vuln.new_critical`, `vuln.new_high`, `sla.breach`, `security_db.updated`, `schedule.daily`.

### Search Expansion and CVE-to-Assets

- `VulnFilter` expanded: `Assignee`, `Ecosystem`, `PkgType`, `VulnIDLike` (substring match on vulnerability_id, e.g. `CVE-2024` or `DEBIAN-`), `HasFix` (`yes`/`no`), `MinCVSS`/`MaxCVSS`, plus sort controls.
- `GET /api/vulnerabilities/affected-assets?vulnerability_id=...`: CVE-to-assets reverse lookup — returns all hosts and containers currently affected by a given CVE in the latest scan, scoped to the caller's RBAC access.
- Dashboard: detailed column filters and CVE-to-assets modal on the vulnerability list.

### Data Freshness

- Security DB sync exponential-backoff retry (`BONGSU_SECURITY_DB_RETRY_BASE_MINUTES`, default 5; `BONGSU_SECURITY_DB_RETRY_MAX_MINUTES`, default 60).
- Security DB bundle now records `exporter_version`; import rejects bundles older than `BONGSU_SECURITY_DB_BUNDLE_MAX_AGE_DAYS` (default 30 days).
- Raw OSV ecosystem `raw_last_update` tracked separately from `indexed_last_update` so source freshness is not overstated by a global affected-index rebuild. Strict live OSV freshness verifier checks raw timestamps.

### Multilingual Landing Page

- `docs/index.html`: one-page project introduction in 8 languages — 한국어, English, 中文, 日本語, Français, Deutsch, Español, Português. Language preference persisted in localStorage; defaults to Korean, falls back to browser language detection.

### Migrations

| # | Change |
|---|---|
| 053 | `vulnerability_triage.assignee` column + index |
| 054 | `notification_rules.channel_type` CHECK extended to include `email` |
| 055 | `hosts.facts` JSONB column + GIN index; `hosts.facts_collected_at` |
| 056 | `container_assets.facts` JSONB column |
| 057 | `notification_rules.trigger_event` CHECK extended to include `scan.failed` |

## [0.1.0] - 2026-06-03

### Phase 0: Structural Decomposition
- Package-level decomposition: `api`, `db`, `cvematch`, `trivydb`, `secdb`, `shared/models`, `shared/trivyparse`
- Agent report endpoint with multipart JSON support
- Host, scan, package, container, and vulnerability data models
- PostgreSQL migrations 001-010
- Source-pattern testing framework (readAllPackageGoFiles + extractFuncBody)

### Phase 1: Operational Safety
- Configurable HTTP timeouts (read, write, idle, read-header)
- Request body size limits (JSON, multipart, CVE DB import, Trivy DB upload, security DB bundle)
- Graceful shutdown (SIGINT/SIGTERM with 10s drain)
- Startup validation for server secrets (BONGSU_ALLOW_WEAK_SECRETS escape hatch)
- Rate limiting (per-IP, separate agent/admin limits)
- Security headers (HSTS, CSP, X-Frame-Options, Permissions-Policy, Referrer-Policy)
- OpenAPI 3.1 spec with 60+ endpoints
- Verification scripts (migrations, deploy config, static binaries, OpenAPI, airgap package)
- Docker Compose with PostgreSQL, trivy-db init, server, and web frontend

### Phase 2: Authentication Hardening
- Session-based web auth with bcrypt password hashing
- Local user management (bootstrap admin, change password)
- Three-tier API authentication (admin API key, agent API key, install token)
- Viewer API keys (read-only access)
- RBAC subjects and policies (CRUD)
- Comprehensive audit logging (all admin actions)
- Session cleanup goroutine

### Phase 3: Fleet Management
- Scheduled scan CRUD with 5-field cron expressions (migrations 043-045)
- Asset groups (static and dynamic with key=value rule matching)
- Scan request lifecycle (create, claim, complete, cancel, requeue)
- Agent version tracking and drift detection
- Host metadata (owner, team, environment, criticality, tags)
- SBOM export (CycloneDX and SPDX formats)
- Installer binary management (agent + trivy download endpoints)

### Phase 4: Actionable Intelligence
- Vulnerability trend snapshots with daily grain (migration 046)
- Top at-risk hosts (risk score aggregation)
- Remediation recommendations (overdue + exploited queries)
- Vulnerability posture comparison (current vs N days ago)
- Notification rules with webhook and log channels (migrations 047-048)
- Notification engine with severity/risk/exploited/host filtering
- Executive summary report (severity counts, SLA compliance, trend, top hosts)
- SLA compliance report (per-severity rates, overdue by owner)
- Risk breakdown report (grouped by owner/team/environment/criticality)
- Report export (JSON and CSV formats)

### Phase 5: Polish
- Performance indexes for common query patterns (migration 049)
- Frontend API integration for all Phase 3-4 endpoints
- Web dashboard views: Schedules, Asset Groups, Trends, Reports, Notifications
- Consistent JSON error responses (writeError helper replacing http.Error)
- CVE DB sync script with per-ecosystem OSV and per-year NVD imports
