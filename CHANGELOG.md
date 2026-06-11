# Changelog

All notable changes to Bongsu are documented in this file.

## [Unreleased] - 2026-06-11

### Scanning
- Native, dependency-free package scanner (`internal/agent/scanner/`) replacing trivy as the default: pure-Go dpkg/apk readers and rpm via the host/container `rpm` binary
- Agent `-scanner native|trivy` flag (`BONGSU_AGENT_SCANNER`), defaulting to `native`; the agent no longer requires the trivy binary
- Language dependency scanning outside the OS package manager (pyenv, nvm, app bundles, vendored deps) via `-lang-scan-roots` (`BONGSU_AGENT_LANG_SCAN_ROOTS`, sentinels `none`/`all`) and `-lang-scan-depth` (`BONGSU_AGENT_LANG_SCAN_DEPTH`)
- Container rootfs scanned natively through the merged overlay, with per-container facts; the same `ScanRoot` path serves hosts and containers
- Multi-runtime container enumeration across docker, podman, nerdctl, and crictl with dedup by container ID

### Inventory/Facts
- Comprehensive host facts collected directly from `/proc`, `/sys`, `/etc` (os-release, kernel, cpu, memory, dmi, virtualization, network, filesystems) into `hosts.facts` (JSONB)
- Distro-identity container facts into `container_assets.facts`
- Facts surfaced in the dashboard: host detail "System Facts" card and container row expansion

### Vulnerability Management
- Per-finding triage assignee (담당자) with `?assignee=` filter and `unassigned` sentinel
- Distro backport version ordering fix, reducing missed Debian/Ubuntu `+debNuM`/`+ubuntu` findings

### Notifications
- SMTP email notification channel (`BONGSU_SMTP_HOST/PORT/USERNAME/PASSWORD/FROM/ENCRYPTION`, starttls/tls/none) alongside webhook and log; per-rule recipients via channel_config

### Data freshness
- Security DB sync exponential-backoff retry (`BONGSU_SECURITY_DB_RETRY_BASE_MINUTES`/`MAX_MINUTES`)
- Security DB bundle records `exporter_version` and rejects stale bundles on airgap import (`BONGSU_SECURITY_DB_BUNDLE_MAX_AGE_DAYS`, default 30 days)
- Raw OSV ecosystem freshness tracking and verification improvements

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
