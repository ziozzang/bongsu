# Changelog

All notable changes to Bongsu are documented in this file.

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
