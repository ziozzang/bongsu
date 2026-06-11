# TODO

> **Scope of this file:** Forward-looking roadmap checklist — what is planned, in-progress, or remaining. For a structured evidence matrix of what has been built and verified, see [`docs/requirements-audit.md`](docs/requirements-audit.md).

This file tracks remaining work items. Items marked **DONE** are implemented and verifiable in code.

---

## Scanning

- [x] **DONE** Native, dependency-free package scanner (pure-Go dpkg/apk, rpm via exec) — `internal/agent/scanner/`
- [x] **DONE** `-scanner native|trivy` flag; `native` is the default and requires no external binary
- [x] **DONE** Language dependency scanning from lockfiles/manifests (npm, PyPI, Go, Cargo, Gem) — `ScanLanguagePackages`
- [x] **DONE** Runtime detection from filesystem layout (Python/pyenv, Node, JDK/JRE, Ruby, PHP, Go SDK) — `ScanRuntimes`
- [x] **DONE** Container rootfs scanned natively through merged overlay; host and container share `ScanRoot`
- [x] **DONE** Multi-runtime container enumeration (docker, podman, nerdctl, crictl) with dedup
- [ ] **REMAINING** Registry/OCI image scanning (pull image, scan without running container)
- [ ] **REMAINING** IaC and secrets scanning (Terraform, Helm, Kubernetes YAML, env files)
- [ ] **REMAINING** Windows agent / WMI-based inventory

## Version Comparison and CVE Matching

- [x] **DONE** Ecosystem-aware vercmp engine (`internal/server/vercmp/`): dpkg, rpmvercmp, apk, semver
- [x] **DONE** Epoch-loss tolerance to cut false positives from distro epoch bumps
- [x] **DONE** Version-gated CPE matching for runtimes (`compatibleCPECandidate`)
- [x] **DONE** Runtime CPE matching against NVD advisories, refreshed on DB recalculation
- [x] **DONE** Distro backport suffix ordering (`+debNuM`, `+ubuntu`)
- [ ] **REMAINING** Maven/Gradle POM version comparison (maven version ordering has additional rules)
- [ ] **REMAINING** Debian/Ubuntu DSA-to-CVE resolution completeness audit

## Facts and Inventory

- [x] **DONE** Comprehensive host facts (os_release, kernel, cpu, memory, dmi, virtualization, network, filesystems) in `hosts.facts` JSONB
- [x] **DONE** Container distro-identity facts in `container_assets.facts` JSONB
- [x] **DONE** Facts surfaced in dashboard (host System Facts card, container row expansion)
- [ ] **REMAINING** Kubernetes node/pod inventory (native CRI/containerd enumeration or k8s API)
- [ ] **REMAINING** Cloud instance metadata (EC2 IMDSv2, GCP metadata server) as optional fact source

## Vulnerability Management

- [x] **DONE** Per-finding triage assignee with `?assignee=` filter and `unassigned` sentinel
- [x] **DONE** Owner auto-assign on scan ingestion (`BONGSU_AUTO_ASSIGN_BY_OWNER`)
- [x] **DONE** Triage status workflow (open, in_progress, accepted_risk, false_positive, fixed, ignored)
- [x] **DONE** Triage expiry with time-bound exceptions
- [x] **DONE** SLA days per severity (`BONGSU_SLA_*_DAYS`)
- [x] **DONE** Risk score (CVSS + EPSS + KEV + criticality)
- [x] **DONE** `GET /api/vulnerabilities/affected-assets` CVE-to-assets reverse lookup
- [x] **DONE** Detailed VulnFilter (assignee, ecosystem, pkg_type, vuln_id_like, has_fix, min/max_cvss)
- [ ] **REMAINING** Ticketing integration (Jira, ServiceNow, GitHub Issues) for triage-to-ticket workflow
- [ ] **REMAINING** Bulk triage export/import (CSV round-trip for offline review)

## Notifications

- [x] **DONE** Webhook channel (per-rule URL, HMAC signing)
- [x] **DONE** SMTP email channel (starttls/tls/none, per-rule recipients)
- [x] **DONE** Log channel
- [x] **DONE** `scan.failed` trigger
- [x] **DONE** Full trigger taxonomy: scan.completed, scan.failed, vuln.new_critical, vuln.new_high, sla.breach, security_db.updated, schedule.daily
- [ ] **REMAINING** Slack / Teams / PagerDuty notification channels
- [ ] **REMAINING** Per-host or per-owner notification routing

## CVE Database and Data Sources

- [x] **DONE** Multi-source CVE DB: OSV, NVD, EPSS, CISA-KEV, Trivy
- [x] **DONE** Security DB sync with exponential-backoff retry
- [x] **DONE** Airgap bundle export/import with age validation and `exporter_version` check
- [x] **DONE** Raw OSV ecosystem freshness (`raw_last_update`) separate from index freshness
- [ ] **REMAINING** GitHub Security Advisory (GHSA) direct API import (currently covered via OSV aliases)
- [ ] **REMAINING** Vendor-specific advisory feeds (Red Hat RHSA API, Debian LTS, Ubuntu USN direct)

## Security

- [x] **DONE** Session-based web auth, bcrypt passwords, OIDC bearer JWT
- [x] **DONE** Three-tier API keys (admin, agent, install token)
- [x] **DONE** RBAC (host/container/image/asset_group scopes, viewer/export/write/admin)
- [x] **DONE** Audit logging for all admin and agent events
- [x] **DONE** Agent host-binding token (`BONGSU_AGENT_HOST_BINDING`)
- [x] **DONE** Security headers (HSTS, CSP, X-Frame-Options, Permissions-Policy)
- [ ] **REMAINING** TLS termination in the server binary itself (`BONGSU_TLS_CERT`/`BONGSU_TLS_KEY`); currently delegated to reverse proxy
- [ ] **REMAINING** Release binary signing and bundle signature verification (GPG/cosign)
- [ ] **REMAINING** SAST/dependency audit CI gate (govulncheck, `go mod verify`)

## Database and Query Performance

- [x] **DONE** Materialize CVE reference-group counts into `cve_reference_group_summary` (migration 058), refreshed at the end of every reference-index rebuild; CVE search reads it with PK lookups, removing the "group summary unavailable" failure mode.
- [x] **DONE** Query-optimization pass on the hot paths: CVE search bounded count + parallel count/data + work_mem (8.25s -> 2.3s); dashboard aggregates pinned in MATERIALIZED CTEs (vuln-summary 2168ms -> 140ms, executive-summary ~2s -> 154ms); migration 059 `vulnerabilities(host_id, severity)` and migration 060 `vulnerabilities(scan_id, cvss_score DESC)` (cvss-sorted list 3.3s -> 0.1s).
- [x] **DONE** Pre-built, revision-keyed airgap export bundle cache (export TTFB ~28s -> ~2s).
- [x] **DONE** Cache the CVE reference-key index stats (`count(DISTINCT cve_id)` over 1.8M rows, ~3.5s) with a 60s TTL invalidated on index rebuild, so admin `/api/health` polling no longer re-scans the whole table.
- [ ] **REMAINING** `GET /api/packages?has_vulns=true` (~9.5s): a behavior-identical reshape to force the nested-loop semi-join (verified ~476ms) — the actionable-finding EXISTS is correlated to the package row, so it is a planner cost-estimate problem, not a missing index.
- [x] **DONE** `GET /api/packages?has_vulns=true` now filters on the precomputed package_vulnerability_summaries table via an indexed EXISTS (7.5s -> 0.04s).
- [x] **DONE** `/api/stats` and admin `/api/health` operational block served from short-TTL scope-keyed response caches, invalidated on scan ingest (cold 2-3.5s -> warm sub-ms; the dashboard polls both so it is warm after first load).
- [ ] **REMAINING** `GET /api/cve-db/search?q=<broad-substring>` (e.g. "CVE-202" matching ~47% of the table) is ~3s: the data query scans ~450k matching rows and sorts ~290k by CVSS. Specific searches (a package, an exact CVE) are already sub-200ms. Consider a keyset/seek pagination or a materialized "recent CVEs by score" path if broad substring scans become common.
- [ ] **REMAINING** `GET /api/containers` is ~3-4s in the current dataset state (no containers in the latest scans but ~1k in older scans): the assembled query executes ~3s despite each component being sub-ms — a planner pathology with the nested actionable-finding subqueries. The page-limit + single-eval reshape helps when containers are present; a deeper fix is to derive container vuln counts from package_vulnerability_summaries (a semantic change worth verifying against real container data).
- [ ] **REMAINING** Background `VACUUM`/`ANALYZE` and bloat monitoring guidance for long-running deployments with frequent rematch churn.

## Infrastructure and Deployment

- [x] **DONE** Docker Compose deployment (connected and airgap compose files)
- [x] **DONE** Static binary build with version/commit/build-date ldflags
- [x] **DONE** One-liner agent installer (cron and systemd modes)
- [x] **DONE** Airgap release archive (`scripts/package.sh`) with SHA256 manifest
- [ ] **REMAINING** Kubernetes / Helm chart for the management server
- [ ] **REMAINING** Multi-tenancy (separate namespaces or organizations within one deployment)
- [ ] **REMAINING** HA mode (multiple server replicas with shared PostgreSQL)
- [ ] **REMAINING** Official OCI image publishing (GitHub Container Registry)

## Dashboard and UX

- [x] **DONE** React dashboard with Vite
- [x] **DONE** Hosts, Containers, Packages, Vulnerabilities, Scan History, CVE Search, Trends, Reports, Notifications, Schedules, Asset Groups, RBAC, Audit Log views
- [x] **DONE** CVE-to-assets modal in vulnerability list
- [x] **DONE** Multilingual landing page (`docs/index.html`) — 8 languages
- [ ] **REMAINING** Mobile-responsive layout improvements
- [ ] **REMAINING** Customizable dashboard widgets / saved filter presets

## Testing

- [x] **DONE** Go unit tests (`go test ./...`)
- [x] **DONE** Python API e2e robustness suite (`tests/e2e/api_e2e.py`)
- [x] **DONE** Playwright browser smoke (`web/tests/e2e/cve-db.spec.ts`)
- [x] **DONE** Live verification scripts (`scripts/verify-*.sh`)
- [x] **DONE** Release readiness gate (`scripts/verify-release-readiness.sh`)
- [ ] **REMAINING** Agent integration test with real package DB fixtures (dpkg/apk/rpm)
- [ ] **REMAINING** Fuzz testing for vercmp and lockfile parsers
