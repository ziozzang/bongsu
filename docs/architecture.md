# Bongsu Architecture

Bongsu means "봉수대": a watchtower network that sends signals from the edge back to a central point. The system follows that model.

## Goals

- Collect host and running-container package inventories natively, without requiring Trivy or other external binaries on the target host.
- Detect language dependency installations outside the OS package manager (pyenv, nvm, app bundles, vendored lockfiles).
- Detect language runtime interpreters (Python/Node.js/JDK/Ruby/PHP/Go SDK) from filesystem layout.
- Collect comprehensive host and container facts (OS identity, hardware, network, virtualization).
- Send SBOM-like package data to the central server with host, OS, container, runtime, and facts context.
- Build and maintain a merged security database from public sources: CISA KEV, FIRST EPSS, OSV, NVD, and Trivy DB.
- Match packages using ecosystem-aware version comparison (dpkg/rpmvercmp/apk/semver) with false-positive reductions.
- Support connected and air-gapped deployments; connected sites update every 6 hours, air-gapped sites import exported bundles.
- Separate OS package advisories from code library advisories; match language runtime CVEs via NVD CPE with version gating.
- Provide a web dashboard, one-line agent install, force scan requests, triage workflow with assignee/auto-assign, multi-channel notifications, and an RBAC-ready data model.

## Component Overview

```
┌────────────────────────────────────────────────────────────────┐
│                         Agent (each host)                       │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                 Native Scanner                            │   │
│  │  ScanRoot       dpkg (pure-Go) / apk (pure-Go) / rpm    │   │
│  │  ScanLanguagePackages  lockfiles & manifests             │   │
│  │  ScanRuntimes   Python/Node/JDK/Ruby/PHP/Go SDK          │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ CollectFacts │  │  Containers  │  │ Collector (users,    │  │
│  │ (host facts) │  │ docker/podman│  │ processes, ports)    │  │
│  │ ContainerFact│  │ nerdctl/crictl│  │                      │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│                         ↓ JSON over HTTPS                        │
└──────────────────────────┼─────────────────────────────────────-┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                      Server (Go binary)                          │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   Ingest pipeline                        │    │
│  │  /api/report  → hosts, scans, packages, containers,     │    │
│  │                 vulnerabilities, users, processes, ports │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │               Matcher / Recalc pipeline                  │    │
│  │  OSV ecosystem matcher   (ecosystem+name+version+range)  │    │
│  │  vercmp engine           (dpkg/rpmvercmp/apk/semver)     │    │
│  │  CPE matcher             (NVD, version-gated)            │    │
│  │  EPSS/KEV enrichment     (columns on CVE rows)           │    │
│  │  Stale-rematch cleanup   (removes superseded findings)   │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │               Triage / Notification pipeline             │    │
│  │  Auto-assign by owner   (BONGSU_AUTO_ASSIGN_BY_OWNER)   │    │
│  │  Rule notifier          (webhook / email / log)          │    │
│  │  Triggers: scan.completed, scan.failed, vuln.new_*,     │    │
│  │            sla.breach, security_db.updated, schedule.*  │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │               Security DB manager                        │    │
│  │  OSV (per-ecosystem chunks, merge mode)                  │    │
│  │  NVD (per-year JSONL, single replace)                    │    │
│  │  CISA KEV / FIRST EPSS (enrichment, no name matching)   │    │
│  │  Trivy DB (supplemental OS/library advisories)           │    │
│  │  Sync: online every 6h with exponential-backoff retry    │    │
│  │  Airgap: bundle export/import with age validation        │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                      API layer                            │   │
│  │  60+ endpoints: hosts, scans, packages, vulnerabilities, │   │
│  │  CVE search, triage, reports, RBAC, notifications,       │   │
│  │  schedules, asset groups, export/import, audit           │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
          ┌────────────────┴─────────────────┐
          │                                   │
    ┌─────▼──────┐                   ┌────────▼───────┐
    │ PostgreSQL │                   │ React Dashboard│
    │ (state)    │                   │ (Vite, port    │
    └────────────┘                   │  5678)         │
                                     └────────────────┘
```

## Agent Subsystems

### Native Scanner (`internal/agent/scanner/`)

The scanner runs on the target host (or inside a container rootfs) without any external binary dependency for dpkg and apk:

- **`scanner.go` / `ScanRoot(root)`**: probes `var/lib/dpkg/status` (Debian/Ubuntu), `lib/apk/db/installed` (Alpine), then falls back to the `rpm` binary for RHEL-family. Same entry point for host (`/`) and container (merged overlay path). Returns `Result{Packages, OSFamily, Source}`.
- **`dpkg.go`**: pure-Go dpkg status parser. Reads `Package`/`Version`/`Architecture`/`Status` fields; sets `PkgType` to `debian` or `ubuntu` from `os-release`.
- **`apk.go`**: pure-Go apk installed-packages parser (`P:`/`V:`/`A:` fields).
- **`rpm.go`**: invokes the host `rpm -qa --queryformat ...` binary; used for BerkeleyDB/NDB/sqlite RPM DB formats that have no pure-Go reader.
- **`lang.go` / `ScanLanguagePackages(root, maxDepth)`**: bounded `WalkDir` for lockfiles and manifests. Prunes pseudo-filesystems at depth 1 and skips `.git`, `__pycache__`, `.terraform`, `.gradle`, `.m2`. Source field: `native-lang`.
- **`runtime.go` / `ScanRuntimes(root, maxDepth)`**: same bounded walk pattern; identifies runtime interpreters from on-disk layout without executing any binary. Source field: `native-runtime`. Sets `PkgType=runtime` and a CPE-product ecosystem key.
- **`ecosystem.go`**: maps `pkg_type` strings to normalized OSV/CPE ecosystem names.

### Facts Collector (`internal/agent/system/facts.go`)

- **`CollectFacts()`**: reads `/proc/cpuinfo`, `/proc/meminfo`, `/proc/mounts`, `/proc/uptime`, `/proc/loadavg`, `/sys/class/dmi/id/*`, `/etc/os-release`, `/etc/resolv.conf`, etc. Never executes external binaries. Gracefully degrades; unreadable sections are omitted, never fatal.
- **`CollectContainerFacts(root)`**: reads only distro-identity files from inside the container rootfs (`etc/os-release`, `etc/lsb-release`, distro release markers). Host-level facts (cpu, memory, dmi, kernel, network) are intentionally excluded from container facts.

### Collector (`internal/agent/collector/`)

Orchestrates the full scan run: invokes `ScanRoot`, `ScanLanguagePackages`, `ScanRuntimes`, `CollectFacts`, container enumeration (docker/podman/nerdctl/crictl), user accounts, process snapshots, and listening ports. Optional Trivy path (`-scanner trivy`) is also wired here.

## Server Subsystems

### Matching and Version Comparison

**`internal/server/vercmp/`** — ecosystem-aware version comparison:
- `vercmp.go`: `Compare(ecosystem, a, b)` dispatches to the correct algorithm by family.
- `deb.go`: full Debian `verrevcmp` (deb-version(5)), including epoch and debian-revision.
- `rpm.go`: RPM `rpmvercmp` with EVR (epoch:version-release), tilde, and caret.
- `apk.go`: Alpine apk version tokenizer.
- `generic.go`: semver-leaning fallback for language package ecosystems.

**`internal/server/db/classify.go`** — CVE matching policy:
- `compatibleSecurityCandidate`: OSV/Trivy ecosystem-aware matching. Requires package name, compatible ecosystem/category, and a version range or fixed version that covers the installed version. Uses `compareVersions` which calls the vercmp engine.
- `compareVersions`: adds epoch-loss tolerance on top of the vercmp engine — strips advisory epoch when the installed version has none.
- `compatibleCPECandidate`: NVD CPE matching for runtimes. Requires product name match (tolerates nodejs/node.js, jdk/jre spelling variants) AND at least one explicit version bound or exact version. Returns false for product-name-only entries with no version constraints.
- `cpeVersionAffected`: evaluates `VersionStartIncluding`, `VersionStartExcluding`, `VersionEndIncluding`, `VersionEndExcluding`, and exact `Version` fields from NVD CPE advisory data.

### Ingest Pipeline (`internal/server/api/report.go`)

`POST /api/report` flow after authentication:
1. Upsert host (with agent token binding check).
2. Insert containers, packages, vulnerabilities (scanner-provided or empty).
3. If no scanner vulns: run server-side CVE matching via `s.matcher.Match(...)`.
4. `RematchCVEs`: OSV/Trivy ecosystem rematch against the CVE DB for this scan's packages.
5. `RematchCPE`: match detected runtimes (`PkgType=runtime`) against NVD CPE advisories.
6. Insert users, processes, ports.
7. Rebuild package vulnerability summaries; complete scan with status.
8. Auto-assign findings to host owner if `BONGSU_AUTO_ASSIGN_BY_OWNER=true`.
9. Fire `scan.completed` rule notifier asynchronously; fire `scan.failed` if the scan is degraded/failed.

### Notification Pipeline

`ruleNotifier.evaluateAndDispatch(ctx, event, payload)` evaluates all configured notification rules against the event type and payload, then delivers to each rule's channel:
- `webhook`: HTTP POST with optional HMAC signing.
- `email`: SMTP via `notifier_email.go` (`smtpConfigFromEnv()` reads `BONGSU_SMTP_*`); supports starttls, implicit TLS, and plain. Retried with bounded backoff.
- `log`: writes to server log.

### Security DB and Recalculation Pipeline

On a successful DB change (sync, import, manual trigger):
1. CVSS recalculation for all CVE rows.
2. Vulnerability enrichment (enrich findings with latest CVE scores/titles).
3. Stale-rematch cleanup (remove `finding_source=cve-db` findings that no longer match).
4. CVE rematch (`RematchCVEs`): re-evaluate all packages against the updated CVE DB.
5. CPE rematch (`RematchCPE`): re-evaluate all runtimes against NVD CPE.
6. Queue automatic `security-db-update` package-only rescans for recently-seen hosts.

The recalculation runs as a serialized background worker; concurrent imports queue one follow-up pass.

### Data Flow: Triage and Auto-Assign

```
POST /api/report
  → insert vulns (scan_id, host_id, pkg_id, vuln_id)
  → resolve host.owner from DB (agent reports do not carry owner)
  → INSERT INTO vulnerability_triage (assignee=owner)
      ON CONFLICT DO NOTHING  ← never overwrites human triage
  → ruleNotifier.evaluateAndDispatch("scan.completed", ...)
  → if degraded/failed: ruleNotifier.evaluateAndDispatch("scan.failed", ...)
```

## Security Sources

Security sources are classified into:

- `os-package`: Debian, Ubuntu, Alpine, RHEL-family, SUSE, Wolfi/Chainguard, and similar distribution advisories.
- `code-library`: PyPI, npm, Go, Maven, crates.io, NuGet, RubyGems, Packagist, and similar language ecosystems.
- `general-cve`: NVD/CPE-oriented records and priority feeds such as CISA KEV and FIRST EPSS.
- `custom`: locally imported or future proprietary feeds.

Classification logic is in `internal/server/db/classify.go` (`ClassifySecuritySource`, `packageCategory`, `isOSEcosystem`).

## Database Schema (Key Tables)

| Table | Purpose |
|---|---|
| `hosts` | Host identity, metadata, agent status, `facts` JSONB |
| `scans` | Per-host scan lifecycle (running/completed/degraded/failed) |
| `packages` | Per-scan package inventory (OS, language, runtime) |
| `container_assets` | Container metadata per scan, `facts` JSONB |
| `vulnerabilities` | CVE findings linked to packages and scans |
| `vulnerability_triage` | Per-finding triage decisions with `assignee` |
| `cve_database` | Merged CVE advisories from all sources |
| `cve_affected_packages` | Materialized matchable affected-package index |
| `cve_reference_keys` | Normalized CVE/GHSA/vendor reference key index |
| `notification_rules` | Rules with trigger_event, channel_type (webhook/email/log), channel_config |
| `notification_log` | Delivery results per rule dispatch |
| `scan_requests` | Force scan request lifecycle |
| `audit_logs` | Append-only admin/agent event trail |

## Migrations

Migrations are SQL files in `migrations/` numbered 001–057. Applied once at startup, tracked with per-file SHA-256 checksums in `schema_migrations`. Startup rejects a modified applied file. Migrations 053–057 added: triage assignee, email channel, host facts, container facts, scan.failed trigger.

## Connected vs Air-Gapped Update Flow

**Connected**: server runs `BONGSU_SECURITY_DB_SYNC_CMD` on start and every `BONGSU_SECURITY_DB_INTERVAL_HOURS` (default 6). Failed syncs retry with exponential backoff (`BONGSU_SECURITY_DB_RETRY_BASE_MINUTES`).

**Air-gapped**: export a bundle in the connected environment, transfer it, import via `/api/admin/security-db/import` or the dashboard. Bundle age is validated against `BONGSU_SECURITY_DB_BUNDLE_MAX_AGE_DAYS` (default 30). The `exporter_version` field is recorded and checked on import.

## Dashboard

React single-page app served by a static web server on port 5678, proxying API calls to port 5677. Built with Vite. Key views: Hosts (with System Facts), Containers, Packages, Vulnerabilities (with CVE-to-assets modal and detailed filters), Scan History, CVE Search, Trends, Reports, Notifications, Schedules, Asset Groups, RBAC, Audit Log.

## Auth

- **Admin API**: `X-API-Key: <BONGSU_API_KEY>` on `/api/admin/*` and write endpoints.
- **Agent API**: `X-API-Key: <BONGSU_AGENT_API_KEY>` on `/api/report` and scan-request endpoints.
- **Install token**: `X-Install-Token: <BONGSU_INSTALL_TOKEN>` on `/api/install.sh`.
- **Session**: cookie-based web session from `POST /api/auth/login`.
- **OIDC**: RS256 JWT bearer verification; maps user/group claims to RBAC subjects.
- **Viewer keys**: `BONGSU_VIEWER_API_KEYS=key:subject`; scoped via RBAC policies.
- **Trusted headers**: `BONGSU_TRUSTED_IDENTITY_HEADER` / `BONGSU_TRUSTED_GROUPS_HEADER` for reverse-proxy auth.

## Test Surface

- `go test ./...` — unit tests including `classify_test.go` (OSV matching, CPE matching, vercmp), `lang_test.go` (lockfile parsing), `runtime_test.go` (runtime detection), `apk_test.go`/`deb_test.go`/`rpm_test.go`/`generic_test.go` (vercmp algorithms), `cpe_match_test.go` (CPE version gating).
- `tests/e2e/api_e2e.py` — Python API robustness suite.
- `web/tests/e2e/cve-db.spec.ts` — Playwright browser smoke.
- `scripts/verify-*.sh` — live operator verification scripts.
- `scripts/verify-release-readiness.sh` — full release gate (34 sub-gates).
