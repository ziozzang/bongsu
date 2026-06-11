# Bongsu Agent Handoff

Updated: 2026-06-11

This document is the handoff point for the next engineer session. Read `docs/architecture.md` first for the full component map, then come back here for practical orientation.

---

## Non-Negotiable Constraints

- Product name: `bongsu`, meaning "봉수대".
- Repository: `/home/ziozzang/bongsu`.
- Remote target: push local `master` to `origin/main`.
- Web UI listens on `http://10.2.2.10:5678/`. API listens on port `5677`.
- Do not touch or reconfigure Caddy.
- Docker Compose deployment must remain available for the management server.
- Air-gapped deployment is required: update outside, export bundle, import inside.
- Air-gapped release archives must include static server/agent binaries, source sync scripts, import/export scripts, server/web/agent/postgres Docker images, migrations, web assets, docs, and a `SHA256SUMS` manifest.
- CVE matching must use only matchable affected package evidence: package name + ecosystem/target + fixed-version or range data. Name-only, priority-only, URL/hash-like fixed values, and literal `0` fixed placeholders must not create rematch/rescan findings.
- `TEMP-*` and `CVD-*` placeholder vulnerabilities must not appear in `cve_database`, `cve_affected_packages`, reference keys, or rematch candidates.
- EPSS belongs on matching CVE/advisory rows as `epss_score`/`epss_percentile` columns, not only as separate EPSS source records.
- `BONGSU_AUTO_ASSIGN_BY_OWNER` defaults `true`; the server resolves owner from the DB (not from the agent report) before auto-assigning findings.

---

## Current Subsystem Map

```
cmd/
  agent/main.go          Agent entry point; all flags and env vars
  server/main.go         Server entry point

internal/
  agent/
    scanner/             Native package scanner (dpkg/apk/rpm/lang/runtime)
      scanner.go         ScanRoot — OS package entry point
      dpkg.go            Pure-Go dpkg reader
      apk.go             Pure-Go apk reader
      rpm.go             rpm exec-based reader (RHEL-family)
      lang.go            ScanLanguagePackages — lockfile/manifest walk
      runtime.go         ScanRuntimes — interpreter detection from filesystem
      ecosystem.go       pkg_type → ecosystem normalization
    system/
      facts.go           CollectFacts / CollectContainerFacts (no exec)
    collector/
      collector.go       Orchestrates full scan: scanner + facts + containers + users/procs/ports
    reporter/            HTTP client for posting reports to the server

  server/
    api/
      api.go             Mux setup; all route registrations
      report.go          POST /api/report — ingest pipeline + auto-assign + notifications
      vulnerability.go   GET /api/vulnerabilities + handleAffectedAssets
      notifier_email.go  SMTP email notification channel
      notifier_engine.go Rule notifier dispatch
      notify.go          Webhook / global notification helpers
      (many other handlers for hosts, scans, schedules, RBAC, etc.)
    db/
      classify.go        compatibleSecurityCandidate, compatibleCPECandidate,
                         compareVersions (epoch-loss), vercmpGeneric
      cvedb.go           RematchCVEs, RematchCPE, CVE DB management
      vulnerability.go   ListVulnerabilities (VulnFilter), AffectedAssetsForVulnerability
      (other domain files: host.go, scan.go, container.go, notification.go, ...)
    vercmp/
      vercmp.go          Compare(ecosystem, a, b) — dispatch
      deb.go             Debian verrevcmp
      rpm.go             RPM rpmvercmp
      apk.go             Alpine apk version algorithm
      generic.go         Semver fallback

  shared/
    models/              Shared data models (Package, Vulnerability, ScanReport, etc.)
    trivyparse/          Trivy JSON output parser

migrations/              SQL files 001–057; applied once at startup
web/                     React/Vite dashboard source
deploy/                  Docker Compose files, Dockerfiles, nginx config
scripts/                 Operational scripts (sync, verify, package, backup/restore)
tests/e2e/               Python API e2e suite
docs/                    Architecture, handoff, runbooks, openapi.yaml, index.html
```

---

## Where Matching Lives

### OSV / Trivy ecosystem matching
- **Entry**: `internal/server/db/cvedb.go` → `RematchCVEs(ctx, opts)`
- **Compatibility check**: `internal/server/db/classify.go` → `compatibleSecurityCandidate(pkgName, pkgType, pkgEco, installedVersion, cveCategory, cveEco, affectedProducts)`
- **Version comparison**: `compareVersions(eco, a, b)` in `classify.go` → `vercmp.Compare(eco, a, b)` in `internal/server/vercmp/`
- **Epoch-loss**: applied in `compareVersions` before calling vercmp

### NVD CPE matching (runtimes)
- **Entry**: `internal/server/db/cvedb.go` → `RematchCPE(ctx, opts)`
- **Compatibility check**: `internal/server/db/classify.go` → `compatibleCPECandidate(cpeProduct, installedVersion, affectedProducts)`
- **Version gating**: `cpeVersionAffected(installed, p)` — returns false if no version bounds present
- **Product normalization**: `cpeProductMatches(pkgProduct, advProduct)` — tolerates nodejs/node.js, jdk/jre, etc.

### Both paths are triggered
1. Per-scan after `POST /api/report` (report.go lines ~190–196)
2. On CVE DB recalculation (triggered after any successful DB sync/import)

---

## Running Tests

```bash
# Unit tests (includes vercmp, classify, lang/runtime parsers, cpe_match, etc.)
go test ./...

# Python API e2e suite
python3 tests/e2e/api_e2e.py

# Playwright browser smoke (requires npm deps)
npm --prefix web install
npm --prefix web run test:e2e

# Verify migrations are consistent
./scripts/verify-migrations.sh

# CVE matching invariants (same-name OS/library collisions, epoch, pre-release, CPE gating)
./scripts/verify-cve-matching-invariants.sh

# Full release readiness gate (34 sub-gates, light mode)
BONGSU_RELEASE_READINESS_SKIP_HEAVY=true ./scripts/verify-release-readiness.sh
```

---

## Running the Server Locally

```bash
# Build
commit=$(git rev-parse --short=12 HEAD)
build_date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
go build -trimpath -ldflags "-s -w -X main.version=0.1.0 -X main.commit=${commit} -X main.buildDate=${build_date}" \
  -o /tmp/bongsu-server ./cmd/server

# Run (env vars from file or inline)
BONGSU_API_KEY=test-admin-key \
BONGSU_AGENT_API_KEY=test-agent-key \
BONGSU_DB_PASSWORD=bongsu \
/tmp/bongsu-server
```

API: `http://localhost:5677` (or `http://10.2.2.10:5677` on the live target)
Web: `http://localhost:5678` (or `http://10.2.2.10:5678`)

---

## Deploy Stack

The management server runs from `deploy/`:
- `docker-compose.yml` — connected deployment (PostgreSQL + server + web + trivy-db init)
- `docker-compose.airgap.yml` — air-gapped variant (no outbound CVE sync)
- `Dockerfile.server`, `Dockerfile.agent`, `Dockerfile.web` — build targets
- `.env.example` — all configurable env vars with defaults

Key env vars for a new deployment:

| Variable | Role |
|---|---|
| `BONGSU_API_KEY` | Admin API key |
| `BONGSU_AGENT_API_KEY` | Agent reports and scan-request polling |
| `BONGSU_INSTALL_TOKEN` | One-liner installer generation |
| `BONGSU_DB_PASSWORD` | PostgreSQL password |
| `BONGSU_SMTP_HOST` + `BONGSU_SMTP_FROM` | Email notifications (optional) |
| `BONGSU_AUTO_ASSIGN_BY_OWNER` | Auto-assign findings to host owner (default `true`) |

---

## Live Runtime State

Live target:
- Web: `http://10.2.2.10:5678/`
- API: `http://10.2.2.10:5677/`

After any rebuild, verify the login path:
```bash
curl -sS -X POST http://127.0.0.1:5677/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<password>"}' | jq .
```

If `/api/auth/login` returns HTTP 500, check that port 5677 is listening and that the running binary was rebuilt from the current checkout. A stale binary from an earlier session will lack recent routes.

---

## Key Verification Commands

Run these after pulling a new session state:

```bash
git status --short --branch
go test ./...
./scripts/verify-migrations.sh
./scripts/verify-deploy-config.sh
./scripts/verify-cve-matching-invariants.sh
./scripts/verify-openapi.sh
./scripts/verify-backup-restore-archive.sh
./scripts/verify-installer-smoke.sh
./scripts/verify-static-binaries.sh
npm --prefix web run build
BONGSU_DB_PASSWORD=bongsu docker compose -f deploy/docker-compose.yml config >/tmp/bongsu-compose.out
```

Live checks (require a running API):
```bash
# CVE DB stats
curl -sS -H 'X-API-Key: test-admin-key' http://127.0.0.1:5677/api/cve-db/stats | jq .

# CVE search
curl -sS -H 'X-API-Key: test-admin-key' 'http://127.0.0.1:5677/api/cve-db/search?q=openssl&limit=5' | jq .

# Vulnerability list with new filters
curl -sS -H 'X-API-Key: test-admin-key' \
  'http://127.0.0.1:5677/api/vulnerabilities?ecosystem=debian&has_fix=yes&limit=5' | jq .

# CVE-to-assets reverse lookup
curl -sS -H 'X-API-Key: test-admin-key' \
  'http://127.0.0.1:5677/api/vulnerabilities/affected-assets?vulnerability_id=CVE-2024-1234' | jq .

# Live web smoke
BONGSU_WEB_BASE=http://127.0.0.1:5678 BONGSU_API_KEY=test-admin-key ./scripts/verify-live-web-smoke.sh

# Full live CVE DB quality check (needs BONGSU_DB_DSN for direct DB checks)
BONGSU_API_KEY=test-admin-key \
  BONGSU_DB_DSN='postgres://bongsu:bongsu@localhost:5432/bongsu?sslmode=disable' \
  ./scripts/verify-live-cvedb-quality.sh

# Release readiness gate (live mode)
BONGSU_RELEASE_READINESS_SKIP_HEAVY=true \
  BONGSU_RELEASE_READINESS_LIVE=true \
  ./scripts/verify-release-readiness.sh
```

---

## Matching Rules Reminder

See `docs/vulnerability-matching-rules.md` for the detailed source of truth. Short version:

- A valid matchable row: `phenx/php-svg-lib / Packagist / Fixed: 0.5.2` — has name, ecosystem, fixed version.
- Invalid for matching: rows without name, ecosystem, or fixed-version/range evidence.
- EPSS and CISA KEV can enrich risk signals but must not create package-name findings by themselves.
- CPE matching for runtimes: requires version bounds; product-name-only NVD entries never match.
- Epoch-loss tolerance: if the installed version has no epoch and the advisory does, strip the advisory epoch before comparing.

---

## What Was Completed in This Wave (2026-06-11)

The following subsystems were built and are verifiable in the current codebase:

1. **Native scanner GA** — `internal/agent/scanner/` with dpkg/apk/rpm/lang/runtime. Default `-scanner native`.
2. **vercmp engine** — `internal/server/vercmp/` with dpkg/rpmvercmp/apk/semver; replaces all version heuristics.
3. **Epoch-loss tolerance** — `compareVersions` in `classify.go`.
4. **Runtime CPE matching** — `RematchCPE` + `compatibleCPECandidate` version-gated; refreshed on DB recalc.
5. **Host and container facts** — `CollectFacts`/`CollectContainerFacts` in `system/facts.go`; migrations 055/056.
6. **Triage assignee** — migration 053; `VulnFilter.Assignee`; `unassigned` sentinel.
7. **Owner auto-assign** — `autoAssignFindingsToOwner` in `report.go`; resolves owner from DB.
8. **Email notification channel** — `notifier_email.go`; migration 054; SMTP starttls/tls/none.
9. **scan.failed trigger** — migration 057; `scanFailedPayload` in `report.go`.
10. **VulnFilter expansion** — ecosystem, pkg_type, vuln_id_like, has_fix, min/max_cvss, assignee.
11. **CVE-to-assets endpoint** — `GET /api/vulnerabilities/affected-assets`; `AffectedAssetsForVulnerability`.
12. **Multilingual landing page** — `docs/index.html`; 8 languages with language switcher.

---

## Next Work

1. Confirm this handoff commit is pushed to `origin/main`.
2. Re-run the full verification suite after pulling the latest state; do not assume long-running local processes survived.
3. Re-run `BONGSU_WEB_BASE=http://127.0.0.1:5678 BONGSU_API_KEY=test-admin-key ./scripts/verify-live-web-smoke.sh` after any UI change.
4. Consider adding Go unit tests for `ScanRuntimes` (runtime.go) — the `runtime_test.go` file exists; expand fixture coverage for JDK `release` file parsing and Node tarball path detection.
5. Add Go unit tests for `CollectFacts` and `CollectContainerFacts` using mock filesystem roots.
6. Continue requirement audit against the original product list. See `TODO.md` for remaining items: registry/OCI image scanning, IaC/secrets scanning, Kubernetes inventory, ticketing integration, TLS in-process, release binary signing, multi-tenancy.
7. Repeat the airgap archive/load/compose/import rehearsal after any packaging or security DB import change.
8. Keep extending Playwright coverage: CVE-to-assets modal, assignee filter, scan.failed notification rule creation.
