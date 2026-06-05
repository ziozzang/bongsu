# Bongsu Operations Runbook

Updated: 2026-06-05 09:29:11 KST

This runbook is for operators running Bongsu in connected or air-gapped environments. It assumes the API listens on `5677`, the web UI listens on `5678`, and Caddy or any external reverse proxy is managed outside Bongsu.

## Production Readiness Checklist

- Set unique strong values for `BONGSU_DB_PASSWORD`, `BONGSU_API_KEY`, `BONGSU_AGENT_API_KEY`, and `BONGSU_INSTALL_TOKEN`.
- Keep `BONGSU_ALLOW_WEAK_SECRETS=false`, `BONGSU_WEB_AUTH=true`, `BONGSU_AGENT_HOST_BINDING=true`, and same-origin CORS unless a specific origin is required.
- Bongsu supports OIDC bearer token authentication for API/UI requests that already have an access token: set `BONGSU_OIDC_ISSUER`, `BONGSU_OIDC_CLIENT_ID`, and optionally `BONGSU_OIDC_JWKS_URL`, `BONGSU_OIDC_GROUPS_CLAIM`, `BONGSU_OIDC_SUBJECT_CLAIM`, `BONGSU_OIDC_ADMIN_USERS`, and `BONGSU_OIDC_ADMIN_GROUPS`. Browser password login remains available unless disabled by deployment policy. For browser redirect login, put Bongsu behind a trusted OIDC/auth proxy and configure `BONGSU_TRUSTED_IDENTITY_HEADER`, `BONGSU_TRUSTED_GROUPS_HEADER`, and `BONGSU_TRUSTED_IDENTITY_PROXY_CIDRS` so only that proxy can supply user/group RBAC subjects.
- Confirm Docker Compose renders the intended connected or air-gapped mode before startup:

```bash
BONGSU_DB_PASSWORD=... BONGSU_API_KEY=... BONGSU_AGENT_API_KEY=... BONGSU_INSTALL_TOKEN=... \
docker compose -f deploy/docker-compose.yml config >/tmp/bongsu-compose.yml
```

- Verify the deployment gates before release or handoff:

```bash
./scripts/verify-release-readiness.sh
```

The consolidated release gate runs the non-live test, documentation, packaging, static-binary, web, and compose checks. Use the expanded form when validating a generated archive or a live staging deployment:

```bash
BONGSU_RELEASE_READINESS_REPORT=/tmp/bongsu-release-readiness.json ./scripts/verify-release-readiness.sh
BONGSU_RELEASE_ARCHIVE=bongsu-0.1.0.tar.gz ./scripts/verify-release-readiness.sh
BONGSU_DB_DSN="$BONGSU_DB_DSN" BONGSU_RELEASE_READINESS_LIVE=true ./scripts/verify-release-readiness.sh
```

Set `BONGSU_RELEASE_READINESS_REPORT` during release or handoff runs to persist a JSON evidence report with the source commit, selected options, each gate command, exit status, timestamps, duration, and total failed gate count. Keep this report with the release archive, CI artifact, or handoff notes so a failed promotion has an auditable record instead of only terminal output.
Live release readiness enables strict CVE source freshness automatically; stale or missing required sources must be fixed before promotion. It requires `BONGSU_DB_DSN` by default so direct PostgreSQL CVE DB invariants run during release promotion; set `BONGSU_RELEASE_READINESS_REQUIRE_DB=false` only for non-release smoke runs where database access is intentionally unavailable.
In connected live environments it also compares selected OSV upstream `all.zip` `Last-Modified` headers with the local OSV source timestamp, so an OSV feed that is behind upstream beyond the configured grace window fails promotion. The default and release-readiness grace is `BONGSU_VERIFY_CVEDB_OSV_UPSTREAM_GRACE_SECONDS=3600`, short enough to catch source-specific OSV lag inside the 6-hour sync cadence while tolerating feed updates that land during a full OSV import. With `BONGSU_DB_DSN`, the same gate checks each sentinel ecosystem's affected-package index timestamp so one fresh OSV chunk cannot hide another stale ecosystem.
It verifies the live API server build first: `/api/health` must expose a non-empty version, build date, and a commit matching the latest server/runtime source commit, or a newer commit whose server/runtime build inputs are identical.
It also verifies the live one-line installer payload: `/api/admin/installer/status` must report ready agent and Trivy binaries, valid SHA256 metadata, an install token, and an agent version containing the latest agent/installer source commit.
It then exercises the actual live one-line installer and download URLs with `./scripts/verify-live-install-script.sh`: `/api/install.sh`, `/api/downloads/bongsu-agent`, and `/api/downloads/trivy` must reject unauthenticated and query-token requests, accept header authentication, expose checksum headers, and serve binaries whose SHA256 matches the advertised value.
It verifies the live security DB schedule with `./scripts/verify-live-security-db-schedule.sh`: `/api/health` must show configured source sync, healthy persisted freshness, and a `next_sync` timestamp no later than the latest persisted CVE source update plus `security_db.interval` and a small grace window. This catches API restarts that would otherwise delay the required 6-hour OSV/NVD/Trivy refresh cadence.
It verifies local session auth with `./scripts/verify-live-session-auth.sh`: `/api/auth/login`, `/api/auth/me`, and `/api/auth/logout` must work on the API port and through the web proxy, and a logged-out bearer token must be rejected.
It verifies trusted identity RBAC with `./scripts/verify-live-trusted-identity-rbac.sh`: direct unauthenticated admin access must remain `401`, while the configured trusted reverse-proxy user/group headers must authorize `/api/admin/rbac/status` through `BONGSU_TRUSTED_ADMIN_GROUPS`.
It verifies airgap bundle readiness with `./scripts/verify-live-security-db-export-freshness.sh`: `/api/admin/security-db/status` must report `security_db_export.status == "ok"`, no `outdated_sources`, complete `latest_exported_at` / `latest_source_update_at` timestamps, and healthy `security_db_freshness` by default. If this gate fails, export a new security DB bundle before moving data into an air-gapped deployment.
It verifies export freshness failure handling with `./scripts/verify-security-db-export-freshness-fixtures.sh`: representative status fixtures for stale exports, never-exported DBs, missing export metadata, incomplete timestamps, and stale source freshness must fail closed without requiring a live API.
It verifies CVE DB observability under concurrent operator load with `./scripts/verify-live-cvedb-concurrency.sh`: multiple forced stats refreshes, admin security DB status, and admin metrics must complete with `2xx` responses, valid JSON or Prometheus bodies, healthy CVE DB quality, and no new PostgreSQL shared-memory errors in the API log.
It verifies stale scan-request recovery with `./scripts/verify-live-scan-request-recovery.sh`: a fixture host-specific request is claimed, aged in PostgreSQL, surfaced by the stale request filter, requeued through `/api/scan-requests/requeue-stale`, audited, and proven claimable again.
It verifies security DB auto-rescan queueing with `./scripts/verify-live-security-db-auto-rescan.sh`: a fixture host reports inventory, a finalized temporary CVE source import triggers `security_db.changed`, recalculation, and `security_db.auto_rescan`, and the host receives a claimable `security-db-update` packages-only scan request stamped with the new security DB revision.
It verifies destructive retention pruning with `./scripts/verify-live-retention-prune.sh`: synthetic 2001-era scan, inventory, scan-request, and audit rows are inserted only after the verifier confirms no non-fixture rows are eligible under the very old cutoff, then dry-run and prune responses must report exact fixture-only blast-radius counts while preserving the latest usable scan, an old running scan, and an old pending scan request.
It verifies CVE DB rematch end-to-end with `./scripts/verify-live-cve-rematch-workflow.sh`: a fixture SBOM reports `phenx/php-svg-lib@0.5.0` as a Packagist package, report-triggered automatic rematch must create `cve-db` findings from OSV, explicit scan-scoped rematch must be idempotent, and the findings must preserve package ecosystem, installed version, fixed-version, and OSV advisory evidence.
It verifies vulnerability triage lifecycle behavior with `./scripts/verify-live-vulnerability-triage.sh`: a fixture vulnerability is uploaded, suppressing statuses without a reason must fail closed, accepted-risk triage must be visible through filters, stats, Prometheus metrics, JSON/CSV exports, and audit logs, and an expired false-positive decision must stop applying so the current finding returns to `open`.
It verifies report export RBAC with `./scripts/verify-live-report-export-rbac.sh`: allowed and denied fixture hosts both report active findings, the viewer receives only an `export` permission for the allowed asset group, risk and executive report exports must include allowed data while excluding denied host/team evidence, and export-only permission must not grant read access to the non-export report endpoints.
It verifies SBOM export RBAC with `./scripts/verify-live-sbom-export-rbac.sh`: allowed and denied fixture hosts both report package inventories, the viewer receives only an `export` permission for the allowed asset group, CycloneDX and SPDX exports for the allowed host must succeed, and the denied host SBOM export must fail closed with HTTP 403 and a forbidden audit row.
It verifies SBOM export end-to-end with `./scripts/verify-live-sbom-export-workflow.sh`: a fixture report contains host OS packages, host code libraries, container OS packages, and container code libraries, then both CycloneDX and SPDX exports must preserve host ID, scan ID, package purl, asset type, container ID, image name, image ID, and target evidence. The same gate also fails if mixed host/container OS packages produce a server-side Trivy `server_match` ingest error such as the `deb`/`apk` mixed-SBOM aggregation failure, because package-only scans must isolate matching by asset instead of letting one container package type degrade the whole host report.
It verifies vulnerability export RBAC with `./scripts/verify-live-vulnerability-export-rbac.sh`: allowed and denied fixture hosts both report vulnerabilities, the viewer receives only an `export` permission for the allowed asset group, JSON and CSV vulnerability exports must exclude denied data, and an explicit denied-host export must fail closed with HTTP 403.
It verifies fixture cleanup hygiene with `./scripts/verify-live-fixture-cleanup.sh`: live verifier scripts that create `host-*` fixtures must install `trap cleanup EXIT` and visibly remove fixture hosts through the host delete API or explicit database cleanup so release gates do not leave synthetic hosts that degrade agent-fleet health.

Individual gates remain useful while debugging:

```bash
go test ./...
./scripts/verify-migrations.sh
./scripts/verify-deploy-config.sh
./scripts/verify-requirements-audit.sh
./scripts/verify-operations-runbook.sh
./scripts/verify-cve-matching-invariants.sh
./scripts/verify-openapi.sh
./scripts/verify-backup-restore-archive.sh
./scripts/verify-installer-smoke.sh
./scripts/verify-live-installer-payload.sh
./scripts/verify-live-install-script.sh
./scripts/verify-live-security-db-schedule.sh
./scripts/verify-live-security-db-export-freshness.sh
./scripts/verify-live-fixture-cleanup.sh
./scripts/verify-security-db-export-helper-fixtures.sh
./scripts/verify-security-db-export-freshness-fixtures.sh
./scripts/verify-live-session-auth.sh
./scripts/verify-live-oidc-rbac.sh
./scripts/verify-live-trusted-identity-rbac.sh
./scripts/verify-live-server-build.sh
./scripts/verify-live-cvedb-concurrency.sh
./scripts/verify-live-cve-rematch-workflow.sh
./scripts/verify-live-vulnerability-triage.sh
./scripts/verify-live-report-export-rbac.sh
./scripts/verify-live-sbom-export-rbac.sh
./scripts/verify-live-scan-request-recovery.sh
./scripts/verify-live-security-db-auto-rescan.sh
./scripts/verify-live-retention-prune.sh
./scripts/verify-static-binaries.sh
npm --prefix web run build
npm --prefix web run test:e2e
```

- Against a running API, exercise the operator workflow before staging or release promotion:

```bash
BONGSU_API_BASE=http://localhost:5677 \
BONGSU_API_KEY="$BONGSU_API_KEY" \
BONGSU_ADMIN_USERNAME="$BONGSU_ADMIN_USERNAME" \
BONGSU_ADMIN_PASSWORD="$BONGSU_ADMIN_PASSWORD" \
./scripts/verify-operator-workflow.sh
```

For large CVE DB snapshots, keep `BONGSU_VERIFY_CURL_MAX_TIME_SECONDS` above `BONGSU_ADMIN_METRICS_DB_TIMEOUT_SECONDS` so the live operator verifier does not abort a valid admin metrics scrape.

For source imports and OSV finalization, keep `BONGSU_CVE_AFFECTED_INDEX_REBUILD_TIMEOUT_SECONDS` and `BONGSU_CVE_REFERENCE_INDEX_REBUILD_TIMEOUT_SECONDS` high enough for a production-sized database. The default is `900` seconds because production-scale OSV affected/reference index rebuilds can take several minutes. The connected sync scripts read the server's current rebuild timeout through `/api/admin/security-db/status` before downloading source feeds and fail early when either timeout is below `BONGSU_CVE_INDEX_REBUILD_MIN_SERVER_TIMEOUT_SECONDS` (default `600`). The separate `BONGSU_CVE_AFFECTED_INDEX_TIMEOUT_SECONDS` and `BONGSU_CVE_REFERENCE_INDEX_TIMEOUT_SECONDS` settings are intentionally short health/detail lookup budgets and should not be used to size rebuild work. If startup affected-package index preparation exceeds its rebuild timeout, the API still starts, records a warning in logs, and queues the same async rebuild path exposed by `/api/admin/cve-db/affected-index/rebuild?async=true`; watch `/api/health`, `/api/cve-db/stats`, or `/api/admin/metrics` for `cve_affected_index_rebuild` progress and degraded index quality until it completes.

For large remediation exports, tune `BONGSU_VULNERABILITY_EXPORT_TIMEOUT_SECONDS` together with `BONGSU_VULN_EXPORT_MAX_ROWS`. The timeout bounds the vulnerability export DB lookup and security DB revision metadata lookup, defaults to 60 seconds, is clamped to 300 seconds, returns `504 vulnerability export timeout` on expiry, and writes a `vulnerability.export` audit row with `db lookup timed out` plus `timeout_seconds`.

The operator workflow also validates the live observability and inventory surfaces that should back production monitoring: `/api/health` must expose security DB revision or revision-error state, security recalculation state, and usable affected/reference index status; `/api/admin/security-db/status` must expose source-sync manager state, persisted source freshness, effective persisted freshness fields (`effective_status`, `effective_source`, `effective_last_sync`) aligned with `security_db_freshness.status`, `latest_source`, and `latest_last_update`, recalculation state, latest bundle import provenance under `security_db_bundle_import.last_result`, CVE DB quality, affected/reference index health, warnings, and recommended actions for stale or missing security sources; `/api/admin/agent-fleet/status` must expose installer readiness, host status counts, agent version counts, current/outdated/unknown version drift, outdated percentage, warnings, and recommended actions for missing installer payloads or stale/outdated agents; `/api/admin/rbac/status` must expose RBAC subject, policy, orphan, wildcard, resource, and permission counters plus auth configuration visibility for web auth, viewer keys, trusted identity headers, trusted proxy CIDRs, and trusted admin allowlists without exposing secret values; `/api/admin/metrics` must expose Prometheus gauges for effective persisted security DB status/source/last-sync (`bongsu_security_db_effective_status`, `bongsu_security_db_effective_source_info`, `bongsu_security_db_effective_last_sync_timestamp_seconds`), security DB revision or revision-error state, recalculation, affected/reference indexes, OSV ecosystem affected-index freshness, EPSS enrichment, and security DB rescan progress; `/api/admin/retention/prune` must support audited dry-runs with cutoff timestamps and numeric blast-radius counters before operators execute destructive pruning, and `./scripts/verify-live-retention-prune.sh` must pass in staging before using destructive retention settings on production data; host runtime inventory endpoints must return the latest reported user accounts, process snapshot, and listening ports after report ingest.

- Verify the real agent binary collection path with fixture Trivy/osquery/docker tools:

```bash
BONGSU_API_BASE=http://localhost:5677 \
BONGSU_API_KEY="$BONGSU_API_KEY" \
BONGSU_AGENT_API_KEY="$BONGSU_AGENT_API_KEY" \
./scripts/verify-agent-binary-workflow.sh
```

This verifier uses `--host-id` to report two logical hosts with distinct container identities, then proves host-specific inventory and force-scan request completion stay separated.

- Verify host-token binding against the live API:

```bash
BONGSU_API_BASE=http://localhost:5677 \
BONGSU_API_KEY="$BONGSU_API_KEY" \
BONGSU_AGENT_API_KEY="$BONGSU_AGENT_API_KEY" \
./scripts/verify-live-agent-token-binding.sh
```

This verifier requires `BONGSU_AGENT_HOST_BINDING=true` on the API. It binds a host to one agent token, then proves a different token cannot report inventory, claim scan requests, or complete requests for that host.

- Verify the live installer payload before asking operators to redeploy agents:

```bash
BONGSU_API_BASE=http://localhost:5677 \
BONGSU_API_KEY="$BONGSU_API_KEY" \
./scripts/verify-live-installer-payload.sh
```

This verifier checks `/api/admin/installer/status` for ready agent and Trivy payloads, valid SHA256 and byte metadata, install-token configuration, and an agent version that includes the latest commit touching agent or installer source paths. Set `BONGSU_VERIFY_INSTALLER_AGENT_COMMIT=<12-char-commit>` for packaged or externally built releases where the source checkout is not available.

- Verify the live install script and binary download URLs before publishing the enrollment command:

```bash
BONGSU_API_BASE=http://localhost:5677 \
BONGSU_API_KEY="$BONGSU_API_KEY" \
BONGSU_INSTALL_TOKEN="$BONGSU_INSTALL_TOKEN" \
./scripts/verify-live-install-script.sh
```

This verifier downloads `/api/install.sh` with `X-Install-Token`, confirms the generated script uses header-authenticated binary downloads instead of query tokens, checks systemd and cron install paths, rejects unauthenticated `/api/downloads/*` access, and validates the advertised `X-Bongsu-SHA256` header against the downloaded agent and Trivy bytes.

- Verify the live API server binary before promoting a running deployment:

```bash
BONGSU_API_BASE=http://localhost:5677 \
BONGSU_API_KEY="$BONGSU_API_KEY" \
./scripts/verify-live-server-build.sh
```

This verifier checks `/api/health` for usable health, non-empty version/build-date metadata, and a commit matching the latest commit that touched server/runtime source paths. Set `BONGSU_VERIFY_SERVER_COMMIT=<12-char-commit>` for externally built releases where the source checkout is not available. Set `BONGSU_VERIFY_SERVER_ALLOW_DEV_VERSION=true` only for local development gates.

Live verifier scripts create short-lived hosts and delete them during cleanup through `DELETE /api/hosts/{id}`. If an interrupted verifier leaves synthetic hosts behind, remove only hosts whose IDs match the verifier prefixes, such as `host-operator-verify-*`, `host-rbac-live-*`, `host-agent-binding-*`, or `host-agent-binary-*`; the host delete API cascades collected inventory and host-scoped operational rows while preserving audit logs. Do not delete real enrolled hosts just to clear an agent-fleet warning; an actual `dev` or outdated agent version should be fixed by redeploying the one-line installer or restarting the updated service.

- Verify the deployed web UI on port `5678` with a live browser smoke test:

```bash
BONGSU_WEB_BASE=http://localhost:5678 \
BONGSU_API_KEY="$BONGSU_API_KEY" \
./scripts/verify-live-web-smoke.sh
```

To verify the username/password login path through the web proxy instead of an API key, pass the initial admin credentials:

```bash
BONGSU_WEB_BASE=http://localhost:5678 \
BONGSU_ADMIN_USERNAME="$BONGSU_ADMIN_USERNAME" \
BONGSU_ADMIN_PASSWORD="$BONGSU_ADMIN_PASSWORD" \
./scripts/verify-live-web-smoke.sh
```

For a faster API/proxy session-auth check without a browser, run:

```bash
BONGSU_API_BASE=http://localhost:5677 \
BONGSU_WEB_BASE=http://localhost:5678 \
BONGSU_ADMIN_USERNAME="$BONGSU_ADMIN_USERNAME" \
BONGSU_ADMIN_PASSWORD="$BONGSU_ADMIN_PASSWORD" \
./scripts/verify-live-session-auth.sh
```

This verifier logs in on `5677` and, if reachable, `5678`, checks the returned bearer token against `/api/auth/me` and `/api/admin/rbac/status`, logs out, and confirms the same bearer token no longer authenticates.

For direct OIDC bearer-token RBAC, run:

```bash
./scripts/verify-live-oidc-rbac.sh
```

This verifier starts an isolated temporary API process on a non-production port with a generated RS256 signing key, JWKS endpoint, admin JWT, viewer JWT, wrong-audience JWT, and expired JWT. It verifies unauthenticated admin access is rejected, invalid OIDC tokens fail closed, a non-admin OIDC identity can authenticate web APIs but not admin APIs, an admin group token can read `/api/admin/rbac/status`, and local API-key admin auth still works while OIDC is enabled.

If `POST http://<web>:5678/api/auth/login` returns HTTP 500, first verify that the API is actually listening on `5677` and that the running binary was built from the current checkout:

```bash
curl -fsS http://localhost:5677/api/ready
curl -fsS -X POST -H 'Content-Type: application/json' \
  -d "{\"username\":\"$BONGSU_ADMIN_USERNAME\",\"password\":\"$BONGSU_ADMIN_PASSWORD\"}" \
  http://localhost:5677/api/auth/login
```

The web server proxies `/api` to `5677`; a stopped API or stale server binary can surface as a web-side 500 even when the dashboard itself loads on `5678`.

## Install

Connected deployment:

```bash
cp deploy/.env.example deploy/.env
# Edit deploy/.env with strong secrets.
cd deploy
docker compose up -d --build
curl -fsS http://localhost:5677/api/health
```

Air-gapped deployment:

```bash
./scripts/verify-airgap-package-smoke.sh
./scripts/package.sh 0.1.0
sha256sum -c bongsu-0.1.0.tar.gz.sha256
./scripts/verify-airgap-release-archive.sh bongsu-0.1.0.tar.gz
./scripts/verify-airgap-offline-rehearsal.sh bongsu-0.1.0.tar.gz
# Transfer bongsu-0.1.0.tar.gz and a security DB bundle into the offline network.
tar xzf bongsu-0.1.0.tar.gz
cd bongsu-0.1.0
sha256sum -c SHA256SUMS
./load-images.sh
cp deploy/.env.example deploy/.env
# Edit deploy/.env with strong secrets and keep online sync disabled.
cd deploy
docker compose -f docker-compose.airgap.yml up -d
../scripts/import-security-db-bundle.sh http://localhost:5677 "$BONGSU_API_KEY" ../bongsu-security-db-bundle.tar.gz
```

Agent enrollment:

```bash
curl -fsSL -H "X-Install-Token: $BONGSU_INSTALL_TOKEN" "http://server:5678/api/install.sh" | sudo bash
```

For packaged or offline `scripts/install-agent.sh` use `BONGSU_AGENT_API_KEY` instead of putting the agent API key in the shell command arguments:

```bash
sudo BONGSU_AGENT_API_KEY="$BONGSU_AGENT_API_KEY" ./scripts/install-agent.sh http://server:5677
```

For cloned, golden-image, or containerized hosts where `/etc/machine-id` is not unique, set a stable identity during install so SBOM, force-scan, and RBAC records do not collapse into one host:

```bash
curl -fsSL -H "X-Install-Token: $BONGSU_INSTALL_TOKEN" "http://server:5678/api/install.sh" | \
  sudo BONGSU_HOST_ID="$(hostname -f)" bash
```

For large hosts or dense container nodes, bound agent scans so one scheduled run cannot monopolize the host. These values are persisted into the agent config and are used by both scheduled package-only scans and the force-scan daemon:

```bash
curl -fsSL -H "X-Install-Token: $BONGSU_INSTALL_TOKEN" "http://server:5678/api/install.sh" | \
  sudo BONGSU_AGENT_TRIVY_TIMEOUT_SECONDS=1800 \
       BONGSU_AGENT_CONTAINER_TIMEOUT_SECONDS=600 \
       BONGSU_AGENT_COMMAND_TIMEOUT_SECONDS=30 \
       BONGSU_AGENT_MAX_CONTAINERS=20 \
       bash
```

Set `BONGSU_AGENT_SKIP_CONTAINERS=true` for constrained hosts where container inventory should be deferred; bongsu records that as a degraded inventory signal instead of silently pretending container coverage is complete. `BONGSU_AGENT_COMMAND_TIMEOUT_SECONDS` bounds Docker inspection, osquery, process, hostname, and kernel helper commands so an unhealthy runtime cannot hang the whole scan before Trivy timeouts apply.

Live RBAC scope verification:

```bash
# Start the API with BONGSU_VIEWER_API_KEYS containing this key-to-subject mapping first.
BONGSU_VIEWER_API_KEY=viewer-test-key \
BONGSU_VIEWER_SUBJECT=rbac-live-viewer \
./scripts/verify-live-rbac-scope.sh
```

This verifier ingests a two-host/two-container fixture, grants the viewer through a dynamic `asset_group` policy such as `team:rbac-allowed`, and proves that the viewer can see the allowed host, its host and container packages, its container, scans, and scan requests while the denied host and denied container stay hidden or return `403` on explicit denied-host filters.

For SSO-backed RBAC, Bongsu supports two production paths. If a client already has an OIDC access token, configure OIDC bearer token authentication and send `Authorization: Bearer <jwt>` directly to Bongsu. Set `BONGSU_OIDC_ISSUER` to the expected issuer, `BONGSU_OIDC_CLIENT_ID` to the required `aud`, and optionally `BONGSU_OIDC_JWKS_URL` when the JWKS endpoint is not `${issuer}/.well-known/jwks.json`. `BONGSU_OIDC_SUBJECT_CLAIM` defaults to `sub`, `BONGSU_OIDC_GROUPS_CLAIM` defaults to `groups`, and successful tokens become RBAC subjects `user:<claim>` plus `group:<claim>`. `BONGSU_OIDC_ADMIN_USERS` and `BONGSU_OIDC_ADMIN_GROUPS` grant admin API access for selected OIDC identities; keep these allowlists narrow.

For browser redirect login, terminate login in an auth/OIDC reverse proxy and let Bongsu trust only that proxy's identity headers. Set `BONGSU_TRUSTED_IDENTITY_HEADER` for the authenticated user header, `BONGSU_TRUSTED_GROUPS_HEADER` for comma- or semicolon-separated group memberships, and `BONGSU_TRUSTED_IDENTITY_PROXY_CIDRS` to the proxy address range. Header values become RBAC subjects `user:<value>` and `group:<value>`, so create matching `access_subjects` and policies before granting access. Use `BONGSU_TRUSTED_ADMIN_USERS` or `BONGSU_TRUSTED_ADMIN_GROUPS` sparingly for administrative access.

```bash
BONGSU_API_BASE=http://localhost:5677 \
BONGSU_VERIFY_TRUSTED_IDENTITY_ADMIN_GROUP=security-admins \
./scripts/verify-live-trusted-identity-rbac.sh
```

Live CVE DB quality and performance verification:

```bash
BONGSU_DB_DSN="$BONGSU_DB_DSN" \
./scripts/verify-live-cvedb-quality.sh
```

Concurrent CVE DB observability verification:

```bash
BONGSU_API_BASE=http://localhost:5677 \
BONGSU_API_KEY="$BONGSU_API_KEY" \
./scripts/verify-live-cvedb-concurrency.sh
```

This gate starts several `/api/cve-db/stats?refresh=true` requests together with `/api/admin/security-db/status` and `/api/admin/metrics`, then fails on non-2xx responses, malformed JSON/metrics output, degraded CVE DB quality, or new PostgreSQL shared-memory errors in `BONGSU_API_LOG_FILE` (default `/tmp/bongsu-api-5677.log`). Use `BONGSU_VERIFY_CVEDB_CONCURRENCY_STATS_REQUESTS` and `BONGSU_VERIFY_CVEDB_CONCURRENCY_CURL_MAX_TIME_SECONDS` to tune the stress level and timeout for larger deployments.

For release-candidate or production health gates, require source freshness as well as match quality:

```bash
BONGSU_VERIFY_CVEDB_REQUIRE_FRESH_SOURCES=true \
BONGSU_VERIFY_CVEDB_REQUIRE_OSV_UPSTREAM_FRESHNESS=true \
BONGSU_VERIFY_CVEDB_OSV_UPSTREAM_GRACE_SECONDS=3600 \
BONGSU_DB_DSN="$BONGSU_DB_DSN" \
./scripts/verify-live-cvedb-quality.sh
```

For connected security DB syncs, keep OSV ecosystem chunks in append/upsert mode and defer finalization until the OSV loop finishes. `scripts/sync-all-cvedb.sh` sends `replace=false` and `finalize=false` for each OSV chunk because all chunks share `source=osv`; importing each chunk with source replacement enabled leaves only the last ecosystem in the live CVE DB, and finalizing every chunk repeats expensive affected/reference index rebuilds and recalculation. Deferred OSV chunk imports do not refresh the aggregate `security_sources.osv` registry row; only a finalized import or successful source-wide stale-prune after the complete OSV loop may publish OSV source freshness. OSV rows can also share the same CVE alias across different ecosystems, so the CVE upsert path merges existing and incoming `affected_products`/`refs` arrays instead of overwriting the previous row. This keeps examples such as `phenx/php-svg-lib` / `Packagist` / fixed `0.5.2` matchable even when a later distro chunk references the same CVE. After all OSV chunks succeed, the script prunes `source=osv` rows older than the sync start timestamp so upstream deletions are reflected, then queues asynchronous affected-package and reference-key index rebuilds, polls `/api/health` for completion, and queues security recalculation once. Tune the index wait loop with `BONGSU_CVE_INDEX_REBUILD_WAIT_SECONDS` (default `900`) and `BONGSU_CVE_INDEX_REBUILD_POLL_SECONDS` (default `5`) for very large imports; tune the preflight threshold with `BONGSU_CVE_INDEX_REBUILD_MIN_SERVER_TIMEOUT_SECONDS` (default `600`) when a deployment intentionally uses smaller feeds. Non-OSV sources still use source replacement and immediate finalization by default.

When `BONGSU_DB_DSN` is set, this verifier also queries PostgreSQL directly for `TEMP-*`/`CVD-*` placeholders across `cve_database`, `cve_affected_packages`, and `cve_reference_keys`, affected-package rows missing package/ecosystem/fixed evidence, non-version fixed-version evidence such as URL/package URL/git URL/branch/hash-like values, index orphans, EPSS columns on non-EPSS CVE rows, canonical CVE reference keys that merge multiple non-priority sources, vendor/advisory keys materialized beside canonical CVE keys, `/api/health` freshness alignment with the `security_sources` registry, and OSV registry freshness that has not been promoted by a deferred `finalize=false` chunk import. It uses local `psql` when available, or `docker exec` against `BONGSU_DB_PSQL_CONTAINER` which defaults to `bongsu-postgres`.

Live web UI route and API response verification:

```bash
BONGSU_WEB_BASE=http://localhost:5678 \
BONGSU_API_KEY="$BONGSU_API_KEY" \
./scripts/verify-live-web-smoke.sh
```

This smoke covers dashboard, CVE Search, Hosts, Packages, Containers, Scan History, Vulnerabilities, RBAC, Audit Log, Schedules, Asset Groups, Trends, Reports, and Notifications, and fails if any live `/api/` response returns a 5xx status.

Use systemd mode when immediate force-scan polling is required:

```bash
curl -fsSL -H "X-Install-Token: $BONGSU_INSTALL_TOKEN" "http://server:5678/api/install.sh" | \
  sudo BONGSU_INSTALL_MODE=systemd BONGSU_FORCE_SCAN_DAEMON=true bash
```

## Upgrade

1. Export a current security DB bundle and take a PostgreSQL backup before replacing services.
2. Build or receive the new release package, verify `SHA256SUMS`, and load Docker images.
3. Review `deploy/.env.example` for new required settings and merge them into the local `.env`.
4. Apply the new compose file and let startup migrations run with `BONGSU_AUTO_MIGRATE=true`.
5. Check `/api/health`, `/api/cve-db/stats?refresh=true`, and the dashboard CVE DB status card. `/api/health` uses indexed-only CVE index summaries for liveness; use stats, admin security DB status, and `./scripts/verify-live-cvedb-quality.sh` for detailed affected/reference coverage and OSV upstream freshness. In the stats response, review `osv_ecosystems` for the largest OSV ecosystems and their affected-package index `last_update` values when investigating partial OSV refresh lag.
6. Re-enroll or update agents only after installer readiness reports the expected agent binary version.

Connected upgrade example:

```bash
cd deploy
docker compose pull || true
docker compose up -d --build
docker compose logs -f server
```

Air-gapped upgrade example:

```bash
tar xzf bongsu-NEWVERSION.tar.gz
cd bongsu-NEWVERSION
sha256sum -c SHA256SUMS
./load-images.sh
cp -n deploy/.env.example deploy/.env
cd deploy
docker compose -f docker-compose.airgap.yml up -d
```

## Backup And Restore

Back up PostgreSQL and security DB transfer artifacts:

```bash
docker compose -f deploy/docker-compose.yml exec -T postgres \
  pg_dump -U "${BONGSU_DB_USER:-bongsu}" "${BONGSU_DB_NAME:-bongsu}" > bongsu-postgres.sql

./scripts/export-security-db-bundle.sh http://localhost:5677 "$BONGSU_API_KEY" bongsu-security-db-bundle.tar.gz
sha256sum bongsu-postgres.sql bongsu-security-db-bundle.tar.gz > bongsu-backup.sha256
```

`export-security-db-bundle.sh` downloads to a temporary file, runs the live export freshness verifier by default, and publishes the final bundle filename plus `.sha256` sidecar only after that verifier passes. Set `BONGSU_BUNDLE_VERIFY_FRESHNESS=false` only for emergency backup capture when the bundle is not being promoted as the current security DB.

For large backups, restores, Trivy DB downloads, or connected CVE source syncs on hosts with a small `/tmp`, set `BONGSU_TMPDIR=/path/with/space` before running the packaged scripts. The backup, restore, Trivy DB download, NVD/OSV/Trivy CVE sync, OSV download, and Trivy CVE extraction scripts create managed `bongsu-*` work directories under that path and remove them on exit.

Restore PostgreSQL to a stopped or fresh deployment:

```bash
docker compose -f deploy/docker-compose.yml down
docker compose -f deploy/docker-compose.yml up -d postgres
docker compose -f deploy/docker-compose.yml exec -T postgres \
  psql -U "${BONGSU_DB_USER:-bongsu}" -d "${BONGSU_DB_NAME:-bongsu}" < bongsu-postgres.sql
docker compose -f deploy/docker-compose.yml up -d
```

After restore, verify:

```bash
./scripts/verify-backup-restore-archive.sh
curl -fsS -H "X-API-Key: $BONGSU_API_KEY" http://localhost:5677/api/health
curl -fsS -H "X-API-Key: $BONGSU_API_KEY" "http://localhost:5677/api/cve-db/stats?refresh=true"
./scripts/verify-live-cvedb-quality.sh
```

Restore refuses archives with unsafe paths, duplicate or missing required members, unexpected files, archive sidecar checksum mismatches, or manifest checksum mismatches. Backup exports write a `<backup>.sha256` sidecar for transfer integrity, backup manifests include `database_dump_sha256` and, when present, `trivy_cache_sha256`, and backup self-validation runs `restore.sh --dry-run` against the generated archive unless `BONGSU_BACKUP_VALIDATE_ARCHIVE=false` is set for emergency diagnostics.

## Security DB Operations

Connected environments should keep these defaults unless a source is intentionally disabled:

```text
BONGSU_SECURITY_DB_SYNC_CMD=/app/scripts/sync-all-cvedb.sh http://localhost:5677
BONGSU_SECURITY_DB_INTERVAL_HOURS=6
BONGSU_SECURITY_DB_SYNC_ON_START=true
BONGSU_SYNC_REQUIRE_TRIVY_SOURCE=true
```

If `/api/admin/security-db/status` reports only a stale `trivy` CVE source, refresh that source without running the full OSV/NVD/EPSS sync:

```bash
TRIVY_BIN=/usr/local/bin/trivy \
./scripts/sync-trivy-cvedb.sh http://localhost:5677 "$BONGSU_API_KEY"
```

If OSV upstream feeds have changed but the persisted source freshness window has not yet marked `osv` stale, refresh only OSV without replacing unrelated CISA, EPSS, NVD, or Trivy source rows:

```bash
./scripts/sync-osv-cvedb.sh http://localhost:5677 "$BONGSU_API_KEY"
```

The OSV-only refresh uses the same per-ecosystem append/upsert mode as the full connected sync, prunes stale `source=osv` rows only after every configured ecosystem succeeds, then queues asynchronous affected-package and reference-key rebuilds, waits for them to finish through `/api/health`, and queues security recalculation once. For a single lagging upstream sentinel, run the same script with `BONGSU_OSV_ECOSYSTEMS=<ecosystem>`; partial overrides intentionally skip source-wide stale prune, do not promote aggregate OSV source freshness, and should be followed by `BONGSU_VERIFY_CVEDB_REQUIRE_OSV_UPSTREAM_FRESHNESS=true ./scripts/verify-live-cvedb-quality.sh`.

If only NVD is stale, refresh it without running OSV or Trivy extraction:

```bash
./scripts/sync-nvd-cvedb.sh http://localhost:5677 "$BONGSU_API_KEY"
```

The NVD-only refresh downloads the configured NVD year range into one JSONL file and replaces the `nvd` source once, so yearly chunks cannot overwrite each other. Use `BONGSU_NVD_YEARS=2023,2024,2025,2026` or `BONGSU_NVD_YEAR_WINDOW=5` to tune the retained publication-year range.

Air-gapped environments should disable online sync and import signed transfer bundles:

```text
BONGSU_TRIVY_DB_INTERVAL_HOURS=0
BONGSU_SECURITY_DB_SYNC_CMD=
BONGSU_SECURITY_DB_SYNC_ON_START=false
BONGSU_SYNC_REQUIRE_TRIVY_SOURCE=false
```

After any import or update, check:

```bash
curl -fsS -H "X-API-Key: $BONGSU_API_KEY" "http://localhost:5677/api/cve-db/stats?refresh=true"
curl -fsS -H "X-API-Key: $BONGSU_API_KEY" "http://localhost:5677/api/admin/metrics"
./scripts/verify-live-security-db-schedule.sh
./scripts/verify-live-security-db-export-freshness.sh
```

On large CVE DB snapshots, avoid launching several forced `refresh=true` stats checks in parallel with admin status or metrics. `/api/health` intentionally uses indexed-only CVE summaries, while `/api/cve-db/stats` shares one in-flight build per API process and limits its own heavy subqueries with `BONGSU_CVE_STATS_QUERY_CONCURRENCY` (default `2`, range `1..7`), and repeated `security_db_revision` lookups share a short success-only cache controlled by `BONGSU_SECURITY_DB_REVISION_CACHE_SECONDS` (default `30`, max `300`). The shared revision query uses its own `BONGSU_SECURITY_DB_REVISION_TIMEOUT_SECONDS` budget (default `30`, max `300`) so a short health or export caller does not cancel the in-flight calculation for every waiter. Each additional endpoint can still consume PostgreSQL work memory. If PostgreSQL returns shared-memory resize errors while operators are auditing the CVE DB, lower `BONGSU_CVE_STATS_QUERY_CONCURRENCY`, retry the verifier serially, and check `/api/admin/security-db/status` before treating the source DB as unhealthy.

The CVE DB is operationally degraded if required sources are missing, `TEMP-*` or `CVD-*` placeholders appear in API results or direct DB invariants, affected/reference indexes are stale, affected-package index rows lack package/ecosystem/fixed evidence, affected-package fixed evidence is URL/package URL/git URL/branch/hash-like non-version data, or EPSS enrichment coverage unexpectedly drops.

## Monitoring And Alerting

Scrape `/api/admin/metrics` with the admin API key and alert on:

- Any `bongsu_*_metrics_error` gauge greater than zero; increase `BONGSU_ADMIN_METRICS_DB_TIMEOUT_SECONDS` or investigate the failing DB query before trusting the affected metric family.
- `bongsu_security_db_effective_status{status="ok"} != 1`, missing `bongsu_security_db_effective_source_info`, or a stale `bongsu_security_db_effective_last_sync_timestamp_seconds`; these describe the persisted CVE DB currently used for matching, not only the in-process sync manager.
- `bongsu_security_source_registry_ok_sources` lower than `bongsu_security_source_registry_enabled_sources`, nonzero `bongsu_security_source_registry_error`, missing `bongsu_security_source_registry_records{source="osv",...}`, stale `bongsu_security_source_registry_last_export_timestamp_seconds`, or nonzero `bongsu_security_source_registry_export_stale_sources`; these expose the persisted source registry that backs the dashboard Source Registry card and airgap export traceability.
- `bongsu_security_db_source_stale` or missing required sources.
- `bongsu_cve_placeholder_records` greater than zero.
- `bongsu_cve_affected_index_stale` or low affected-index coverage.
- `bongsu_cve_osv_ecosystem_metrics_error` greater than zero or stale `bongsu_cve_osv_ecosystem_last_update_timestamp_seconds` for sentinel ecosystems.
- `bongsu_cve_epss_loaded_without_enrichment` greater than zero.
- `bongsu_security_db_rescan_open` remaining high after a DB update.
- `bongsu_scan_request_stale` for pending or claimed requests.
- `bongsu_agent_fleet_degraded` greater than zero, nonzero `bongsu_agent_fleet_warnings`, or unexpectedly high `bongsu_agent_outdated_percent`.
- `bongsu_installer_ready` equal to zero.
- PostgreSQL pool exhaustion or repeated health-check failures.

Use webhooks for operational notifications:

```text
BONGSU_WEBHOOK_URL=https://hooks.example/internal/bongsu
BONGSU_WEBHOOK_SECRET=<strong-shared-secret>
BONGSU_WEBHOOK_MIN_SEVERITY=HIGH
BONGSU_WEBHOOK_MIN_RISK_LEVEL=high
BONGSU_WEBHOOK_INVENTORY_STATUSES=empty,degraded
BONGSU_NOTIFICATION_RETRY_ATTEMPTS=3
BONGSU_NOTIFICATION_RETRY_DELAY_MS=1000
```

For notification rules created in the Notifications UI, use the `webhook` channel with a per-rule `url` and `secret`. Bongsu signs each rule webhook with `X-Bongsu-Signature-256`, retries network failures, HTTP 429, and HTTP 5xx responses, does not retry HTTP 4xx receiver errors, and records the final delivery status plus attempt count in Notification Log. `./scripts/verify-operator-workflow.sh` runs a local webhook receiver during live verification and proves this signed retry path before release promotion.

## Incident Response

Security DB import failure:

1. Open Audit Log and filter `resource_type=security_db`.
2. Check server logs for the failed stage and bounded command output.
3. Keep the previous DB active; direct imports and bundles are all-or-nothing.
4. Re-run source sync or import a known-good bundle.

Placeholder CVE records detected:

1. Stop using CVE DB rematch until `/api/cve-db/stats` reports zero placeholder rows.
2. Rebuild affected and reference indexes after cleanup:

```bash
curl -X POST -H "X-API-Key: $BONGSU_API_KEY" "http://localhost:5677/api/admin/cve-db/affected-index/rebuild?async=true"
curl -X POST -H "X-API-Key: $BONGSU_API_KEY" "http://localhost:5677/api/admin/cve-db/reference-index/rebuild?async=true"
```

Stuck force-scan queue:

1. Open Scan History and filter by stale pending or claimed requests.
2. Requeue stale claims:

```bash
curl -fsS -X POST -H "X-API-Key: $BONGSU_API_KEY" -H "Content-Type: application/json" \
  -d '{"timeout_minutes":60}' http://localhost:5677/api/scan-requests/requeue-stale
```

3. Verify agent daemon service status on affected hosts. `./scripts/verify-live-scan-request-recovery.sh` exercises this stale-claim path against a fixture request when `BONGSU_DB_DSN` is available.

Compromised or reinstalled host agent:

1. Reset the host agent token from Host Detail or `/api/hosts/{id}/agent-token/reset`.
2. Reinstall the agent so it receives a fresh persistent `agent.token`.
3. Confirm new reports bind successfully and old-token requests are rejected; `./scripts/verify-live-agent-token-binding.sh` exercises the same report, claim, and completion rejection path in a fixture host.

Retired host or interrupted verifier fixture:

1. Confirm the host is intentionally retired or synthetic. Verifier host IDs start with prefixes such as `host-operator-verify-`, `host-rbac-live-`, `host-agent-binding-`, or `host-agent-binary-`.
2. Delete it from the Hosts view or call `DELETE /api/hosts/{id}` with an admin key.
3. Recheck `/api/admin/agent-fleet/status`; remaining outdated-version warnings should correspond to real enrolled hosts that need redeployment, not verifier leftovers.

## Routine Maintenance

- Review CVE DB source freshness and matchability daily. `/api/health` and the dashboard show the latest persisted CVE source update through `security_db_freshness.latest_source` / `latest_last_update`, and separately identify the oldest or stale source. `security_db.status` is the sync manager process state, while `security_db.effective_status`, `effective_source`, and `effective_last_sync` describe the CVE DB currently usable for matching. If `security_db.status` is `never` immediately after a server restart but `effective_status` is `ok`, the persisted CVE DB is loaded and the next scheduled sync has not run yet in the new process.
- Review failed/degraded scan requests daily.
- Run retention dry-run before pruning:

```bash
curl -fsS -X POST -H "X-API-Key: $BONGSU_API_KEY" -H "Content-Type: application/json" \
  -d '{"dry_run":true}' http://localhost:5677/api/admin/retention/prune
```

- Before enabling destructive retention in production or after changing retention code, run `./scripts/verify-live-retention-prune.sh` in staging. It aborts if any non-fixture scan, terminal scan request, or audit row is eligible under its old cutoff, then proves only the synthetic fixture rows are pruned.
- Export a security DB bundle after each successful connected source refresh for air-gapped promotion.
- Verify `SHA256SUMS` on every package before moving it into an air-gapped environment.
