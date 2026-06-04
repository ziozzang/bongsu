# Bongsu Operations Runbook

Updated: 2026-06-04 15:24:27 KST

This runbook is for operators running Bongsu in connected or air-gapped environments. It assumes the API listens on `5677`, the web UI listens on `5678`, and Caddy or any external reverse proxy is managed outside Bongsu.

## Production Readiness Checklist

- Set unique strong values for `BONGSU_DB_PASSWORD`, `BONGSU_API_KEY`, `BONGSU_AGENT_API_KEY`, and `BONGSU_INSTALL_TOKEN`.
- Keep `BONGSU_ALLOW_WEAK_SECRETS=false`, `BONGSU_WEB_AUTH=true`, `BONGSU_AGENT_HOST_BINDING=true`, and same-origin CORS unless a specific origin is required.
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
BONGSU_RELEASE_ARCHIVE=bongsu-0.1.0.tar.gz ./scripts/verify-release-readiness.sh
BONGSU_DB_DSN="$BONGSU_DB_DSN" BONGSU_RELEASE_READINESS_LIVE=true ./scripts/verify-release-readiness.sh
```

Live release readiness enables strict CVE source freshness automatically; stale or missing required sources must be fixed before promotion. It requires `BONGSU_DB_DSN` by default so direct PostgreSQL CVE DB invariants run during release promotion; set `BONGSU_RELEASE_READINESS_REQUIRE_DB=false` only for non-release smoke runs where database access is intentionally unavailable.
In connected live environments it also compares selected OSV upstream `all.zip` `Last-Modified` headers with the local OSV source timestamp, so an OSV feed that is behind upstream beyond the configured grace window fails promotion. With `BONGSU_DB_DSN`, the same gate checks each sentinel ecosystem's affected-package index timestamp so one fresh OSV chunk cannot hide another stale ecosystem.
It verifies the live API server build first: `/api/health` must expose a non-empty version, build date, and a commit matching the latest server/runtime source commit.
It also verifies the live one-line installer payload: `/api/admin/installer/status` must report ready agent and Trivy binaries, valid SHA256 metadata, an install token, and an agent version containing the latest agent/installer source commit.

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
./scripts/verify-live-server-build.sh
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

The operator workflow also validates the live observability and inventory surfaces that should back production monitoring: `/api/health` must expose security DB revision or revision-error state, security recalculation state, and usable affected/reference index status; `/api/admin/security-db/status` must expose source-sync manager state, persisted source freshness, recalculation state, CVE DB quality, affected/reference index health, warnings, and recommended actions for stale or missing security sources; `/api/admin/agent-fleet/status` must expose installer readiness, host status counts, agent version counts, current/outdated/unknown version drift, outdated percentage, warnings, and recommended actions for missing installer payloads or stale/outdated agents; `/api/admin/rbac/status` must expose RBAC subject, policy, orphan, wildcard, resource, and permission counters; `/api/admin/metrics` must expose Prometheus gauges for security DB revision or revision-error state, recalculation, affected/reference indexes, OSV ecosystem affected-index freshness, EPSS enrichment, and security DB rescan progress; host runtime inventory endpoints must return the latest reported user accounts, process snapshot, and listening ports after report ingest.

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
       BONGSU_AGENT_MAX_CONTAINERS=20 \
       bash
```

Set `BONGSU_AGENT_SKIP_CONTAINERS=true` for constrained hosts where container inventory should be deferred; bongsu records that as a degraded inventory signal instead of silently pretending container coverage is complete.

Live RBAC scope verification:

```bash
# Start the API with BONGSU_VIEWER_API_KEYS containing this key-to-subject mapping first.
BONGSU_VIEWER_API_KEY=viewer-test-key \
BONGSU_VIEWER_SUBJECT=rbac-live-viewer \
./scripts/verify-live-rbac-scope.sh
```

This verifier ingests a two-host/two-container fixture, grants the viewer through a dynamic `asset_group` policy such as `team:rbac-allowed`, and proves that the viewer can see the allowed host, its host and container packages, its container, scans, and scan requests while the denied host and denied container stay hidden or return `403` on explicit denied-host filters.

Live CVE DB quality and performance verification:

```bash
BONGSU_DB_DSN="$BONGSU_DB_DSN" \
./scripts/verify-live-cvedb-quality.sh
```

For release-candidate or production health gates, require source freshness as well as match quality:

```bash
BONGSU_VERIFY_CVEDB_REQUIRE_FRESH_SOURCES=true \
BONGSU_DB_DSN="$BONGSU_DB_DSN" \
./scripts/verify-live-cvedb-quality.sh
```

For connected security DB syncs, keep OSV ecosystem chunks in append/upsert mode and defer finalization until the OSV loop finishes. `scripts/sync-all-cvedb.sh` sends `replace=false` and `finalize=false` for each OSV chunk because all chunks share `source=osv`; importing each chunk with source replacement enabled leaves only the last ecosystem in the live CVE DB, and finalizing every chunk repeats expensive affected/reference index rebuilds and recalculation. OSV rows can also share the same CVE alias across different ecosystems, so the CVE upsert path merges existing and incoming `affected_products`/`refs` arrays instead of overwriting the previous row. This keeps examples such as `phenx/php-svg-lib` / `Packagist` / fixed `0.5.2` matchable even when a later distro chunk references the same CVE. After all OSV chunks succeed, the script prunes `source=osv` rows older than the sync start timestamp so upstream deletions are reflected, then rebuilds affected-package and reference-key indexes once and queues security recalculation once. Non-OSV sources still use source replacement and immediate finalization by default.

When `BONGSU_DB_DSN` is set, this verifier also queries PostgreSQL directly for `TEMP-*`/`CVD-*` placeholders across `cve_database`, `cve_affected_packages`, and `cve_reference_keys`, affected-package rows missing package/ecosystem/fixed evidence, index orphans, EPSS columns on non-EPSS CVE rows, canonical CVE reference keys that merge multiple non-priority sources, and vendor/advisory keys materialized beside canonical CVE keys. It uses local `psql` when available, or `docker exec` against `BONGSU_DB_PSQL_CONTAINER` which defaults to `bongsu-postgres`.

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
5. Check `/api/health`, `/api/cve-db/stats?refresh=true`, and the dashboard CVE DB status card. In the stats response, review `osv_ecosystems` for the largest OSV ecosystems and their affected-package index `last_update` values when investigating partial OSV refresh lag.
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

Restore refuses archives with unsafe paths, duplicate or missing required members, unexpected files, archive sidecar checksum mismatches, or manifest checksum mismatches. Backup exports write a `<backup>.sha256` sidecar for transfer integrity, and backup manifests include `database_dump_sha256` and, when present, `trivy_cache_sha256`.

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

The OSV-only refresh uses the same per-ecosystem append/upsert mode as the full connected sync, prunes stale `source=osv` rows only after every configured ecosystem succeeds, then rebuilds affected-package and reference-key indexes and queues security recalculation once.

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
```

The CVE DB is operationally degraded if required sources are missing, `TEMP-*` or `CVD-*` placeholders appear in API results or direct DB invariants, affected/reference indexes are stale, affected-package index rows lack package/ecosystem/fixed evidence, or EPSS enrichment coverage unexpectedly drops.

## Monitoring And Alerting

Scrape `/api/admin/metrics` with the admin API key and alert on:

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
```

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

3. Verify agent daemon service status on affected hosts.

Compromised or reinstalled host agent:

1. Reset the host agent token from Host Detail or `/api/hosts/{id}/agent-token/reset`.
2. Reinstall the agent so it receives a fresh persistent `agent.token`.
3. Confirm new reports bind successfully and old-token requests are rejected; `./scripts/verify-live-agent-token-binding.sh` exercises the same report, claim, and completion rejection path in a fixture host.

Retired host or interrupted verifier fixture:

1. Confirm the host is intentionally retired or synthetic. Verifier host IDs start with prefixes such as `host-operator-verify-`, `host-rbac-live-`, `host-agent-binding-`, or `host-agent-binary-`.
2. Delete it from the Hosts view or call `DELETE /api/hosts/{id}` with an admin key.
3. Recheck `/api/admin/agent-fleet/status`; remaining outdated-version warnings should correspond to real enrolled hosts that need redeployment, not verifier leftovers.

## Routine Maintenance

- Review CVE DB source freshness and matchability daily. `/api/health` and the dashboard show the latest persisted CVE source update through `security_db_freshness.latest_source` / `latest_last_update`, and separately identify the oldest or stale source. If `security_db.status` is `never` immediately after a server restart but `latest_source` is recent, the persisted CVE DB is loaded and the next scheduled sync has not run yet in the new process.
- Review failed/degraded scan requests daily.
- Run retention dry-run before pruning:

```bash
curl -fsS -X POST -H "X-API-Key: $BONGSU_API_KEY" -H "Content-Type: application/json" \
  -d '{"dry_run":true}' http://localhost:5677/api/admin/retention/prune
```

- Export a security DB bundle after each successful connected source refresh for air-gapped promotion.
- Verify `SHA256SUMS` on every package before moving it into an air-gapped environment.
