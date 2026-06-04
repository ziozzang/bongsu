# Bongsu Operations Runbook

Updated: 2026-06-04 13:54:52 KST

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
BONGSU_RELEASE_READINESS_LIVE=true ./scripts/verify-release-readiness.sh
```

Individual gates remain useful while debugging:

```bash
go test ./...
./scripts/verify-migrations.sh
./scripts/verify-deploy-config.sh
./scripts/verify-requirements-audit.sh
./scripts/verify-cve-matching-invariants.sh
./scripts/verify-openapi.sh
./scripts/verify-backup-restore-archive.sh
./scripts/verify-installer-smoke.sh
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

For cloned, golden-image, or containerized hosts where `/etc/machine-id` is not unique, set a stable identity during install so SBOM, force-scan, and RBAC records do not collapse into one host:

```bash
curl -fsSL -H "X-Install-Token: $BONGSU_INSTALL_TOKEN" "http://server:5678/api/install.sh" | \
  sudo BONGSU_HOST_ID="$(hostname -f)" bash
```

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

For connected security DB syncs, keep OSV ecosystem chunks in append/upsert mode and defer finalization until the OSV loop finishes. `scripts/sync-all-cvedb.sh` sends `replace=false` and `finalize=false` for each OSV chunk because all chunks share `source=osv`; importing each chunk with source replacement enabled leaves only the last ecosystem in the live CVE DB, and finalizing every chunk repeats expensive affected/reference index rebuilds and recalculation. After all OSV chunks succeed, the script rebuilds affected-package and reference-key indexes once and queues security recalculation once. Non-OSV sources still use source replacement and immediate finalization by default.

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
5. Check `/api/health`, `/api/cve-db/stats?refresh=true`, and the dashboard CVE DB status card.
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

Restore refuses archives with unsafe paths, duplicate or missing required members, unexpected files, or manifest checksum mismatches. Backup manifests include `database_dump_sha256` and, when present, `trivy_cache_sha256`.

## Security DB Operations

Connected environments should keep these defaults unless a source is intentionally disabled:

```text
BONGSU_SECURITY_DB_SYNC_CMD=/app/scripts/sync-all-cvedb.sh http://localhost:5677
BONGSU_SECURITY_DB_INTERVAL_HOURS=6
BONGSU_SECURITY_DB_SYNC_ON_START=true
BONGSU_SYNC_REQUIRE_TRIVY_SOURCE=true
```

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
- `bongsu_cve_epss_loaded_without_enrichment` greater than zero.
- `bongsu_security_db_rescan_open` remaining high after a DB update.
- `bongsu_scan_request_stale` for pending or claimed requests.
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

## Routine Maintenance

- Review CVE DB source freshness and matchability daily.
- Review failed/degraded scan requests daily.
- Run retention dry-run before pruning:

```bash
curl -fsS -X POST -H "X-API-Key: $BONGSU_API_KEY" -H "Content-Type: application/json" \
  -d '{"dry_run":true}' http://localhost:5677/api/admin/retention/prune
```

- Export a security DB bundle after each successful connected source refresh for air-gapped promotion.
- Verify `SHA256SUMS` on every package before moving it into an air-gapped environment.
