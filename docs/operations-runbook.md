# Bongsu Operations Runbook

Updated: 2026-06-01 19:57:17 KST

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
go test ./...
./scripts/verify-migrations.sh
./scripts/verify-deploy-config.sh
./scripts/verify-requirements-audit.sh
./scripts/verify-installer-smoke.sh
./scripts/verify-static-binaries.sh
npm --prefix web run build
npm --prefix web run test:e2e
```

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
./scripts/package.sh 0.1.0
sha256sum -c bongsu-0.1.0.tar.gz.sha256
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
curl -fsS -H "X-API-Key: $BONGSU_API_KEY" http://localhost:5677/api/health
curl -fsS -H "X-API-Key: $BONGSU_API_KEY" "http://localhost:5677/api/cve-db/stats?refresh=true"
```

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

The CVE DB is operationally degraded if required sources are missing, `TEMP-*` or `CVD-*` placeholders appear, affected/reference indexes are stale, or EPSS enrichment coverage unexpectedly drops.

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
3. Confirm new reports bind successfully and old-token requests are rejected.

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
