# Bongsu (봉수) — Package Vulnerability Monitor

Self-hosted package vulnerability monitoring system with server-side CVE matching. Bongsu means "봉수대", a watchtower that carries signals from the edge to a central place.

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌──────────┐
│  Agent      │────▶│  Server          │────▶│ PostgreSQL│
│  (per host) │     │  + Trivy         │     │          │
└─────────────┘     │  + Web Dashboard │     └──────────┘
                    └──────────────────┘
```

- **Agent**: Collects packages from hosts/containers via Trivy. Sends package list to server.
- **Server**: Server-side CVE matching via Trivy SBOM scan. Web dashboard for browsing.
- **trivy-db init container**: Downloads vulnerability DB from `ghcr.io/aquasecurity/trivy-db` on first start. Stored in shared volume.
- **Packages-only mode**: Agent sends only package lists. Server handles all CVE matching.

## Quick Start (Connected Environment)

```bash
# 1. Configure
cp deploy/.env.example deploy/.env
# Edit deploy/.env — set BONGSU_API_KEY, BONGSU_AGENT_API_KEY, BONGSU_INSTALL_TOKEN, and BONGSU_DB_PASSWORD

# 2. Build and start
cd deploy && docker compose up -d --build

# 3. Check health
curl http://localhost:8080/api/health

# 4. Install agent on target host
curl -fsSL -H "X-Install-Token: $BONGSU_INSTALL_TOKEN" "http://your-server:8080/api/install.sh" | sudo bash
```

## Air-Gapped Deployment

### On Internet-Connected Machine

```bash
# 1. Build package
./scripts/package.sh 0.1.0
# Creates: bongsu-0.1.0.tar.gz

# 2. Download trivy-db (for air-gapped import)
./scripts/download-trivy-db.sh trivy-db.tar.gz
```

### Transfer to Air-Gapped Network

```bash
# Copy bongsu-0.1.0.tar.gz and trivy-db.tar.gz via USB/sneakernet
```

### On Air-Gapped Machine

```bash
# 1. Extract
tar xzf bongsu-0.1.0.tar.gz
cd bongsu-0.1.0

# 2. Load Docker images
./load-images.sh

# 3. Configure
cp deploy/.env.example deploy/.env
# Edit deploy/.env:
#   BONGSU_API_KEY=your-admin-secret-key
#   BONGSU_AGENT_API_KEY=your-agent-secret-key
#   BONGSU_INSTALL_TOKEN=your-install-token
#   BONGSU_DB_PASSWORD=secure-password
#   BONGSU_TRIVY_DB_INTERVAL_HOURS=0

# 4. Start services without online build/update jobs
cd deploy && docker compose -f docker-compose.airgap.yml up -d

# 5. Import security DB bundle
./scripts/import-security-db-bundle.sh http://localhost:8080 your-secret-key ../bongsu-security-db-bundle.tar.gz

# 6. Install agents on target hosts
curl -fsSL -H "X-Install-Token: $BONGSU_INSTALL_TOKEN" "http://server-host:8080/api/install.sh" | sudo bash
```

## Updating Vulnerability Database (CVSS Data)

### Connected Environment

trivy-db is managed by docker-compose. The init container downloads the DB on first start and stores it in a shared volume; the server then refreshes Trivy DB and the merged OSV/NVD/Trivy CVE sources every 6 hours by default, runs the source sync once after the HTTP listener starts, and queues automatic rescans after each successful DB update.

**Update to latest:**
```bash
docker compose run --rm trivy-db sh -c "rm -rf /cache/db/* && trivy image --download-db-only --cache-dir /cache"
docker compose restart server
```

**Override auto-update** (optional `.env`):
```
BONGSU_TRIVY_DB_INTERVAL_HOURS=6
BONGSU_SECURITY_DB_SYNC_CMD=/app/scripts/sync-all-cvedb.sh http://localhost:8080
BONGSU_SECURITY_DB_INTERVAL_HOURS=6
BONGSU_SECURITY_DB_SYNC_ON_START=true
BONGSU_AUTO_RESCAN_ON_DB_UPDATE=true
BONGSU_AUTO_RESCAN_LAST_SEEN_HOURS=720
```

After a Trivy DB upload/update, CVE JSONL import, manual or periodic security DB sync, or air-gapped bundle import, bongsu recalculates CVSS/enrichment/rematches in the background and queues package-only scan requests for recently seen hosts. Recalculation is serialized and coalesced, so a multi-source sync that imports CISA KEV, FIRST EPSS, OSV, NVD, and Trivy data does not run overlapping recalculation jobs. CVE JSONL imports are committed as a single transaction; malformed JSONL or row-level insert failures reject the whole payload and record a failed audit event. Failed manual or periodic security DB sync commands also write `status=error` audit rows with the bounded command error captured by the sync manager. Pending automatic rescan requests are deduplicated per host in the database, so overlapping DB update hooks do not create duplicate pending work. Auto-rescan audit metadata records eligible, queued, and already-pending counts so operators can distinguish no eligible agents from a pending backlog. Dashboard stats show pending, claimed, degraded, and failed automatic rescan requests for the current `security_db_revision` separately from manual or daily scan requests; each count opens Scan History with the matching status/type/revision filters, where request age and claim age highlight stuck work using server-side stale flags, and failed/degraded/cancelled rows can be requeued individually or in bulk after confirming the active filters without losing revision provenance. If a new CVE DB update lands while a previous automatic rescan is already claimed, bongsu still leaves a follow-up pending rescan for the newer DB contents. Agents running in daemon mode pick those requests up through the normal force-scan polling path; claimed scan requests record the claiming host and can only be completed by that same host.

### Air-Gapped Environment

```bash
# On connected machine:
./scripts/export-security-db-bundle.sh http://connected-server:8080 your-api-key bongsu-security-db-bundle.tar.gz

# Transfer to air-gapped, then:
./scripts/import-security-db-bundle.sh http://server:8080 your-api-key bongsu-security-db-bundle.tar.gz
```

Bundle import verifies manifest SHA-256 checksums for `cve-database.jsonl` and optional `trivy-db.tar.gz` before applying any database or cache changes. The manifest also carries `security_db_revision`, and export/import audit rows record it so operators can correlate an offline bundle with the automatic rescans it triggers. `/health` and the dashboard show the current merged revision and source freshness, with revision lookup and freshness errors limited to admin health responses. Direct CVE JSONL import responses and CVE import/export audit rows also include the resulting revision. A corrupt or tampered bundle is rejected, the full CVE database is replaced inside one database transaction, and Trivy DB archives are staged before replacing the active cache so bad rows or invalid archives do not leave partially committed CVE/cache data. Direct source imports replace existing rows for that source in the same transaction, so advisories removed upstream do not remain as stale matches.

## Agent Installation

### On Bare-Metal/VM Host

```bash
# Copy bongsu-agent binary and install-agent.sh to target host
./install-agent.sh http://server:8080 your-api-key
```

The script:
- Installs agent binary to `/opt/bongsu/bin/`
- Creates credential-bearing config at `/opt/bongsu/config.yaml` with `0600` permissions
- Sets up daily cron job at 03:00
- Runs first scan immediately

### On Kubernetes (as CronJob)

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: bongsu-agent
spec:
  schedule: "0 3 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: agent
            image: bongsu-agent:0.1.0
            args:
              - --server
              - http://bongsu-server:8080
              - --api-key
              - $(BONGSU_API_KEY)
              - --packages-only
          restartPolicy: OnFailure
```

## Environment Variables

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `BONGSU_API_KEY` | *required* | API key for authentication |
| `BONGSU_AGENT_API_KEY` | *required* | Agent-only report upload and force-scan polling key; keep it distinct from the admin key |
| `BONGSU_INSTALL_TOKEN` | *required for installer* | Token required for `/api/install.sh`; binary downloads accept this token or an admin API key header |
| `BONGSU_ALLOW_WEAK_SECRETS` | `false` | Development-only override for missing, placeholder, short, or duplicate server secrets; keep `false` in production |
| `BONGSU_AGENT_HOST_BINDING` | `true` | Require each agent to present a persistent per-host token in addition to `BONGSU_AGENT_API_KEY` |
| `BONGSU_ACCESS_LOG` | `true` | Emit request-scoped access logs with method, path, status, bytes, duration, IP, and `X-Request-ID` |
| `BONGSU_ACCESS_LOG_HEALTH` | `false` | Include `/api/health` in access logs when enabled |
| `BONGSU_HTTP_READ_HEADER_TIMEOUT_SECONDS` | `10` | Maximum seconds allowed to read request headers before closing the connection |
| `BONGSU_HTTP_READ_TIMEOUT_SECONDS` | `30` | Maximum seconds allowed to read a full request, including upload body |
| `BONGSU_HTTP_WRITE_TIMEOUT_SECONDS` | `120` | Maximum seconds allowed to write a response |
| `BONGSU_HTTP_IDLE_TIMEOUT_SECONDS` | `120` | Maximum keep-alive idle seconds per connection |
| `BONGSU_HTTP_MAX_HEADER_BYTES` | `1048576` | Maximum accepted HTTP request header size |
| `BONGSU_VIEWER_API_KEYS` | empty | Comma-separated `key:subject` viewer keys scoped by RBAC; use `key:user:alice` or `key:group:platform` when user and group IDs may overlap |
| `BONGSU_CORS_ALLOWED_ORIGINS` | empty | Comma-separated browser origins allowed to call the API; empty keeps same-origin only, `*` explicitly allows all |
| `BONGSU_PORT` | `8080` | Server listen port |
| `BONGSU_DB_DSN` | `postgres://bongsu:...` | PostgreSQL connection string |
| `BONGSU_DB_MAX_OPEN_CONNS` | `25` | Maximum open PostgreSQL connections from the server |
| `BONGSU_DB_MAX_IDLE_CONNS` | `5` | Maximum idle PostgreSQL connections retained |
| `BONGSU_DB_CONN_MAX_LIFETIME_MINUTES` | `5` | Maximum lifetime for pooled PostgreSQL connections |
| `BONGSU_AUTO_MIGRATE` | `true` | Run checksum-tracked DB migrations on startup |
| `BONGSU_TRIVY_PATH` | `trivy` | Trivy binary path |
| `BONGSU_TRIVY_CACHE_DIR` | `/app/trivy-cache` | Trivy cache directory |
| `BONGSU_TRIVY_DB_REPO` | `ghcr.io/aquasecurity/trivy-db` | Trivy DB registry |
| `BONGSU_TRIVY_DB_INTERVAL_HOURS` | `6` connected, `0` airgap | DB update interval (`0`=disabled) |
| `BONGSU_SECURITY_DB_SYNC_CMD` | `/app/scripts/sync-all-cvedb.sh http://localhost:8080` connected, empty airgap | Command for OSV/NVD/Trivy source sync; the bundled script reads `BONGSU_API_KEY` from the container environment |
| `BONGSU_SECURITY_DB_INTERVAL_HOURS` | `6` | Security source sync interval |
| `BONGSU_SECURITY_DB_SYNC_ON_START` | `true` | Run the configured security source sync once on server startup before waiting for the periodic interval |
| `BONGSU_SECURITY_DB_SYNC_OUTPUT_MAX_BYTES` | `8192` | Tail bytes of the most recent source sync output retained in admin-authenticated health checks and failed update responses |
| `BONGSU_SECURITY_DB_MAX_SOURCE_AGE_HOURS` | `30` | Mark merged security DB source freshness as stale when any source has not updated within this many hours (`0` disables age-based staleness) |
| `BONGSU_SYNC_REQUIRE_TRIVY_SOURCE` | `true` connected, `false` airgap | Fail the bundled source sync if Trivy CVE extraction is missing or empty instead of silently producing a partial source set |
| `BONGSU_AUTO_RESCAN_ON_DB_UPDATE` | `true` | Queue background rescans after security DB changes |
| `BONGSU_AUTO_RESCAN_LAST_SEEN_HOURS` | `720` | Only auto-rescan hosts seen within this many hours (`0`=all hosts) |
| `BONGSU_CVE_MATCH_SOURCES` | empty | Optional comma-separated CVE source allowlist for automatic rematch |
| `BONGSU_CVE_MATCH_MIN_SOURCE_MATCHABLE_PERCENT` | `0` | Skip CVE sources below this matchable-record percentage during automatic rematch; matchable records require name, ecosystem, and fixed-version data |
| `BONGSU_CVE_MATCH_CANDIDATE_LIMIT` | `50000` | Maximum candidate package/advisory pairs evaluated per rematch pass, clamped at 1000000; responses and audit logs mark `limited=true` when reached |
| `BONGSU_AGENT_REPORT_MAX_BYTES` | `536870912` | Maximum accepted agent report body size |
| `BONGSU_TRIVY_DB_UPLOAD_MAX_BYTES` | `2147483648` | Maximum accepted direct Trivy DB upload size |
| `BONGSU_CVE_DB_IMPORT_MAX_BYTES` | `2147483648` | Maximum accepted CVE JSONL import size |
| `BONGSU_SECURITY_DB_BUNDLE_MAX_BYTES` | `4294967296` | Maximum accepted air-gap security DB bundle import size |
| `BONGSU_MULTIPART_MEMORY_MAX_BYTES` | `33554432` | Multipart form memory threshold before large upload parts spill to temporary files |
| `BONGSU_API_MAX_PAGE_LIMIT` | `1000` | Maximum `limit` accepted by paginated API endpoints |
| `BONGSU_API_MAX_PAGE_OFFSET` | `1000000` | Maximum `offset` accepted by paginated API endpoints |
| `BONGSU_VULN_EXPORT_MAX_ROWS` | `100000` | Maximum vulnerability rows per report export |
| `BONGSU_WEBHOOK_URL` | empty | Optional outbound webhook URL for scan/security DB events |
| `BONGSU_WEBHOOK_SECRET` | empty | Optional HMAC-SHA256 signing secret for webhooks |
| `BONGSU_WEBHOOK_MIN_SEVERITY` | `HIGH` | Minimum scan severity that triggers `scan.completed` webhook |
| `BONGSU_WEBHOOK_MIN_RISK_LEVEL` | `high` | Minimum computed risk level that triggers `scan.completed` webhook (`critical`,`high`,`medium`,`low`; use `off` to disable) |
| `BONGSU_WEBHOOK_INVENTORY_STATUSES` | `empty` | Comma-separated inventory states that trigger `scan.completed` webhook (`healthy`,`degraded`,`stale`,`empty`,`none`) |
| `BONGSU_WEBHOOK_RETRY_ATTEMPTS` | `3` | Webhook delivery attempts for network errors, HTTP 429, and HTTP 5xx responses; clamped to 1-10 |
| `BONGSU_WEBHOOK_RETRY_DELAY_MS` | `1000` | Delay between retryable webhook attempts in milliseconds |
| `BONGSU_SLA_CRITICAL_DAYS` | `7` | Remediation SLA days for critical findings |
| `BONGSU_SLA_HIGH_DAYS` | `30` | Remediation SLA days for high findings |
| `BONGSU_SLA_MEDIUM_DAYS` | `90` | Remediation SLA days for medium findings |
| `BONGSU_SLA_LOW_DAYS` | `180` | Remediation SLA days for low findings |
| `BONGSU_AGENT_ONLINE_MINUTES` | `1560` | Last-seen age treated as online (26h default for daily scans) |
| `BONGSU_AGENT_OFFLINE_MINUTES` | `4320` | Last-seen age treated as offline after this threshold |
| `BONGSU_INVENTORY_STALE_HOURS` | `48` | Latest completed inventory older than this is `stale` in host filters |
| `BONGSU_RETENTION_SCAN_DAYS` | `180` | Default scan history retention for admin prune action |
| `BONGSU_RETENTION_SCAN_REQUEST_DAYS` | `90` | Default completed/degraded/failed/cancelled scan request retention |
| `BONGSU_RETENTION_AUDIT_DAYS` | `365` | Default audit log retention for admin prune action |
| `BONGSU_SCAN_REQUEST_CLAIM_TIMEOUT_MINUTES` | `60` | Requeue claimed force-scan requests after this age |
| `BONGSU_WEB_AUTH` | `true` | Web UI authentication (`true`=API key required, `false`=no login for private lab networks only) |

### Agent

| Variable | Flag | Description |
|----------|------|-------------|
| `BONGSU_SERVER_URL` | `--server` | Server URL |
| `BONGSU_API_KEY` | `--api-key` | Agent API key, preferably `BONGSU_AGENT_API_KEY` from server config |
| `BONGSU_AGENT_TOKEN` | config `agent_token` | Optional persistent per-host token; generated automatically by the installer/agent if omitted |
| - | `--work-dir` | Working directory (default: `/opt/bongsu`) |
| - | `--packages-only` | Server-side CVE matching |
| - | `--type` | Scan type: `daily` or `manual` |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/report` | Agent scan report submission, including bounded optional `errors[]` collection failures that mark scans degraded |
| `GET` | `/api/stats` | Dashboard totals, raw vulnerability rows, active remediation finding/risk-level counts, and scan request backlog counts |
| `GET` | `/api/hosts` | List hosts with `agent_status` and `inventory_status` filters (`healthy`,`degraded`,`stale`,`empty`,`none`), RBAC scope, raw and active vulnerability counts, and latest inventory summary |
| `POST` | `/api/hosts/{id}/metadata` | Update host owner/team/environment/criticality/tags |
| `POST` | `/api/hosts/{id}/agent-token/reset` | Admin-only reset of a host's bound agent token for reinstall or token-loss recovery |
| `GET` | `/api/hosts/{id}/sbom` | Export latest host SBOM as CycloneDX JSON with stable `bom-ref` dependencies or SPDX JSON with `format=spdx` |
| `GET` | `/api/vulnerabilities` | List latest-scan CVEs with risk score/level, host/container/owner/team/environment/finding-source/CISA-KEV/EPSS filters, and package type/ecosystem context |
| `GET` | `/api/vulnerabilities/filters` | List vulnerability filter options scoped to the caller's latest-scan RBAC visibility |
| `GET` | `/api/vulnerabilities/export` | Export filtered vulnerability report as CSV or JSON with host metadata |
| `GET` | `/api/vuln-summary?group_by=owner` | Group active remediation findings and risk-level counts by owner/team/environment/criticality |
| `POST` | `/api/vulnerabilities/triage` | Set persistent vulnerability triage status/scope/expiry |
| `GET` | `/api/packages` | List latest-scan packages with active finding `max_cvss`/`vuln_count` (supports `sort_by`, `q`, filters, pagination) |
| `GET` | `/api/packages/filters` | List package filter options scoped to the caller's latest-scan RBAC visibility |
| `GET` | `/api/packages/{id}/vulnerabilities` | Latest-scan active package vulnerability details |
| `GET` | `/api/containers` | List latest container/image assets with host-scoped RBAC |
| `GET` | `/api/scans` | Scan history with inventory counts and package delta |
| `DELETE` | `/api/scans/{id}` | Delete scan and associated data |
| `POST` | `/api/admin/trivy-db` | Upload trivy-db (air-gapped update) |
| `POST` | `/api/admin/security-db/update` | Run configured source sync command |
| `GET` | `/api/admin/security-db/export` | Export CVE DB + optional Trivy DB bundle |
| `POST` | `/api/admin/security-db/import` | Import exported security DB bundle |
| `GET` | `/api/cve-db/stats` | Source counts, matchable percentage, and quality counters for matchable/fixed/range/CVSS data |
| `GET` | `/api/admin/cve-db/export` | Export merged CVE database as JSONL |
| `POST` | `/api/admin/cve-db/import` | Import merged CVE database JSONL atomically |
| `POST` | `/api/admin/cve-db/rematch` | Rematch packages, optionally with `sources`, `min_source_matchable_percent`, and `scan_id` JSON filters |
| `GET` | `/api/admin/metrics` | Admin-only Prometheus text metrics for DB pool health, security recalculation state, Trivy readiness, security source freshness/quality, active risk-level backlog, and automatic rescan backlog |
| `POST` | `/api/admin/retention/prune` | Dry-run or prune old scans, completed scan requests, and audit logs |
| `GET` | `/api/admin/rbac/subjects` | List RBAC subjects for admin UI/API |
| `POST` | `/api/admin/rbac/subjects` | Create or update RBAC subject |
| `DELETE` | `/api/admin/rbac/subjects/{id}` | Delete RBAC subject and its policies |
| `GET` | `/api/admin/rbac/policies` | List RBAC policies, optionally filtered by `subject_external_id` such as `user:alice` or `group:platform` |
| `POST` | `/api/admin/rbac/policies` | Create RBAC policy by `subject_id` or `subject_external_id` |
| `DELETE` | `/api/admin/rbac/policies/{id}` | Delete RBAC policy |
| `GET` | `/api/admin/audit-logs` | Query audit log events by actor/action/resource/status/time range; Audit Log UI includes security/export/agent-token action presets |
| `POST` | `/api/scan-requests` | Request force scan for host/all |
| `GET` | `/api/scan-requests` | List force scan requests with host-scoped RBAC; filter by `status`, `scan_type`, and `security_db_revision` |
| `POST` | `/api/scan-requests/{id}/cancel` | Cancel pending or claimed force scan request |
| `POST` | `/api/scan-requests/{id}/requeue` | Requeue failed, degraded, or cancelled force scan request |
| `POST` | `/api/scan-requests/requeue-filtered` | Bulk requeue failed/degraded/cancelled force scan requests matching at least one filter |
| `POST` | `/api/scan-requests/requeue-stale` | Requeue claimed force-scan requests older than timeout |
| `POST` | `/api/agent/scan-requests/claim` | Agent claims a pending force scan |
| `POST` | `/api/agent/scan-requests/{id}/complete` | Agent completes/fails a force scan |
| `GET` | `/api/health` | Health check with Trivy readiness, merged security DB revision, and source freshness |

## RBAC Quick Start

```bash
# Map a viewer API key to user subject "alice"
echo 'BONGSU_VIEWER_API_KEYS=viewer-secret:user:alice' >> deploy/.env

# Create subject and grant read access to one host
curl -X POST -H "X-API-Key: $BONGSU_API_KEY" -H "Content-Type: application/json" \
  -d '{"subject_type":"user","external_id":"alice","display_name":"Alice"}' \
  http://localhost:8080/api/admin/rbac/subjects

curl -X POST -H "X-API-Key: $BONGSU_API_KEY" -H "Content-Type: application/json" \
  -d '{"subject_external_id":"user:alice","resource_type":"host","resource_id":"HOST_ID","permission":"read"}' \
  http://localhost:8080/api/admin/rbac/policies

# Grant export permission separately for SBOM/vulnerability report downloads
curl -X POST -H "X-API-Key: $BONGSU_API_KEY" -H "Content-Type: application/json" \
  -d '{"subject_external_id":"user:alice","resource_type":"host","resource_id":"HOST_ID","permission":"export"}' \
  http://localhost:8080/api/admin/rbac/policies

# Container and image policies resolve through the latest container inventory
curl -X POST -H "X-API-Key: $BONGSU_API_KEY" -H "Content-Type: application/json" \
  -d '{"subject_external_id":"user:alice","resource_type":"image","resource_id":"registry.local/app/api:2026.06","permission":"read"}' \
  http://localhost:8080/api/admin/rbac/policies

# Asset group policies resolve through current host metadata
curl -X POST -H "X-API-Key: $BONGSU_API_KEY" -H "Content-Type: application/json" \
  -d '{"subject_external_id":"user:alice","resource_type":"asset_group","resource_id":"team:platform","permission":"read"}' \
  http://localhost:8080/api/admin/rbac/policies
```

## Troubleshooting

**"trivy-db not found" on startup**: Expected on first start in air-gapped environments. Use `scripts/update-trivy-db.sh` to import, or the init container downloads it automatically in connected environments.

**API key mismatch**: Web/admin calls use `BONGSU_API_KEY`; agents should use `BONGSU_AGENT_API_KEY`.

**Agent connection failures**: Verify network connectivity and that `BONGSU_SERVER_URL` points to the correct address.

**Empty scan results**: Ensure `--packages-only` flag is used. The agent needs Trivy installed at `<work-dir>/bin/trivy` for scanning.
