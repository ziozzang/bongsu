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
./scripts/install-agent.sh http://your-server:8080 your-api-key
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
./scripts/install-agent.sh http://server-host:8080 your-secret-key
```

## Updating Vulnerability Database (CVSS Data)

### Connected Environment

trivy-db is managed by the init container in docker-compose. The init container downloads the DB on first start and stores it in a shared volume.

**Update to latest:**
```bash
docker compose run --rm trivy-db sh -c "rm -rf /cache/db/* && trivy image --download-db-only --cache-dir /cache"
docker compose restart server
```

**Or enable auto-update** (add to `.env`):
```
BONGSU_TRIVY_DB_INTERVAL_HOURS=6
BONGSU_SECURITY_DB_SYNC_CMD=/app/scripts/sync-all-cvedb.sh http://localhost:8080 your-api-key
BONGSU_SECURITY_DB_INTERVAL_HOURS=6
BONGSU_AUTO_RESCAN_ON_DB_UPDATE=true
BONGSU_AUTO_RESCAN_LAST_SEEN_HOURS=720
```

After a Trivy DB upload/update, CVE JSONL import, security DB sync, or air-gapped bundle import, bongsu recalculates CVSS/enrichment/rematches in the background and queues package-only scan requests for recently seen hosts. Agents running in daemon mode pick those requests up through the normal force-scan polling path.

### Air-Gapped Environment

```bash
# On connected machine:
./scripts/export-security-db-bundle.sh http://connected-server:8080 your-api-key bongsu-security-db-bundle.tar.gz

# Transfer to air-gapped, then:
./scripts/import-security-db-bundle.sh http://server:8080 your-api-key bongsu-security-db-bundle.tar.gz
```

## Agent Installation

### On Bare-Metal/VM Host

```bash
# Copy bongsu-agent binary and install-agent.sh to target host
./install-agent.sh http://server:8080 your-api-key
```

The script:
- Installs agent binary to `/opt/bongsu/bin/`
- Creates config at `/opt/bongsu/config.yaml`
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
| `BONGSU_AGENT_API_KEY` | `BONGSU_API_KEY` | Agent-only report upload and force-scan polling key |
| `BONGSU_INSTALL_TOKEN` | empty | Optional token required for `/api/install.sh` and binary downloads |
| `BONGSU_VIEWER_API_KEYS` | empty | Comma-separated `key:subject` viewer keys scoped by RBAC |
| `BONGSU_PORT` | `8080` | Server listen port |
| `BONGSU_DB_DSN` | `postgres://bongsu:...` | PostgreSQL connection string |
| `BONGSU_AUTO_MIGRATE` | `true` | Run DB migrations on startup |
| `BONGSU_TRIVY_PATH` | `trivy` | Trivy binary path |
| `BONGSU_TRIVY_CACHE_DIR` | `/app/trivy-cache` | Trivy cache directory |
| `BONGSU_TRIVY_DB_REPO` | `ghcr.io/aquasecurity/trivy-db` | Trivy DB registry |
| `BONGSU_TRIVY_DB_INTERVAL_HOURS` | `0` | DB update interval (`0`=disabled, `6`=connected) |
| `BONGSU_SECURITY_DB_SYNC_CMD` | empty | Command for OSV/NVD/Trivy source sync |
| `BONGSU_SECURITY_DB_INTERVAL_HOURS` | `6` | Security source sync interval |
| `BONGSU_AUTO_RESCAN_ON_DB_UPDATE` | `true` | Queue background rescans after security DB changes |
| `BONGSU_AUTO_RESCAN_LAST_SEEN_HOURS` | `720` | Only auto-rescan hosts seen within this many hours (`0`=all hosts) |
| `BONGSU_VULN_EXPORT_MAX_ROWS` | `100000` | Maximum vulnerability rows per report export |
| `BONGSU_WEB_AUTH` | `true` | Web UI authentication (`true`=API key required, `false`=no login) |

### Agent

| Variable | Flag | Description |
|----------|------|-------------|
| `BONGSU_SERVER_URL` | `--server` | Server URL |
| `BONGSU_API_KEY` | `--api-key` | Agent API key, preferably `BONGSU_AGENT_API_KEY` from server config |
| - | `--work-dir` | Working directory (default: `/opt/bongsu`) |
| - | `--packages-only` | Server-side CVE matching |
| - | `--type` | Scan type: `daily` or `manual` |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/report` | Agent scan report submission |
| `GET` | `/api/hosts` | List hosts |
| `GET` | `/api/hosts/{id}/sbom` | Export latest host SBOM as CycloneDX JSON |
| `GET` | `/api/vulnerabilities` | List CVEs (supports `sort_by`, `severity`, pagination) |
| `GET` | `/api/vulnerabilities/export` | Export filtered vulnerability report as CSV or JSON |
| `POST` | `/api/vulnerabilities/triage` | Set persistent vulnerability triage status/scope |
| `GET` | `/api/packages` | List packages (supports `sort_by`, `q`, filters, pagination) |
| `GET` | `/api/packages/{id}/vulnerabilities` | Package vulnerability details |
| `GET` | `/api/scans` | Scan history |
| `DELETE` | `/api/scans/{id}` | Delete scan and associated data |
| `POST` | `/api/admin/trivy-db` | Upload trivy-db (air-gapped update) |
| `POST` | `/api/admin/security-db/update` | Run configured source sync command |
| `GET` | `/api/admin/security-db/export` | Export CVE DB + optional Trivy DB bundle |
| `POST` | `/api/admin/security-db/import` | Import exported security DB bundle |
| `GET` | `/api/admin/cve-db/export` | Export merged CVE database as JSONL |
| `POST` | `/api/admin/cve-db/import` | Import merged CVE database JSONL |
| `POST` | `/api/admin/rbac/subjects` | Create or update RBAC subject |
| `POST` | `/api/admin/rbac/policies` | Create RBAC policy |
| `GET` | `/api/admin/audit-logs` | Query audit log events by actor/action/resource/status |
| `POST` | `/api/scan-requests` | Request force scan for host/all |
| `GET` | `/api/scan-requests` | List force scan requests |
| `POST` | `/api/agent/scan-requests/claim` | Agent claims a pending force scan |
| `POST` | `/api/agent/scan-requests/{id}/complete` | Agent completes/fails a force scan |
| `GET` | `/api/health` | Health check |

## RBAC Quick Start

```bash
# Map a viewer API key to subject "alice"
echo 'BONGSU_VIEWER_API_KEYS=viewer-secret:alice' >> deploy/.env

# Create subject and grant read access to one host
curl -X POST -H "X-API-Key: $BONGSU_API_KEY" -H "Content-Type: application/json" \
  -d '{"subject_type":"user","external_id":"alice","display_name":"Alice"}' \
  http://localhost:8080/api/admin/rbac/subjects

curl -X POST -H "X-API-Key: $BONGSU_API_KEY" -H "Content-Type: application/json" \
  -d '{"subject_external_id":"alice","resource_type":"host","resource_id":"HOST_ID","permission":"read"}' \
  http://localhost:8080/api/admin/rbac/policies
```

## Troubleshooting

**"trivy-db not found" on startup**: Expected on first start in air-gapped environments. Use `scripts/update-trivy-db.sh` to import, or the init container downloads it automatically in connected environments.

**API key mismatch**: Web/admin calls use `BONGSU_API_KEY`; agents should use `BONGSU_AGENT_API_KEY`.

**Agent connection failures**: Verify network connectivity and that `BONGSU_SERVER_URL` points to the correct address.

**Empty scan results**: Ensure `--packages-only` flag is used. The agent needs Trivy installed at `<work-dir>/bin/trivy` for scanning.
