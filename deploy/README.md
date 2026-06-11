# Bongsu (봉수) — Operator Deployment Guide

Bongsu is a package vulnerability monitor: lightweight agents inventory the OS and
language packages on your hosts, the server matches them against aggregated CVE
sources (OSV, NVD, CISA KEV, EPSS, and optionally the Trivy DB), and a web UI
presents findings, triage, SLAs, and exports. ("봉수대" is a watchtower that relays
signals from the edge to a central place.)

This directory contains everything needed to run a production-grade containerized
deployment. You do **not** need a checkout of the source tree to operate it — only
this `deploy/` directory plus pre-built images (or a single source checkout to build
them once).

---

## Architecture

```
                 ┌────────────┐        ┌──────────────┐
   agents ─────▶ │  server    │ ─────▶ │  postgres    │
 (host/container)│ (API + web)│        │  (inventory, │
                 │  :5677     │ ◀───── │   CVE data)  │
                 └─────┬──────┘        └──────────────┘
                       │  serves embedded web UI at /
                       ▼
                  operators / browsers
```

| Component  | Image                 | Purpose                                              |
|------------|-----------------------|------------------------------------------------------|
| `postgres` | `postgres:16-alpine`  | Inventory + CVE storage. Persisted to the `pgdata` volume. |
| `server`   | `bongsu-server`       | REST API, CVE matching engine, scheduler, embedded web UI (`web/dist` is baked into the image). Runs DB migrations on start. |
| `trivy-db` | `bongsu-server` (init)| **Optional** one-shot. Pre-seeds the Trivy vulnerability DB for the optional `trivy` CVE source. Exits 0 even if the download fails. |
| `web`      | `bongsu-web` (nginx)  | **Optional.** The server already serves the UI; this is only useful if you want a separate nginx front-end. |
| `agent`    | `bongsu-agent`        | **Optional** (compose profile `agent`). Scans the docker host from a container. Agents usually run as a bare binary on each target host instead. |

The default agent scanner is **`native`** — a built-in package reader that needs **no
external scan engine** (no Trivy binary). Trivy remains available as an optional CVE
source on the server and as an optional agent scanner (`-scanner trivy`).

---

## Prerequisites

- Docker Engine 24+ and the Docker Compose v2 plugin (`docker compose ...`).
- For building images from source: a checkout of the Bongsu repo. The Go 1.25 and
  Node 22 toolchains are pulled automatically inside the multi-stage builds — you do
  **not** need them installed on the host.
- ~1 GB RAM and a few GB of disk for Postgres + CVE data to start; more as inventory
  grows.
- Outbound HTTPS for connected installs (to fetch CVE feeds). Air-gapped installs are
  fully supported — see [Air-Gapped Deployment](#air-gapped-deployment).

---

## 1. Configure `.env`

Copy the template and fill in the secrets:

```bash
cp deploy/.env.example deploy/.env
```

**Required** values (the stack refuses to start without strong, distinct secrets):

| Variable                | What it is                                                        |
|-------------------------|-------------------------------------------------------------------|
| `BONGSU_DB_PASSWORD`    | Postgres password.                                                |
| `BONGSU_API_KEY`        | Admin/operator API key (also the web admin key).                  |
| `BONGSU_AGENT_API_KEY`  | Agent ingest key. **Must differ** from `BONGSU_API_KEY`.          |
| `BONGSU_INSTALL_TOKEN`  | Gates `/api/install.sh` and binary downloads.                     |

Secret rules (enforced at startup unless `BONGSU_ALLOW_WEAK_SECRETS=true`):
- At least **16 characters**.
- Must not contain placeholder substrings (`change-me`, `your-`, `password`,
  `admin-key`, `agent-key`, `install-token`, `example`, ...).
- `BONGSU_AGENT_API_KEY` must be distinct from `BONGSU_API_KEY`.

Generate strong values:

```bash
openssl rand -hex 24   # run once per secret
```

**Recommended** for first login (creates the initial admin when no users exist):

```ini
BONGSU_ADMIN_USERNAME=admin
BONGSU_ADMIN_PASSWORD=<at-least-16-chars>
```

**Optional** features (see `.env.example` and the compose file for the full list):
- Email notifications: `BONGSU_SMTP_HOST`, `BONGSU_SMTP_PORT`, `BONGSU_SMTP_FROM`,
  `BONGSU_SMTP_USERNAME`, `BONGSU_SMTP_PASSWORD`, `BONGSU_SMTP_ENCRYPTION`
  (`starttls` | `tls` | `none`). Email is sent only when both `BONGSU_SMTP_HOST` and
  `BONGSU_SMTP_FROM` are set.
- `BONGSU_AUTO_ASSIGN_BY_OWNER` — auto-assign findings to the inventory owner.
  **Default: `true`** (on). Set to `false` to disable.
- Reverse-proxy SSO via trusted identity headers
  (`BONGSU_TRUSTED_IDENTITY_HEADER`, `BONGSU_TRUSTED_ADMIN_GROUPS`, ...).

---

## 2. Bring up the stack

Build the images once and start everything:

```bash
docker compose -f deploy/docker-compose.yml up -d --build
```

The build context is the **repo root** (`context: ..`) with the Dockerfiles under
`deploy/`. To build images by hand:

```bash
# from the repo root
docker build -f deploy/Dockerfile.server -t bongsu-server:0.2.0 .
docker build -f deploy/Dockerfile.agent  -t bongsu-agent:0.2.0  .
docker build -f deploy/Dockerfile.web    -t bongsu-web:0.2.0    .   # optional
```

Service ordering and health are handled for you:
- `server` waits for `postgres` to be **healthy** and for the optional `trivy-db`
  init container to **complete**.
- The server applies database migrations automatically on start
  (`BONGSU_AUTO_MIGRATE=true`; look for `Database migrations applied` in the logs).
- Compose health probes hit `/api/ready` (server) and `pg_isready` (postgres).

Check it is up:

```bash
curl -sf http://localhost:${BONGSU_API_PORT:-5677}/api/health
docker compose -f deploy/docker-compose.yml logs -f server   # watch startup
```

Ports (override in `.env`):

| Variable           | Default | Service           |
|--------------------|---------|-------------------|
| `BONGSU_API_PORT`  | `5677`  | server API + UI   |
| `BONGSU_WEB_PORT`  | `5678`  | optional nginx UI |

---

## 3. First login / admin bootstrap

- Open `http://<host>:${BONGSU_API_PORT}/` in a browser.
- Log in with `BONGSU_ADMIN_USERNAME` / `BONGSU_ADMIN_PASSWORD` set in step 1.
  The admin user is created automatically **only on first start, only when the user
  table is empty** (idempotent — changing the env later does not reset an existing
  admin). Watch for `Bootstrapped initial admin user: <name>` in the server log.
- If you skip the admin env vars, set `BONGSU_WEB_AUTH=false` for a private-lab,
  no-login mode (not recommended on shared networks), or create users via the API
  using `BONGSU_API_KEY`.

API access for automation uses the `X-API-Key` header:

```bash
curl -H "X-API-Key: $BONGSU_API_KEY" http://localhost:5677/api/hosts
```

---

## 4. Deploy the agent

The agent reports to the server using the **agent** key (`-api-key
$BONGSU_AGENT_API_KEY`). The default scanner is `native`; add `-packages-only` to let
the server do CVE matching (recommended).

### 4a. Bare binary (recommended for most hosts)

Download the agent from the running server (gated by `BONGSU_INSTALL_TOKEN`) or copy
`bongsu-agent` + `scripts/install-agent.sh` onto the host, then:

```bash
# one-shot scan
sudo bongsu-agent \
  -server http://<server-host>:5677 \
  -api-key <BONGSU_AGENT_API_KEY> \
  -scanner native \
  -packages-only

# or install as a cron/daemon via the installer
sudo BONGSU_SERVER_URL=http://<server-host>:5677 \
     BONGSU_AGENT_API_KEY=<BONGSU_AGENT_API_KEY> \
     BONGSU_PACKAGES_ONLY=true \
     ./install-agent.sh
```

The installer creates/reuses `/opt/bongsu/agent.token` to bind the agent to its host
identity (`BONGSU_AGENT_HOST_BINDING=true` on the server). Keep that token stable
across reinstalls; for cloned VMs/images use `-host-id <unique-id>`.

### 4b. Container mode (scan the docker host itself)

Run the agent as a container with the host root filesystem mounted read-only at
`/host` (for package discovery) and the docker socket mounted (for running-container
image detection):

```bash
docker run --rm \
  --network bongsu-stack_bongsu-net \
  -v /:/host:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  bongsu-agent:0.2.0 \
  -server http://server:5677 \
  -api-key <BONGSU_AGENT_API_KEY> \
  -scanner native \
  -scan-root /host \
  -packages-only
```

Or enable the bundled agent service (one-shot + force-scan daemon) from compose:

```bash
docker compose -f deploy/docker-compose.yml --profile agent up -d agent
```

The compose `agent` service already wires `/:/host:ro`, the docker socket,
`-scan-root /host`, `-scanner native`, and `-packages-only`. The agent image ships a
`docker` CLI so running-container image detection works.

> Native container *image* scanning needs access to the live overlay2 layers. When
> those are not reachable the agent logs a warning and continues — host OS/language
> package ingestion is unaffected. Build the agent image with
> `--build-arg INSTALL_TRIVY=true` and run `-scanner trivy` if you require deep
> container image scanning.

---

## Air-Gapped Deployment

Air-gapped installs use a separate compose file that disables all online jobs
(`deploy/docker-compose.airgap.yml`: no Trivy download, no CVE sync on start).

**On a connected machine** — export the CVE/security DB bundle from a running server:

```bash
scripts/export-security-db-bundle.sh http://localhost:5677 ./bongsu-secdb.tar.gz
# (authenticate with BONGSU_API_KEY as the script documents)
```

Also `docker save` the images so they can be loaded offline:

```bash
docker save bongsu-server:0.2.0 bongsu-web:0.2.0 postgres:16-alpine \
  -o bongsu-images.tar
```

**Transfer** `bongsu-images.tar`, `bongsu-secdb.tar.gz`, and `deploy/` via your
approved sneakernet path.

**On the air-gapped machine:**

```bash
docker load -i bongsu-images.tar
cp deploy/.env.example deploy/.env   # fill in secrets; online jobs are already off
docker compose -f deploy/docker-compose.airgap.yml up -d

# import the security DB bundle
scripts/import-security-db-bundle.sh http://localhost:5677 ./bongsu-secdb.tar.gz
```

The airgap compose sets `BONGSU_SECURITY_DB_SYNC_ON_START=false`,
`BONGSU_TRIVY_DB_INTERVAL_HOURS=0`, and `BONGSU_SYNC_REQUIRE_TRIVY_SOURCE=false` so the
server never reaches the internet. Refresh CVE data later by re-running the export on a
connected machine and re-importing the bundle.

---

## Upgrade path

Migrations run automatically on every server start, so upgrades are:

```bash
# 1. Pull / load the new images (set BONGSU_VERSION in .env or pass the tag)
docker compose -f deploy/docker-compose.yml pull          # or: docker load -i ...

# 2. Recreate; postgres data persists in the pgdata volume
docker compose -f deploy/docker-compose.yml up -d

# 3. Confirm
curl -sf http://localhost:5677/api/health
docker compose -f deploy/docker-compose.yml logs server | grep -i 'migrations applied'
```

Take a `pg_dump`/volume snapshot before major upgrades. Migrations are forward-only;
do not downgrade the server image against a migrated database.

---

## Operations cheatsheet

```bash
# status / logs
docker compose -f deploy/docker-compose.yml ps
docker compose -f deploy/docker-compose.yml logs -f server

# refresh the optional Trivy DB (connected)
docker compose -f deploy/docker-compose.yml run --rm trivy-db \
  sh -c "rm -rf /cache/db/* && trivy image --download-db-only --cache-dir /cache"
docker compose -f deploy/docker-compose.yml restart server

# back up postgres
docker compose -f deploy/docker-compose.yml exec postgres \
  pg_dump -U "$BONGSU_DB_USER" "$BONGSU_DB_NAME" > bongsu-backup.sql

# tear down (KEEPS data)        # tear down (DELETES volumes)
docker compose -f deploy/docker-compose.yml down
docker compose -f deploy/docker-compose.yml down -v
```

---

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `... API_KEY is missing, too short, or still uses a placeholder value` | Secret is `<16` chars or contains a banned placeholder word. Regenerate with `openssl rand -hex 24`. |
| `BONGSU_AGENT_API_KEY must be distinct from BONGSU_API_KEY` | Use two different random secrets. |
| Server stuck `Restarting` | Check `docker compose logs server`. Usually a secret/DSN problem or postgres not ready. |
| `/api/health` shows `"status":"degraded"` | Normal before the first CVE sync completes (no security DB yet). Package inventory still works. Import/sync a security DB to clear it. |
| Agent: `agent token does not match host binding` | The host already bound a different `/opt/bongsu/agent.token`. Reuse the original token, reset it via the host's API, or pass a unique `-host-id`. |
| Agent: `trivy not found` warnings during container scans | Expected with the default native scanner when container overlay layers aren't reachable; host package ingestion is unaffected. Build the agent with `--build-arg INSTALL_TRIVY=true` and use `-scanner trivy` for deep image scans. |

For the full list of server/agent environment variables, see `deploy/.env.example`
and the inline comments in `deploy/docker-compose.yml`.
