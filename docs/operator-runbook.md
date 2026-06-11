# Bongsu Operator Runbook

This runbook covers the agent and operator workflows added in the latest cycle: the native scanner, language scanning, SMTP email alerts, the airgap export/import flow with freshness guards, and security DB auto-update behavior. It complements [operations-runbook.md](operations-runbook.md) (production readiness, auth, release gates) — it does not repeat it.

Conventions: API on `5677`, web UI on `5678`. The agent lives in `/opt/bongsu`.

## 1. Deploy the agent with the native scanner

The agent defaults to the **native scanner** — pure-Go dpkg/apk readers plus rpm via the local `rpm` binary — so the `trivy` binary is not required.

```bash
# One-line install (downloads bongsu-agent, and trivy only if available)
curl -fsSL -H "X-Install-Token: $BONGSU_INSTALL_TOKEN" "http://server:5678/api/install.sh" | sudo bash

# Run a scan (native is the default)
/opt/bongsu/bin/bongsu-agent --config /opt/bongsu/config.yaml

# Resident mode for force-scan requests
/opt/bongsu/bin/bongsu-agent --config /opt/bongsu/config.yaml --daemon --poll-interval 60s
```

Choosing the engine:

| Mode | Flag / Env | Notes |
| --- | --- | --- |
| Native (default) | `-scanner native` / `BONGSU_AGENT_SCANNER=native` | No external binary. dpkg/apk parsed in pure Go; rpm uses the host's own `rpm`. |
| Trivy | `-scanner trivy` / `BONGSU_AGENT_SCANNER=trivy` | Falls back to the trivy binary; only then do `-trivy-timeout`/`-container-timeout` apply. |

Container coverage:
- Containers are enumerated across **docker, podman, nerdctl, and crictl**; duplicates are deduped by container ID.
- Native container scanning reads the merged overlay (`GraphDriver.Data.MergedDir`), so the agent needs read access to the runtime overlay storage — run as **root**.
- Skip containers with `-skip-containers` (`BONGSU_AGENT_SKIP_CONTAINERS`) or cap them with `-max-containers` (`BONGSU_AGENT_MAX_CONTAINERS`).

Host and container facts (os-release, kernel, cpu, memory, dmi, virtualization, network, filesystems) are collected from `/proc`, `/sys`, `/etc` and shown in the dashboard's host "System Facts" card and container row expansion. No tuning required.

## 2. Enable and tune language scanning

The agent also inventories language runtimes/dependencies installed outside the OS package manager (pyenv, nvm, app bundles, vendored deps).

| Flag | Env | Default |
| --- | --- | --- |
| `-lang-scan-roots` | `BONGSU_AGENT_LANG_SCAN_ROOTS` | `/opt,/srv,/usr/local,/var/www,/app,/home,/root` |
| `-lang-scan-depth` | `BONGSU_AGENT_LANG_SCAN_DEPTH` | `12` |

- Sentinels: `none` disables language scanning entirely; `all` walks the whole host scan-root.
- Narrow `-lang-scan-roots` to just your app directories on busy hosts, and lower `-lang-scan-depth` if walks are slow. The walk already prunes heavy/irrelevant trees and the real `/proc`, `/sys`, `/dev`, `/run` at the scan root.

```bash
# Only scan application bundles, shallower walk
/opt/bongsu/bin/bongsu-agent --lang-scan-roots /opt/app,/srv/app --lang-scan-depth 8
# Disable language scanning
BONGSU_AGENT_LANG_SCAN_ROOTS=none /opt/bongsu/bin/bongsu-agent
```

## 3. Configure SMTP email alerts

Email is a notification channel alongside `webhook` and `log`. Set the server-wide SMTP config (on the server/compose env), then add a notification rule with the `email` channel.

| Env | Default | Notes |
| --- | --- | --- |
| `BONGSU_SMTP_HOST` | — | Required to enable email |
| `BONGSU_SMTP_FROM` | — | Required (sender address) |
| `BONGSU_SMTP_PORT` | `587` (starttls), `465` (tls) | Override as needed |
| `BONGSU_SMTP_USERNAME` / `BONGSU_SMTP_PASSWORD` | — | Auth credentials |
| `BONGSU_SMTP_ENCRYPTION` | `starttls` | `starttls`, `tls`, or `none` (lab only) |
| `BONGSU_SMTP_TIMEOUT_SECONDS` | `30` | Send timeout |

Per-rule recipients go in the rule's `channel_config`:

```json
{ "to": "secops@example.com,oncall@example.com", "subject_prefix": "[Bongsu]" }
```

Recipients without an `@` are dropped. If `BONGSU_SMTP_HOST`/`BONGSU_SMTP_FROM` are unset, the email channel returns a configuration error — check the audit log / notification send status.

Triage tip: each finding can carry an assignee (담당자). Filter the vulnerability list with `?assignee=<name>` or `?assignee=unassigned` to triage by owner.

## 4. Airgap export / import with freshness guards

Export on the connected side, copy the bundle (and its `.sha256` sidecar) into the air-gapped environment, then import.

```bash
# Connected side: export and verify freshness
./scripts/export-security-db-bundle.sh http://server:5677 "$BONGSU_API_KEY" bongsu-security-db-bundle.tar.gz

# Air-gapped side: import
./scripts/import-security-db-bundle.sh http://airgap-server:5677 "$BONGSU_API_KEY" bongsu-security-db-bundle.tar.gz
```

Guards on import:
- The bundle manifest records `exporter_version` and a `created_at`. Import **rejects bundles older than `BONGSU_SECURITY_DB_BUNDLE_MAX_AGE_DAYS`** (default 30) to prevent stale/replayed imports. Export a fresh bundle, or raise the threshold (set to `0` to disable the check entirely).
- CVE database and (if present) trivy DB checksums in the manifest must match the actual files (SHA-256), or import fails.
- The exporter writes a `.sha256` sidecar and verifies `/api/admin/security-db/status` reports a fresh bundle before the file is promoted.

If import is rejected as stale: re-run the export on the connected side rather than bumping the age limit, unless you knowingly need an older bundle.

## 5. Security DB auto-update and retry

Connected servers sync the security DB on start and on a fixed interval (default 6h). On a failed sync the manager retries with **exponential backoff** instead of waiting a full interval:

| Env | Default | Notes |
| --- | --- | --- |
| `BONGSU_SECURITY_DB_RETRY_BASE_MINUTES` | `5` | First retry delay |
| `BONGSU_SECURITY_DB_RETRY_MAX_MINUTES` | `60` | Cap; also capped at the regular sync interval |
| `BONGSU_SECURITY_DB_SYNC_ON_START` | `true` (typical) | Sync on startup |
| `BONGSU_SECURITY_DB_INTERVAL_HOURS` | `6` | Steady-state cadence |

The delay grows `base * 2^(streak-1)`, capped at the retry max and the sync interval. Watch for `security-db sync retry in <delay> (consecutive failures: N)` in the server log; a rising failure streak means the sync command/source is unhealthy.

## 6. Troubleshooting

- **Agent token / host binding mismatch** — Each agent binds to its host via an agent token (`X-Bongsu-Agent-Token`; from config `agent_token` or `BONGSU_AGENT_TOKEN`, auto-generated in the work-dir if unset). Reports return `403 agent token does not match host binding` when a different token reports for an already-bound host. This is expected after cloning a VM: set a distinct `-host-id` (`BONGSU_AGENT_HOST_ID`) for cloned/containerized agents, or clear the stale binding on the server.
- **Container rootfs scan fails / containers missing packages** — Native container scanning reads the runtime's overlay storage, which requires **root**. Run the agent as root (or via the systemd unit/cron entry the installer creates). Without overlay read access the container scan errors and falls back.
- **RPM containers report no packages** — RPM databases aren't parsed in pure Go yet. The host's `rpm` is used for the host; for a container whose RPM DB the agent can't read, the agent runs the **container's own `rpm`** via `<runtime> exec`. This needs `rpm` present inside the container image and a docker/podman/nerdctl-compatible runtime (CRI/crictl rootfs scanning is not wired). If a minimal/distroless RPM image has no `rpm`, those packages can't be enumerated.
- **No container runtime found** — The agent errors with `no container runtime CLI found (docker, podman, nerdctl, crictl)`; install one or pass `-skip-containers`.
- **Email not delivered** — Confirm `BONGSU_SMTP_HOST` and `BONGSU_SMTP_FROM` are set on the server, encryption matches the port, and rule recipients contain `@`. Check the notification send status / audit log for the SMTP error.
