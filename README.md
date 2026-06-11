# Bongsu (봉수)

> Self-hosted package vulnerability monitoring platform. The name comes from 봉수대 (beacon-fire towers) — just as those towers relayed warning signals across the land, Bongsu agents relay package and runtime inventory from every host to a central server.

Repository: <https://github.com/ziozzang/bongsu> · License: MIT

## What it does

- **Native dependency-free agents** — pure-Go dpkg/apk parsers; rpm via host binary exec; language lockfiles (npm, pip, Go, Cargo, Gemfile); runtime detection for pyenv Python, Node, JDK, Ruby, PHP, Go SDK from filesystem layout; scans both the host and inside containers; collects detailed host and container facts from `/proc`/`/sys`/`/etc` without external tools.
- **Multi-source CVE database** — OSV, NVD, EPSS, CISA-KEV, and Trivy advisories with automatic online updates and airgap bundle import/export.
- **Ecosystem-aware version matching** — full dpkg `verrevcmp`, apk fuzzy compare, RPM `rpmvercmp` (epoch/tilde/caret), and semver algorithms; epoch-loss tolerance and version-gated CPE matching to reduce false positives.
- **Triage workflow** — per-finding assignee, owner auto-assign after scan, configurable SLA deadlines by severity, risk score combining CVSS + EPSS + KEV + host criticality.
- **Notifications** — webhook (HMAC-signed) and SMTP email; triggers include `scan.completed`, `scan.failed`, `vuln.new_critical`, `sla.breach`, and more.
- **RBAC, audit log, SBOM export** (CycloneDX 1.5 / SPDX 2.3), detailed vulnerability search including CVE→assets reverse lookup, and a React dashboard.

## Quick start

```bash
cd deploy
cp .env.example .env          # set BONGSU_DB_PASSWORD and other secrets
docker compose up -d --build  # starts server, web UI, and database
# open http://localhost:5678 for the dashboard
# install the agent on each target host:
curl -fsSL -H "X-Install-Token: $BONGSU_INSTALL_TOKEN" "http://your-server:5678/api/install.sh" | sudo bash
```

Full deployment guide: [deploy/README.md](deploy/README.md)

## Architecture

```
 Agent (each host)
    │  OS packages, lockfiles, runtimes, host/container facts
    ▼
 Server + Web UI  ←──  CVE sources (OSV / NVD / EPSS / CISA-KEV / Trivy)
    │
    ▼
 PostgreSQL
```

- **Agent** — collects packages, language dependencies, runtimes, and facts; sends to server.
- **Server** — CVE matching, version comparison, triage workflow, REST API.
- **Web UI** — React dashboard on port 5678; API on port 5677.

See [docs/architecture.md](docs/architecture.md) for full component and data-flow documentation.

## Documentation

- [deploy/README.md](deploy/README.md) — deployment, configuration, environment variables
- [docs/architecture.md](docs/architecture.md) — component design and implementation notes
- [docs/operations-runbook.md](docs/operations-runbook.md) — canonical operator runbook (install, upgrade, backup, security DB, monitoring, incident response)
- [docs/vulnerability-matching-rules.md](docs/vulnerability-matching-rules.md) — matching engine, version algorithms, false-positive reduction
- [docs/requirements-audit.md](docs/requirements-audit.md) — requirement traceability matrix and verification suite
- [docs/agent-handoff.md](docs/agent-handoff.md) — contributor / engineer onboarding
- [TODO.md](TODO.md) — roadmap
- [docs/proposals/](docs/proposals/) — unimplemented design proposals
- [docs/openapi.yaml](docs/openapi.yaml) — API reference
- [docs/index.html](docs/index.html) — multilingual landing page

## License

MIT
