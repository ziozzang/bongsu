# Bongsu Operator Runbook

> This runbook has been merged into the canonical
> **[operations-runbook.md](operations-runbook.md)** to eliminate divergence.
> All agent/operator content now lives there. This file is kept only as a
> pointer so existing links keep working.

Conventions: API on `5677`, web UI on `5678`. The agent lives in `/opt/bongsu`.

Find the former sections in [operations-runbook.md](operations-runbook.md):

| Topic | Section |
| --- | --- |
| Deploy the agent with the native scanner; engine selection (`-scanner` / `BONGSU_AGENT_SCANNER`) | [Agent Deployment And Native Scanner](operations-runbook.md#agent-deployment-and-native-scanner) |
| Language/runtime scanning (`-lang-scan-roots`, `-lang-scan-depth`), container coverage, facts, auto-assign-by-owner | [Agent Deployment And Native Scanner](operations-runbook.md#agent-deployment-and-native-scanner) |
| SMTP email alerts (`BONGSU_SMTP_*`), notification trigger taxonomy incl. `scan.failed` | [Email Alerts (SMTP)](operations-runbook.md#email-alerts-smtp) |
| Airgap export/import with freshness guards | [Install](operations-runbook.md#install) and [Security DB Operations](operations-runbook.md#security-db-operations) |
| Security DB auto-update, retry backoff, bundle max-age | [Security DB Operations](operations-runbook.md#security-db-operations) |
| Agent troubleshooting (token binding, container rootfs, RPM containers, email) | [Agent troubleshooting](operations-runbook.md#agent-troubleshooting) |

The vulnerability matching engine (OSV path, CPE/runtime path, version
comparison, epoch-loss policy, rematch/cleanup lifecycle) is documented in
[vulnerability-matching-rules.md](vulnerability-matching-rules.md).
