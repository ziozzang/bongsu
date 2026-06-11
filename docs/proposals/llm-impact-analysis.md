Status: proposal — not implemented.

# LLM Integration Design: Impact Analysis and Log-Based Detection

## Background

CVSS and EPSS scores describe a vulnerability's *general* severity, not its **actual impact in our specific environment**. Bongsu already collects nearly all the context an LLM needs to reason about real-world impact:

| Data Bongsu already has | Impact-assessment relevance |
|---|---|
| CVE description + CVSS vector + EPSS + CISA KEV | General severity and real-world exploitation status |
| Package name, installed version, fixed version | Patchability, exposure window |
| Host metadata (owner/team/environment/criticality) | Business impact weighting |
| Process snapshots + listening ports (`process_snapshots`, `port_info`) | Is the vulnerable package actually *running* and *network-exposed*? |
| Container/image associations | Blast radius (other containers sharing the same image) |
| Triage history + assignee | Operational context |

The combination — "CVE-X affects openssl, which is loaded by an nginx process listening on 0.0.0.0:443 on a production/critical host" — is difficult to generalize with rules and is exactly the kind of reasoning LLMs handle well.

## Phase 1 — Vulnerability Impact Analysis (Recommended Starting Point)

### Architecture

```
VulnDetail "Analyze Impact" button  /  nightly batch (top-N risk)
        │
        ▼
internal/server/llm/  (new package, anthropic-sdk-go)
  Input:  vulnerability + package + host metadata + port/process summary
  Output (enforced JSON schema):
        { impact_level, exposure, blast_radius,
          recommended_priority, rationale, suggested_mitigations[] }
        │
        ▼
vulnerability_impact_assessments table
  (vulnerability_id, host_id, pkg_name, security_db_revision,
   model, impact_level, payload JSONB, created_at)
        │
        ▼
UI: VulnDetail card + Vulnerabilities sort/filter + Reports summary
```

### Implementation Notes

- **SDK**: `github.com/anthropics/anthropic-sdk-go`. Default model `claude-opus-4-8` (`anthropic.ModelClaudeOpus4_8`) with adaptive thinking (`anthropic.ThinkingConfigParamUnion{OfAdaptive: &anthropic.ThinkingConfigAdaptiveParam{}}`). High-volume nightly batches can use `claude-haiku-4-5` for cost reduction (two-tier model selection).
- **Structured output**: Use `output_config.format` (json_schema) to enforce the output schema and eliminate parse failures.
- **Prompt caching**: Pin the system prompt (evaluation rubric + output schema description) as a fixed prefix with a `cache_control` breakpoint — this reduces effective per-finding input cost to roughly 0.1×.
- **Batch processing**: Nightly full sweeps use the Message Batches API (async, 50% discount). On-demand single assessments use regular calls.
- **Re-evaluation trigger**: Mark assessments stale when `security_db_revision` changes; re-evaluate only the affected findings after rematch (not a full re-sweep — cost control).
- **Configuration**: `BONGSU_LLM_API_KEY`, `BONGSU_LLM_MODEL`, `BONGSU_LLM_BASE_URL` (for proxy/gateway). Disabled by default. Feature is hidden in the UI when unconfigured.

### Cost Estimate (Approximate)

Roughly 2K input tokens per finding (effective ~300 with cache hits), ~400 output tokens.
- On-demand (opus-4-8): ~$0.02 per finding
- Nightly top-500 batch (haiku-4-5 + batch discount): ~$0.50/day

### Caveats

- **Air-gap environments**: External API calls are not possible; the feature is fully disabled by default via a feature flag. Routing through an internal gateway via `BONGSU_LLM_BASE_URL` is possible but is a separate work item.
- **Prompt injection**: CVE descriptions, package names, and process command lines are *untrusted input*. Mitigations: instruct the system prompt to ignore directives inside data blocks; enforce structured output to constrain output shape; treat assessment results as advisory information always subject to human review (never wire directly to automated blocking or triage changes).
- **Audit**: LLM calls are recorded in `audit_logs` (model, token usage, target finding).
- **Secrets in process cmdlines**: Tokens and passwords may appear in process command lines — a masking filter is required before transmission.

## Phase 2 — Operational Digest (Low-Cost Extension of Phase 1)

Requires no new data collection — works entirely from existing aggregates. An LLM summarizes weekly/daily changes (new criticals, KEV additions, rematch results, upcoming SLA breaches) and delivers the summary via the existing email/webhook notification channels. "This week's top 5 priorities and why" arrives in email. Digest quality improves as Phase 1 impact assessments accumulate.

## Phase 3 — Log Collection and Detection (Long-Term)

The agent already collects processes and ports, so adding log collection is a natural extension — but the guiding principle is **not to rebuild a SIEM**. Scope is limited to "anomalies correlated with vulnerability context."

### Incremental Design

1. **Collection (LLM-independent)**: Add a log whitelist collector to the agent (auth.log/journald for sshd and sudo, docker events, etc.). Send aggregated events to the server — not raw log lines — for example: "247 SSH failures from host X in one hour, top 3 source IPs." Store in a new table or external store.
2. **First-pass filter (rules, LLM-independent)**: Use Sigma-style rules and thresholds to extract candidate events. Raw logs cannot go directly to an LLM (token cost) — rules always filter first.
3. **Second-pass classification (LLM)**: Bundle candidate events with the corresponding host's vulnerability and exposure context and classify in batch: `{false_positive | suspicious | likely_incident}` with rationale. Example: "SSH brute-force candidate + KEV CVE for sshd present on the same host" → elevated priority.
4. **Notification integration**: Route `likely_incident` events through the existing `notification_rules` (email/webhook).

### Prerequisites

- Log retention and PII policy (masking and retention settings)
- Event volume control (agent-side aggregation is critical — no raw lines sent to the server)
- Reuse of the LLM client, audit infrastructure, and cost controls from Phase 1

## Recommended Roadmap

| Order | Item | Effort | Value |
|---|---|---|---|
| 1 | On-demand impact analysis (VulnDetail button) | Small | Immediate feedback + builds infrastructure |
| 2 | Nightly top-N batch + sort/filter integration | Medium | Automated prioritization |
| 3 | Weekly digest → email alert | Small | Automated operational reporting |
| 4 | Log collector + rule filter (LLM-independent parts) | Medium | Detection foundation |
| 5 | LLM event classification + vulnerability context fusion | Medium | Differentiated detection |
