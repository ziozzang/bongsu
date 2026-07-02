# Bongsu Security-Intelligence Backbone

The intelligence layer (`internal/server/intel/`) runs **agentic reasoning over
Bongsu's own security data**. It drives an external intelligence backbone — the
[jikji](https://github.com/jikji-labs/jikji) server, used over its HTTP API and
never imported as source — and lets that agent call back into a set of
**read-only, scope-checked, fully-audited** Bongsu tools.

It is a strict add-on: the scan/match pipeline (`internal/server/db`,
`internal/agent`) has **zero dependency** on this package, and a backbone that is
unconfigured or unreachable degrades gracefully (the intel API returns 503; the
scanner is unaffected).

---

## 1. Architecture (two planes)

```
   operator / web ─┐
                   │  POST /api/intel/{runs,pipelines,verify}
                   ▼
        ┌──────────────────────┐   POST /v1/runs      ┌───────────────────┐
        │  Bongsu intel.Service │ ───────────────────► │   jikji backbone   │
        │  (runner + store)     │ ◄─────────────────── │   (agent loop)     │
        └──────────────────────┘   run + events        └─────────┬─────────┘
                   ▲                                              │ MCP stdio
                   │ persist runs / audit / reports               │ tools/call
                   ▼                                              ▼
             Postgres (intel_*)                     bongsu-server intel-mcp
                                                    (advisory_for, query_vulns, …)
                                                              │
                                                              ▼
                                                     Postgres (cve_database, …)
```

- **Outbound plane** — `Service.RunScenario` builds a deterministic prompt and
  POSTs it to jikji `/v1/runs`. Bongsu never spawns jikji or `jikjictl`; jikji is
  configured once at *its* boot.
- **Inbound plane** — jikji, during the run, calls Bongsu's tools over an **MCP
  stdio subprocess** (`bongsu-server intel-mcp`). Every tool is read-only,
  constrained to the run's RBAC scope, and audited.

---

## 2. Module map

| File | Responsibility |
|------|----------------|
| `runner.go` | HTTP client of jikji `/v1/runs`; bounded concurrency + per-run timeout; parses the run response + reconstructs the tool-call audit from events. |
| `run.go` | `Service` — the runtime entrypoint. `RunScenario`, `RunPipeline`/`RunNamedPipeline`. Persists every run; best-effort report persistence. |
| `scenario.go` | `ScenarioRegistry` + the 7 built-in scenarios; the shared `toolPreamble`; deterministic prompt builders. |
| `pipelines.go` | `PipelineRegistry` — code-registered named chains (no caller-defined DAGs). |
| `verification.go` | Majority-vote adversarial verification (`RunVerification`) — N independent lens-diverse voters + a pure aggregate. |
| `report.go` | Finding-report persistence: dedup-key normalization, upsert, list/get. |
| `validate.go` | Lightweight output-schema validation (required-field check + fenced-JSON extraction). |
| `tool.go`, `tools_reference.go`, `tools_scoped.go` | The tool registry and the read-only tools (reference + host-scoped). |
| `mcp_server.go` | Serves the tools over MCP stdio — the single policy + audit chokepoint. |
| `store.go` | Postgres persistence: `intel_runs`, `intel_tool_calls`, `intel_verifications`, `intel_finding_reports`. |

External touch points (only three): `api/intel.go` (HTTP handlers),
`api/api.go` (route wiring), `cmd/server/intel_mcp.go` (the MCP subcommand).

---

## 3. Setup

### 3.1 Configure jikji with the Bongsu tools

Point a jikji server at the Bongsu MCP tool server via `sorts.mcp_servers`. The
tools register as `bongsu.<tool>` and pass jikji's normal rubric/sandbox/audit
gates.

```yaml
# jikji config (excerpt)
press:
  listen_host: 127.0.0.1
  listen_port: 1385

typebackbone:
  # The report scenario synthesizes structured JSON after tool calls; use a
  # capable model (a fast non-reasoning model tends to echo raw tool output).
  default_provider: zai
  default_model: glm-5.2
  providers:
    - name: zai
      kind: glm
      model: glm-5.2
      base_url: https://api.z.ai/api/paas/v4
      api_key_env: Z_AI_API_KEY
      supports_tools: true

sorts:
  mcp_servers:
    - name: bongsu
      transport: stdio
      command: /usr/local/bin/bongsu-server
      args: [intel-mcp]
      call_timeout: 30s

forme:
  model: glm-5.2
  system_prompt: |
    You are Bongsu's security-intelligence agent. Use the provided bongsu.* tools
    to gather facts; never invent data. Return EXACTLY one JSON object.
```

The spawned `bongsu-server intel-mcp` subprocess reads its DB DSN from the
**inherited environment** (jikji has no per-server env field), so launch jikji
with `BONGSU_DB_DSN` set:

```bash
BONGSU_DB_DSN="postgres://bongsu:***@localhost:5432/bongsu?sslmode=disable" \
  jikji serve --config /etc/jikji/bongsu.yaml
```

### 3.2 Point Bongsu at jikji

Configure the Bongsu server with `BONGSU_INTEL_*`:

| Env var | Default | Meaning |
|---------|---------|---------|
| `BONGSU_INTEL_JIKJI_URL` | *(empty = disabled)* | jikji base URL, e.g. `http://127.0.0.1:1385`. Empty disables the whole layer. |
| `BONGSU_INTEL_JIKJI_TOKEN` | *(empty)* | Bearer token sent to an authenticated backbone (see §3.4). Required when jikji enforces `runs:write`. |
| `BONGSU_INTEL_MAX_CONCURRENCY` | `4` | Concurrent `/v1/runs` cap (e.g. parallel verify voters). |
| `BONGSU_INTEL_TIMEOUT_SECONDS` | `120` | Per-run wall-clock deadline. Should be ≥ the scenario timeouts. |
| `BONGSU_INTEL_MAX_STEPS` | `8` | Agent step budget (jikji caps at 64). |
| `BONGSU_INTEL_REQUIRE_ADMIN` | `true` | `false` relaxes trigger authz to any authenticated web caller. |
| `BONGSU_INTEL_AUDIT_BUFFER` | `1024` | Tool-call audit channel size. |

### 3.3 The `intel-mcp` subcommand

`bongsu-server intel-mcp` serves the read-only tools over MCP stdio:

```
bongsu-server intel-mcp [--dsn <DSN>] [--run-id <id>]
```

- `--dsn` / `BONGSU_DB_DSN` — the (read-only-use) database.
- `--run-id` — per-run scope + audit (the stdio-per-run model). Omitted =
  **service scope** (admin), which is the mode used with the persistent HTTP
  `/v1/runs` backbone; authorization is enforced at the API trigger and the
  tool-call audit is reconstructed from the run's events.

### 3.4 Authenticating to the backbone

A production jikji backbone should not be an open endpoint. Enable jikji's
`imprimatur` auth with a key scoped for the intel driver, and give Bongsu the
matching token via `BONGSU_INTEL_JIKJI_TOKEN` (the runner then sends
`Authorization: Bearer <token>` on every request):

```yaml
# jikji config
imprimatur:
  enabled: true
  tenants: [{ id: local, name: Local }]
  keys:
    - name: bongsu-backbone
      tenant_id: local
      token_env: JIKJI_LOCAL_API_KEY   # export the same secret jikji-side
      scopes: [runs:read, runs:write, sessions:read, tools:read, tools:write, tools:execute, chat.completions:write, models:read, providers:read]
```

With auth off, jikji grants the caller a default scope; a build that no longer
includes `runs:write` in that default rejects runs with `403 scope "runs:write"
is required` — the signal to configure a token.

---

## 4. Usage

### 4.1 Scenarios — `POST /api/intel/runs`

```json
{ "scenario": "report", "params": { "cve": "CVE-2024-3094" }, "session_id": "" }
```

| Scenario | Params | Purpose |
|----------|--------|---------|
| `correlate` | `cve` | Reconcile a CVE across OSV/NVD/Trivy; decide a canonical severity. |
| `triage` | `cve`, `scan_id?`, `package?` | Judge reachability / false-positive. |
| `campaign` | `ecosystem`, `package` | Estimate supply-chain blast radius from an IOC. |
| `remediate` | `cve` | Fix plan (fixed version, upgrade path, dependents). |
| `verify` | `cve`, `scan_id?`, `package?`, `lens?` | Adversarially refute a finding. |
| `report` | `cve` | CVE-grade structured report with a stable `dedup_key`. |
| `nl_query` | `question` | Free-form security question over the caller's assets. |

A non-empty `session_id` continues an interactive audit session (the follow-up
run builds on the prior conversation). The response is a `RunOutcome`
(`run_id`, `status`, `response`, `tool_steps`, `total_tokens`, and — for a
persisted report — `report_id`/`report_dedup_key`/`report_persisted`).

### 4.2 Named pipelines — `POST /api/intel/pipelines`

Pipelines are **code-registered fixed chains** (the API takes a *name*, never an
arbitrary scenario list — anti-abuse). Each stage runs under one threaded
session (recon → … → verify → report).

```json
{ "pipeline": "audit", "params": { "cve": "CVE-2024-3094" } }
```

| Pipeline | Stages |
|----------|--------|
| `audit` | `triage` → `verify` → `report` |
| `assess` | `correlate` → `remediate` |
| `campaign_sweep` | `campaign` → `verify` → `report` |

### 4.3 Majority-vote verification — `POST /api/intel/verify`

```json
{ "cve": "CVE-2024-3094", "voters": 3 }
```

Runs N **independent** voters (each a `verify` run in its own session), each
under a distinct refutation lens (`accuracy`, `reachability`, `version_presence`,
`ecosystem_match`), and aggregates a majority over the *successful* voters. Ties
→ `refuted` (conservative). Too few successful voters → `inconclusive` (never a
false verdict). Returns per-voter breakdown + `verdict`/`confidence`.

### 4.4 Finding reports — `GET /api/intel/reports`

The `report` scenario persists its output keyed **UNIQUE by `dedup_key`**, so
re-reporting the same finding collapses onto one row (bumping
`seen_count`/`last_seen`). Reports accumulate into a queryable asset.

```
GET /api/intel/reports?severity=critical&finding=CVE-2024
GET /api/intel/report?dedup_key=cve-2024-3094:xz
```

### 4.5 API summary

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/intel/scenarios` | List scenarios + pipeline catalog (and `enabled`). |
| POST | `/api/intel/runs` | Run one scenario. |
| POST | `/api/intel/pipelines` | Run a named pipeline. |
| POST | `/api/intel/verify` | Majority-vote verification. |
| GET | `/api/intel/reports` | List persisted finding reports. |
| GET | `/api/intel/report?dedup_key=` | One finding report. |
| GET | `/api/intel/runs/{id}` | Read a persisted run. |

The web UI surfaces all of this under **Security Intelligence** (`IntelView`):
Scenario / Pipeline / Verify (vote) / Reports tabs.

---

## 5. Data model

| Table | Migration | Holds |
|-------|-----------|-------|
| `intel_runs` | 073 (+076 session, +077 validation) | One agentic run: scenario, RBAC snapshot, status, output, token usage, `session_id`, `output_valid`. |
| `intel_tool_calls` | 073 | 100% tool-call audit (name, args, result, duration) per run. |
| `intel_verifications` | 078 | Majority-vote aggregate; voter runs link back by FK. |
| `intel_finding_reports` | 080 | Deduplicated reports (`dedup_key` UNIQUE, severity/cvss, `seen_count`). |

---

## 6. Operational notes

- **Model choice matters for `report`.** A fast non-reasoning model tends to echo
  a tool's raw JSON as its answer (which output validation rejects, so nothing
  persists). Use a capable model (e.g. `glm-5.2`) for the report/pipeline path.
  The `toolPreamble` also instructs the agent to synthesize, not echo.
- **Concurrency + the stdio MCP subprocess.** Parallel runs (verify voters) drive
  concurrent tool calls into one stdio MCP subprocess. Bongsu's MCP server is
  strictly serial and correct; the backbone's stdio MCP *client* must be
  concurrency-safe (a shared-decoder race there manifests as a jikji-side
  `JSON decoder out of sync` panic).
- **Graceful degrade.** No `BONGSU_INTEL_JIKJI_URL` → the layer is disabled and
  the API returns 503; an unreachable backbone → 503 on `Health`. The scanner is
  never affected.
- **RBAC.** Admin-only by default; `BONGSU_INTEL_REQUIRE_ADMIN=false` relaxes the
  trigger to any authenticated web caller (the run still operates under a service
  scope, and every tool call is scope-checked + audited).

---

## 7. Testing

- Unit + integration tests live alongside the package
  (`-tags=integration`, `BONGSU_TEST_DB`, run with `-p 1`).
- A **dormant live-smoke harness** (`live_smoke_test.go`) exercises the layer
  against a *real* jikji backbone:

  ```bash
  BONGSU_INTEL_LIVE=1 \
  BONGSU_INTEL_JIKJI_URL=http://127.0.0.1:1385 \
  BONGSU_TEST_DB=postgres://.../bongsu_test?sslmode=disable \
    go test -tags=integration -p 1 -run TestIntelLiveSmoke -v ./internal/server/intel/
  ```

  It verifies the runner parses the live `/v1/runs` shape, real tool data flows
  end-to-end, report persistence works, and parallel verify voters aggregate
  without crashing the backbone.
