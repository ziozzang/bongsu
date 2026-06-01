# Bongsu Agent Handoff

Updated: 2026-06-01 19:14:06 KST

This document is the handoff point for the next agent session. Continue from the repository state after this file is committed and pushed.

## Non-Negotiable Constraints

- Product name: `bongsu`, meaning "봉수대".
- Repository: `/home/ziozzang/bongsu`.
- Remote target: push local `master` to `origin/main`.
- Web UI must listen on `http://10.2.2.10:5678/`.
- API must listen on port `5677`.
- Do not touch or reconfigure Caddy.
- Docker Compose deployment must remain available for the management server.
- Air-gapped deployment is required: update outside, export bundle, import inside.
- CVE matching must use only matchable affected package evidence: package name, ecosystem/target such as `Packagist`, and fixed-version/range data. Name-only or priority-only records must remain searchable but must not create rematch/rescan findings.
- `TEMP-*` and `CVD-*` placeholder vulnerabilities are invalid for the CVE DB and should not appear in `cve_database`, `cve_affected_packages`, reference keys, or rematch candidates.
- EPSS belongs on matching CVE/advisory rows as columns, not only as separate EPSS source records.

## Current Git State

Expected committed head before this handoff work:

```text
48015b1 (master, origin/main) Serve stale CVE stats during refresh
```

Important recent commits:

```text
48015b1 Serve stale CVE stats during refresh
b7e7361 Reduce CVE stats cold path latency
993cb03 Optimize vulnerability mismatch filtering
f53d9a2 Use matchable CVE index for vulnerability evidence
8b86461 Bound vulnerability list requests
9310f6b Bound CVE affected package lookups
c86ee65 Bound CVE reference group lookups
24b4251 Bound CVE search request runtime
```

This handoff commit should include:

- `docs/agent-handoff.md`
- Dashboard/API client change showing `/api/cve-db/stats` cache status, generated time, and duration in the CVE DB dashboard card.

## Live Runtime

The current live target is:

- Web: `http://10.2.2.10:5678/`
- API: `http://10.2.2.10:5677/`

Last known listener state:

```text
0.0.0.0:5678  web static server
*:5677        bongsu API server
```

API was last started with:

```bash
BONGSU_DB_DSN="postgres://bongsu:bongsu@localhost:5432/bongsu?sslmode=disable" \
BONGSU_API_KEY=test-admin BONGSU_AGENT_API_KEY=test-agent BONGSU_INSTALL_TOKEN=test-install \
BONGSU_ALLOW_WEAK_SECRETS=true BONGSU_WEB_AUTH=false \
BONGSU_SECURITY_DB_SYNC_ON_START=false BONGSU_SECURITY_DB_SYNC_CMD="" \
BONGSU_TRIVY_DB_INTERVAL_HOURS=0 BONGSU_AGENT_BIN=/home/ziozzang/bongsu/bin/bongsu-agent \
BONGSU_CVE_AFFECTED_INDEX_REBUILD_TIMEOUT_SECONDS=180 \
BONGSU_STARTUP_RECALC_TIMEOUT_SECONDS=120 \
BONGSU_STALE_REMATCH_CLEANUP_BATCH_SIZE=10000 \
BONGSU_CVE_SEARCH_TIMEOUT_SECONDS=15 \
BONGSU_CVE_REFERENCE_GROUP_TIMEOUT_SECONDS=10 \
BONGSU_CVE_AFFECTED_PACKAGES_TIMEOUT_SECONDS=10 \
BONGSU_VULNERABILITY_LIST_TIMEOUT_SECONDS=15 \
BONGSU_PORT=5677 go run ./cmd/server
```

Do not change this to `8080`. Keep API and web split as `5677` and `5678`.

## Current CVE DB Status

Last verified operational metrics:

```text
/api/cve-db/stats miss: ~2.32s, X-Bongsu-Cache: miss
/api/cve-db/stats hit:  ~0.0006s, X-Bongsu-Cache: hit
stale stats path:       ~0.0005s, X-Bongsu-Cache: stale
/api/vulnerabilities?limit=50: ~0.69-0.71s
/api/cve-db/search?q=openssl&limit=20: ~0.25s
```

Last quality snapshot:

```json
{
  "temporary_placeholders": 0,
  "total_records": 760499,
  "total_matchable": 111300,
  "affected_index_coverage": 100,
  "affected_index_orphans": 0,
  "reference_index_coverage": 100,
  "reference_index_orphans": 0,
  "epss_non_epss_coverage": 96.5
}
```

Last direct DB check found zero `TEMP-*` and zero `CVD-*` rows in both `cve_database` and `cve_affected_packages`.

## What Has Been Completed

- Management server and dashboard are deployed locally with web on `5678` and API on `5677`.
- Security DB ingest/import/export exists for connected and air-gapped flows.
- CVE DB quality and status are visible on the dashboard.
- CVE search is backed by indexes and bounded request timeouts.
- Affected packages lookup and reference grouping are bounded.
- Matchable CVE evidence is materialized into `cve_affected_packages`.
- Vulnerability evidence/listing now uses matchable affected package rows instead of raw JSON name matches.
- CVE DB rematch filters require compatible package name, ecosystem, fixed version/range, and affected range semantics.
- EPSS data is merged into matching non-EPSS CVE/advisory rows.
- TEMP placeholder identifiers are blocked/removed from CVE DB matching paths.
- CVSS v2/v3.x/v4 recalculation support exists and startup recalculation is timeout-bounded.
- Background stale-while-revalidate cache for `/api/cve-db/stats` is implemented.
- The dashboard API client now reads `X-Bongsu-Cache` for CVE DB stats and the dashboard card exposes cache state, generated timestamp, and stats duration.

## Verification Commands

Run these after pulling this handoff state:

```bash
git status --short --branch
go test ./...
./scripts/verify-static-binaries.sh
npm --prefix web run build
BONGSU_DB_PASSWORD=bongsu docker compose -f deploy/docker-compose.yml config >/tmp/bongsu-compose.out
BONGSU_DB_PASSWORD=bongsu docker compose -f deploy/docker-compose.airgap.yml config >/tmp/bongsu-airgap-compose.out
git diff --check
```

Useful live checks:

```bash
curl -sS -H 'X-API-Key: test-admin' http://127.0.0.1:5677/api/cve-db/stats -o /tmp/cve-stats.json -D /tmp/cve-stats.headers
cat /tmp/cve-stats.headers
curl -sS -H 'X-API-Key: test-admin' 'http://127.0.0.1:5677/api/cve-db/search?q=openssl&limit=20' >/tmp/cve-search.json
curl -sS http://127.0.0.1:5678/ >/tmp/bongsu-web.html
```

TEMP/CVD direct DB check:

```bash
psql 'postgres://bongsu:bongsu@localhost:5432/bongsu?sslmode=disable' -c "
select 'cve_database' as table_name, count(*) from cve_database
where vulnerability_id like 'TEMP-%' or vulnerability_id like 'CVD-%'
union all
select 'cve_affected_packages', count(*) from cve_affected_packages
where vulnerability_id like 'TEMP-%' or vulnerability_id like 'CVD-%'
union all
select 'cve_reference_keys', count(*) from cve_reference_keys
where cve_id like 'TEMP-%' or cve_id like 'CVD-%'
   or reference_key like '%TEMP-%' or reference_key like '%CVD-%';
"
```

## Next Work

1. Confirm this handoff commit is pushed to `origin/main`.
2. Re-run full verification after the next session starts; do not assume long-running local processes survived.
3. Open the web UI at `http://10.2.2.10:5678/` and visually verify dashboard, CVE Search, vulnerability list, RBAC/admin pages, and force scan controls.
4. Add a lightweight browser/E2E test for the CVE Search menu and dashboard CVE DB status card.
5. Continue requirement audit against the original product list. The system is not yet declared complete.
6. Improve one-line installer end-to-end tests, especially air-gapped binary download and service installation paths.
7. Keep optimizing CVE DB quality/statistics paths if the imported DB grows beyond the current snapshot.

## Matching Rules Reminder

Use `docs/vulnerability-matching-rules.md` as the detailed source of truth. The short rule is:

- Affected package row such as `phenx/php-svg-lib / Packagist / Fixed: 0.5.2` is valid and matchable.
- Rows without package name, ecosystem target, or fixed-version/range evidence are reference/enrichment data only.
- Priority sources such as EPSS and CISA KEV can enrich risk, but must not create package-name findings by themselves.
- Multiple source records for the same CVE can be grouped by CVE/reference key, but matching must still be package/ecosystem/range safe.
