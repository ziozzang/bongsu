# Testing

Three layers, each with a distinct job. Don't duplicate a check across layers.

| Layer | Command | Needs | Covers |
|---|---|---|---|
| Unit | `make test` (`go test ./...`) | nothing | pure logic: matching gates, vercmp, parsers, SQL builders (fake driver) |
| DB integration | `make test-integration` | Postgres | real matching outcomes against seeded rows, pagination, scoping |
| API e2e | `scripts/verify-e2e-api.sh` | live server | black-box HTTP behavior: filters, lifecycles, auth |

## Unit tests

Standard `go test ./...`. No tags, no DB, fast. SQL-builder correctness is
tested with the registered fake-`database/sql`-driver pattern (see
`internal/server/db/cve_rematch_exec_test.go`): the driver captures generated
SQL and bound args so tests assert exact `$n` placement without a database.

## DB integration tests

Build-tagged `//go:build integration` so `go test ./...` never compiles them.

- Gate: `BONGSU_TEST_DB` — a Postgres DSN whose database name **must end in
  `_test`** (the harness refuses anything else, so a mistyped DSN can never
  truncate dev data). Unset → tests skip.
- Harness: `openIntegrationDB(t)` in
  `internal/server/db/integration_harness_test.go` connects, locates the repo
  root (RunMigrations reads the relative `migrations/` dir — the harness
  chdirs to the repo root once), applies all migrations, and TRUNCATEs every
  data table so each test starts clean.
- Run: `make test-integration` — derives a DSN from the `bongsu-postgres` dev
  container automatically (creating the `bongsu_test` database if missing), or
  uses `BONGSU_TEST_DB` if set. Prints `SKIPPED` and exits 0 when no database
  is reachable, so CI without Postgres stays green.

Write integration tests only for what unit tests can't express (real matching
outcomes, keyset pagination, RBAC scope resolution) and the e2e suite doesn't
already cover black-box.

## API e2e

`tests/e2e/api_e2e.py`, run by `scripts/verify-e2e-api.sh <base-url> <admin-key>`
against a live server. Covers HTTP behavior end to end. See also the
`scripts/verify-live-*.sh` checks for destructive/stateful paths.
