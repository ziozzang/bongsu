#!/usr/bin/env bash
# Run the DB-backed Go integration suite (build tag: integration).
#
# Usage:
#   BONGSU_TEST_DB=postgres://user:pw@host:5432/bongsu_test?sslmode=disable \
#     ./scripts/verify-integration-db.sh
#
# Without BONGSU_TEST_DB the script tries to derive one from the local dev
# stack (the bongsu-postgres container), creating the bongsu_test database if
# missing. When no database is reachable it prints SKIPPED and exits 0 so CI
# without Postgres stays green.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -z "${BONGSU_TEST_DB:-}" ]; then
  if docker exec bongsu-postgres true 2>/dev/null; then
    PGPW=$(docker exec bongsu-postgres sh -c 'echo "$POSTGRES_PASSWORD"')
    docker exec bongsu-postgres psql -U bongsu -d postgres -tA \
      -c "SELECT 1 FROM pg_database WHERE datname='bongsu_test'" | grep -q 1 ||
      docker exec bongsu-postgres psql -U bongsu -d postgres -c "CREATE DATABASE bongsu_test" >/dev/null
    BONGSU_TEST_DB="postgres://bongsu:${PGPW}@localhost:5432/bongsu_test?sslmode=disable"
    export BONGSU_TEST_DB
  else
    echo "SKIPPED: BONGSU_TEST_DB not set and no bongsu-postgres container reachable"
    exit 0
  fi
fi

case "$BONGSU_TEST_DB" in
  *_test*) ;;
  *)
    echo "ERROR: BONGSU_TEST_DB database name must end in _test" >&2
    exit 1
    ;;
esac

echo "Running DB integration suite against ${BONGSU_TEST_DB%%:*}://...(_test db)"
go test -tags=integration ./internal/server/db/... -count=1 "$@"
echo "DB integration verification passed"
