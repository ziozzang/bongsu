//go:build integration

package db

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Integration harness: DB-backed tests against a real PostgreSQL.
//
// Contract:
//   - Gated by BONGSU_TEST_DB (a postgres DSN). Unset → every test skips.
//   - The DSN's database name MUST end in `_test` — the harness refuses to run
//     against anything else so a mistyped DSN can never truncate dev data.
//   - openIntegrationDB applies all migrations (handling RunMigrations'
//     relative `migrations/` read by chdir-ing to the repo root once) and
//     TRUNCATEs every data table before handing the DB to the test, so each
//     test starts from a clean schema-complete database.
//
// Run via `make test-integration` or scripts/verify-integration-db.sh.

// integrationChdirMu serializes the temporary chdir used while running
// migrations so concurrent openIntegrationDB calls cannot observe a half-moved
// working directory.
var integrationChdirMu sync.Mutex

func openIntegrationDB(t *testing.T) *DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("BONGSU_TEST_DB"))
	if dsn == "" {
		t.Skip("BONGSU_TEST_DB not set; skipping DB integration test")
	}
	requireTestDatabaseName(t, dsn)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	database, err := New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect integration db: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	// RunMigrations reads the relative `migrations/` directory, so it must run
	// from the repo root. Chdir only for the duration of the migration run and
	// restore the original working directory afterwards: leaving the process in
	// the repo root would break the package's source-scanning unit tests, which
	// read files relative to the package directory.
	runMigrationsFromRepoRoot(t, ctx, database)

	truncateAllDataTables(t, ctx, database)
	return database
}

func runMigrationsFromRepoRoot(t *testing.T, ctx context.Context, database *DB) {
	t.Helper()
	integrationChdirMu.Lock()
	defer integrationChdirMu.Unlock()

	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root, err := findRepoRoot()
	if err != nil {
		t.Fatalf("locate repo root for migrations: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir to repo root: %v", err)
	}
	defer func() {
		if err := os.Chdir(orig); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	}()

	if err := database.RunMigrations(ctx); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
}

// requireTestDatabaseName guards against pointing the suite at a real
// database: the database segment of the DSN must end in `_test`.
func requireTestDatabaseName(t *testing.T, dsn string) {
	t.Helper()
	name := ""
	if u, err := url.Parse(dsn); err == nil && u.Path != "" {
		name = strings.TrimPrefix(u.Path, "/")
	}
	if name == "" {
		// key=value DSN form
		for _, kv := range strings.Fields(dsn) {
			if strings.HasPrefix(kv, "dbname=") {
				name = strings.TrimPrefix(kv, "dbname=")
			}
		}
	}
	if !strings.HasSuffix(name, "_test") {
		t.Fatalf("BONGSU_TEST_DB database %q must end in _test (refusing to run against a non-test database)", name)
	}
}

func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found above %s", dir)
		}
		dir = parent
	}
}

func truncateAllDataTables(t *testing.T, ctx context.Context, database *DB) {
	t.Helper()
	rows, err := database.QueryContext(ctx, `
SELECT tablename FROM pg_tables
WHERE schemaname='public' AND tablename <> 'schema_migrations'`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan table name: %v", err)
		}
		tables = append(tables, `"`+name+`"`)
	}
	if len(tables) == 0 {
		return
	}
	if _, err := database.ExecContext(ctx, "TRUNCATE "+strings.Join(tables, ", ")+" CASCADE"); err != nil {
		t.Fatalf("truncate data tables: %v", err)
	}
}
