package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	staleCleanupDriverOnce   sync.Once
	staleCleanupDriverMu     sync.Mutex
	staleCleanupDriverStates = map[string]*staleCleanupDriverState{}
)

type staleCleanupDriverState struct {
	mu           sync.Mutex
	rows         [][]driver.Value
	query        string
	queryArgs    []driver.Value
	deleteArgs   []driver.Value
	deleteCount  int64
	queryCount   int
	deleteCalled bool
}

type staleCleanupDriver struct{}

func (d staleCleanupDriver) Open(name string) (driver.Conn, error) {
	staleCleanupDriverMu.Lock()
	state := staleCleanupDriverStates[name]
	staleCleanupDriverMu.Unlock()
	if state == nil {
		return nil, fmt.Errorf("unknown stale cleanup driver state %q", name)
	}
	return &staleCleanupConn{state: state}, nil
}

type staleCleanupConn struct {
	state *staleCleanupDriverState
}

func (c *staleCleanupConn) Prepare(string) (driver.Stmt, error) {
	return nil, fmt.Errorf("prepared statements are not supported by stale cleanup test driver")
}

func (c *staleCleanupConn) Close() error { return nil }

func (c *staleCleanupConn) Begin() (driver.Tx, error) {
	return nil, fmt.Errorf("transactions are not supported by stale cleanup test driver")
}

func (c *staleCleanupConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	values := namedValues(args)
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	if !strings.Contains(query, "WITH candidate_vulns AS") {
		return nil, fmt.Errorf("unexpected query: %s", query)
	}
	c.state.query = query
	c.state.queryArgs = values
	c.state.queryCount++
	return &staleCleanupRows{
		columns: []string{"id", "package_name", "pkg_type", "package_ecosystem", "installed_version", "cve_category", "cve_ecosystem", "affected_products", "is_withdrawn"},
		rows:    append([][]driver.Value(nil), c.state.rows...),
	}, nil
}

func (c *staleCleanupConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	values := namedValues(args)
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	if !strings.Contains(query, "DELETE FROM vulnerabilities WHERE id = ANY") {
		return nil, fmt.Errorf("unexpected exec: %s", query)
	}
	c.state.deleteCalled = true
	c.state.deleteArgs = values
	c.state.deleteCount = int64(staleCleanupArrayLen(values))
	return staleCleanupResult(c.state.deleteCount), nil
}

type staleCleanupRows struct {
	columns []string
	rows    [][]driver.Value
	index   int
}

func (r *staleCleanupRows) Columns() []string { return r.columns }
func (r *staleCleanupRows) Close() error      { return nil }

func (r *staleCleanupRows) Next(dest []driver.Value) error {
	if r.index >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.index])
	r.index++
	return nil
}

type staleCleanupResult int64

func (r staleCleanupResult) LastInsertId() (int64, error) { return 0, nil }
func (r staleCleanupResult) RowsAffected() (int64, error) { return int64(r), nil }

func staleCleanupArrayLen(values []driver.Value) int {
	if len(values) != 1 {
		return 0
	}
	text := fmt.Sprint(values[0])
	if text == "" || text == "{}" {
		return 0
	}
	return strings.Count(text, "vuln-")
}

func staleCleanupRow(id, pkgName, pkgType, pkgEco, installed, cveCategory, cveEco, affected string) []driver.Value {
	return []driver.Value{id, pkgName, pkgType, pkgEco, installed, cveCategory, cveEco, affected, false}
}

// staleCleanupRowWithdrawn is a row whose advisory is withdrawn (retracted).
func staleCleanupRowWithdrawn(id, pkgName, pkgType, pkgEco, installed, cveCategory, cveEco, affected string) []driver.Value {
	return []driver.Value{id, pkgName, pkgType, pkgEco, installed, cveCategory, cveEco, affected, true}
}

func newStaleCleanupTestDB(t *testing.T, state *staleCleanupDriverState) *DB {
	t.Helper()
	staleCleanupDriverOnce.Do(func() {
		sql.Register("bongsu-stale-cleanup-test", staleCleanupDriver{})
	})
	name := fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())
	staleCleanupDriverMu.Lock()
	staleCleanupDriverStates[name] = state
	staleCleanupDriverMu.Unlock()
	t.Cleanup(func() {
		staleCleanupDriverMu.Lock()
		delete(staleCleanupDriverStates, name)
		staleCleanupDriverMu.Unlock()
	})
	raw, err := sql.Open("bongsu-stale-cleanup-test", name)
	if err != nil {
		t.Fatalf("open fake db: %v", err)
	}
	t.Cleanup(func() {
		_ = raw.Close()
	})
	return &DB{DB: raw}
}

func TestRemoveStaleRematchedVulnerabilitiesDeletesOnlyStaleCveDbFindings(t *testing.T) {
	t.Setenv("BONGSU_STALE_REMATCH_CLEANUP_BATCH_SIZE", "10")
	state := &staleCleanupDriverState{
		rows: [][]driver.Value{
			staleCleanupRow("vuln-compatible", "left-pad", "npm", "npm", "1.0.0", "code-library", "npm", `[{"name":"left-pad","ecosystem":"npm","fixed":["1.1.0"]}]`),
			staleCleanupRow("vuln-missing-fixed", "left-pad", "npm", "npm", "1.0.0", "code-library", "npm", `[{"name":"left-pad","ecosystem":"npm"}]`),
			staleCleanupRow("vuln-wrong-ecosystem", "left-pad", "npm", "npm", "1.0.0", "os-package", "Debian", `[{"name":"left-pad","ecosystem":"Debian","fixed":["1.1.0"]}]`),
			// Retracted advisory: compatible by version, but withdrawn -> stale.
			staleCleanupRowWithdrawn("vuln-withdrawn", "left-pad", "npm", "npm", "1.0.0", "code-library", "npm", `[{"name":"left-pad","ecosystem":"npm","fixed":["1.1.0"]}]`),
		},
	}
	database := newStaleCleanupTestDB(t, state)

	result, err := database.RemoveStaleRematchedVulnerabilities(context.Background())
	if err != nil {
		t.Fatalf("RemoveStaleRematchedVulnerabilities failed: %v", err)
	}
	if result.Scanned != 4 || result.Removed != 3 || result.Batches != 1 || result.BatchSize != 10 {
		t.Fatalf("cleanup result = %+v, want scanned=4 removed=3 batches=1 batch_size=10", result)
	}

	state.mu.Lock()
	defer state.mu.Unlock()
	if state.queryCount != 1 {
		t.Fatalf("query count = %d", state.queryCount)
	}
	if !strings.Contains(state.query, "v.finding_source = 'cve-db'") {
		t.Fatalf("cleanup query must restrict candidates to cve-db findings: %s", state.query)
	}
	if len(state.queryArgs) != 2 || state.queryArgs[0] != "" || state.queryArgs[1] != int64(10) {
		t.Fatalf("query args = %#v, want afterID empty and limit 10", state.queryArgs)
	}
	if !state.deleteCalled {
		t.Fatal("expected stale findings to be deleted")
	}
	deleted := fmt.Sprint(state.deleteArgs)
	for _, want := range []string{"vuln-missing-fixed", "vuln-wrong-ecosystem", "vuln-withdrawn"} {
		if !strings.Contains(deleted, want) {
			t.Fatalf("delete args missing %q: %#v", want, state.deleteArgs)
		}
	}
	if strings.Contains(deleted, "vuln-compatible") {
		t.Fatalf("compatible cve-db finding must be kept, delete args: %#v", state.deleteArgs)
	}
}
