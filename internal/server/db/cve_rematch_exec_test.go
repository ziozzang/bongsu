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
	rematchDriverOnce   sync.Once
	rematchDriverMu     sync.Mutex
	rematchDriverStates = map[string]*rematchDriverState{}
)

type rematchDriverState struct {
	mu              sync.Mutex
	candidates      [][]driver.Value
	insertedArgs    [][]driver.Value
	matchQueryArgs  []driver.Value
	existsChecks    [][]driver.Value
	beginCount      int
	commitCount     int
	rollbackCount   int
	matchQueryCount int
}

type rematchDriver struct{}

func (d rematchDriver) Open(name string) (driver.Conn, error) {
	rematchDriverMu.Lock()
	state := rematchDriverStates[name]
	rematchDriverMu.Unlock()
	if state == nil {
		return nil, fmt.Errorf("unknown rematch driver state %q", name)
	}
	return &rematchConn{state: state}, nil
}

type rematchConn struct {
	state *rematchDriverState
}

func (c *rematchConn) Prepare(query string) (driver.Stmt, error) {
	return &rematchStmt{state: c.state, query: query}, nil
}

func (c *rematchConn) Close() error { return nil }

func (c *rematchConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *rematchConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	c.state.mu.Lock()
	c.state.beginCount++
	c.state.mu.Unlock()
	return &rematchTx{state: c.state}, nil
}

func (c *rematchConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	values := namedValues(args)
	c.state.mu.Lock()
	defer c.state.mu.Unlock()

	if strings.Contains(query, "JOIN cve_affected_packages cap") {
		c.state.matchQueryCount++
		c.state.matchQueryArgs = values
		return &rematchRows{columns: rematchCandidateColumns(), rows: append([][]driver.Value(nil), c.state.candidates...)}, nil
	}
	if strings.Contains(query, "SELECT EXISTS(SELECT 1 FROM vulnerabilities") {
		c.state.existsChecks = append(c.state.existsChecks, values)
		return &rematchRows{columns: []string{"exists"}, rows: [][]driver.Value{{false}}}, nil
	}
	return nil, fmt.Errorf("unexpected query: %s", query)
}

type rematchStmt struct {
	state *rematchDriverState
	query string
}

func (s *rematchStmt) Close() error  { return nil }
func (s *rematchStmt) NumInput() int { return -1 }

func (s *rematchStmt) Exec(args []driver.Value) (driver.Result, error) {
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	if !strings.Contains(s.query, "INSERT INTO vulnerabilities") {
		return nil, fmt.Errorf("unexpected exec: %s", s.query)
	}
	s.state.insertedArgs = append(s.state.insertedArgs, append([]driver.Value(nil), args...))
	return rematchResult(1), nil
}

func (s *rematchStmt) Query([]driver.Value) (driver.Rows, error) {
	return nil, fmt.Errorf("unexpected prepared query: %s", s.query)
}

type rematchTx struct {
	state *rematchDriverState
}

func (tx *rematchTx) Commit() error {
	tx.state.mu.Lock()
	tx.state.commitCount++
	tx.state.mu.Unlock()
	return nil
}

func (tx *rematchTx) Rollback() error {
	tx.state.mu.Lock()
	tx.state.rollbackCount++
	tx.state.mu.Unlock()
	return nil
}

type rematchRows struct {
	columns []string
	rows    [][]driver.Value
	index   int
}

func (r *rematchRows) Columns() []string { return r.columns }
func (r *rematchRows) Close() error      { return nil }

func (r *rematchRows) Next(dest []driver.Value) error {
	if r.index >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.index])
	r.index++
	return nil
}

type rematchResult int64

func (r rematchResult) LastInsertId() (int64, error) { return 0, nil }
func (r rematchResult) RowsAffected() (int64, error) { return int64(r), nil }

func namedValues(args []driver.NamedValue) []driver.Value {
	values := make([]driver.Value, 0, len(args))
	for _, arg := range args {
		values = append(values, arg.Value)
	}
	return values
}

func rematchCandidateColumns() []string {
	return []string{
		"id", "name", "src_name", "version", "host_id", "scan_id", "container", "file_path",
		"pkg_type", "ecosystem", "vulnerability_id", "severity", "cvss_score", "cvss_vector",
		"title", "description", "refs", "category", "cve_ecosystem", "affected_products",
	}
}

func rematchCandidate(vulnID, pkgEco, cveCategory, cveEco, version, affected string) []driver.Value {
	return []driver.Value{
		"pkg-1", "left-pad", "", version, "host-1", "scan-1", "", "/app/package-lock.json",
		"npm", pkgEco, vulnID, "LOW", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		vulnID + " title", vulnID + " description", `[{"url":"https://example.test/` + vulnID + `"}]`,
		cveCategory, cveEco, affected,
	}
}

func newRematchTestDB(t *testing.T, state *rematchDriverState) *DB {
	t.Helper()
	rematchDriverOnce.Do(func() {
		sql.Register("bongsu-rematch-test", rematchDriver{})
	})
	name := fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())
	rematchDriverMu.Lock()
	rematchDriverStates[name] = state
	rematchDriverMu.Unlock()
	t.Cleanup(func() {
		rematchDriverMu.Lock()
		delete(rematchDriverStates, name)
		rematchDriverMu.Unlock()
	})
	raw, err := sql.Open("bongsu-rematch-test", name)
	if err != nil {
		t.Fatalf("open fake db: %v", err)
	}
	t.Cleanup(func() {
		_ = raw.Close()
	})
	return &DB{DB: raw}
}

func TestRematchCVEsInsertsOnlyCompatibleMatchableCandidates(t *testing.T) {
	state := &rematchDriverState{
		candidates: [][]driver.Value{
			rematchCandidate("CVE-2026-0001", "npm", "code-library", "npm", "1.0.0", `[{"name":"left-pad","ecosystem":"npm","fixed":["1.1.0"]}]`),
			rematchCandidate("CVE-2026-0002", "npm", "code-library", "npm", "1.0.0", `[{"name":"left-pad","ecosystem":"npm"}]`),
			rematchCandidate("CVE-2026-0003", "npm", "code-library", "npm", "1.2.0", `[{"name":"left-pad","ecosystem":"npm","fixed":["1.1.0"]}]`),
			rematchCandidate("CVE-2026-0004", "npm", "os-package", "Debian", "1.0.0", `[{"name":"left-pad","ecosystem":"Debian","fixed":["1.1.0"]}]`),
		},
	}
	database := newRematchTestDB(t, state)

	result, err := database.RematchCVEs(context.Background(), RematchOptions{CandidateLimit: 10})
	if err != nil {
		t.Fatalf("RematchCVEs failed: %v", err)
	}
	if result.ScannedCandidates != 4 || result.Matched != 1 || result.NewVulns != 1 || result.Skipped != 3 || result.Limited {
		t.Fatalf("rematch result = %+v, want scanned=4 matched=1 new=1 skipped=3 limited=false", result)
	}

	state.mu.Lock()
	defer state.mu.Unlock()
	if state.matchQueryCount != 1 {
		t.Fatalf("match query count = %d", state.matchQueryCount)
	}
	if len(state.matchQueryArgs) != 1 || state.matchQueryArgs[0] != int64(1000) {
		t.Fatalf("match query args = %#v, want row limit 1000", state.matchQueryArgs)
	}
	if len(state.existsChecks) != 1 {
		t.Fatalf("exists checks = %d, want only the compatible candidate checked", len(state.existsChecks))
	}
	if len(state.insertedArgs) != 1 {
		t.Fatalf("inserted rows = %d, want 1", len(state.insertedArgs))
	}
	insert := state.insertedArgs[0]
	if insert[4] != "CVE-2026-0001" || insert[5] != "CRITICAL" || insert[11] != "1.1.0" || insert[17] != "cve-db" {
		t.Fatalf("insert args = %#v", insert)
	}
	if state.beginCount != 1 || state.commitCount != 1 || state.rollbackCount != 0 {
		t.Fatalf("transaction counts begin=%d commit=%d rollback=%d", state.beginCount, state.commitCount, state.rollbackCount)
	}
}
