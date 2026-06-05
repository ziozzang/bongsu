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
	rescanDriverOnce   sync.Once
	rescanDriverMu     sync.Mutex
	rescanDriverStates = map[string]*rescanDriverState{}
)

type rescanDriverState struct {
	mu              sync.Mutex
	hosts           []string
	inserted        []bool
	hostQuery       string
	hostQueryArgs   []driver.Value
	insertArgs      [][]driver.Value
	beginCount      int
	commitCount     int
	rollbackCount   int
	insertCallCount int
}

type rescanDriver struct{}

func (d rescanDriver) Open(name string) (driver.Conn, error) {
	rescanDriverMu.Lock()
	state := rescanDriverStates[name]
	rescanDriverMu.Unlock()
	if state == nil {
		return nil, fmt.Errorf("unknown rescan driver state %q", name)
	}
	return &rescanConn{state: state}, nil
}

type rescanConn struct {
	state *rescanDriverState
}

func (c *rescanConn) Prepare(string) (driver.Stmt, error) {
	return nil, fmt.Errorf("prepared statements are not supported by rescan test driver")
}

func (c *rescanConn) Close() error { return nil }

func (c *rescanConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *rescanConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	c.state.mu.Lock()
	c.state.beginCount++
	c.state.mu.Unlock()
	return &rescanTx{state: c.state}, nil
}

func (c *rescanConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	values := make([]driver.Value, 0, len(args))
	for _, arg := range args {
		values = append(values, arg.Value)
	}
	c.state.mu.Lock()
	defer c.state.mu.Unlock()

	if strings.Contains(query, "SELECT id FROM hosts") {
		c.state.hostQuery = query
		c.state.hostQueryArgs = values
		rows := make([][]driver.Value, 0, len(c.state.hosts))
		for _, host := range c.state.hosts {
			rows = append(rows, []driver.Value{host})
		}
		return &rescanRows{columns: []string{"id"}, rows: rows}, nil
	}
	if strings.Contains(query, "INSERT INTO scan_requests") {
		if c.state.insertCallCount >= len(c.state.inserted) {
			return nil, fmt.Errorf("unexpected insert call %d", c.state.insertCallCount+1)
		}
		c.state.insertArgs = append(c.state.insertArgs, values)
		inserted := c.state.inserted[c.state.insertCallCount]
		c.state.insertCallCount++
		return &rescanRows{columns: []string{"inserted"}, rows: [][]driver.Value{{inserted}}}, nil
	}
	return nil, fmt.Errorf("unexpected query: %s", query)
}

type rescanTx struct {
	state *rescanDriverState
}

func (tx *rescanTx) Commit() error {
	tx.state.mu.Lock()
	tx.state.commitCount++
	tx.state.mu.Unlock()
	return nil
}

func (tx *rescanTx) Rollback() error {
	tx.state.mu.Lock()
	tx.state.rollbackCount++
	tx.state.mu.Unlock()
	return nil
}

type rescanRows struct {
	columns []string
	rows    [][]driver.Value
	index   int
}

func (r *rescanRows) Columns() []string { return r.columns }
func (r *rescanRows) Close() error      { return nil }

func (r *rescanRows) Next(dest []driver.Value) error {
	if r.index >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.index])
	r.index++
	return nil
}

func newRescanTestDB(t *testing.T, state *rescanDriverState) *DB {
	t.Helper()
	rescanDriverOnce.Do(func() {
		sql.Register("bongsu-rescan-test", rescanDriver{})
	})
	name := fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())
	rescanDriverMu.Lock()
	rescanDriverStates[name] = state
	rescanDriverMu.Unlock()
	t.Cleanup(func() {
		rescanDriverMu.Lock()
		delete(rescanDriverStates, name)
		rescanDriverMu.Unlock()
	})
	raw, err := sql.Open("bongsu-rescan-test", name)
	if err != nil {
		t.Fatalf("open fake db: %v", err)
	}
	t.Cleanup(func() {
		_ = raw.Close()
	})
	return &DB{DB: raw}
}

func TestQueueSecurityDBRescansExecutesAtomicQueueAndCountsDedupe(t *testing.T) {
	state := &rescanDriverState{
		hosts:    []string{"host-a", "host-b", "host-c"},
		inserted: []bool{true, false, true},
	}
	database := newRescanTestDB(t, state)
	lastSeenAfter := time.Date(2026, 6, 4, 1, 2, 3, 0, time.UTC)

	result, err := database.QueueSecurityDBRescans(context.Background(), "system", "security-db periodic sync", "rev-20260604", lastSeenAfter)
	if err != nil {
		t.Fatalf("QueueSecurityDBRescans failed: %v", err)
	}
	if result.Eligible != 3 || result.Queued != 2 || result.AlreadyPending != 1 {
		t.Fatalf("queue result = %+v, want eligible=3 queued=2 already_pending=1", result)
	}

	state.mu.Lock()
	defer state.mu.Unlock()
	if !strings.Contains(state.hostQuery, "WHERE last_seen >= $1") || !strings.Contains(state.hostQuery, "ORDER BY hostname") {
		t.Fatalf("host query should apply last_seen filter and stable ordering: %s", state.hostQuery)
	}
	if len(state.hostQueryArgs) != 1 || state.hostQueryArgs[0] != lastSeenAfter {
		t.Fatalf("host query args = %#v, want lastSeenAfter", state.hostQueryArgs)
	}
	if state.beginCount != 1 || state.commitCount != 1 || state.rollbackCount != 0 {
		t.Fatalf("transaction counts begin=%d commit=%d rollback=%d", state.beginCount, state.commitCount, state.rollbackCount)
	}
	if len(state.insertArgs) != 3 {
		t.Fatalf("insert calls = %d, want 3", len(state.insertArgs))
	}
	for i, args := range state.insertArgs {
		if len(args) != 5 {
			t.Fatalf("insert args[%d] = %#v", i, args)
		}
		if args[1] != state.hosts[i] || args[2] != "system" || args[3] != "security-db periodic sync" || args[4] != "rev-20260604" {
			t.Fatalf("insert args[%d] = %#v", i, args)
		}
	}
	sql := queueSecurityDBRescanInsertSQL()
	for _, want := range []string{
		"created_at=now()",
		"claimed_at=NULL",
		"claimed_by_host_id=''",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("deduped pending security DB rescan must refresh stale queue metadata, missing %q: %s", want, sql)
		}
	}
}
