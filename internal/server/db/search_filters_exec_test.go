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

// search_filters_exec_test.go uses a fake SQL driver to capture the query text
// and bound arguments produced by the filter builders (SearchPackages,
// ListVulnerabilities) without a live database. The assertions pin down the
// exact SQL fragments and $N argument ordering each filter contributes — the
// places where a refactor can silently drop or misbind a filter and quietly
// change which findings a user sees.

var (
	captureDriverOnce   sync.Once
	captureDriverMu     sync.Mutex
	captureDriverStates = map[string]*captureDriverState{}
)

type capturedQuery struct {
	query string
	args  []driver.Value
}

type captureDriverState struct {
	mu      sync.Mutex
	queries []capturedQuery
	// columns to return for the data (non-count) query. The count query always
	// returns a single integer column.
	dataColumns []string
}

func (s *captureDriverState) record(query string, args []driver.Value) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries = append(s.queries, capturedQuery{query: query, args: append([]driver.Value(nil), args...)})
}

// queriesContaining returns the captured queries whose text contains needle.
func (s *captureDriverState) queriesContaining(needle string) []capturedQuery {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []capturedQuery
	for _, q := range s.queries {
		if strings.Contains(q.query, needle) {
			out = append(out, q)
		}
	}
	return out
}

type captureDriver struct{}

func (captureDriver) Open(name string) (driver.Conn, error) {
	captureDriverMu.Lock()
	state := captureDriverStates[name]
	captureDriverMu.Unlock()
	if state == nil {
		return nil, fmt.Errorf("unknown capture driver state %q", name)
	}
	return &captureConn{state: state}, nil
}

type captureConn struct{ state *captureDriverState }

func (c *captureConn) Prepare(query string) (driver.Stmt, error) {
	return &captureStmt{state: c.state, query: query}, nil
}
func (c *captureConn) Close() error              { return nil }
func (c *captureConn) Begin() (driver.Tx, error) { return captureTx{}, nil }

func (c *captureConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	values := namedValues(args)
	c.state.record(query, values)
	if strings.HasPrefix(strings.TrimSpace(query), "SELECT count(*)") {
		return &captureRows{columns: []string{"count"}, rows: [][]driver.Value{{int64(0)}}}, nil
	}
	cols := c.state.dataColumns
	// Return zero rows: the builders only need the columns to scan an empty set.
	return &captureRows{columns: cols}, nil
}

type captureStmt struct {
	state *captureDriverState
	query string
}

func (s *captureStmt) Close() error  { return nil }
func (s *captureStmt) NumInput() int { return -1 }
func (s *captureStmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, fmt.Errorf("unexpected exec: %s", s.query)
}
func (s *captureStmt) Query([]driver.Value) (driver.Rows, error) {
	return nil, fmt.Errorf("unexpected prepared query: %s", s.query)
}

type captureTx struct{}

func (captureTx) Commit() error   { return nil }
func (captureTx) Rollback() error { return nil }

type captureRows struct {
	columns []string
	rows    [][]driver.Value
	index   int
}

func (r *captureRows) Columns() []string { return r.columns }
func (r *captureRows) Close() error      { return nil }
func (r *captureRows) Next(dest []driver.Value) error {
	if r.index >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.index])
	r.index++
	return nil
}

func newCaptureTestDB(t *testing.T, dataColumns []string) (*DB, *captureDriverState) {
	t.Helper()
	captureDriverOnce.Do(func() {
		sql.Register("bongsu-capture-test", captureDriver{})
	})
	state := &captureDriverState{dataColumns: dataColumns}
	name := fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())
	captureDriverMu.Lock()
	captureDriverStates[name] = state
	captureDriverMu.Unlock()
	t.Cleanup(func() {
		captureDriverMu.Lock()
		delete(captureDriverStates, name)
		captureDriverMu.Unlock()
	})
	raw, err := sql.Open("bongsu-capture-test", name)
	if err != nil {
		t.Fatalf("open capture db: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	return &DB{DB: raw}, state
}

// dataQuery returns the single non-count query captured (the filter builders
// run one count query then one data query). It asserts exactly one data query
// was issued.
func dataQuery(t *testing.T, state *captureDriverState) capturedQuery {
	t.Helper()
	state.mu.Lock()
	defer state.mu.Unlock()
	var data []capturedQuery
	for _, q := range state.queries {
		if !strings.HasPrefix(strings.TrimSpace(q.query), "SELECT count(*)") {
			data = append(data, q)
		}
	}
	if len(data) != 1 {
		t.Fatalf("expected exactly 1 data query, got %d", len(data))
	}
	return data[0]
}

func countQuery(t *testing.T, state *captureDriverState) capturedQuery {
	t.Helper()
	qs := state.queriesContaining("SELECT count(*)")
	if len(qs) != 1 {
		t.Fatalf("expected exactly 1 count query, got %d", len(qs))
	}
	return qs[0]
}

func mustContain(t *testing.T, haystack, needle, label string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("%s: query missing %q\nquery: %s", label, needle, haystack)
	}
}

func mustNotContain(t *testing.T, haystack, needle, label string) {
	t.Helper()
	if strings.Contains(haystack, needle) {
		t.Fatalf("%s: query unexpectedly contains %q\nquery: %s", label, needle, haystack)
	}
}

// ---- SearchPackages -------------------------------------------------------

// packageDataColumns mirrors the columns selected by SearchPackages so the fake
// rows scan cleanly. The builder selects pkgCols + pkgVulnSelect; we only need
// the count to match for scanning an empty result, so we derive the count by
// running once and trusting Go's scanner over zero rows (no rows → no scan).
func searchPackagesNoColumnsNeeded() []string { return nil }

func TestSearchPackagesNameExactLowersAndBinds(t *testing.T) {
	db, state := newCaptureTestDB(t, searchPackagesNoColumnsNeeded())
	if _, _, err := db.SearchPackages(context.Background(), PackageFilter{NameExact: "OpenSSL", Limit: 10}); err != nil {
		t.Fatalf("SearchPackages: %v", err)
	}
	cnt := countQuery(t, state)
	mustContain(t, cnt.query, "lower(p.name)=lower($1)", "NameExact")
	if len(cnt.args) != 1 || cnt.args[0] != "OpenSSL" {
		t.Fatalf("NameExact args = %#v, want [OpenSSL] (case preserved, lowered in SQL)", cnt.args)
	}
}

func TestSearchPackagesVersionExactAndLike(t *testing.T) {
	db, state := newCaptureTestDB(t, nil)
	if _, _, err := db.SearchPackages(context.Background(), PackageFilter{Version: "1.2.3", Limit: 10}); err != nil {
		t.Fatalf("SearchPackages exact: %v", err)
	}
	cnt := countQuery(t, state)
	mustContain(t, cnt.query, "p.version=$1", "Version exact")
	if len(cnt.args) != 1 || cnt.args[0] != "1.2.3" {
		t.Fatalf("Version exact args = %#v, want [1.2.3]", cnt.args)
	}

	db2, state2 := newCaptureTestDB(t, nil)
	if _, _, err := db2.SearchPackages(context.Background(), PackageFilter{VersionLike: "1.2", Limit: 10}); err != nil {
		t.Fatalf("SearchPackages like: %v", err)
	}
	cnt2 := countQuery(t, state2)
	mustContain(t, cnt2.query, "p.version ILIKE $1", "VersionLike")
	if len(cnt2.args) != 1 || cnt2.args[0] != "%1.2%" {
		t.Fatalf("VersionLike args = %#v, want [%%1.2%%]", cnt2.args)
	}
}

func TestSearchPackagesEcosystemDualCondition(t *testing.T) {
	db, state := newCaptureTestDB(t, nil)
	if _, _, err := db.SearchPackages(context.Background(), PackageFilter{Ecosystem: "debian", Limit: 10}); err != nil {
		t.Fatalf("SearchPackages: %v", err)
	}
	cnt := countQuery(t, state)
	// Both the raw-ecosystem equality and the normalized-family condition must
	// reference the same single bind parameter ($1).
	mustContain(t, cnt.query, "lower(p.ecosystem)=lower($1)", "Ecosystem raw")
	mustContain(t, cnt.query, "=lower($1))", "Ecosystem normalized family")
	if len(cnt.args) != 1 || cnt.args[0] != "debian" {
		t.Fatalf("Ecosystem args = %#v, want [debian] bound once", cnt.args)
	}
}

func TestSearchPackagesArchBinds(t *testing.T) {
	db, state := newCaptureTestDB(t, nil)
	if _, _, err := db.SearchPackages(context.Background(), PackageFilter{Arch: "amd64", Limit: 10}); err != nil {
		t.Fatalf("SearchPackages: %v", err)
	}
	cnt := countQuery(t, state)
	mustContain(t, cnt.query, "p.arch=$1", "Arch")
	if len(cnt.args) != 1 || cnt.args[0] != "amd64" {
		t.Fatalf("Arch args = %#v, want [amd64]", cnt.args)
	}
}

func TestSearchPackagesImageNameWraps(t *testing.T) {
	db, state := newCaptureTestDB(t, nil)
	if _, _, err := db.SearchPackages(context.Background(), PackageFilter{ImageName: "nginx", Limit: 10}); err != nil {
		t.Fatalf("SearchPackages: %v", err)
	}
	cnt := countQuery(t, state)
	mustContain(t, cnt.query, "p.image_name ILIKE $1", "ImageName")
	if len(cnt.args) != 1 || cnt.args[0] != "%nginx%" {
		t.Fatalf("ImageName args = %#v, want [%%nginx%%]", cnt.args)
	}
}

func TestSearchPackagesAssetTypeHostAndContainer(t *testing.T) {
	dbHost, stateHost := newCaptureTestDB(t, nil)
	if _, _, err := dbHost.SearchPackages(context.Background(), PackageFilter{AssetType: "host", Limit: 10}); err != nil {
		t.Fatalf("SearchPackages host: %v", err)
	}
	cntHost := countQuery(t, stateHost)
	mustContain(t, cntHost.query, "AND (p.container='' OR p.container IS NULL)", "AssetType host")
	if len(cntHost.args) != 0 {
		t.Fatalf("AssetType host should add no args, got %#v", cntHost.args)
	}

	dbCon, stateCon := newCaptureTestDB(t, nil)
	if _, _, err := dbCon.SearchPackages(context.Background(), PackageFilter{AssetType: "container", Limit: 10}); err != nil {
		t.Fatalf("SearchPackages container: %v", err)
	}
	cntCon := countQuery(t, stateCon)
	mustContain(t, cntCon.query, "AND p.container<>''", "AssetType container")
	if len(cntCon.args) != 0 {
		t.Fatalf("AssetType container should add no args, got %#v", cntCon.args)
	}
}

func TestSearchPackagesHasVulnsAddsExists(t *testing.T) {
	db, state := newCaptureTestDB(t, nil)
	if _, _, err := db.SearchPackages(context.Background(), PackageFilter{HasVulns: true, Limit: 10}); err != nil {
		t.Fatalf("SearchPackages: %v", err)
	}
	cnt := countQuery(t, state)
	// HasVulns gates on a current-actionable EXISTS subquery over vulnerabilities.
	mustContain(t, cnt.query, "EXISTS (SELECT 1 FROM package_vulnerability_summaries pvs", "HasVulns summary EXISTS")
	mustContain(t, cnt.query, "pvs.vuln_count > 0", "HasVulns summary gate")
	mustNotContain(t, cnt.query, "v.cvss_score >=", "HasVulns alone must not add a CVSS bound")
	if len(cnt.args) != 0 {
		t.Fatalf("HasVulns alone should add no args, got %#v", cnt.args)
	}
}

func TestSearchPackagesMinCVSSBindsInExists(t *testing.T) {
	db, state := newCaptureTestDB(t, nil)
	if _, _, err := db.SearchPackages(context.Background(), PackageFilter{MinCVSS: 7.5, Limit: 10}); err != nil {
		t.Fatalf("SearchPackages: %v", err)
	}
	cnt := countQuery(t, state)
	mustContain(t, cnt.query, "EXISTS (SELECT 1 FROM package_vulnerability_summaries pvs", "MinCVSS summary EXISTS")
	mustContain(t, cnt.query, "AND pvs.max_cvss >= $1)", "MinCVSS bound")
	if len(cnt.args) != 1 || cnt.args[0] != 7.5 {
		t.Fatalf("MinCVSS args = %#v, want [7.5]", cnt.args)
	}
}

func TestSearchPackagesCombinedFiltersOrderArgs(t *testing.T) {
	db, state := newCaptureTestDB(t, nil)
	f := PackageFilter{
		HostID:    "host-1",
		NameExact: "openssl",
		Version:   "1.1.1",
		Ecosystem: "debian",
		MinCVSS:   9.0,
		Limit:     25,
		Offset:    5,
	}
	if _, _, err := db.SearchPackages(context.Background(), f); err != nil {
		t.Fatalf("SearchPackages: %v", err)
	}
	cnt := countQuery(t, state)
	// $1 host, $2 name, $3 version, $4 ecosystem, $5 cvss — in builder order.
	mustContain(t, cnt.query, "p.host_id=$1", "combined host")
	mustContain(t, cnt.query, "lower(p.name)=lower($2)", "combined name")
	mustContain(t, cnt.query, "p.version=$3", "combined version")
	mustContain(t, cnt.query, "lower(p.ecosystem)=lower($4)", "combined ecosystem")
	mustContain(t, cnt.query, "AND pvs.max_cvss >= $5)", "combined cvss")
	wantArgs := []driver.Value{"host-1", "openssl", "1.1.1", "debian", 9.0}
	if len(cnt.args) != len(wantArgs) {
		t.Fatalf("combined count args = %#v, want %#v", cnt.args, wantArgs)
	}
	for i := range wantArgs {
		if cnt.args[i] != wantArgs[i] {
			t.Fatalf("combined count arg[%d] = %#v, want %#v", i, cnt.args[i], wantArgs[i])
		}
	}
	// The data query appends LIMIT/OFFSET as the next two args ($6, $7).
	data := dataQuery(t, state)
	if len(data.args) != len(wantArgs)+2 {
		t.Fatalf("data query args = %#v, want filter args + limit + offset", data.args)
	}
	if data.args[len(data.args)-2] != int64(25) || data.args[len(data.args)-1] != int64(5) {
		t.Fatalf("data query limit/offset args = %#v, want [25 5] at the tail", data.args)
	}
}

// ---- ListVulnerabilities --------------------------------------------------

func TestListVulnerabilitiesMaxCVSSBinds(t *testing.T) {
	db, state := newCaptureTestDB(t, nil)
	if _, _, err := db.ListVulnerabilities(context.Background(), VulnFilter{MaxCVSS: 4.0}, 50, 0); err != nil {
		t.Fatalf("ListVulnerabilities: %v", err)
	}
	cnt := countQuery(t, state)
	mustContain(t, cnt.query, "v.cvss_score<=$1", "MaxCVSS")
	if len(cnt.args) != 1 || cnt.args[0] != 4.0 {
		t.Fatalf("MaxCVSS args = %#v, want [4.0]", cnt.args)
	}
}

func TestListVulnerabilitiesPkgTypeExists(t *testing.T) {
	db, state := newCaptureTestDB(t, nil)
	if _, _, err := db.ListVulnerabilities(context.Background(), VulnFilter{PkgType: "alpine"}, 50, 0); err != nil {
		t.Fatalf("ListVulnerabilities: %v", err)
	}
	cnt := countQuery(t, state)
	mustContain(t, cnt.query, "EXISTS(SELECT 1 FROM packages pf WHERE pf.id=v.package_id AND pf.pkg_type=$1)", "PkgType EXISTS")
	if len(cnt.args) != 1 || cnt.args[0] != "alpine" {
		t.Fatalf("PkgType args = %#v, want [alpine]", cnt.args)
	}
}

func TestListVulnerabilitiesEcosystemExistsDualCondition(t *testing.T) {
	db, state := newCaptureTestDB(t, nil)
	if _, _, err := db.ListVulnerabilities(context.Background(), VulnFilter{Ecosystem: "npm"}, 50, 0); err != nil {
		t.Fatalf("ListVulnerabilities: %v", err)
	}
	cnt := countQuery(t, state)
	mustContain(t, cnt.query, "EXISTS(SELECT 1 FROM packages pf WHERE pf.id=v.package_id AND (lower(pf.ecosystem)=lower($1)", "Ecosystem EXISTS")
	mustContain(t, cnt.query, "=lower($1)))", "Ecosystem normalized family in EXISTS")
	if len(cnt.args) != 1 || cnt.args[0] != "npm" {
		t.Fatalf("Ecosystem args = %#v, want [npm] bound once", cnt.args)
	}
}

func TestListVulnerabilitiesVulnIDLikeWraps(t *testing.T) {
	db, state := newCaptureTestDB(t, nil)
	if _, _, err := db.ListVulnerabilities(context.Background(), VulnFilter{VulnIDLike: "CVE-2024"}, 50, 0); err != nil {
		t.Fatalf("ListVulnerabilities: %v", err)
	}
	cnt := countQuery(t, state)
	mustContain(t, cnt.query, "v.vulnerability_id ILIKE $1", "VulnIDLike")
	if len(cnt.args) != 1 || cnt.args[0] != "%CVE-2024%" {
		t.Fatalf("VulnIDLike args = %#v, want [%%CVE-2024%%]", cnt.args)
	}
}

func TestListVulnerabilitiesHasFixBranchesAddNoArgs(t *testing.T) {
	// HasFix "yes" appends the fixedVersionEvidence predicate; "no" negates it.
	// Both are pure SQL (no bound args).
	dbYes, stateYes := newCaptureTestDB(t, nil)
	if _, _, err := dbYes.ListVulnerabilities(context.Background(), VulnFilter{HasFix: "yes"}, 50, 0); err != nil {
		t.Fatalf("ListVulnerabilities yes: %v", err)
	}
	cntYes := countQuery(t, stateYes)
	evidence := fixedVersionEvidenceSQL("v")
	mustContain(t, cntYes.query, " AND ("+evidence+")", "HasFix yes")
	mustNotContain(t, cntYes.query, "NOT ("+evidence+")", "HasFix yes must not negate")
	if len(cntYes.args) != 0 {
		t.Fatalf("HasFix yes should add no args, got %#v", cntYes.args)
	}

	dbNo, stateNo := newCaptureTestDB(t, nil)
	if _, _, err := dbNo.ListVulnerabilities(context.Background(), VulnFilter{HasFix: "no"}, 50, 0); err != nil {
		t.Fatalf("ListVulnerabilities no: %v", err)
	}
	cntNo := countQuery(t, stateNo)
	mustContain(t, cntNo.query, " AND NOT ("+evidence+")", "HasFix no")
	if len(cntNo.args) != 0 {
		t.Fatalf("HasFix no should add no args, got %#v", cntNo.args)
	}
}

func TestListVulnerabilitiesAssigneeUnassignedSpecialCase(t *testing.T) {
	// "unassigned" is a sentinel: it must produce an empty-assignee predicate
	// with no bound argument, while a real assignee binds.
	dbUn, stateUn := newCaptureTestDB(t, nil)
	if _, _, err := dbUn.ListVulnerabilities(context.Background(), VulnFilter{Assignee: "unassigned"}, 50, 0); err != nil {
		t.Fatalf("ListVulnerabilities unassigned: %v", err)
	}
	cntUn := countQuery(t, stateUn)
	mustContain(t, cntUn.query, "AND COALESCE(vt.assignee, '')=''", "Assignee unassigned")
	if len(cntUn.args) != 0 {
		t.Fatalf("Assignee unassigned should add no args, got %#v", cntUn.args)
	}

	dbReal, stateReal := newCaptureTestDB(t, nil)
	if _, _, err := dbReal.ListVulnerabilities(context.Background(), VulnFilter{Assignee: "alice"}, 50, 0); err != nil {
		t.Fatalf("ListVulnerabilities assignee: %v", err)
	}
	cntReal := countQuery(t, stateReal)
	mustContain(t, cntReal.query, "AND COALESCE(vt.assignee, '')=$1", "Assignee real")
	if len(cntReal.args) != 1 || cntReal.args[0] != "alice" {
		t.Fatalf("Assignee real args = %#v, want [alice]", cntReal.args)
	}
}
