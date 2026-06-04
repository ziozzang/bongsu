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
	sbomPackageDriverOnce   sync.Once
	sbomPackageDriverMu     sync.Mutex
	sbomPackageDriverStates = map[string]*sbomPackageDriverState{}
)

type sbomPackageDriverState struct {
	mu        sync.Mutex
	rows      [][]driver.Value
	query     string
	queryArgs []driver.Value
}

type sbomPackageDriver struct{}

func (d sbomPackageDriver) Open(name string) (driver.Conn, error) {
	sbomPackageDriverMu.Lock()
	state := sbomPackageDriverStates[name]
	sbomPackageDriverMu.Unlock()
	if state == nil {
		return nil, fmt.Errorf("unknown sbom package driver state %q", name)
	}
	return &sbomPackageConn{state: state}, nil
}

type sbomPackageConn struct {
	state *sbomPackageDriverState
}

func (c *sbomPackageConn) Prepare(string) (driver.Stmt, error) {
	return nil, fmt.Errorf("prepared statements are not supported by sbom package test driver")
}

func (c *sbomPackageConn) Close() error { return nil }

func (c *sbomPackageConn) Begin() (driver.Tx, error) {
	return nil, fmt.Errorf("transactions are not supported by sbom package test driver")
}

func (c *sbomPackageConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	values := namedValues(args)
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	if !strings.Contains(query, "FROM packages p JOIN") {
		return nil, fmt.Errorf("unexpected query: %s", query)
	}
	c.state.query = query
	c.state.queryArgs = values
	return &sbomPackageRows{columns: sbomPackageColumns(), rows: append([][]driver.Value(nil), c.state.rows...)}, nil
}

type sbomPackageRows struct {
	columns []string
	rows    [][]driver.Value
	index   int
}

func (r *sbomPackageRows) Columns() []string { return r.columns }
func (r *sbomPackageRows) Close() error      { return nil }

func (r *sbomPackageRows) Next(dest []driver.Value) error {
	if r.index >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.index])
	r.index++
	return nil
}

func sbomPackageColumns() []string {
	return []string{
		"id", "scan_id", "host_id", "asset_type", "asset_id", "source", "container",
		"container_id", "image_name", "image_id", "name", "version", "arch", "pkg_type",
		"ecosystem", "purl", "src_name", "file_path", "layer_id", "target", "created_at",
		"max_cvss", "vuln_count",
	}
}

func sbomPackageRow() []driver.Value {
	return []driver.Value{
		"pkg-container-1", "scan-latest-1", "host-1", "container", "container-asset-1", "trivy", "api",
		"container-sha256-abc", "registry.example/api:1.0", "image-sha256-def", "openssl", "3.0.13",
		"amd64", "deb", "Ubuntu", "pkg:deb/ubuntu/openssl@3.0.13?arch=amd64", "openssl",
		"/usr/lib", "layer-sha256-ghi", "ubuntu:24.04", time.Date(2026, 6, 4, 3, 2, 1, 0, time.UTC),
		9.8, int64(2),
	}
}

func newSBOMPackageTestDB(t *testing.T, state *sbomPackageDriverState) *DB {
	t.Helper()
	sbomPackageDriverOnce.Do(func() {
		sql.Register("bongsu-sbom-package-test", sbomPackageDriver{})
	})
	name := fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())
	sbomPackageDriverMu.Lock()
	sbomPackageDriverStates[name] = state
	sbomPackageDriverMu.Unlock()
	t.Cleanup(func() {
		sbomPackageDriverMu.Lock()
		delete(sbomPackageDriverStates, name)
		sbomPackageDriverMu.Unlock()
	})
	raw, err := sql.Open("bongsu-sbom-package-test", name)
	if err != nil {
		t.Fatalf("open fake db: %v", err)
	}
	t.Cleanup(func() {
		_ = raw.Close()
	})
	return &DB{DB: raw}
}

func TestGetLatestPackagesForSBOMPreservesContainerPackageOntology(t *testing.T) {
	state := &sbomPackageDriverState{rows: [][]driver.Value{sbomPackageRow()}}
	database := newSBOMPackageTestDB(t, state)

	pkgs, err := database.GetLatestPackagesForSBOM(context.Background(), "host-1")
	if err != nil {
		t.Fatalf("GetLatestPackagesForSBOM failed: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("packages = %d, want 1", len(pkgs))
	}
	pkg := pkgs[0]
	if pkg.ID != "pkg-container-1" || pkg.ScanID != "scan-latest-1" || pkg.HostID != "host-1" {
		t.Fatalf("package identity not preserved: %+v", pkg)
	}
	if pkg.AssetType != "container" || pkg.AssetID != "container-asset-1" || pkg.Source != "trivy" {
		t.Fatalf("package asset source context not preserved: %+v", pkg)
	}
	if pkg.Container != "api" || pkg.ContainerID != "container-sha256-abc" || pkg.ImageName != "registry.example/api:1.0" || pkg.ImageID != "image-sha256-def" {
		t.Fatalf("container/image context not preserved: %+v", pkg)
	}
	if pkg.PURL != "pkg:deb/ubuntu/openssl@3.0.13?arch=amd64" || pkg.SrcName != "openssl" || pkg.FilePath != "/usr/lib" || pkg.LayerID != "layer-sha256-ghi" || pkg.Target != "ubuntu:24.04" {
		t.Fatalf("package location/target context not preserved: %+v", pkg)
	}
	if pkg.MaxCVSS != 9.8 || pkg.VulnCount != 2 {
		t.Fatalf("package vulnerability summary not preserved: %+v", pkg)
	}

	state.mu.Lock()
	defer state.mu.Unlock()
	for _, want := range []string{
		"JOIN (",
		"p.scan_id = ls.id",
		"p.host_id=$1",
		"ORDER BY p.asset_type, p.container, p.name, p.version",
		"p.container_id",
		"p.image_name",
		"p.image_id",
		"p.target",
	} {
		if !strings.Contains(state.query, want) {
			t.Fatalf("SBOM package query missing %q: %s", want, state.query)
		}
	}
	if len(state.queryArgs) != 1 || state.queryArgs[0] != "host-1" {
		t.Fatalf("query args = %#v, want host-1", state.queryArgs)
	}
}
