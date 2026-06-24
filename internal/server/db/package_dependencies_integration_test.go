//go:build integration

package db

import (
	"context"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// TestPackageDependenciesTransitive verifies migration 070 applies and the
// reverse-reachability (transitive dependents) query works: given app -> express
// -> lodash, the dependents of lodash are {app, express}.
func TestPackageDependenciesTransitive(t *testing.T) {
	database := openIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	host := &models.Host{ID: "7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e", Hostname: "dep-host", OSName: "sbom", LastSeen: time.Now()}
	if err := database.UpsertHost(ctx, host); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	scan := &models.Scan{ID: "7e7e-scan-0000-0000-000000000001", HostID: host.ID, ScanType: "sbom", Status: "completed"}
	if err := database.CreateScan(ctx, scan); err != nil {
		t.Fatalf("seed scan: %v", err)
	}

	edges := [][2]string{
		{"pkg:npm/app@1.0.0", "pkg:npm/express@4.18.2"},
		{"pkg:npm/express@4.18.2", "pkg:npm/lodash@4.17.21"},
		{"pkg:npm/app@1.0.0", "pkg:npm/lodash@4.17.21"},
	}
	if err := database.StorePackageDependencies(ctx, scan.ID, edges); err != nil {
		t.Fatalf("store deps: %v", err)
	}

	got, err := database.DependentsOf(ctx, scan.ID, "pkg:npm/lodash@4.17.21")
	if err != nil {
		t.Fatalf("dependents: %v", err)
	}
	want := []string{"pkg:npm/app@1.0.0", "pkg:npm/express@4.18.2"}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("transitive dependents = %v, want %v", got, want)
	}

	// Re-store (idempotent): a leaf with no dependents stays empty, and the row
	// count does not grow.
	if err := database.StorePackageDependencies(ctx, scan.ID, edges); err != nil {
		t.Fatalf("re-store deps: %v", err)
	}
	var rows int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM package_dependencies WHERE scan_id=$1`, scan.ID).Scan(&rows); err != nil {
		t.Fatalf("count edges: %v", err)
	}
	if rows != 3 {
		t.Fatalf("re-store must replace, not accumulate: %d rows", rows)
	}
	top, err := database.DependentsOf(ctx, scan.ID, "pkg:npm/app@1.0.0")
	if err != nil {
		t.Fatalf("dependents of root: %v", err)
	}
	if len(top) != 0 {
		t.Fatalf("root package must have no dependents, got %v", top)
	}
}
