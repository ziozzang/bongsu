//go:build integration

package intel

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/server/db"
	"github.com/ziozzang/bongsu/internal/shared/models"
)

// TestScopedToolsEnforceRBAC is the security-critical test for the intelligence
// layer: a viewer granted access to host A only must, through the intelligence
// tools, see host A's findings and be DENIED host B's — the tools can never
// widen access beyond what the caller could see in the UI.
func TestScopedToolsEnforceRBAC(t *testing.T) {
	database := openIntelDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	hostA := &models.Host{ID: "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0", Hostname: "host-a", OSName: "ubuntu", LastSeen: time.Now()}
	hostB := &models.Host{ID: "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0", Hostname: "host-b", OSName: "ubuntu", LastSeen: time.Now()}
	for _, h := range []*models.Host{hostA, hostB} {
		if err := database.UpsertHost(ctx, h); err != nil {
			t.Fatalf("seed host: %v", err)
		}
	}
	scanA := &models.Scan{ID: "a0a0-scan-0000-0000-000000000001", HostID: hostA.ID, ScanType: "manual", Status: "completed"}
	scanB := &models.Scan{ID: "b0b0-scan-0000-0000-000000000001", HostID: hostB.ID, ScanType: "manual", Status: "completed"}
	for _, s := range []*models.Scan{scanA, scanB} {
		if err := database.CreateScan(ctx, s); err != nil {
			t.Fatalf("seed scan: %v", err)
		}
	}
	pkgs := []models.Package{
		{ID: "intel-pkg-a", ScanID: scanA.ID, HostID: hostA.ID, Name: "lodash", Version: "4.17.20", PkgType: "node-pkg", Ecosystem: "npm", Source: "native-lang", Dependencies: []string{"foo"}},
		{ID: "intel-pkg-foo-a", ScanID: scanA.ID, HostID: hostA.ID, Name: "foo", Version: "1.0.0", PkgType: "node-pkg", Ecosystem: "npm", Source: "native-lang"},
		{ID: "intel-pkg-b", ScanID: scanB.ID, HostID: hostB.ID, Name: "left-pad", Version: "1.0.0", PkgType: "node-pkg", Ecosystem: "npm", Source: "native-lang"},
	}
	if err := database.InsertPackages(ctx, pkgs); err != nil {
		t.Fatalf("seed packages: %v", err)
	}
	if err := database.StorePackageDependencies(ctx, scanA.ID, [][2]string{{"pkg:npm/foo@1.0.0", "pkg:npm/lodash@4.17.20"}}); err != nil {
		t.Fatalf("seed deps: %v", err)
	}
	vulns := []models.Vulnerability{
		{ID: "intel-v-a", PackageID: "intel-pkg-a", ScanID: scanA.ID, HostID: hostA.ID, VulnerabilityID: "CVE-A-1", PkgName: "lodash", Severity: "HIGH", CVSSScore: 7.5, FindingSource: "cve-db"},
		{ID: "intel-v-b", PackageID: "intel-pkg-b", ScanID: scanB.ID, HostID: hostB.ID, VulnerabilityID: "CVE-B-1", PkgName: "left-pad", Severity: "HIGH", CVSSScore: 7.5, FindingSource: "cve-db"},
	}
	if _, err := database.InsertVulnerabilities(ctx, vulns); err != nil {
		t.Fatalf("seed vulns: %v", err)
	}

	// Grant user:alice read access to host A only.
	if err := database.UpsertAccessSubject(ctx, "intel-subj-alice", "user", "alice", "Alice"); err != nil {
		t.Fatalf("seed subject: %v", err)
	}
	if err := database.UpsertAccessPolicy(ctx, "intel-pol-a", "intel-subj-alice", "alice", "host", hostA.ID, "read"); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	reg := NewRegistry()
	RegisterScopedTools(reg, database)
	alice := &Scope{Subjects: []string{"user:alice"}}
	admin := &Scope{Admin: true}

	// 1) query_vulns (no host): alice sees ONLY host A's finding.
	res, err := reg.Call(WithScope(ctx, alice), alice, "query_vulns", map[string]any{})
	if err != nil {
		t.Fatalf("query_vulns(alice): %v", err)
	}
	var q struct {
		Findings []struct {
			VulnerabilityID string `json:"vulnerability_id"`
			HostID          string `json:"host_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(res), &q); err != nil {
		t.Fatalf("decode: %v (%s)", err, res)
	}
	for _, f := range q.Findings {
		if f.HostID != hostA.ID {
			t.Fatalf("alice must only see host A findings; leaked %s on %s", f.VulnerabilityID, f.HostID)
		}
	}
	if len(q.Findings) == 0 {
		t.Fatalf("alice must see host A's finding, got none: %s", res)
	}

	// 2) query_vulns(host_id=B): denied.
	if _, err := reg.Call(WithScope(ctx, alice), alice, "query_vulns", map[string]any{"host_id": hostB.ID}); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("alice querying host B must be forbidden, got err=%v", err)
	}

	// 3) dependents_of on host B's scan: denied.
	if _, err := reg.Call(WithScope(ctx, alice), alice, "dependents_of", map[string]any{"scan_id": scanB.ID, "package": "left-pad"}); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("alice dependents_of on host B scan must be forbidden, got err=%v", err)
	}

	// 4) dependents_of on host A's scan: allowed (and finds the transitive parent).
	dres, err := reg.Call(WithScope(ctx, alice), alice, "dependents_of", map[string]any{"scan_id": scanA.ID, "package": "pkg:npm/lodash@4.17.20"})
	if err != nil {
		t.Fatalf("alice dependents_of host A: %v", err)
	}
	if !strings.Contains(dres, "pkg:npm/foo@1.0.0") {
		t.Fatalf("dependents_of should find the transitive parent: %s", dres)
	}

	// 5) sbom_at on host B's scan: denied.
	if _, err := reg.Call(WithScope(ctx, alice), alice, "sbom_at", map[string]any{"scan_id": scanB.ID}); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("alice sbom_at on host B must be forbidden, got err=%v", err)
	}

	// 6) admin sees both hosts.
	ares, err := reg.Call(WithScope(ctx, admin), admin, "query_vulns", map[string]any{})
	if err != nil {
		t.Fatalf("query_vulns(admin): %v", err)
	}
	if !strings.Contains(ares, "CVE-A-1") || !strings.Contains(ares, "CVE-B-1") {
		t.Fatalf("admin must see both hosts' findings: %s", ares)
	}
}

// resolveAccessScope sanity: nil scope denies.
func TestResolveAccessScopeNilDenies(t *testing.T) {
	database := openIntelDB(t)
	if _, err := resolveAccessScope(context.Background(), database, nil); err == nil {
		t.Fatal("nil scope must deny")
	}
	_ = db.AccessScope{}
}
