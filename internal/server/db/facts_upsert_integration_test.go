//go:build integration

package db

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// TestUpsertHostFactsPreservedOnEmptyIntegration pins the host facts upsert
// contract (host.go UpsertHostWithAgentToken): UpsertHost with a facts blob
// persists it (GetHost returns it), and a SECOND UpsertHost carrying EMPTY facts
// must NOT wipe the previously stored operator-visible facts. The SQL coalesces
// empty ({}) facts to the existing column value, so an agent report that omits
// facts cannot blank out a host's recorded facts. This is the sane behavior; the
// test fails loudly if the code ever starts wiping.
func TestUpsertHostFactsPreservedOnEmptyIntegration(t *testing.T) {
	database := openIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const hostID = "fac70000fac70000fac70000fac70000"
	factsJSON := `{"role":"db-primary","region":"eu-west-1"}`

	// First report carries facts.
	h := &models.Host{ID: hostID, Hostname: "facts-host", OSName: "debian", LastSeen: time.Now(), Facts: json.RawMessage(factsJSON)}
	if err := database.UpsertHost(ctx, h); err != nil {
		t.Fatalf("first UpsertHost: %v", err)
	}
	got, err := database.GetHost(ctx, hostID)
	if err != nil {
		t.Fatalf("GetHost after first upsert: %v", err)
	}
	if !jsonEqual(t, string(got.Facts), factsJSON) {
		t.Fatalf("facts after first upsert = %q, want %q", string(got.Facts), factsJSON)
	}
	if got.FactsCollectedAt == nil {
		t.Fatalf("facts_collected_at is nil after a non-empty facts upsert, want a timestamp")
	}

	// Second report carries NO facts (empty -> {}). The prior facts must survive.
	h2 := &models.Host{ID: hostID, Hostname: "facts-host-renamed", OSName: "debian", LastSeen: time.Now()}
	if err := database.UpsertHost(ctx, h2); err != nil {
		t.Fatalf("second UpsertHost (empty facts): %v", err)
	}
	got2, err := database.GetHost(ctx, hostID)
	if err != nil {
		t.Fatalf("GetHost after empty-facts upsert: %v", err)
	}
	if !jsonEqual(t, string(got2.Facts), factsJSON) {
		t.Fatalf("facts after empty-facts upsert = %q, want them preserved as %q (empty agent report must not wipe facts)", string(got2.Facts), factsJSON)
	}
	// Non-facts columns still update on the second upsert.
	if got2.Hostname != "facts-host-renamed" {
		t.Fatalf("hostname after second upsert = %q, want facts-host-renamed (non-facts columns still update)", got2.Hostname)
	}
}

// TestInsertContainersFactsIntegration pins the container facts behavior
// (container.go InsertContainers). InsertContainers is INSERT-only (one row per
// scan, keyed by id) -- there is no upsert path that could wipe prior facts.
// This test encodes what the code DOES: a container inserted with facts exposes
// them via SearchContainers, and a container inserted with EMPTY facts stores no
// facts ({}) -- there is nothing to "preserve" because each scan writes fresh
// rows. The container must be reachable through SearchContainers, which requires
// the owning scan to be the host's latest completed scan.
func TestInsertContainersFactsIntegration(t *testing.T) {
	database := openIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	host := &models.Host{ID: "c0117a1ec0117a1ec0117a1ec0117a1e", Hostname: "container-facts-host", OSName: "debian", LastSeen: time.Now()}
	if err := database.UpsertHost(ctx, host); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	scan := &models.Scan{ID: "c011-scan-0000-0000-000000000001", HostID: host.ID, ScanType: "manual", Status: "completed"}
	if err := database.CreateScan(ctx, scan); err != nil {
		t.Fatalf("seed scan: %v", err)
	}

	factsJSON := `{"runtime_user":"app","cgroup":"v2"}`
	containers := []models.ContainerAsset{
		{ID: "ctr-with-facts", ScanID: scan.ID, HostID: host.ID, Runtime: "docker", ContainerID: "deadbeef01", Name: "with-facts", ImageName: "nginx", State: "running", Facts: json.RawMessage(factsJSON)},
		{ID: "ctr-no-facts", ScanID: scan.ID, HostID: host.ID, Runtime: "docker", ContainerID: "deadbeef02", Name: "no-facts", ImageName: "redis", State: "running"},
	}
	if err := database.InsertContainers(ctx, containers); err != nil {
		t.Fatalf("InsertContainers: %v", err)
	}

	got, _, err := database.SearchContainers(ctx, ContainerFilter{HostID: host.ID, Limit: 100})
	if err != nil {
		t.Fatalf("SearchContainers: %v", err)
	}
	byName := map[string]models.ContainerAsset{}
	for _, c := range got {
		byName[c.Name] = c
	}
	if len(byName) != 2 {
		t.Fatalf("got %d containers, want 2", len(byName))
	}
	if !jsonEqual(t, string(byName["with-facts"].Facts), factsJSON) {
		t.Fatalf("with-facts container facts = %q, want %q", string(byName["with-facts"].Facts), factsJSON)
	}
	// Empty-facts container stores {} which GetHost-style readers expose as
	// empty (the read path drops {} to nil); confirm no facts leak in.
	if len(byName["no-facts"].Facts) != 0 {
		t.Fatalf("no-facts container facts = %q, want empty (inserted with no facts)", string(byName["no-facts"].Facts))
	}
}

func jsonEqual(t *testing.T, a, b string) bool {
	t.Helper()
	var av, bv any
	if err := json.Unmarshal([]byte(a), &av); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(b), &bv); err != nil {
		t.Fatalf("expected-json unmarshal %q: %v", b, err)
	}
	ab, _ := json.Marshal(av)
	bb, _ := json.Marshal(bv)
	return string(ab) == string(bb)
}
