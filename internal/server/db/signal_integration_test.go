//go:build integration

package db

import (
	"context"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// TestSignalPlaneEquivalence is the core guarantee of the secdb signal-plane
// extraction: after RefreshSignalTables, the new cve_kev / cve_epss read path
// yields exactly the exploited flag and EPSS score the old co-mingled
// cve_database rows did. A regression here silently changes every risk score.
func TestSignalPlaneEquivalence(t *testing.T) {
	database := openIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Seed cve_database the way the secdb bundle does: an advisory row, a KEV
	// signal row, and an EPSS signal row for the same CVE.
	entries := []models.CveEntry{
		{ID: "adv-CVE-9000-1", VulnerabilityID: "CVE-9000-1", Source: "osv", Severity: "HIGH", CVSSScore: 7.5,
			Ecosystem: "npm", Category: "code-library", AffectedProducts: `[{"name":"foo","ecosystem":"npm","fixed":["1.0.1"]}]`, References: `[]`, RawData: `{}`},
		{ID: "kev-CVE-9000-1", VulnerabilityID: "CVE-9000-1", Source: "cisa-kev", Severity: "", AffectedProducts: `[]`, References: `[]`, RawData: `{"knownRansomwareCampaignUse":"Known"}`},
		{ID: "epss-CVE-9000-1", VulnerabilityID: "CVE-9000-1", Source: "epss", EPSSScore: 0.42, EPSSPercentile: 0.97, AffectedProducts: `[]`, References: `[]`, RawData: `{}`},
		// A second CVE with EPSS only (no KEV).
		{ID: "epss-CVE-9000-2", VulnerabilityID: "CVE-9000-2", Source: "epss", EPSSScore: 0.10, EPSSPercentile: 0.60, AffectedProducts: `[]`, References: `[]`, RawData: `{}`},
	}
	if _, err := database.UpsertCveEntries(ctx, entries); err != nil {
		t.Fatalf("seed cve entries: %v", err)
	}
	if _, err := database.SyncEPSSPriorityColumns(ctx); err != nil { // also refreshes signal tables
		t.Fatalf("sync/refresh: %v", err)
	}

	// New read path (signal tables) vs the OLD read path (co-mingled cve_database),
	// computed for the same vulnerability_id — they must agree.
	check := func(vid string) {
		var newExploited, oldExploited bool
		var newScore, oldScore, newPct, oldPct float64
		row := database.QueryRowContext(ctx, `
			SELECT
			  EXISTS(SELECT 1 FROM cve_kev k WHERE k.vulnerability_id=$1),
			  EXISTS(SELECT 1 FROM cve_database kev WHERE kev.source='cisa-kev' AND kev.vulnerability_id=$1),
			  COALESCE((SELECT e.score FROM cve_epss e WHERE e.vulnerability_id=$1),0),
			  COALESCE((SELECT MAX(c.epss_score) FROM cve_database c WHERE c.vulnerability_id=$1),0),
			  COALESCE((SELECT e.percentile FROM cve_epss e WHERE e.vulnerability_id=$1),0),
			  COALESCE((SELECT MAX(c.epss_percentile) FROM cve_database c WHERE c.vulnerability_id=$1),0)`, vid)
		if err := row.Scan(&newExploited, &oldExploited, &newScore, &oldScore, &newPct, &oldPct); err != nil {
			t.Fatalf("equivalence query %s: %v", vid, err)
		}
		if newExploited != oldExploited {
			t.Fatalf("%s exploited: new=%v old=%v", vid, newExploited, oldExploited)
		}
		if newScore != oldScore {
			t.Fatalf("%s epss score: new=%v old=%v", vid, newScore, oldScore)
		}
		if newPct != oldPct {
			t.Fatalf("%s epss percentile: new=%v old=%v", vid, newPct, oldPct)
		}
	}
	check("CVE-9000-1")
	check("CVE-9000-2")

	// Concrete expectations.
	var kevCount int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM cve_kev WHERE vulnerability_id='CVE-9000-1'`).Scan(&kevCount); err != nil {
		t.Fatalf("kev count: %v", err)
	}
	if kevCount != 1 {
		t.Fatalf("CVE-9000-1 must be in cve_kev exactly once, got %d", kevCount)
	}
	var score float64
	if err := database.QueryRowContext(ctx, `SELECT score FROM cve_epss WHERE vulnerability_id='CVE-9000-1'`).Scan(&score); err != nil {
		t.Fatalf("epss read: %v", err)
	}
	if score < 0.41 || score > 0.43 {
		t.Fatalf("CVE-9000-1 epss score = %v, want ~0.42", score)
	}

	// CVE-9000-2 has EPSS but no KEV -> not in cve_kev.
	var noKev int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM cve_kev WHERE vulnerability_id='CVE-9000-2'`).Scan(&noKev); err != nil {
		t.Fatalf("kev count 2: %v", err)
	}
	if noKev != 0 {
		t.Fatalf("CVE-9000-2 must not be KEV, got %d", noKev)
	}
}
