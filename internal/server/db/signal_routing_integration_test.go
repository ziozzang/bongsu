//go:build integration

package db

import (
	"context"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// TestSignalIngestRouting is the Phase 2b guarantee: KEV/EPSS bundle entries are
// routed straight to the signal-plane tables (cve_kev / cve_epss) and never into
// cve_database, while advisory entries land in cve_database without any EPSS
// column. The read path (vulnExploitedExpr / vulnEPSSScoreExpr) reads the signal
// tables, so a finding's exploited flag and EPSS still resolve.
func TestSignalIngestRouting(t *testing.T) {
	database := openIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	entries := []models.CveEntry{
		{ID: "osv-CVE-9000-1", VulnerabilityID: "CVE-9000-1", Source: "osv", Severity: "HIGH", CVSSScore: 7.5,
			Ecosystem: "npm", Category: "code-library", AffectedProducts: `[{"name":"foo","ecosystem":"npm","fixed":["1.0.1"]}]`, References: `[]`, RawData: `{}`},
		{ID: "kev-CVE-9000-1", VulnerabilityID: "CVE-9000-1", Source: "cisa-kev", AffectedProducts: `[]`, References: `[]`, RawData: `{"knownRansomwareCampaignUse":"Known"}`},
		{ID: "epss-CVE-9000-1", VulnerabilityID: "CVE-9000-1", Source: "epss", EPSSScore: 0.42, EPSSPercentile: 0.97, AffectedProducts: `[]`, References: `[]`, RawData: `{}`},
		{ID: "epss-CVE-9000-2", VulnerabilityID: "CVE-9000-2", Source: "epss", EPSSScore: 0.10, EPSSPercentile: 0.60, AffectedProducts: `[]`, References: `[]`, RawData: `{}`},
	}
	if _, err := database.UpsertCveEntries(ctx, entries); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	// cve_database holds ONLY the advisory row.
	var dbSignalRows int
	if err := database.QueryRowContext(ctx,
		`SELECT count(*) FROM cve_database WHERE source IN ('cisa-kev','epss')`).Scan(&dbSignalRows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if dbSignalRows != 0 {
		t.Fatalf("signal rows must not land in cve_database, got %d", dbSignalRows)
	}

	// Signal tables were populated by routing.
	var kev int
	var score float64
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM cve_kev WHERE vulnerability_id='CVE-9000-1'`).Scan(&kev); err != nil {
		t.Fatalf("kev: %v", err)
	}
	if kev != 1 {
		t.Fatalf("CVE-9000-1 must be in cve_kev once, got %d", kev)
	}
	if err := database.QueryRowContext(ctx, `SELECT score FROM cve_epss WHERE vulnerability_id='CVE-9000-1'`).Scan(&score); err != nil {
		t.Fatalf("epss: %v", err)
	}
	if score < 0.41 || score > 0.43 {
		t.Fatalf("epss score = %v, want ~0.42", score)
	}

	// Re-ingest (upsert) updates in place — no duplication.
	entries[2].EPSSScore = 0.55
	if _, err := database.UpsertCveEntries(ctx, entries); err != nil {
		t.Fatalf("re-ingest: %v", err)
	}
	var rows int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM cve_epss WHERE vulnerability_id='CVE-9000-1'`).Scan(&rows); err != nil {
		t.Fatalf("count epss: %v", err)
	}
	if err := database.QueryRowContext(ctx, `SELECT score FROM cve_epss WHERE vulnerability_id='CVE-9000-1'`).Scan(&score); err != nil {
		t.Fatalf("epss2: %v", err)
	}
	if rows != 1 || score < 0.54 || score > 0.56 {
		t.Fatalf("upsert must replace in place: rows=%d score=%v", rows, score)
	}

	// The read path resolves exploited + EPSS from the signal tables.
	var exploited bool
	var readScore float64
	if err := database.QueryRowContext(ctx, `
		SELECT EXISTS(SELECT 1 FROM cve_kev k WHERE k.vulnerability_id='CVE-9000-1'),
		       COALESCE((SELECT e.score FROM cve_epss e WHERE e.vulnerability_id='CVE-9000-1'),0)`).
		Scan(&exploited, &readScore); err != nil {
		t.Fatalf("read path: %v", err)
	}
	if !exploited || readScore < 0.54 {
		t.Fatalf("read path wrong: exploited=%v score=%v", exploited, readScore)
	}
}

// TestCveDatabaseRejectsSignalSource is the DB-level invariant guard (migration
// 075): a cisa-kev/epss row can never be written directly into the advisory
// table, even bypassing the ingest router.
func TestCveDatabaseRejectsSignalSource(t *testing.T) {
	database := openIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, src := range []string{"cisa-kev", "epss"} {
		_, err := database.ExecContext(ctx,
			`INSERT INTO cve_database (id, vulnerability_id, source, affected_products, refs, raw_data)
			 VALUES ($1, 'CVE-GUARD-1', $2, '[]', '[]', '{}')`, "guard-"+src, src)
		if err == nil {
			t.Fatalf("inserting a %s row into cve_database must be rejected by the invariant constraint", src)
		}
	}
	// A normal advisory source is still accepted.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO cve_database (id, vulnerability_id, source, affected_products, refs, raw_data)
		 VALUES ('guard-osv', 'CVE-GUARD-2', 'osv', '[]', '[]', '{}')`); err != nil {
		t.Fatalf("advisory source must still be accepted: %v", err)
	}
	// A custom feed name (not a reserved signal name) is accepted.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO cve_database (id, vulnerability_id, source, affected_products, refs, raw_data)
		 VALUES ('guard-custom', 'CVE-GUARD-3', 'my-internal-feed', '[]', '[]', '{}')`); err != nil {
		t.Fatalf("custom advisory source must be accepted (constraint is narrow): %v", err)
	}
}
