//go:build integration

package intel

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/server/db"
	"github.com/ziozzang/bongsu/internal/shared/models"
)

// TestAdvisoryForTool exercises advisory_for against a real CVE that has
// multi-source advisories + a KEV signal + an EPSS score — the xz-utils
// backdoor (CVE-2024-3094) shape: critical, known-exploited.
func TestAdvisoryForTool(t *testing.T) {
	database := openIntelDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	entries := []models.CveEntry{
		{ID: "osv-CVE-2024-3094", VulnerabilityID: "CVE-2024-3094", Source: "osv", Severity: "CRITICAL", CVSSScore: 10.0,
			Title: "xz backdoor", Ecosystem: "Debian:12", Category: "os-package", AffectedProducts: `[{"name":"xz-utils","ecosystem":"Debian:12","fixed":["5.6.2-1"]}]`, References: `[]`, RawData: `{}`},
		{ID: "nvd-CVE-2024-3094", VulnerabilityID: "CVE-2024-3094", Source: "nvd", Severity: "CRITICAL", CVSSScore: 10.0,
			Title: "Malicious code in xz", AffectedProducts: `[]`, References: `[]`, RawData: `{}`},
		{ID: "kev-CVE-2024-3094", VulnerabilityID: "CVE-2024-3094", Source: "cisa-kev", AffectedProducts: `[]`, References: `[]`, RawData: `{}`},
		{ID: "epss-CVE-2024-3094", VulnerabilityID: "CVE-2024-3094", Source: "epss", EPSSScore: 0.85, EPSSPercentile: 0.99, AffectedProducts: `[]`, References: `[]`, RawData: `{}`},
	}
	if _, err := database.UpsertCveEntries(ctx, entries); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := database.SyncEPSSPriorityColumns(ctx); err != nil { // refreshes cve_kev/cve_epss
		t.Fatalf("refresh signals: %v", err)
	}

	reg := NewRegistry()
	RegisterReferenceTools(reg, database)
	res, err := reg.Call(WithScope(ctx, &Scope{Subjects: []string{"user:any"}}), &Scope{Subjects: []string{"user:any"}}, "advisory_for", map[string]any{"cve": "CVE-2024-3094"})
	if err != nil {
		t.Fatalf("advisory_for: %v", err)
	}
	var got struct {
		CVE       string  `json:"cve"`
		Exploited bool    `json:"exploited_kev"`
		EPSSScore float64 `json:"epss_score"`
		Sources   []struct {
			Source string `json:"source"`
		} `json:"sources"`
	}
	if err := json.Unmarshal([]byte(res), &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, res)
	}
	if !got.Exploited {
		t.Fatalf("CVE-2024-3094 must be flagged KEV-exploited: %s", res)
	}
	if got.EPSSScore < 0.84 || got.EPSSScore > 0.86 {
		t.Fatalf("epss score wrong: %v", got.EPSSScore)
	}
	// Signal sources (cisa-kev/epss) must NOT appear as advisory sources.
	if len(got.Sources) != 2 {
		t.Fatalf("want 2 advisory sources (osv,nvd), got %d: %s", len(got.Sources), res)
	}
	for _, s := range got.Sources {
		if s.Source == "cisa-kev" || s.Source == "epss" {
			t.Fatalf("signal source leaked into advisory sources: %s", res)
		}
	}
}

// TestExposureLookupTool exercises exposure_lookup with ecosystem/name
// normalization (PyPI Pillow -> pillow) and the version filter.
func TestExposureLookupTool(t *testing.T) {
	database := openIntelDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cat := `{"schema_version":"0.1.0","entries":[
	  {"id":"MAL-INTEL-1","name":"pillow poisoned","ecosystem":"PyPI","package":"pillow","versions":["9.0.0","9.0.1"],"severity":"critical"}
	]}`
	_, parsed, err := db.ParseBumblebeeCatalog([]byte(cat))
	if err != nil {
		t.Fatalf("parse catalog: %v", err)
	}
	if _, err := database.UpsertExposureCatalog(ctx, "intel-test", "Intel Test", "tester", "0.1.0", []byte(cat), parsed); err != nil {
		t.Fatalf("upsert catalog: %v", err)
	}

	reg := NewRegistry()
	RegisterReferenceTools(reg, database)
	scope := &Scope{Subjects: []string{"user:any"}}

	// Input "Pillow" (mixed case) + version 9.0.0 -> normalized match.
	res, err := reg.Call(WithScope(ctx, scope), scope, "exposure_lookup", map[string]any{"ecosystem": "PyPI", "package": "Pillow", "version": "9.0.0"})
	if err != nil {
		t.Fatalf("exposure_lookup: %v", err)
	}
	var got struct {
		Matched bool `json:"matched"`
		Matches []struct {
			CatalogID string `json:"catalog_id"`
			Version   string `json:"version"`
		} `json:"matches"`
	}
	if err := json.Unmarshal([]byte(res), &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, res)
	}
	if !got.Matched || len(got.Matches) != 1 || got.Matches[0].CatalogID != "MAL-INTEL-1" {
		t.Fatalf("normalized version match wrong: %s", res)
	}

	// A clean version must not match.
	res2, _ := reg.Call(WithScope(ctx, scope), scope, "exposure_lookup", map[string]any{"ecosystem": "pypi", "package": "pillow", "version": "10.0.0"})
	var got2 struct {
		Matched bool `json:"matched"`
	}
	_ = json.Unmarshal([]byte(res2), &got2)
	if got2.Matched {
		t.Fatalf("clean version must not match: %s", res2)
	}
}
