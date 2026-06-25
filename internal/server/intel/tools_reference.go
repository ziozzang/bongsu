package intel

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ziozzang/bongsu/internal/server/db"
)

// Reference-data tools read secdb catalogs (advisories, exposure IOCs) that are
// not scoped to any host, so they are readable by any authenticated caller (a
// non-nil scope). They give the intelligence agent the authoritative advisory
// and supply-chain-compromise context for a CVE or package.

// RegisterReferenceTools registers the host-independent reference tools.
func RegisterReferenceTools(reg *Registry, database *db.DB) {
	reg.Register(&advisoryForTool{db: database})
	reg.Register(&exposureLookupTool{db: database})
}

// DefaultRegistry builds a registry with every built-in intelligence tool
// (reference + host-scoped). This is the toolset the MCP server exposes.
func DefaultRegistry(database *db.DB) *Registry {
	reg := NewRegistry()
	RegisterReferenceTools(reg, database)
	RegisterScopedTools(reg, database)
	return reg
}

// ── advisory_for(cve) ──────────────────────────────────────────────────────

type advisoryForTool struct{ db *db.DB }

func (advisoryForTool) Name() string { return "advisory_for" }
func (advisoryForTool) Description() string {
	return "Return the multi-source advisory metadata for a CVE/advisory id, plus the exploited-in-the-wild (KEV) flag and EPSS exploit-probability signal."
}
func (advisoryForTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"cve":{"type":"string","description":"CVE or advisory id, e.g. CVE-2024-3094"}},"required":["cve"]}`)
}

func (t *advisoryForTool) Call(ctx context.Context, args map[string]any) (string, error) {
	if s := ScopeFromContext(ctx); s == nil {
		return "", ToolError("forbidden: no caller scope")
	}
	cve := argString(args, "cve")
	if cve == "" {
		return "", ToolError("advisory_for requires a 'cve' argument")
	}
	type source struct {
		Source   string  `json:"source"`
		Severity string  `json:"severity"`
		CVSS     float64 `json:"cvss_score"`
		Title    string  `json:"title"`
	}
	out := struct {
		CVE            string   `json:"cve"`
		Exploited      bool     `json:"exploited_kev"`
		EPSSScore      float64  `json:"epss_score"`
		EPSSPercentile float64  `json:"epss_percentile"`
		Sources        []source `json:"sources"`
	}{CVE: cve, Sources: []source{}}

	rows, err := t.db.QueryContext(ctx,
		`SELECT source, COALESCE(severity,''), COALESCE(cvss_score,0), COALESCE(title,'')
		   FROM cve_database
		  WHERE vulnerability_id=$1 AND source IN ('osv','nvd','trivy','custom')
		  ORDER BY cvss_score DESC NULLS LAST`, cve)
	if err != nil {
		return "", fmt.Errorf("advisory_for query: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var s source
		if err := rows.Scan(&s.Source, &s.Severity, &s.CVSS, &s.Title); err != nil {
			return "", err
		}
		out.Sources = append(out.Sources, s)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	_ = t.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM cve_kev WHERE vulnerability_id=$1)`, cve).Scan(&out.Exploited)
	_ = t.db.QueryRowContext(ctx, `SELECT COALESCE(score,0), COALESCE(percentile,0) FROM cve_epss WHERE vulnerability_id=$1`, cve).Scan(&out.EPSSScore, &out.EPSSPercentile)

	return marshalToolResult(out)
}

// ── exposure_lookup(ecosystem, package, version?) ──────────────────────────

type exposureLookupTool struct{ db *db.DB }

func (exposureLookupTool) Name() string { return "exposure_lookup" }
func (exposureLookupTool) Description() string {
	return "Check whether a package (optionally a specific version) matches a known-compromised release in the exposure catalogs (supply-chain IOCs)."
}
func (exposureLookupTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"ecosystem":{"type":"string"},"package":{"type":"string"},"version":{"type":"string","description":"optional exact version"}},"required":["ecosystem","package"]}`)
}

func (t *exposureLookupTool) Call(ctx context.Context, args map[string]any) (string, error) {
	if s := ScopeFromContext(ctx); s == nil {
		return "", ToolError("forbidden: no caller scope")
	}
	ecoIn := argString(args, "ecosystem")
	pkgIn := argString(args, "package")
	version := argString(args, "version")
	if ecoIn == "" || pkgIn == "" {
		return "", ToolError("exposure_lookup requires 'ecosystem' and 'package'")
	}
	eco := db.NormalizeEcosystem(ecoIn)
	norm := db.NormalizePkgName(eco, pkgIn)

	type match struct {
		CatalogID   string `json:"catalog_id"`
		CatalogName string `json:"catalog_name"`
		Version     string `json:"version"`
		Severity    string `json:"severity"`
		Confidence  string `json:"confidence"`
	}
	out := struct {
		Ecosystem string  `json:"ecosystem"`
		Package   string  `json:"package"`
		Version   string  `json:"version,omitempty"`
		Matched   bool    `json:"matched"`
		Matches   []match `json:"matches"`
	}{Ecosystem: eco, Package: norm, Version: version, Matches: []match{}}

	rows, err := t.db.QueryContext(ctx,
		`SELECT e.catalog_id, COALESCE(e.catalog_name,''), e.version, e.severity, e.confidence
		   FROM exposure_catalog_entries e
		   JOIN exposure_catalog_sources s ON s.id=e.source_id AND s.active
		  WHERE e.ecosystem=$1 AND e.normalized_name=$2 AND ($3='' OR e.version=$3)
		  ORDER BY e.version`, eco, norm, version)
	if err != nil {
		return "", fmt.Errorf("exposure_lookup query: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var m match
		if err := rows.Scan(&m.CatalogID, &m.CatalogName, &m.Version, &m.Severity, &m.Confidence); err != nil {
			return "", err
		}
		out.Matches = append(out.Matches, m)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	out.Matched = len(out.Matches) > 0
	return marshalToolResult(out)
}

// marshalToolResult renders a tool's result struct as compact JSON text.
func marshalToolResult(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("marshal tool result: %w", err)
	}
	return string(raw), nil
}
