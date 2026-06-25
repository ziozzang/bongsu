package intel

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ziozzang/bongsu/internal/server/db"
)

// Host-scoped tools read host/asset-specific data and MUST constrain every read
// to the caller's RBAC scope. The scope (intel.Scope: admin + subjects) is
// resolved to a db.AccessScope (all hosts, or an explicit host-id set) via the
// same GetAccessScope/MergeAccessScopes the HTTP layer uses, so the intelligence
// agent can never see a host the caller couldn't see in the UI. A request for a
// specific host/scan outside the scope is denied (model-visible), never widened.

// RegisterScopedTools registers the host-scoped intelligence tools.
func RegisterScopedTools(reg *Registry, database *db.DB) {
	reg.Register(&queryVulnsTool{db: database})
	reg.Register(&dependentsOfTool{db: database})
	reg.Register(&sbomAtTool{db: database})
}

// resolveAccessScope maps a caller scope to a db.AccessScope. Admin sees all;
// otherwise the union of each subject's granted scope. A nil/empty scope yields
// an empty AccessScope (no hosts), i.e. deny.
func resolveAccessScope(ctx context.Context, database *db.DB, s *Scope) (db.AccessScope, error) {
	if s == nil {
		return db.AccessScope{}, ToolError("forbidden: no caller scope")
	}
	if s.Admin {
		return db.AccessScope{All: true}, nil
	}
	scopes := make([]db.AccessScope, 0, len(s.Subjects))
	for _, sub := range s.Subjects {
		sc, err := database.GetAccessScope(ctx, sub)
		if err != nil {
			return db.AccessScope{}, fmt.Errorf("resolve access scope: %w", err)
		}
		scopes = append(scopes, sc)
	}
	return db.MergeAccessScopes(scopes...), nil
}

func scopeAllowsHost(as db.AccessScope, hostID string) bool {
	if as.All {
		return true
	}
	for _, id := range as.HostIDs {
		if id == hostID {
			return true
		}
	}
	return false
}

func (t *baseScoped) scanHost(ctx context.Context, scanID string) (string, error) {
	var hostID string
	err := t.db.QueryRowContext(ctx, `SELECT host_id FROM scans WHERE id=$1`, scanID).Scan(&hostID)
	return hostID, err
}

type baseScoped struct{ db *db.DB }

// ── query_vulns(filter) ─────────────────────────────────────────────────────

type queryVulnsTool struct{ db *db.DB }

func (queryVulnsTool) Name() string { return "query_vulns" }
func (queryVulnsTool) Description() string {
	return "List vulnerability findings the caller may see, filtered by host, severity, ecosystem, package, exploited/EPSS, or CVE-id pattern. Results are scoped to the caller's hosts and capped."
}
func (queryVulnsTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"host_id":{"type":"string"},"severity":{"type":"string"},"ecosystem":{"type":"string"},"pkg_name":{"type":"string"},"vuln_id_like":{"type":"string"},"exploited":{"type":"boolean"},"min_epss":{"type":"number"},"limit":{"type":"integer"}}}`)
}

func (t *queryVulnsTool) Call(ctx context.Context, args map[string]any) (string, error) {
	as, err := resolveAccessScope(ctx, t.db, ScopeFromContext(ctx))
	if err != nil {
		return "", err
	}
	reqHost := argString(args, "host_id")
	if reqHost != "" && !scopeAllowsHost(as, reqHost) {
		return "", ToolError("forbidden: host %s is outside the caller's scope", reqHost)
	}
	f := db.VulnFilter{
		Severity:   argString(args, "severity"),
		Ecosystem:  argString(args, "ecosystem"),
		PkgName:    argString(args, "pkg_name"),
		VulnIDLike: argString(args, "vuln_id_like"),
		Exploited:  argBool(args, "exploited"),
		MinEPSS:    argFloat(args, "min_epss"),
		SortBy:     "risk_score",
		SortDesc:   true,
	}
	switch {
	case reqHost != "":
		f.HostID = reqHost
	case !as.All:
		// No explicit host: constrain to the caller's host set. An empty set with
		// no "all" grant means the caller sees nothing.
		if len(as.HostIDs) == 0 {
			return marshalToolResult(map[string]any{"total": 0, "findings": []any{}})
		}
		f.HostIDs = as.HostIDs
	}
	limit := argInt(args, "limit", 50)
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	vulns, total, err := t.db.ListVulnerabilities(ctx, f, limit, 0)
	if err != nil {
		return "", fmt.Errorf("query_vulns: %w", err)
	}
	type finding struct {
		VulnerabilityID string  `json:"vulnerability_id"`
		PkgName         string  `json:"pkg_name"`
		Severity        string  `json:"severity"`
		CVSS            float64 `json:"cvss_score"`
		HostID          string  `json:"host_id"`
		Installed       string  `json:"installed_version"`
		Fixed           string  `json:"fixed_version"`
		Source          string  `json:"finding_source"`
	}
	findings := make([]finding, 0, len(vulns))
	for i := range vulns {
		v := &vulns[i]
		findings = append(findings, finding{
			VulnerabilityID: v.VulnerabilityID, PkgName: v.PkgName, Severity: v.Severity,
			CVSS: v.CVSSScore, HostID: v.HostID, Installed: v.InstalledVer,
			Fixed: v.FixedVersion, Source: v.FindingSource,
		})
	}
	return marshalToolResult(map[string]any{
		"total":     total,
		"returned":  len(findings),
		"truncated": total > len(findings),
		"findings":  findings,
	})
}

// ── dependents_of(scan_id, package) ─────────────────────────────────────────

type dependentsOfTool struct{ db *db.DB }

func (dependentsOfTool) Name() string { return "dependents_of" }
func (dependentsOfTool) Description() string {
	return "Return the transitive set of packages that depend on a given package within a scan (its dependency blast radius). Scoped to the scan's host."
}
func (dependentsOfTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"scan_id":{"type":"string"},"package":{"type":"string","description":"PURL or package name"}},"required":["scan_id","package"]}`)
}

func (t *dependentsOfTool) Call(ctx context.Context, args map[string]any) (string, error) {
	as, err := resolveAccessScope(ctx, t.db, ScopeFromContext(ctx))
	if err != nil {
		return "", err
	}
	scanID := argString(args, "scan_id")
	pkg := argString(args, "package")
	if scanID == "" || pkg == "" {
		return "", ToolError("dependents_of requires 'scan_id' and 'package'")
	}
	hostID, err := (&baseScoped{db: t.db}).scanHost(ctx, scanID)
	if err != nil {
		return "", ToolError("scan %s not found", scanID)
	}
	if !scopeAllowsHost(as, hostID) {
		return "", ToolError("forbidden: scan %s is outside the caller's scope", scanID)
	}
	key := db.DependencyKey(pkg, pkg)
	dependents, err := t.db.DependentsOf(ctx, scanID, key)
	if err != nil {
		return "", fmt.Errorf("dependents_of: %w", err)
	}
	truncated := false
	if len(dependents) > 200 {
		dependents = dependents[:200]
		truncated = true
	}
	return marshalToolResult(map[string]any{
		"scan_id": scanID, "package": pkg, "count": len(dependents),
		"truncated": truncated, "dependents": dependents,
	})
}

// ── sbom_at(scan_id) ────────────────────────────────────────────────────────

type sbomAtTool struct{ db *db.DB }

func (sbomAtTool) Name() string { return "sbom_at" }
func (sbomAtTool) Description() string {
	return "Return SBOM provenance metadata (format, component count, source) for a scan. Scoped to the scan's host."
}
func (sbomAtTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"scan_id":{"type":"string"},"format":{"type":"string","description":"cyclonedx|spdx (default cyclonedx)"}},"required":["scan_id"]}`)
}

func (t *sbomAtTool) Call(ctx context.Context, args map[string]any) (string, error) {
	as, err := resolveAccessScope(ctx, t.db, ScopeFromContext(ctx))
	if err != nil {
		return "", err
	}
	scanID := argString(args, "scan_id")
	if scanID == "" {
		return "", ToolError("sbom_at requires 'scan_id'")
	}
	hostID, err := (&baseScoped{db: t.db}).scanHost(ctx, scanID)
	if err != nil {
		return "", ToolError("scan %s not found", scanID)
	}
	if !scopeAllowsHost(as, hostID) {
		return "", ToolError("forbidden: scan %s is outside the caller's scope", scanID)
	}
	format := argString(args, "format")
	if format == "" {
		format = "cyclonedx"
	}
	sbom, err := t.db.GetScanSBOM(ctx, scanID, format)
	if err != nil {
		return marshalToolResult(map[string]any{"scan_id": scanID, "available": false})
	}
	return marshalToolResult(map[string]any{
		"scan_id": scanID, "available": true, "format": sbom.Format, "origin": sbom.Origin,
		"component_count": sbom.ComponentCount, "spec_version": sbom.SpecVersion, "source_ref": sbom.SourceRef,
	})
}

func argBool(args map[string]any, key string) bool {
	if v, ok := args[key].(bool); ok {
		return v
	}
	return false
}

func argFloat(args map[string]any, key string) float64 {
	switch v := args[key].(type) {
	case float64:
		return v
	case json.Number:
		f, _ := v.Float64()
		return f
	}
	return 0
}

func argInt(args map[string]any, key string, def int) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	}
	return def
}
