package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Asset knowledge graph.
//
// This is a typed, read-only semantic projection over the existing inventory and
// CVE tables — NOT a new source of truth. Nodes and edges are derived live from
// the latest scan per host (latestScansSub) so the graph never goes stale.
//
// Ontology (node types and the relations between them):
//
//	host    --runs-->        container
//	host    --installs-->    package      (asset_type='host')
//	container --contains-->  package      (asset_type='container')
//	host    --exposes-->     service      (port_info)
//	host    --member_of-->   group        (asset_group_members)
//	package --affected_by--> cve          (vulnerabilities.vulnerability_id)
//	host    --exposed_to-->  cve          (derived: host has a package affected by cve)
//
// All queries are host-scoped via AccessScope so RBAC visibility is preserved.

// GraphNodeType is one of the ontology entity kinds.
type GraphNodeType string

const (
	NodeHost      GraphNodeType = "host"
	NodeContainer GraphNodeType = "container"
	NodePackage   GraphNodeType = "package"
	NodeService   GraphNodeType = "service"
	NodeCVE       GraphNodeType = "cve"
	NodeGroup     GraphNodeType = "group"
)

// GraphRel is one of the ontology relation kinds.
type GraphRel string

const (
	RelRuns       GraphRel = "runs"
	RelInstalls   GraphRel = "installs"
	RelContains   GraphRel = "contains"
	RelExposes    GraphRel = "exposes"
	RelMemberOf   GraphRel = "member_of"
	RelAffectedBy GraphRel = "affected_by"
	RelExposedTo  GraphRel = "exposed_to"
)

// GraphNode is a single typed entity in the graph.
type GraphNode struct {
	Type  GraphNodeType  `json:"type"`
	ID    string         `json:"id"`
	Label string         `json:"label"`
	Attrs map[string]any `json:"attrs,omitempty"`
}

// GraphEdge is a typed directed relation between two nodes.
type GraphEdge struct {
	Rel     GraphRel       `json:"rel"`
	SrcType GraphNodeType  `json:"src_type"`
	SrcID   string         `json:"src_id"`
	DstType GraphNodeType  `json:"dst_type"`
	DstID   string         `json:"dst_id"`
	Attrs   map[string]any `json:"attrs,omitempty"`
}

// GraphNeighborhood is a root node plus its 1-hop expansion.
type GraphNeighborhood struct {
	Root      GraphNode   `json:"root"`
	Nodes     []GraphNode `json:"nodes"`
	Edges     []GraphEdge `json:"edges"`
	Truncated bool        `json:"truncated"`
}

// GraphOverview holds top-level node/edge counts for the scope.
type GraphOverview struct {
	Nodes map[GraphNodeType]int `json:"nodes"`
	Edges map[GraphRel]int      `json:"edges"`
}

// scopeClause appends a host-scope predicate on the given column. It returns the
// SQL fragment and the (possibly extended) args slice. When scope.All it adds no
// predicate. Callers must check scope.Empty() first.
func scopeClause(scope AccessScope, column string, args []any) (string, []any) {
	if scope.All {
		return "", args
	}
	args = append(args, pqStringArray(scope.HostIDs))
	return fmt.Sprintf(" AND %s = ANY($%d)", column, len(args)), args
}

func clampLimit(limit, def, max int) int {
	if limit <= 0 {
		return def
	}
	if limit > max {
		return max
	}
	return limit
}

// GraphOverviewForScope returns node and edge counts for the visible inventory.
func (db *DB) GraphOverviewForScope(ctx context.Context, scope AccessScope) (GraphOverview, error) {
	ov := GraphOverview{Nodes: map[GraphNodeType]int{}, Edges: map[GraphRel]int{}}
	if scope.Empty() {
		return ov, nil
	}

	// Each entity is constrained to the latest scan per host so historical scans
	// don't inflate counts.
	type countQuery struct {
		key GraphNodeType
		rel GraphRel
		sql string
		col string // scope column
	}
	nodeQueries := []countQuery{
		{key: NodeHost, sql: `SELECT count(*) FROM hosts h WHERE 1=1`, col: "h.id"},
		{key: NodeContainer, sql: `SELECT count(*) FROM container_assets c JOIN ` + latestScansSub + ` ls ON c.scan_id=ls.id WHERE 1=1`, col: "c.host_id"},
		{key: NodePackage, sql: `SELECT count(*) FROM packages p JOIN ` + latestScansSub + ` ls ON p.scan_id=ls.id WHERE 1=1`, col: "p.host_id"},
		{key: NodeService, sql: `SELECT count(*) FROM port_info pi JOIN ` + latestScansSub + ` ls ON pi.scan_id=ls.id WHERE 1=1`, col: "pi.host_id"},
		{key: NodeCVE, sql: `SELECT count(DISTINCT v.vulnerability_id) FROM vulnerabilities v JOIN ` + latestScansSub + ` ls ON v.scan_id=ls.id WHERE 1=1`, col: "v.host_id"},
		{key: NodeGroup, sql: `SELECT count(DISTINCT agm.group_id) FROM asset_group_members agm WHERE 1=1`, col: "agm.host_id"},
	}
	for _, q := range nodeQueries {
		args := []any{}
		clause, args := scopeClause(scope, q.col, args)
		var n int
		if err := db.QueryRowContext(ctx, q.sql+clause, args...).Scan(&n); err != nil {
			return ov, fmt.Errorf("graph overview node %s: %w", q.key, err)
		}
		ov.Nodes[q.key] = n
	}

	edgeQueries := []countQuery{
		{rel: RelRuns, sql: `SELECT count(*) FROM container_assets c JOIN ` + latestScansSub + ` ls ON c.scan_id=ls.id WHERE 1=1`, col: "c.host_id"},
		{rel: RelInstalls, sql: `SELECT count(*) FROM packages p JOIN ` + latestScansSub + ` ls ON p.scan_id=ls.id WHERE p.asset_type='host'`, col: "p.host_id"},
		{rel: RelContains, sql: `SELECT count(*) FROM packages p JOIN ` + latestScansSub + ` ls ON p.scan_id=ls.id WHERE p.asset_type='container'`, col: "p.host_id"},
		{rel: RelExposes, sql: `SELECT count(*) FROM port_info pi JOIN ` + latestScansSub + ` ls ON pi.scan_id=ls.id WHERE 1=1`, col: "pi.host_id"},
		{rel: RelMemberOf, sql: `SELECT count(*) FROM asset_group_members agm WHERE 1=1`, col: "agm.host_id"},
		{rel: RelAffectedBy, sql: `SELECT count(*) FROM vulnerabilities v JOIN ` + latestScansSub + ` ls ON v.scan_id=ls.id WHERE 1=1`, col: "v.host_id"},
		{rel: RelExposedTo, sql: `SELECT count(DISTINCT (v.host_id, v.vulnerability_id)) FROM vulnerabilities v JOIN ` + latestScansSub + ` ls ON v.scan_id=ls.id WHERE 1=1`, col: "v.host_id"},
	}
	for _, q := range edgeQueries {
		args := []any{}
		clause, args := scopeClause(scope, q.col, args)
		var n int
		if err := db.QueryRowContext(ctx, q.sql+clause, args...).Scan(&n); err != nil {
			return ov, fmt.Errorf("graph overview edge %s: %w", q.rel, err)
		}
		ov.Edges[q.rel] = n
	}
	return ov, nil
}

// HostNeighborhood returns a host-centered subgraph: the host plus its containers
// (runs), exposed services (exposes), asset groups (member_of), and the CVEs it is
// exposed to (exposed_to, top by CVSS), with the linking package as an edge attr.
func (db *DB) HostNeighborhood(ctx context.Context, hostID string, scope AccessScope, cveLimit int) (*GraphNeighborhood, error) {
	if scope.Empty() || !scope.CanReadHost(hostID) {
		return nil, nil
	}
	cveLimit = clampLimit(cveLimit, 100, 500)

	root := GraphNode{Type: NodeHost, ID: hostID, Attrs: map[string]any{}}
	var hostname, osName, osVersion, env, crit string
	err := db.QueryRowContext(ctx,
		`SELECT COALESCE(hostname,''), COALESCE(os_name,''), COALESCE(os_version,''), COALESCE(environment,''), COALESCE(criticality,'') FROM hosts WHERE id=$1`,
		hostID).Scan(&hostname, &osName, &osVersion, &env, &crit)
	if err != nil {
		return nil, err
	}
	root.Label = hostname
	if root.Label == "" {
		root.Label = hostID
	}
	root.Attrs["os"] = strings.TrimSpace(osName + " " + osVersion)
	root.Attrs["environment"] = env
	root.Attrs["criticality"] = crit

	nh := &GraphNeighborhood{Root: root, Nodes: []GraphNode{}, Edges: []GraphEdge{}}

	const containerCap, serviceCap, groupCap = 500, 500, 200

	// Containers (runs).
	rows, err := db.QueryContext(ctx,
		`SELECT c.id, COALESCE(NULLIF(c.name,''), c.container_id, c.id), COALESCE(c.image_name,''), COALESCE(c.state,'')
		 FROM container_assets c JOIN `+latestScansSub+` ls ON c.scan_id=ls.id
		 WHERE c.host_id=$1 ORDER BY c.name LIMIT `+fmt.Sprintf("%d", containerCap), hostID)
	if err != nil {
		return nil, err
	}
	n := 0
	for rows.Next() {
		var id, label, image, state string
		if err := rows.Scan(&id, &label, &image, &state); err != nil {
			rows.Close()
			return nil, err
		}
		n++
		nh.Nodes = append(nh.Nodes, GraphNode{Type: NodeContainer, ID: id, Label: label, Attrs: map[string]any{"image": image, "state": state}})
		nh.Edges = append(nh.Edges, GraphEdge{Rel: RelRuns, SrcType: NodeHost, SrcID: hostID, DstType: NodeContainer, DstID: id})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if n >= containerCap {
		nh.Truncated = true
	}

	// Services (exposes).
	rows, err = db.QueryContext(ctx,
		`SELECT pi.id, COALESCE(NULLIF(pi.name,''), pi.protocol || '/' || pi.port::text), pi.port, COALESCE(pi.protocol,'')
		 FROM port_info pi JOIN `+latestScansSub+` ls ON pi.scan_id=ls.id
		 WHERE pi.host_id=$1 ORDER BY pi.port LIMIT `+fmt.Sprintf("%d", serviceCap), hostID)
	if err != nil {
		return nil, err
	}
	n = 0
	for rows.Next() {
		var id, label, proto string
		var port int
		if err := rows.Scan(&id, &label, &port, &proto); err != nil {
			rows.Close()
			return nil, err
		}
		n++
		nh.Nodes = append(nh.Nodes, GraphNode{Type: NodeService, ID: id, Label: label, Attrs: map[string]any{"port": port, "protocol": proto}})
		nh.Edges = append(nh.Edges, GraphEdge{Rel: RelExposes, SrcType: NodeHost, SrcID: hostID, DstType: NodeService, DstID: id})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if n >= serviceCap {
		nh.Truncated = true
	}

	// Groups (member_of).
	rows, err = db.QueryContext(ctx,
		`SELECT ag.id, ag.name FROM asset_group_members agm JOIN asset_groups ag ON ag.id=agm.group_id
		 WHERE agm.host_id=$1 ORDER BY ag.name LIMIT `+fmt.Sprintf("%d", groupCap), hostID)
	if err != nil {
		return nil, err
	}
	n = 0
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			rows.Close()
			return nil, err
		}
		n++
		nh.Nodes = append(nh.Nodes, GraphNode{Type: NodeGroup, ID: id, Label: name})
		nh.Edges = append(nh.Edges, GraphEdge{Rel: RelMemberOf, SrcType: NodeHost, SrcID: hostID, DstType: NodeGroup, DstID: id})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if n >= groupCap {
		nh.Truncated = true
	}

	// CVE exposure (exposed_to), top by CVSS. The most-severe finding per CVE on
	// this host is kept; the linking package travels as an edge attribute.
	rows, err = db.QueryContext(ctx,
		`SELECT vulnerability_id, severity, cvss_score, pkg_name, installed_version, fixed_version
		 FROM (
		   SELECT DISTINCT ON (v.vulnerability_id) v.vulnerability_id,
		          COALESCE(v.severity,'') AS severity, COALESCE(v.cvss_score,0) AS cvss_score,
		          COALESCE(v.pkg_name,'') AS pkg_name, COALESCE(v.installed_version,'') AS installed_version,
		          COALESCE(v.fixed_version,'') AS fixed_version
		   FROM vulnerabilities v JOIN `+latestScansSub+` ls ON v.scan_id=ls.id
		   WHERE v.host_id=$1
		   ORDER BY v.vulnerability_id, v.cvss_score DESC NULLS LAST
		 ) d
		 ORDER BY cvss_score DESC NULLS LAST, vulnerability_id
		 LIMIT $2`, hostID, cveLimit+1)
	if err != nil {
		return nil, err
	}
	cveCount := 0
	for rows.Next() {
		cveCount++
		if cveCount > cveLimit {
			nh.Truncated = true
			continue
		}
		var vid, sev, pkg, iv, fv string
		var cvss float64
		if err := rows.Scan(&vid, &sev, &cvss, &pkg, &iv, &fv); err != nil {
			rows.Close()
			return nil, err
		}
		nh.Nodes = append(nh.Nodes, GraphNode{Type: NodeCVE, ID: vid, Label: vid, Attrs: map[string]any{"severity": sev, "cvss_score": cvss}})
		nh.Edges = append(nh.Edges, GraphEdge{Rel: RelExposedTo, SrcType: NodeHost, SrcID: hostID, DstType: NodeCVE, DstID: vid,
			Attrs: map[string]any{"package": pkg, "installed_version": iv, "fixed_version": fv, "severity": sev, "cvss_score": cvss}})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return nh, nil
}

// BlastRadiusRollup summarizes the impact footprint of a single CVE.
type BlastRadiusRollup struct {
	VulnerabilityID string         `json:"vulnerability_id"`
	Title           string         `json:"title"`
	Severity        string         `json:"severity"`
	CVSSScore       float64        `json:"cvss_score"`
	EPSSScore       float64        `json:"epss_score"`
	HostCount       int            `json:"host_count"`
	ContainerCount  int            `json:"container_count"`
	PackageCount    int            `json:"package_count"`
	GroupCount      int            `json:"group_count"`
	BySeverity      map[string]int `json:"by_severity"`
	ByEnvironment   map[string]int `json:"by_environment"`
	ByCriticality   map[string]int `json:"by_criticality"`
}

// BlastRadius returns the CVE-centered subgraph (cve -> affected hosts, with the
// groups those hosts belong to) plus an impact rollup. hosts are scope-filtered.
func (db *DB) BlastRadius(ctx context.Context, vulnID string, scope AccessScope, hostLimit int) (*GraphNeighborhood, *BlastRadiusRollup, error) {
	if scope.Empty() {
		return nil, nil, nil
	}
	hostLimit = clampLimit(hostLimit, 300, 2000)

	roll := &BlastRadiusRollup{VulnerabilityID: vulnID, BySeverity: map[string]int{}, ByEnvironment: map[string]int{}, ByCriticality: map[string]int{}}
	// CVE catalog metadata (most severe row across sources).
	_ = db.QueryRowContext(ctx,
		`SELECT COALESCE(title,''), COALESCE(severity,''), COALESCE(cvss_score,0), COALESCE(epss_score,0)
		 FROM cve_database WHERE vulnerability_id=$1 ORDER BY cvss_score DESC NULLS LAST LIMIT 1`,
		vulnID).Scan(&roll.Title, &roll.Severity, &roll.CVSSScore, &roll.EPSSScore)

	root := GraphNode{Type: NodeCVE, ID: vulnID, Label: vulnID, Attrs: map[string]any{
		"title": roll.Title, "severity": roll.Severity, "cvss_score": roll.CVSSScore, "epss_score": roll.EPSSScore,
	}}
	nh := &GraphNeighborhood{Root: root, Nodes: []GraphNode{}, Edges: []GraphEdge{}}

	// Aggregate to exactly ONE row per affected host (worst severity by rank, max
	// CVSS, total findings = package edges, distinct impacted containers) so the
	// LIMIT bounds hosts — not (host,severity) groups — and the rollup totals are
	// computed over whole hosts. severityRank ranks CRITICAL>HIGH>MEDIUM>LOW>other.
	args := []any{vulnID}
	clause, args := scopeClause(scope, "v.host_id", args)
	q := `
SELECT d.host_id, COALESCE(h.hostname,''), COALESCE(h.environment,''), COALESCE(h.criticality,''),
       d.severity, d.cvss, d.findings, d.containers
FROM (
  SELECT v.host_id,
         (array_agg(COALESCE(v.severity,'') ORDER BY ` + severityRankSQL("v.severity") + ` DESC, COALESCE(v.cvss_score,0) DESC))[1] AS severity,
         MAX(COALESCE(v.cvss_score,0)) AS cvss,
         count(*) AS findings,
         count(DISTINCT NULLIF(v.container,'')) AS containers
  FROM vulnerabilities v
  JOIN ` + latestScansSub + ` ls ON v.scan_id=ls.id
  WHERE v.vulnerability_id=$1` + clause + `
  GROUP BY v.host_id
) d
LEFT JOIN hosts h ON h.id=d.host_id
ORDER BY d.cvss DESC NULLS LAST, h.hostname
LIMIT ` + fmt.Sprintf("%d", hostLimit+1)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, nil, err
	}
	hostSeen := map[string]bool{}
	hostCount := 0
	for rows.Next() {
		var hid, hostname, env, crit, sev string
		var cvss float64
		var findings, containers int
		if err := rows.Scan(&hid, &hostname, &env, &crit, &sev, &cvss, &findings, &containers); err != nil {
			rows.Close()
			return nil, nil, err
		}
		hostCount++
		if hostCount > hostLimit {
			nh.Truncated = true
			continue
		}
		hostSeen[hid] = true
		roll.PackageCount += findings
		roll.ContainerCount += containers
		label := hostname
		if label == "" {
			label = hid
		}
		nh.Nodes = append(nh.Nodes, GraphNode{Type: NodeHost, ID: hid, Label: label, Attrs: map[string]any{"environment": env, "criticality": crit, "cvss_score": cvss, "severity": sev}})
		nh.Edges = append(nh.Edges, GraphEdge{Rel: RelExposedTo, SrcType: NodeCVE, SrcID: vulnID, DstType: NodeHost, DstID: hid, Attrs: map[string]any{"severity": sev, "cvss_score": cvss}})
		roll.BySeverity[normalizeRollupKey(sev)]++
		roll.ByEnvironment[normalizeRollupKey(env)]++
		roll.ByCriticality[normalizeRollupKey(crit)]++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	roll.HostCount = len(hostSeen)

	// Impacted groups: groups containing any affected host (member_of edges).
	if len(hostSeen) > 0 {
		hostIDs := make([]string, 0, len(hostSeen))
		for h := range hostSeen {
			hostIDs = append(hostIDs, h)
		}
		grows, err := db.QueryContext(ctx,
			`SELECT DISTINCT ag.id, ag.name FROM asset_group_members agm JOIN asset_groups ag ON ag.id=agm.group_id
			 WHERE agm.host_id = ANY($1) ORDER BY ag.name LIMIT 200`, pqStringArray(hostIDs))
		if err != nil {
			return nil, nil, err
		}
		for grows.Next() {
			var id, name string
			if err := grows.Scan(&id, &name); err != nil {
				grows.Close()
				return nil, nil, err
			}
			roll.GroupCount++
			nh.Nodes = append(nh.Nodes, GraphNode{Type: NodeGroup, ID: id, Label: name})
			// member_of edges from each affected host that belongs to this group are
			// resolved lazily by the UI on expand; the group node itself is included
			// here so the blast-radius view shows organizational reach.
		}
		grows.Close()
		if err := grows.Err(); err != nil {
			return nil, nil, err
		}
	}
	return nh, roll, nil
}

// GroupNeighborhood returns a group-centered subgraph: the group plus its member
// hosts (member_of), each annotated with a vulnerability severity rollup.
func (db *DB) GroupNeighborhood(ctx context.Context, groupID string, scope AccessScope, hostLimit int) (*GraphNeighborhood, error) {
	if scope.Empty() {
		return nil, nil
	}
	hostLimit = clampLimit(hostLimit, 300, 2000)

	// Resolve the group name only if the caller can see at least one of its member
	// hosts (or has full scope). Otherwise return nil so the handler reveals
	// nothing — the group's name must not leak across the RBAC boundary.
	var name string
	if scope.All {
		err := db.QueryRowContext(ctx, `SELECT name FROM asset_groups WHERE id=$1`, groupID).Scan(&name)
		if err == sql.ErrNoRows {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
	} else {
		err := db.QueryRowContext(ctx,
			`SELECT ag.name FROM asset_groups ag
			 WHERE ag.id=$1 AND EXISTS (
			   SELECT 1 FROM asset_group_members agm WHERE agm.group_id=ag.id AND agm.host_id = ANY($2)
			 )`, groupID, pqStringArray(scope.HostIDs)).Scan(&name)
		if err == sql.ErrNoRows {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
	}
	root := GraphNode{Type: NodeGroup, ID: groupID, Label: name}
	nh := &GraphNeighborhood{Root: root, Nodes: []GraphNode{}, Edges: []GraphEdge{}}

	args := []any{groupID}
	clause, args := scopeClause(scope, "agm.host_id", args)
	// Pre-aggregate critical/high CVEs for ONLY the group's (scoped) member hosts
	// rather than running a correlated subquery per member, so this scales with the
	// group size, not the whole vulnerability table.
	q := `
WITH members AS (
  SELECT h.id, COALESCE(h.hostname,'') AS hostname, COALESCE(h.environment,'') AS environment, COALESCE(h.criticality,'') AS criticality
  FROM asset_group_members agm
  JOIN hosts h ON h.id=agm.host_id
  WHERE agm.group_id=$1` + clause + `
)
SELECT m.id, m.hostname, m.environment, m.criticality, COALESCE(ch.crit_high,0)
FROM members m
LEFT JOIN (
  SELECT v.host_id, count(DISTINCT v.vulnerability_id) AS crit_high
  FROM vulnerabilities v
  JOIN ` + latestScansSub + ` ls ON v.scan_id=ls.id
  WHERE v.host_id IN (SELECT id FROM members) AND upper(COALESCE(v.severity,'')) IN ('CRITICAL','HIGH')
  GROUP BY v.host_id
) ch ON ch.host_id=m.id
ORDER BY COALESCE(ch.crit_high,0) DESC, m.hostname
LIMIT ` + fmt.Sprintf("%d", hostLimit+1)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	n := 0
	for rows.Next() {
		n++
		var id, hostname, env, crit string
		var critHigh int
		if err := rows.Scan(&id, &hostname, &env, &crit, &critHigh); err != nil {
			rows.Close()
			return nil, err
		}
		if n > hostLimit {
			nh.Truncated = true
			continue
		}
		label := hostname
		if label == "" {
			label = id
		}
		nh.Nodes = append(nh.Nodes, GraphNode{Type: NodeHost, ID: id, Label: label, Attrs: map[string]any{"environment": env, "criticality": crit, "critical_high_cves": critHigh}})
		nh.Edges = append(nh.Edges, GraphEdge{Rel: RelMemberOf, SrcType: NodeHost, SrcID: id, DstType: NodeGroup, DstID: groupID})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return nh, nil
}

// severityRankSQL returns a SQL CASE expression ranking a severity column so the
// worst severity sorts highest. The column name is a constant from this file
// (never user input), so it is safe to interpolate.
func severityRankSQL(col string) string {
	return `CASE upper(COALESCE(` + col + `,'')) ` +
		`WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END`
}

func normalizeRollupKey(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "unknown"
	}
	return strings.ToLower(v)
}
