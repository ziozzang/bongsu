package db

import (
	"context"
	"fmt"
)

// Knowledge graph extensions: network-reachability, image dedup, exploit/alias
// enrichment, and organizational / remediation / governance rollups. Same design
// rules as graph.go — read-only, latest-scan constrained, RBAC host-scoped.

const (
	NodeProcess     GraphNodeType = "process"
	NodeImage       GraphNodeType = "image"
	NodeTeam        GraphNodeType = "team"
	NodeEnvironment GraphNodeType = "environment"
)

const (
	RelServedBy      GraphRel = "served_by"      // service -> process
	RelBuiltFrom     GraphRel = "built_from"     // container -> image
	RelImageContains GraphRel = "image_contains" // image -> package
	RelRunsOn        GraphRel = "runs_on"        // image -> host
	RelOwnedBy       GraphRel = "owned_by"       // host -> team
	RelInEnvironment GraphRel = "in_environment" // host -> environment
	RelSameAs        GraphRel = "same_as"        // cve -> cve (alias)
)

// kevCTE materializes the small set of known-exploited (CISA KEV) vulnerability
// IDs once per query so KEV membership becomes a hash semijoin (LEFT JOIN kev ...
// kev.vulnerability_id IS NOT NULL) instead of a correlated EXISTS evaluated per
// row. Backed by the partial index idx_cve_database_kev_vuln.
const kevCTE = `kev AS (SELECT vulnerability_id FROM cve_kev)`

// CVESignal is the per-CVE exploit/risk enrichment.
type CVESignal struct {
	KnownExploited bool    `json:"known_exploited"`
	EPSSScore      float64 `json:"epss_score"`
}

// CVESignals batch-fetches KEV (known-exploited) and EPSS for the given
// vulnerability IDs. Missing IDs are simply absent from the map.
func (db *DB) CVESignals(ctx context.Context, vids []string) (map[string]CVESignal, error) {
	out := map[string]CVESignal{}
	if len(vids) == 0 {
		return out, nil
	}
	rows, err := db.QueryContext(ctx, `
SELECT vulnerability_id,
       bool_or(is_kev) AS kev,
       COALESCE(MAX(epss),0) AS epss
FROM (
    SELECT vulnerability_id, true AS is_kev, 0::real AS epss FROM cve_kev WHERE vulnerability_id = ANY($1)
    UNION ALL
    SELECT vulnerability_id, false, score FROM cve_epss WHERE vulnerability_id = ANY($1)
) s
GROUP BY vulnerability_id`, pqStringArray(vids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var vid string
		var sig CVESignal
		if err := rows.Scan(&vid, &sig.KnownExploited, &sig.EPSSScore); err != nil {
			return nil, err
		}
		out[vid] = sig
	}
	return out, rows.Err()
}

// CVEAliases returns the other vulnerability IDs that share a normalized
// reference key with vid (CVE <-> GHSA <-> DSA/DEBIAN equivalence). Bounded.
func (db *DB) CVEAliases(ctx context.Context, vid string) ([]string, error) {
	rows, err := db.QueryContext(ctx, `
WITH keys AS (
  SELECT DISTINCT crk.reference_key
  FROM cve_database cd JOIN cve_reference_keys crk ON crk.cve_id=cd.id
  WHERE cd.vulnerability_id=$1
)
SELECT DISTINCT cd2.vulnerability_id
FROM cve_reference_keys crk2
JOIN cve_database cd2 ON cd2.id=crk2.cve_id
WHERE crk2.reference_key IN (SELECT reference_key FROM keys)
  AND cd2.vulnerability_id <> $1
ORDER BY cd2.vulnerability_id
LIMIT 50`, vid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ExposedService is a network-bound (non-loopback) listening service, joined to
// its backing process (by pid) and annotated with its host's vulnerability risk.
type ExposedService struct {
	HostID           string `json:"host_id"`
	Hostname         string `json:"hostname"`
	Environment      string `json:"environment"`
	Criticality      string `json:"criticality"`
	Address          string `json:"address"`
	Port             int    `json:"port"`
	Protocol         string `json:"protocol"`
	ServiceName      string `json:"service_name"`
	Pid              int    `json:"pid"`
	ProcessName      string `json:"process_name"`
	ProcessUser      string `json:"process_user"`
	Cmdline          string `json:"cmdline"`
	HostCriticalHigh int    `json:"host_critical_high"`
	HostKnownExploit bool   `json:"host_known_exploited"`
}

// ExposedServices ranks network-reachable services by their host's risk so the
// "internet-exposed + vulnerable" attack surface surfaces first. A service is
// considered exposed when bound to a non-loopback address.
func (db *DB) ExposedServices(ctx context.Context, scope AccessScope, limit int) ([]ExposedService, error) {
	if scope.Empty() {
		return []ExposedService{}, nil
	}
	limit = clampLimit(limit, 200, 2000)
	args := []any{}
	clause, args := scopeClause(scope, "pi.host_id", args)
	q := `
WITH ` + kevCTE + `,
exposed AS (
  SELECT pi.host_id, pi.address, pi.port, pi.protocol, pi.name AS service_name, pi.pid
  FROM port_info pi
  JOIN ` + latestScansSub + ` ls ON pi.scan_id=ls.id
  WHERE pi.address NOT IN ('127.0.0.1','::1','0:0:0:0:0:0:0:1','localhost','')
    AND pi.address NOT LIKE '127.%' AND pi.address NOT LIKE '::ffff:127.%'` + clause + `
),
hostrisk AS (
  SELECT v.host_id,
         count(DISTINCT v.vulnerability_id) FILTER (WHERE upper(COALESCE(v.severity,'')) IN ('CRITICAL','HIGH')) AS crit_high,
         bool_or(kev.vulnerability_id IS NOT NULL) AS kev
  FROM vulnerabilities v
  JOIN ` + latestScansSub + ` ls ON v.scan_id=ls.id
  LEFT JOIN kev ON kev.vulnerability_id=v.vulnerability_id
  WHERE v.host_id IN (SELECT DISTINCT host_id FROM exposed)
  GROUP BY v.host_id
)
SELECT e.host_id, COALESCE(h.hostname,''), COALESCE(h.environment,''), COALESCE(h.criticality,''),
       e.address, e.port, COALESCE(e.protocol,''), COALESCE(e.service_name,''), COALESCE(e.pid,0),
       COALESCE(ps.name,''), COALESCE(ps.process_user,''), COALESCE(ps.cmdline,''),
       COALESCE(hr.crit_high,0), COALESCE(hr.kev,false)
FROM exposed e
LEFT JOIN hosts h ON h.id=e.host_id
LEFT JOIN hostrisk hr ON hr.host_id=e.host_id
LEFT JOIN LATERAL (
  SELECT ps.name, ps.user_name AS process_user, ps.cmdline
  FROM process_snapshots ps
  JOIN ` + latestScansSub + ` ls ON ps.scan_id=ls.id
  WHERE ps.host_id=e.host_id AND ps.pid=e.pid AND e.pid>0
  LIMIT 1
) ps ON true
ORDER BY COALESCE(hr.kev,false) DESC, COALESCE(hr.crit_high,0) DESC, h.hostname, e.port
LIMIT ` + fmt.Sprintf("%d", limit)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ExposedService{}
	for rows.Next() {
		var s ExposedService
		if err := rows.Scan(&s.HostID, &s.Hostname, &s.Environment, &s.Criticality,
			&s.Address, &s.Port, &s.Protocol, &s.ServiceName, &s.Pid,
			&s.ProcessName, &s.ProcessUser, &s.Cmdline,
			&s.HostCriticalHigh, &s.HostKnownExploit); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ImageExposure is a container image deduplicated by digest, with its fan-out and
// vulnerability footprint across the visible inventory.
type ImageExposure struct {
	Digest         string  `json:"digest"`
	ImageName      string  `json:"image_name"`
	HostCount      int     `json:"host_count"`
	ContainerCount int     `json:"container_count"`
	PackageCount   int     `json:"package_count"`
	CVECount       int     `json:"cve_count"`
	CriticalHigh   int     `json:"critical_high"`
	MaxCVSS        float64 `json:"max_cvss"`
	KnownExploited bool    `json:"known_exploited"`
}

// Images lists container images (by digest) ranked by vulnerability footprint, so
// patching one image to fix many hosts/containers can be prioritized.
func (db *DB) Images(ctx context.Context, scope AccessScope, limit int) ([]ImageExposure, error) {
	if scope.Empty() {
		return []ImageExposure{}, nil
	}
	limit = clampLimit(limit, 200, 1000)
	args := []any{}
	clause, args := scopeClause(scope, "c.host_id", args)
	// Reliable, scope-safe linkage:
	//  - cimgs: scoped containers (latest scan) grouped under their image digest.
	//  - cpkgs: their container packages joined by (host_id, scan_id, container_id)
	//    — NOT packages.asset_id, which holds the runtime container id, not the
	//    container_assets row id.
	//  - cvuln: vulnerabilities joined to those packages by package_id (the real
	//    FK), not the free-text v.container, so counts can't pull rows from other
	//    hosts/images. Everything descends from the scoped cimgs CTE, so no leak.
	q := `
WITH ` + kevCTE + `,
cimgs AS (
  SELECT c.host_id, c.scan_id, c.container_id, c.id AS container_row_id,
         COALESCE(NULLIF(c.image_digest,''), c.image_name) AS digest, c.image_name
  FROM container_assets c
  JOIN ` + latestScansSub + ` ls ON c.scan_id=ls.id
  WHERE COALESCE(NULLIF(c.image_digest,''), c.image_name) <> ''` + clause + `
),
cpkgs AS (
  SELECT ci.digest, p.id AS package_id
  FROM cimgs ci
  JOIN packages p
    ON p.asset_type='container' AND p.host_id=ci.host_id AND p.scan_id=ci.scan_id
   AND p.container_id <> '' AND p.container_id=ci.container_id
),
cvuln AS (
  SELECT cp.digest, v.vulnerability_id, v.severity, COALESCE(v.cvss_score,0) AS cvss_score,
         (kev.vulnerability_id IS NOT NULL) AS is_kev
  FROM cpkgs cp
  JOIN vulnerabilities v ON v.package_id=cp.package_id
  JOIN ` + latestScansSub + ` ls ON v.scan_id=ls.id
  LEFT JOIN kev ON kev.vulnerability_id=v.vulnerability_id
)
SELECT g.digest, COALESCE(g.image_name,''), g.host_count, g.container_count,
       COALESCE(pc.package_count,0), COALESCE(vc.cve_count,0), COALESCE(vc.crit_high,0),
       COALESCE(vc.max_cvss,0), COALESCE(vc.kev,false)
FROM (
  SELECT digest, MAX(image_name) AS image_name,
         count(DISTINCT host_id) AS host_count,
         count(DISTINCT container_row_id) AS container_count
  FROM cimgs GROUP BY digest
) g
LEFT JOIN (SELECT digest, count(*) AS package_count FROM cpkgs GROUP BY digest) pc ON pc.digest=g.digest
LEFT JOIN (
  SELECT digest, count(DISTINCT vulnerability_id) AS cve_count,
         count(DISTINCT vulnerability_id) FILTER (WHERE upper(COALESCE(severity,'')) IN ('CRITICAL','HIGH')) AS crit_high,
         MAX(cvss_score) AS max_cvss,
         bool_or(is_kev) AS kev
  FROM cvuln GROUP BY digest
) vc ON vc.digest=g.digest
ORDER BY COALESCE(vc.kev,false) DESC, COALESCE(vc.crit_high,0) DESC, COALESCE(vc.max_cvss,0) DESC, g.host_count DESC
LIMIT ` + fmt.Sprintf("%d", limit)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ImageExposure{}
	for rows.Next() {
		var im ImageExposure
		if err := rows.Scan(&im.Digest, &im.ImageName, &im.HostCount, &im.ContainerCount,
			&im.PackageCount, &im.CVECount, &im.CriticalHigh, &im.MaxCVSS, &im.KnownExploited); err != nil {
			return nil, err
		}
		out = append(out, im)
	}
	return out, rows.Err()
}

// OrgExposureRow is one organizational dimension value with its exposure rollup.
type OrgExposureRow struct {
	Key            string `json:"key"`
	HostCount      int    `json:"host_count"`
	CriticalHigh   int    `json:"critical_high"`
	KnownExploited int    `json:"known_exploited_hosts"`
}

// OrgExposure rolls vulnerability exposure up by team, environment, and
// criticality so ownership and risk concentration are visible.
type OrgExposure struct {
	ByTeam        []OrgExposureRow `json:"by_team"`
	ByEnvironment []OrgExposureRow `json:"by_environment"`
	ByCriticality []OrgExposureRow `json:"by_criticality"`
}

func (db *DB) OrgExposure(ctx context.Context, scope AccessScope) (*OrgExposure, error) {
	out := &OrgExposure{ByTeam: []OrgExposureRow{}, ByEnvironment: []OrgExposureRow{}, ByCriticality: []OrgExposureRow{}}
	if scope.Empty() {
		return out, nil
	}
	dims := []struct {
		col  string
		dest *[]OrgExposureRow
	}{
		{"COALESCE(NULLIF(h.team,''),'(unassigned)')", &out.ByTeam},
		{"COALESCE(NULLIF(h.environment,''),'(unknown)')", &out.ByEnvironment},
		{"COALESCE(NULLIF(h.criticality,''),'(unknown)')", &out.ByCriticality},
	}
	for _, d := range dims {
		args := []any{}
		clause, args := scopeClause(scope, "h.id", args)
		q := `
WITH ` + kevCTE + `,
hostrisk AS (
  SELECT v.host_id,
         count(DISTINCT v.vulnerability_id) FILTER (WHERE upper(COALESCE(v.severity,'')) IN ('CRITICAL','HIGH')) AS crit_high,
         bool_or(kev.vulnerability_id IS NOT NULL) AS kev
  FROM vulnerabilities v JOIN ` + latestScansSub + ` ls ON v.scan_id=ls.id
  LEFT JOIN kev ON kev.vulnerability_id=v.vulnerability_id
  GROUP BY v.host_id
)
SELECT ` + d.col + ` AS k, count(*) AS hosts,
       COALESCE(SUM(hr.crit_high),0) AS crit_high,
       count(*) FILTER (WHERE COALESCE(hr.kev,false)) AS kev_hosts
FROM hosts h
LEFT JOIN hostrisk hr ON hr.host_id=h.id
WHERE 1=1` + clause + `
GROUP BY k
ORDER BY crit_high DESC, hosts DESC
LIMIT 100`
		rows, err := db.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var r OrgExposureRow
			if err := rows.Scan(&r.Key, &r.HostCount, &r.CriticalHigh, &r.KnownExploited); err != nil {
				rows.Close()
				return nil, err
			}
			*d.dest = append(*d.dest, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// RemediationRow is a single highest-leverage fix: upgrading one package to a
// fixed version clears CVECount CVEs across HostCount hosts.
type RemediationRow struct {
	PackageName    string  `json:"package_name"`
	Ecosystem      string  `json:"ecosystem"`
	FixedVersion   string  `json:"fixed_version"`
	CVECount       int     `json:"cve_count"`
	HostCount      int     `json:"host_count"`
	CriticalHigh   int     `json:"critical_high"`
	MaxCVSS        float64 `json:"max_cvss"`
	KnownExploited bool    `json:"known_exploited"`
}

// Remediation ranks (package, fixed_version) upgrades by leverage: how many CVEs
// across how many hosts a single upgrade would clear. Only findings that carry a
// concrete fixed_version are actionable.
func (db *DB) Remediation(ctx context.Context, scope AccessScope, limit int) ([]RemediationRow, error) {
	if scope.Empty() {
		return []RemediationRow{}, nil
	}
	limit = clampLimit(limit, 100, 1000)
	args := []any{}
	clause, args := scopeClause(scope, "v.host_id", args)
	q := `
WITH ` + kevCTE + `
SELECT COALESCE(v.pkg_name,'') AS pkg,
       COALESCE((SELECT p.ecosystem FROM packages p WHERE p.id=v.package_id),'') AS eco,
       v.fixed_version,
       count(DISTINCT v.vulnerability_id) AS cve_count,
       count(DISTINCT v.host_id) AS host_count,
       count(DISTINCT v.vulnerability_id) FILTER (WHERE upper(COALESCE(v.severity,'')) IN ('CRITICAL','HIGH')) AS crit_high,
       MAX(COALESCE(v.cvss_score,0)) AS max_cvss,
       bool_or(kev.vulnerability_id IS NOT NULL) AS kev
FROM vulnerabilities v
JOIN ` + latestScansSub + ` ls ON v.scan_id=ls.id
LEFT JOIN kev ON kev.vulnerability_id=v.vulnerability_id
WHERE COALESCE(v.fixed_version,'') <> '' AND COALESCE(v.pkg_name,'') <> ''` + clause + `
GROUP BY v.pkg_name, eco, v.fixed_version
ORDER BY kev DESC, crit_high DESC, cve_count DESC, host_count DESC
LIMIT ` + fmt.Sprintf("%d", limit)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RemediationRow{}
	for rows.Next() {
		var r RemediationRow
		if err := rows.Scan(&r.PackageName, &r.Ecosystem, &r.FixedVersion, &r.CVECount,
			&r.HostCount, &r.CriticalHigh, &r.MaxCVSS, &r.KnownExploited); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
