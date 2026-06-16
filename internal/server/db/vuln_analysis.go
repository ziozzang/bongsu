package db

import (
	"context"
	"fmt"
	"time"
)

// AnalysisCandidate is a finding plus the grounding facts an LLM needs to assess
// it. All facts come from the database — the model is never asked to recall CVE
// details, only to reason over these.
type AnalysisCandidate struct {
	VulnerabilityID    string
	PkgName            string
	HostID             string
	Hostname           string
	Severity           string
	CVSSScore          float64
	EPSSScore          float64
	KnownExploited     bool
	InstalledVersion   string
	FixedVersion       string
	Ecosystem          string
	Environment        string
	Criticality        string
	Title              string
	Description        string
	HostNetworkExposed bool
	StoredInputHash    string // input_hash of an existing analysis (empty if none)
}

// VulnAnalysis is a stored AI assessment of a finding.
type VulnAnalysis struct {
	ID                  string    `json:"id"`
	VulnerabilityID     string    `json:"vulnerability_id"`
	PkgName             string    `json:"pkg_name"`
	HostID              string    `json:"host_id"`
	Provider            string    `json:"provider"`
	Model               string    `json:"model"`
	RiskLevel           string    `json:"risk_level"`
	LikelyFalsePositive bool      `json:"likely_false_positive"`
	Exploitability      string    `json:"exploitability"`
	RecommendedAction   string    `json:"recommended_action"`
	Reasoning           string    `json:"reasoning"`
	Confidence          float64   `json:"confidence"`
	AutoApplied         bool      `json:"auto_applied"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

const loopbackAddrPredicate = `pi.address NOT IN ('127.0.0.1','::1','0:0:0:0:0:0:0:1','localhost','') AND pi.address NOT LIKE '127.%' AND pi.address NOT LIKE '::ffff:127.%'`

// ListAnalysisCandidates returns the highest-priority not-yet-analyzed findings
// (known-exploited first, then critical/high, then CVSS) with their grounding
// facts. Constrained to the latest scan per host.
func (db *DB) ListAnalysisCandidates(ctx context.Context, limit int) ([]AnalysisCandidate, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	q := `
WITH ls AS MATERIALIZED ` + latestScansSub + `,
kev AS (SELECT DISTINCT vulnerability_id FROM cve_database WHERE source='cisa-kev')
SELECT v.vulnerability_id, COALESCE(v.pkg_name,''), v.host_id, COALESCE(h.hostname,''),
       COALESCE(v.severity,''), COALESCE(v.cvss_score,0),
       COALESCE((SELECT MAX(epss_score) FROM cve_database WHERE vulnerability_id=v.vulnerability_id),0),
       (kev.vulnerability_id IS NOT NULL),
       COALESCE(v.installed_version,''), COALESCE(v.fixed_version,''),
       COALESCE((SELECT p.ecosystem FROM packages p WHERE p.id=v.package_id),''),
       COALESCE(h.environment,''), COALESCE(h.criticality,''),
       COALESCE(cd.title,''), COALESCE(cd.description,''),
       EXISTS(SELECT 1 FROM port_info pi JOIN ls ls2 ON pi.scan_id=ls2.id WHERE pi.host_id=v.host_id AND ` + loopbackAddrPredicate + `),
       COALESCE(va.input_hash,'')
FROM vulnerabilities v
JOIN ls ON v.scan_id=ls.id
LEFT JOIN hosts h ON h.id=v.host_id
LEFT JOIN kev ON kev.vulnerability_id=v.vulnerability_id
LEFT JOIN LATERAL (
  SELECT title, description FROM cve_database
  WHERE vulnerability_id=v.vulnerability_id
  ORDER BY length(COALESCE(description,'')) DESC NULLS LAST LIMIT 1
) cd ON true
LEFT JOIN vulnerability_analysis va
  ON va.vulnerability_id=v.vulnerability_id AND va.pkg_name=COALESCE(v.pkg_name,'') AND va.host_id=v.host_id
-- Un-analyzed findings first, then by priority. Already-analyzed rows are still
-- returned (with their stored input_hash) so the worker can re-analyze them when
-- the grounding facts have changed; it skips ones whose hash still matches.
ORDER BY (va.id IS NULL) DESC,
         (kev.vulnerability_id IS NOT NULL) DESC,
         (upper(COALESCE(v.severity,'')) IN ('CRITICAL','HIGH')) DESC,
         COALESCE(v.cvss_score,0) DESC
LIMIT ` + fmt.Sprintf("%d", limit)
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list analysis candidates: %w", err)
	}
	defer rows.Close()
	out := []AnalysisCandidate{}
	for rows.Next() {
		var c AnalysisCandidate
		if err := rows.Scan(&c.VulnerabilityID, &c.PkgName, &c.HostID, &c.Hostname,
			&c.Severity, &c.CVSSScore, &c.EPSSScore, &c.KnownExploited,
			&c.InstalledVersion, &c.FixedVersion, &c.Ecosystem,
			&c.Environment, &c.Criticality, &c.Title, &c.Description, &c.HostNetworkExposed, &c.StoredInputHash); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetAnalysisCandidate fetches the grounding facts for one specific finding (for
// on-demand single-finding analysis from the UI).
func (db *DB) GetAnalysisCandidate(ctx context.Context, vulnID, pkgName, hostID string) (*AnalysisCandidate, error) {
	q := `
WITH ls AS MATERIALIZED ` + latestScansSub + `,
kev AS (SELECT DISTINCT vulnerability_id FROM cve_database WHERE source='cisa-kev')
SELECT v.vulnerability_id, COALESCE(v.pkg_name,''), v.host_id, COALESCE(h.hostname,''),
       COALESCE(v.severity,''), COALESCE(v.cvss_score,0),
       COALESCE((SELECT MAX(epss_score) FROM cve_database WHERE vulnerability_id=v.vulnerability_id),0),
       (kev.vulnerability_id IS NOT NULL),
       COALESCE(v.installed_version,''), COALESCE(v.fixed_version,''),
       COALESCE((SELECT p.ecosystem FROM packages p WHERE p.id=v.package_id),''),
       COALESCE(h.environment,''), COALESCE(h.criticality,''),
       COALESCE(cd.title,''), COALESCE(cd.description,''),
       EXISTS(SELECT 1 FROM port_info pi JOIN ls ls2 ON pi.scan_id=ls2.id WHERE pi.host_id=v.host_id AND ` + loopbackAddrPredicate + `)
FROM vulnerabilities v
JOIN ls ON v.scan_id=ls.id
LEFT JOIN hosts h ON h.id=v.host_id
LEFT JOIN kev ON kev.vulnerability_id=v.vulnerability_id
LEFT JOIN LATERAL (
  SELECT title, description FROM cve_database
  WHERE vulnerability_id=v.vulnerability_id
  ORDER BY length(COALESCE(description,'')) DESC NULLS LAST LIMIT 1
) cd ON true
WHERE v.vulnerability_id=$1 AND COALESCE(v.pkg_name,'')=$2 AND v.host_id=$3
LIMIT 1`
	var c AnalysisCandidate
	err := db.QueryRowContext(ctx, q, vulnID, pkgName, hostID).Scan(
		&c.VulnerabilityID, &c.PkgName, &c.HostID, &c.Hostname,
		&c.Severity, &c.CVSSScore, &c.EPSSScore, &c.KnownExploited,
		&c.InstalledVersion, &c.FixedVersion, &c.Ecosystem,
		&c.Environment, &c.Criticality, &c.Title, &c.Description, &c.HostNetworkExposed)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// UpsertVulnAnalysis stores (or refreshes) the analysis for a finding.
func (db *DB) UpsertVulnAnalysis(ctx context.Context, a *VulnAnalysis, inputHash string) error {
	_, err := db.ExecContext(ctx, `
INSERT INTO vulnerability_analysis
  (vulnerability_id, pkg_name, host_id, input_hash, provider, model, risk_level,
   likely_false_positive, exploitability, recommended_action, reasoning, confidence, auto_applied, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13, now())
ON CONFLICT (vulnerability_id, pkg_name, host_id) DO UPDATE SET
  input_hash=EXCLUDED.input_hash, provider=EXCLUDED.provider, model=EXCLUDED.model,
  risk_level=EXCLUDED.risk_level, likely_false_positive=EXCLUDED.likely_false_positive,
  exploitability=EXCLUDED.exploitability, recommended_action=EXCLUDED.recommended_action,
  reasoning=EXCLUDED.reasoning, confidence=EXCLUDED.confidence, auto_applied=EXCLUDED.auto_applied,
  updated_at=now()`,
		a.VulnerabilityID, a.PkgName, a.HostID, inputHash, a.Provider, a.Model, a.RiskLevel,
		a.LikelyFalsePositive, a.Exploitability, a.RecommendedAction, a.Reasoning, a.Confidence, a.AutoApplied)
	if err != nil {
		return fmt.Errorf("upsert vuln analysis: %w", err)
	}
	return nil
}

// GetVulnAnalysis returns the stored analysis for one finding (or nil).
func (db *DB) GetVulnAnalysis(ctx context.Context, vulnID, pkgName, hostID string) (*VulnAnalysis, error) {
	var a VulnAnalysis
	err := db.QueryRowContext(ctx, `
SELECT id, vulnerability_id, pkg_name, host_id, provider, model, risk_level,
       likely_false_positive, exploitability, recommended_action, reasoning, confidence, auto_applied, created_at, updated_at
FROM vulnerability_analysis WHERE vulnerability_id=$1 AND pkg_name=$2 AND host_id=$3`,
		vulnID, pkgName, hostID).Scan(&a.ID, &a.VulnerabilityID, &a.PkgName, &a.HostID, &a.Provider, &a.Model,
		&a.RiskLevel, &a.LikelyFalsePositive, &a.Exploitability, &a.RecommendedAction, &a.Reasoning, &a.Confidence,
		&a.AutoApplied, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// GetVulnAnalysisByID returns a stored analysis by its row id.
func (db *DB) GetVulnAnalysisByID(ctx context.Context, id string) (*VulnAnalysis, error) {
	var a VulnAnalysis
	err := db.QueryRowContext(ctx, `
SELECT id, vulnerability_id, pkg_name, host_id, provider, model, risk_level,
       likely_false_positive, exploitability, recommended_action, reasoning, confidence, auto_applied, created_at, updated_at
FROM vulnerability_analysis WHERE id=$1`, id).Scan(
		&a.ID, &a.VulnerabilityID, &a.PkgName, &a.HostID, &a.Provider, &a.Model,
		&a.RiskLevel, &a.LikelyFalsePositive, &a.Exploitability, &a.RecommendedAction, &a.Reasoning, &a.Confidence,
		&a.AutoApplied, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// ListVulnAnalyses returns recent analyses, optionally filtered by recommended
// action, newest first.
func (db *DB) ListVulnAnalyses(ctx context.Context, action string, limit int) ([]VulnAnalysis, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	args := []any{}
	filter := ""
	if action != "" {
		args = append(args, action)
		filter = " WHERE recommended_action=$1"
	}
	rows, err := db.QueryContext(ctx, `
SELECT id, vulnerability_id, pkg_name, host_id, provider, model, risk_level,
       likely_false_positive, exploitability, recommended_action, reasoning, confidence, auto_applied, created_at, updated_at
FROM vulnerability_analysis`+filter+`
ORDER BY (recommended_action IN ('patch','investigate')) DESC, confidence DESC, updated_at DESC
LIMIT `+fmt.Sprintf("%d", limit), args...)
	if err != nil {
		return nil, fmt.Errorf("list vuln analyses: %w", err)
	}
	defer rows.Close()
	out := []VulnAnalysis{}
	for rows.Next() {
		var a VulnAnalysis
		if err := rows.Scan(&a.ID, &a.VulnerabilityID, &a.PkgName, &a.HostID, &a.Provider, &a.Model,
			&a.RiskLevel, &a.LikelyFalsePositive, &a.Exploitability, &a.RecommendedAction, &a.Reasoning, &a.Confidence,
			&a.AutoApplied, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CountVulnAnalysesByAction returns counts grouped by recommended_action for
// metrics/overview.
func (db *DB) CountVulnAnalysesByAction(ctx context.Context) (map[string]int, error) {
	rows, err := db.QueryContext(ctx, `SELECT recommended_action, count(*) FROM vulnerability_analysis GROUP BY recommended_action`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rows.Err()
}
