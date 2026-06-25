package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// BumblebeeCatalog is the on-disk exposure-catalog format absorbed from
// perplexityai/bumblebee (Apache-2.0): a list of known-compromised package
// releases.
type BumblebeeCatalog struct {
	SchemaVersion string           `json:"schema_version"`
	Entries       []BumblebeeEntry `json:"entries"`
}

type BumblebeeEntry struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Ecosystem string   `json:"ecosystem"`
	Package   string   `json:"package"`
	Versions  []string `json:"versions"`
	Severity  string   `json:"severity"`
}

// ExposureCatalogSource is one uploaded catalog file.
type ExposureCatalogSource struct {
	ID          int64     `json:"id"`
	SourceName  string    `json:"source_name"`
	DisplayName string    `json:"display_name"`
	SchemaVer   string    `json:"schema_version"`
	EntryCount  int       `json:"entry_count"`
	Checksum    string    `json:"checksum_sha256"`
	UploadedBy  string    `json:"uploaded_by"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

var pypiNameSepRe = regexp.MustCompile(`[-_.]+`)

// normalizePkgName is the Go twin of the SQL bongsu_normalize_pkg_name function
// (migration 071); the two MUST agree (asserted by tests). eco is the already
// normalized ecosystem family (see normalizeEcosystem).
func normalizePkgName(eco, name string) string {
	name = strings.TrimSpace(name)
	switch eco {
	case "pypi":
		return pypiNameSepRe.ReplaceAllString(strings.ToLower(name), "-")
	case "maven":
		return name // Maven coordinates are case-sensitive
	default:
		return strings.ToLower(name)
	}
}

// ParseBumblebeeCatalog parses and flattens a catalog into per-version entries
// ready for storage. Entries with no enumerated versions are skipped (bumblebee
// rule: a version-range-only record is not an exact-match IOC). Ecosystem and
// name are normalized so the stored tuple matches a normalized package directly.
func ParseBumblebeeCatalog(data []byte) (BumblebeeCatalog, []ExposureCatalogEntry, error) {
	var cat BumblebeeCatalog
	if err := json.Unmarshal(data, &cat); err != nil {
		return cat, nil, fmt.Errorf("invalid exposure catalog JSON: %w", err)
	}
	var out []ExposureCatalogEntry
	for _, e := range cat.Entries {
		pkg := strings.TrimSpace(e.Package)
		eco := normalizeEcosystem(e.Ecosystem)
		if e.ID == "" || pkg == "" || eco == "" || len(e.Versions) == 0 {
			continue
		}
		severity := strings.ToLower(strings.TrimSpace(e.Severity))
		if severity == "" {
			severity = "critical"
		}
		raw, _ := json.Marshal(e)
		norm := normalizePkgName(eco, pkg)
		seen := map[string]bool{}
		for _, ver := range e.Versions {
			ver = strings.TrimSpace(ver)
			if ver == "" || seen[ver] {
				continue
			}
			seen[ver] = true
			out = append(out, ExposureCatalogEntry{
				CatalogID:      e.ID,
				CatalogName:    e.Name,
				Ecosystem:      eco,
				PackageName:    pkg,
				NormalizedName: norm,
				Version:        ver,
				Severity:       severity,
				Confidence:     "high",
				Evidence:       "exact name+version match",
				RawEntry:       raw,
			})
		}
	}
	return cat, out, nil
}

// ExposureCatalogEntry is a flattened, stored exposure tuple.
type ExposureCatalogEntry struct {
	CatalogID      string
	CatalogName    string
	Ecosystem      string
	PackageName    string
	NormalizedName string
	Version        string
	Severity       string
	Confidence     string
	Evidence       string
	RawEntry       []byte
}

// UpsertExposureCatalog atomically replaces a named catalog source with a fresh
// set of entries. Concurrent uploads of the same source_name serialize on a
// transaction advisory lock; a failure rolls back, leaving the prior catalog
// intact. Returns the stored entry count.
func (db *DB) UpsertExposureCatalog(ctx context.Context, sourceName, displayName, uploadedBy, schemaVer string, raw []byte, entries []ExposureCatalogEntry) (int, error) {
	sourceName = strings.TrimSpace(sourceName)
	if sourceName == "" {
		return 0, fmt.Errorf("source_name required")
	}
	sum := sha256.Sum256(raw)
	checksum := hex.EncodeToString(sum[:])

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, sourceName); err != nil {
		return 0, fmt.Errorf("lock catalog: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM exposure_catalog_sources WHERE source_name=$1`, sourceName); err != nil {
		return 0, fmt.Errorf("clear prior catalog: %w", err)
	}
	var sourceID int64
	if err := tx.QueryRowContext(ctx,
		`INSERT INTO exposure_catalog_sources (source_name, display_name, schema_version, entry_count, checksum_sha256, uploaded_by)
		 VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		sourceName, displayName, schemaVer, len(entries), checksum, uploadedBy).Scan(&sourceID); err != nil {
		return 0, fmt.Errorf("insert source: %w", err)
	}

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO exposure_catalog_entries
		 (source_id, catalog_id, catalog_name, ecosystem, package_name, normalized_name, version, severity, confidence, evidence, raw_entry)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		 ON CONFLICT (source_id, catalog_id, ecosystem, normalized_name, version) DO NOTHING`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	stored := 0
	for _, e := range entries {
		raw := e.RawEntry
		if len(raw) == 0 {
			raw = []byte("{}")
		}
		if _, err := stmt.ExecContext(ctx, sourceID, e.CatalogID, e.CatalogName, e.Ecosystem,
			e.PackageName, e.NormalizedName, e.Version, e.Severity, e.Confidence, e.Evidence, raw); err != nil {
			return 0, fmt.Errorf("insert entry: %w", err)
		}
		stored++
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return stored, nil
}

// ListExposureCatalogSources returns the uploaded catalogs (provenance + counts).
func (db *DB) ListExposureCatalogSources(ctx context.Context) ([]ExposureCatalogSource, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, source_name, display_name, schema_version, entry_count, checksum_sha256, uploaded_by, active, created_at, updated_at
		   FROM exposure_catalog_sources ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExposureCatalogSource
	for rows.Next() {
		var s ExposureCatalogSource
		if err := rows.Scan(&s.ID, &s.SourceName, &s.DisplayName, &s.SchemaVer, &s.EntryCount,
			&s.Checksum, &s.UploadedBy, &s.Active, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// DeleteExposureCatalogSource removes a catalog (and its entries, via cascade).
func (db *DB) DeleteExposureCatalogSource(ctx context.Context, id int64) (bool, error) {
	res, err := db.ExecContext(ctx, `DELETE FROM exposure_catalog_sources WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// MatchExposureCatalog flags a scan's packages that exactly match a known
// compromised release in any active exposure catalog, inserting a CRITICAL
// finding (finding_source='exposure-catalog') per match. The match is an exact
// (normalized ecosystem, normalized name, verbatim version) equi-join; the
// finding reuses the vulnerabilities row and its triage/VEX/notify machinery.
// Returns the number of new findings created. Idempotent across rescans:
// vulnerability_id is the catalog id, so the (package_id, scan_id,
// vulnerability_id) conflict and the finding_key both dedup re-matches.
func (db *DB) MatchExposureCatalog(ctx context.Context, scanID, hostID string) (int, error) {
	if scanID == "" {
		return 0, nil
	}
	rows, err := db.QueryContext(ctx, `
		SELECT p.id, p.name, COALESCE(p.file_path,''), COALESCE(p.container,''),
		       e.catalog_id, COALESCE(e.catalog_name,''), e.severity, e.confidence
		FROM packages p
		JOIN exposure_catalog_entries e
		  ON e.ecosystem = `+packageEcosystemSQL("p")+`
		 AND e.normalized_name = bongsu_normalize_pkg_name(`+packageEcosystemSQL("p")+`, p.name)
		 AND e.version = p.version
		JOIN exposure_catalog_sources s ON s.id = e.source_id AND s.active
		WHERE p.scan_id = $1`, scanID)
	if err != nil {
		return 0, fmt.Errorf("exposure match query: %w", err)
	}
	defer rows.Close()

	type match struct {
		pkgID, pkgName, pkgPath, container string
		catalogID, catalogName, severity   string
		confidence                         string
	}
	var matches []match
	for rows.Next() {
		var m match
		if err := rows.Scan(&m.pkgID, &m.pkgName, &m.pkgPath, &m.container,
			&m.catalogID, &m.catalogName, &m.severity, &m.confidence); err != nil {
			return 0, err
		}
		matches = append(matches, m)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(matches) == 0 {
		return 0, nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO vulnerabilities
(id, package_id, scan_id, host_id, vulnerability_id, severity, title, description,
 pkg_name, pkg_path, installed_version, fixed_version, cvss_score, cvss_vector,
 primary_url, container, layer_id, finding_source, finding_key, catalog_id, exposure_confidence, created_at, last_seen)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,now(),now())
ON CONFLICT (package_id, scan_id, vulnerability_id) DO NOTHING`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	created := 0
	for _, m := range matches {
		title := "Known-compromised package: " + m.pkgName
		if m.catalogName != "" {
			title = "Known-compromised package: " + m.catalogName
		}
		findingKey := ComputeFindingKey(FindingIdentity{HostID: hostID, PkgName: m.pkgName, PkgPath: m.pkgPath, VulnerabilityID: m.catalogID})
		// Synthetic CVSS 9.8: a known-malicious release carries no CVSS of its
		// own, but is a critical supply-chain compromise; this lets the existing
		// risk score / severity sort / dashboards rank it correctly with no
		// special-casing of the shared risk expression.
		res, err := stmt.ExecContext(ctx,
			uuid.New().String(), m.pkgID, scanID, hostID, m.catalogID, "CRITICAL",
			truncate(title, 500), truncate("Exact match against exposure catalog ("+m.catalogID+"): this installed release is a known-compromised artifact.", 2000),
			m.pkgName, m.pkgPath, "", "", 9.8, "",
			"", m.container, "", "exposure-catalog", findingKey, m.catalogID, m.confidence)
		if err != nil {
			continue
		}
		if n, _ := res.RowsAffected(); n > 0 {
			created++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return created, nil
}
