package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

const CveCols = `id, vulnerability_id, source, category, ecosystem, severity, cvss_score, cvss_vector, epss_score, epss_percentile, title, description, published_date, modified_date, affected_products, refs, raw_data, updated_at`

func ScanCveEntry(scanner interface{ Scan(...interface{}) error }, e *models.CveEntry) error {
	return scanner.Scan(&e.ID, &e.VulnerabilityID, &e.Source, &e.Category, &e.Ecosystem, &e.Severity, &e.CVSSScore, &e.CVSSVector,
		&e.EPSSScore, &e.EPSSPercentile, &e.Title, &e.Description, &e.PublishedDate, &e.ModifiedDate,
		&e.AffectedProducts, &e.References, &e.RawData, &e.UpdatedAt)
}

func (db *DB) UpsertCveEntries(ctx context.Context, entries []models.CveEntry) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	count, err := db.UpsertCveEntriesTx(ctx, tx, entries)
	if err != nil {
		return 0, err
	}
	return count, tx.Commit()
}

func (db *DB) UpsertCveEntriesTx(ctx context.Context, tx *sql.Tx, entries []models.CveEntry) (int, error) {
	return db.upsertCveEntriesTx(ctx, tx, entries, true, true)
}

func (db *DB) UpsertCveEntriesWithoutAffectedIndexTx(ctx context.Context, tx *sql.Tx, entries []models.CveEntry) (int, error) {
	return db.upsertCveEntriesTx(ctx, tx, entries, false, false)
}

func (db *DB) upsertCveEntriesTx(ctx context.Context, tx *sql.Tx, entries []models.CveEntry, refreshAffectedIndex, refreshReferenceIndex bool) (int, error) {
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO cve_database (id, vulnerability_id, source, category, ecosystem, severity, cvss_score, cvss_vector, epss_score, epss_percentile, title, description, published_date, modified_date, affected_products, refs, raw_data, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, now())
ON CONFLICT (vulnerability_id, source) DO UPDATE SET
	category=CASE WHEN EXCLUDED.category <> '' THEN EXCLUDED.category ELSE cve_database.category END,
	ecosystem=CASE WHEN EXCLUDED.ecosystem <> '' THEN EXCLUDED.ecosystem ELSE cve_database.ecosystem END,
	severity=EXCLUDED.severity, cvss_score=EXCLUDED.cvss_score, cvss_vector=EXCLUDED.cvss_vector,
	epss_score=EXCLUDED.epss_score, epss_percentile=EXCLUDED.epss_percentile,
	title=EXCLUDED.title, description=EXCLUDED.description,
	published_date=EXCLUDED.published_date, modified_date=EXCLUDED.modified_date,
	affected_products=(
		SELECT COALESCE(jsonb_agg(DISTINCT ap.elem), '[]'::jsonb)
		FROM jsonb_array_elements(
			(CASE WHEN jsonb_typeof(cve_database.affected_products) = 'array' THEN cve_database.affected_products ELSE '[]'::jsonb END) ||
			(CASE WHEN jsonb_typeof(EXCLUDED.affected_products) = 'array' THEN EXCLUDED.affected_products ELSE '[]'::jsonb END)
		) AS ap(elem)
	),
	refs=(
		SELECT COALESCE(jsonb_agg(DISTINCT ref.elem), '[]'::jsonb)
		FROM jsonb_array_elements(
			(CASE WHEN jsonb_typeof(cve_database.refs) = 'array' THEN cve_database.refs ELSE '[]'::jsonb END) ||
			(CASE WHEN jsonb_typeof(EXCLUDED.refs) = 'array' THEN EXCLUDED.refs ELSE '[]'::jsonb END)
		) AS ref(elem)
	),
	raw_data=EXCLUDED.raw_data, updated_at=now()
RETURNING id`)
	if err != nil {
		return 0, fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	count := 0
	var firstErr error
	for i := range entries {
		e := &entries[i]
		if e.ID == "" {
			e.ID = uuid.New().String()
		}
		// Auto-calculate CVSS score from vector if missing
		if e.CVSSScore == 0 && e.CVSSVector != "" {
			e.CVSSScore = calcCvssScore(e.CVSSVector)
		}
		// Auto-normalize severity from score
		if e.CVSSScore > 0 && (e.Severity == "" || e.Severity == "MODERATE") {
			if e.CVSSScore >= 9.0 {
				e.Severity = "CRITICAL"
			} else if e.CVSSScore >= 7.0 {
				e.Severity = "HIGH"
			} else if e.CVSSScore >= 4.0 {
				e.Severity = "MEDIUM"
			} else {
				e.Severity = "LOW"
			}
		}
		if e.Category == "" || e.Ecosystem == "" {
			e.Category, e.Ecosystem = ClassifySecuritySource(e.Source, e.AffectedProducts)
		}
		var cveID string
		if err := stmt.QueryRowContext(ctx, e.ID, e.VulnerabilityID, e.Source, e.Category, e.Ecosystem, e.Severity,
			e.CVSSScore, e.CVSSVector, e.EPSSScore, e.EPSSPercentile, e.Title, e.Description,
			e.PublishedDate, e.ModifiedDate, e.AffectedProducts, e.References, e.RawData).Scan(&cveID); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("insert %s: %w", e.VulnerabilityID, err)
			}
			log.Printf("rematch scan row: %v", err)
			continue
		}
		if refreshAffectedIndex {
			if _, err := db.RefreshCveAffectedPackagesForCveTx(ctx, tx, cveID); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("refresh affected packages %s: %w", e.VulnerabilityID, err)
				}
				log.Printf("refresh affected package index: %v", err)
				continue
			}
		} else {
			_ = cveID
		}
		if refreshReferenceIndex {
			if _, err := db.RefreshCveReferenceKeysForCveTx(ctx, tx, cveID, *e); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("refresh reference keys %s: %w", e.VulnerabilityID, err)
				}
				log.Printf("refresh CVE reference key index: %v", err)
				continue
			}
		}
		count++
	}
	if firstErr != nil {
		return 0, firstErr
	}
	return count, nil
}

func (db *DB) RefreshCveAffectedPackagesForSourceTx(ctx context.Context, tx *sql.Tx, source string) (int, error) {
	source = strings.TrimSpace(source)
	if source == "" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM cve_affected_packages`); err != nil {
			return 0, err
		}
		return db.insertCveAffectedPackagesTx(ctx, tx, "")
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM cve_affected_packages cap
USING cve_database c
WHERE cap.cve_id = c.id
  AND c.source = $1`, source); err != nil {
		return 0, err
	}
	return db.insertCveAffectedPackagesTx(ctx, tx, source)
}

func (db *DB) RefreshCveReferenceKeysForCveTx(ctx context.Context, tx *sql.Tx, cveID string, entry models.CveEntry) (int, error) {
	if _, err := tx.ExecContext(ctx, `DELETE FROM cve_reference_keys WHERE cve_id=$1`, cveID); err != nil {
		return 0, err
	}
	keys := cveReferenceKeys(entry)
	if len(keys) == 0 {
		return 0, nil
	}
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO cve_reference_keys (cve_id, reference_key, updated_at)
VALUES ($1, $2, now())
ON CONFLICT (cve_id, reference_key) DO UPDATE SET updated_at=now()`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	count := 0
	for _, key := range keys {
		if _, err := stmt.ExecContext(ctx, cveID, key); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func (db *DB) RefreshCveReferenceKeysForSourceTx(ctx context.Context, tx *sql.Tx, source string) (int, error) {
	source = strings.TrimSpace(source)
	args := []any{}
	filter := ""
	if source != "" {
		args = append(args, source)
		filter = " WHERE source = $1"
		if _, err := tx.ExecContext(ctx, `
DELETE FROM cve_reference_keys crk
USING cve_database c
WHERE crk.cve_id = c.id
  AND c.source = $1`, source); err != nil {
			return 0, err
		}
	} else if _, err := tx.ExecContext(ctx, `DELETE FROM cve_reference_keys`); err != nil {
		return 0, err
	}

	rows, err := tx.QueryContext(ctx, `SELECT id, vulnerability_id, title, description, refs::text FROM cve_database`+filter, args...)
	if err != nil {
		return 0, err
	}

	type indexedEntry struct {
		cveID string
		keys  []string
	}
	entries := []indexedEntry{}
	for rows.Next() {
		var e models.CveEntry
		if err := rows.Scan(&e.ID, &e.VulnerabilityID, &e.Title, &e.Description, &e.References); err != nil {
			rows.Close()
			return 0, err
		}
		keys := cveReferenceKeys(e)
		if len(keys) > 0 {
			entries = append(entries, indexedEntry{cveID: e.ID, keys: keys})
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	stmt, err := tx.PrepareContext(ctx, pq.CopyIn("cve_reference_keys", "cve_id", "reference_key", "updated_at"))
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	count := 0
	now := time.Now().UTC()
	for _, entry := range entries {
		for _, key := range entry.keys {
			if _, err := stmt.ExecContext(ctx, entry.cveID, key, now); err != nil {
				return count, err
			}
			count++
		}
	}
	if _, err := stmt.ExecContext(ctx); err != nil {
		return count, err
	}
	return count, nil
}

func (db *DB) insertCveAffectedPackagesTx(ctx context.Context, tx *sql.Tx, source string) (int, error) {
	source = strings.TrimSpace(source)
	args := []any{}
	filter := ""
	if source != "" {
		args = append(args, source)
		filter = " AND c.source = $1"
	}
	fixedExpr := cveAffectedPackageFixedVersionSQL("ap")
	ecosystemExpr := affectedProductEcosystemSQL("c", "ap")
	res, err := tx.ExecContext(ctx, fmt.Sprintf(`
INSERT INTO cve_affected_packages (cve_id, vulnerability_id, source, package_name, ecosystem, fixed_version, affected_product, updated_at)
SELECT DISTINCT ON (c.id, lower(ap->>'name'), %s, %s)
       c.id,
       c.vulnerability_id,
       c.source,
       lower(ap->>'name') AS package_name,
       %s AS ecosystem,
       %s AS fixed_version,
       ap AS affected_product,
       now()
FROM cve_database c
JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(c.affected_products) = 'array' THEN c.affected_products ELSE '[]'::jsonb END) ap ON true
WHERE COALESCE(ap->>'name', '') != ''
  AND COALESCE(NULLIF(ap->>'ecosystem', ''), NULLIF(c.ecosystem, '')) IS NOT NULL
  AND %s IS NOT NULL
  AND %s != ''
  %s
ON CONFLICT (cve_id, package_name, ecosystem, fixed_version) DO UPDATE SET
	affected_product=EXCLUDED.affected_product,
	updated_at=now()`, ecosystemExpr, fixedExpr, ecosystemExpr, fixedExpr, fixedExpr, fixedExpr, filter), args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (db *DB) RefreshCveAffectedPackagesForCveTx(ctx context.Context, tx *sql.Tx, cveID string) (int, error) {
	if _, err := tx.ExecContext(ctx, `DELETE FROM cve_affected_packages WHERE cve_id=$1`, cveID); err != nil {
		return 0, err
	}
	fixedExpr := cveAffectedPackageFixedVersionSQL("ap")
	ecosystemExpr := affectedProductEcosystemSQL("c", "ap")
	res, err := tx.ExecContext(ctx, fmt.Sprintf(`
INSERT INTO cve_affected_packages (cve_id, vulnerability_id, source, package_name, ecosystem, fixed_version, affected_product, updated_at)
SELECT DISTINCT ON (c.id, lower(ap->>'name'), %s, %s)
       c.id,
       c.vulnerability_id,
       c.source,
       lower(ap->>'name') AS package_name,
       %s AS ecosystem,
       %s AS fixed_version,
       ap AS affected_product,
       now()
FROM cve_database c
JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(c.affected_products) = 'array' THEN c.affected_products ELSE '[]'::jsonb END) ap ON true
WHERE c.id=$1
  AND COALESCE(ap->>'name', '') != ''
  AND COALESCE(NULLIF(ap->>'ecosystem', ''), NULLIF(c.ecosystem, '')) IS NOT NULL
  AND %s IS NOT NULL
  AND %s != ''
ON CONFLICT (cve_id, package_name, ecosystem, fixed_version) DO UPDATE SET
	affected_product=EXCLUDED.affected_product,
	updated_at=now()`, ecosystemExpr, fixedExpr, ecosystemExpr, fixedExpr, fixedExpr, fixedExpr), cveID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (db *DB) RebuildCveAffectedPackages(ctx context.Context) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM cve_affected_packages`); err != nil {
		return 0, err
	}
	fixedExpr := cveAffectedPackageFixedVersionSQL("ap")
	ecosystemExpr := affectedProductEcosystemSQL("c", "ap")
	res, err := tx.ExecContext(ctx, fmt.Sprintf(`
INSERT INTO cve_affected_packages (cve_id, vulnerability_id, source, package_name, ecosystem, fixed_version, affected_product, updated_at)
SELECT DISTINCT ON (c.id, lower(ap->>'name'), %s, %s)
       c.id,
       c.vulnerability_id,
       c.source,
       lower(ap->>'name') AS package_name,
       %s AS ecosystem,
       %s AS fixed_version,
       ap AS affected_product,
       now()
FROM cve_database c
JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(c.affected_products) = 'array' THEN c.affected_products ELSE '[]'::jsonb END) ap ON true
WHERE COALESCE(ap->>'name', '') != ''
  AND COALESCE(NULLIF(ap->>'ecosystem', ''), NULLIF(c.ecosystem, '')) IS NOT NULL
  AND %s IS NOT NULL
  AND %s != ''
ON CONFLICT (cve_id, package_name, ecosystem, fixed_version) DO UPDATE SET
	affected_product=EXCLUDED.affected_product,
	updated_at=now()`, ecosystemExpr, fixedExpr, ecosystemExpr, fixedExpr, fixedExpr, fixedExpr))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(n), nil
}

func (db *DB) EnsureCveAffectedPackages(ctx context.Context) (int, error) {
	var cveCount, affectedCount int
	if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM cve_database), (SELECT count(*) FROM cve_affected_packages)`).Scan(&cveCount, &affectedCount); err != nil {
		return 0, err
	}
	if cveCount == 0 || affectedCount > 0 {
		return 0, nil
	}
	return db.RebuildCveAffectedPackages(ctx)
}

func (db *DB) RebuildCveReferenceKeys(ctx context.Context) (int, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, vulnerability_id, title, description, refs::text FROM cve_database`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	type indexedEntry struct {
		cveID string
		keys  []string
	}
	entries := []indexedEntry{}
	for rows.Next() {
		var e models.CveEntry
		if err := rows.Scan(&e.ID, &e.VulnerabilityID, &e.Title, &e.Description, &e.References); err != nil {
			return 0, err
		}
		keys := cveReferenceKeys(e)
		if len(keys) == 0 {
			continue
		}
		entries = append(entries, indexedEntry{cveID: e.ID, keys: keys})
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM cve_reference_keys`); err != nil {
		return 0, err
	}
	stmt, err := tx.PrepareContext(ctx, pq.CopyIn("cve_reference_keys", "cve_id", "reference_key", "updated_at"))
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	count := 0
	now := time.Now().UTC()
	for _, entry := range entries {
		for _, key := range entry.keys {
			if _, err := stmt.ExecContext(ctx, entry.cveID, key, now); err != nil {
				return 0, err
			}
			count++
		}
	}
	if _, err := stmt.ExecContext(ctx); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

func (db *DB) EnsureCveReferenceKeys(ctx context.Context) (int, error) {
	var cveCount, keyCount int
	if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM cve_database), (SELECT count(*) FROM cve_reference_keys)`).Scan(&cveCount, &keyCount); err != nil {
		return 0, err
	}
	if cveCount == 0 || keyCount > 0 {
		return 0, nil
	}
	return db.RebuildCveReferenceKeys(ctx)
}

func (db *DB) DeleteCveEntriesBySourceTx(ctx context.Context, tx *sql.Tx, source string) (int, error) {
	res, err := tx.ExecContext(ctx, `DELETE FROM cve_database WHERE source=$1`, source)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (db *DB) DeleteCveEntriesBySourceUpdatedBeforeTx(ctx context.Context, tx *sql.Tx, source string, before time.Time) (int, error) {
	res, err := tx.ExecContext(ctx, `DELETE FROM cve_database WHERE source=$1 AND updated_at < $2`, source, before)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (db *DB) DeleteAllCveEntriesTx(ctx context.Context, tx *sql.Tx) (int, error) {
	res, err := tx.ExecContext(ctx, `DELETE FROM cve_database`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (db *DB) RefreshSecuritySourceStatusTx(ctx context.Context, tx *sql.Tx, source string) error {
	return db.refreshSecuritySourceStatusTx(ctx, tx, source, false)
}

func (db *DB) EnsureSecuritySourceStatusTx(ctx context.Context, tx *sql.Tx, source string) error {
	return db.refreshSecuritySourceStatusTx(ctx, tx, source, true)
}

func (db *DB) refreshSecuritySourceStatusTx(ctx context.Context, tx *sql.Tx, source string, preserveExistingSync bool) error {
	source = strings.TrimSpace(source)
	if source == "" {
		rows, err := tx.QueryContext(ctx, `SELECT source FROM cve_database WHERE source != '' GROUP BY source`)
		if err != nil {
			return err
		}
		sources := []string{}
		for rows.Next() {
			var rowSource string
			if err := rows.Scan(&rowSource); err != nil {
				return err
			}
			sources = append(sources, rowSource)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		rows.Close()
		for _, rowSource := range sources {
			if err := db.refreshSecuritySourceStatusTx(ctx, tx, rowSource, preserveExistingSync); err != nil {
				return err
			}
		}
		return nil
	}
	meta := securitySourceRegistryMetadata(source)
	_, err := tx.ExecContext(ctx, `
INSERT INTO security_sources (id, name, kind, category, ecosystems, update_interval_seconds, last_sync_started_at, last_sync_finished_at, last_status, last_error, record_count, updated_at)
VALUES (
	$1,
	$2,
	'vulnerability',
	$3,
	$4,
	21600,
	COALESCE((SELECT max(updated_at) FROM cve_database WHERE source=$1), now()),
	COALESCE((SELECT max(updated_at) FROM cve_database WHERE source=$1), now()),
	'ok',
	'',
	(SELECT count(*) FROM cve_database WHERE source=$1),
	now()
)
ON CONFLICT (id) DO UPDATE SET
	name=EXCLUDED.name,
	kind=EXCLUDED.kind,
	category=EXCLUDED.category,
	ecosystems=EXCLUDED.ecosystems,
	last_sync_started_at=CASE WHEN $5 THEN COALESCE(security_sources.last_sync_started_at, EXCLUDED.last_sync_started_at) ELSE EXCLUDED.last_sync_started_at END,
	last_sync_finished_at=CASE WHEN $5 THEN COALESCE(security_sources.last_sync_finished_at, EXCLUDED.last_sync_finished_at) ELSE EXCLUDED.last_sync_finished_at END,
	last_status=EXCLUDED.last_status,
	last_error='',
	record_count=EXCLUDED.record_count,
	updated_at=now()`, source, meta.name, meta.category, pq.Array(meta.ecosystems), preserveExistingSync)
	return err
}

func (db *DB) RefreshSecuritySourceStatus(ctx context.Context, source string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := db.RefreshSecuritySourceStatusTx(ctx, tx, source); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) EnsureSecuritySourceStatus(ctx context.Context, source string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := db.EnsureSecuritySourceStatusTx(ctx, tx, source); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) MarkSecuritySourcesExportedTx(ctx context.Context, tx *sql.Tx, source string, exportedAt time.Time) error {
	source = strings.TrimSpace(source)
	if exportedAt.IsZero() {
		exportedAt = time.Now()
	}
	exportedAt = exportedAt.UTC()
	if err := db.EnsureSecuritySourceStatusTx(ctx, tx, source); err != nil {
		return err
	}
	if source == "" {
		_, err := tx.ExecContext(ctx, `
UPDATE security_sources
SET last_exported_at=$1, updated_at=now()
WHERE id IN (SELECT DISTINCT source FROM cve_database WHERE source != '')`, exportedAt)
		return err
	}
	_, err := tx.ExecContext(ctx, `
UPDATE security_sources
SET last_exported_at=$2, updated_at=now()
WHERE id=$1`, source, exportedAt)
	return err
}

func (db *DB) MarkSecuritySourcesExported(ctx context.Context, source string, exportedAt time.Time) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := db.MarkSecuritySourcesExportedTx(ctx, tx, source, exportedAt); err != nil {
		return err
	}
	return tx.Commit()
}

type SecuritySourceStatus struct {
	ID                 string     `json:"id"`
	Name               string     `json:"name"`
	Kind               string     `json:"kind"`
	Category           string     `json:"category"`
	Ecosystems         []string   `json:"ecosystems"`
	Enabled            bool       `json:"enabled"`
	UpdateIntervalSecs int        `json:"update_interval_seconds"`
	LastSyncStartedAt  *time.Time `json:"last_sync_started_at,omitempty"`
	LastSyncFinishedAt *time.Time `json:"last_sync_finished_at,omitempty"`
	LastExportedAt     *time.Time `json:"last_exported_at,omitempty"`
	LastStatus         string     `json:"last_status"`
	LastError          string     `json:"last_error"`
	RecordCount        int64      `json:"record_count"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

func (db *DB) ListSecuritySourceStatuses(ctx context.Context) ([]SecuritySourceStatus, error) {
	rows, err := db.QueryContext(ctx, `
SELECT id, name, kind, category, ecosystems, enabled, update_interval_seconds,
       last_sync_started_at, last_sync_finished_at, last_exported_at, last_status, last_error, record_count, updated_at
FROM security_sources
ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SecuritySourceStatus{}
	for rows.Next() {
		var item SecuritySourceStatus
		var started, finished, exported sql.NullTime
		if err := rows.Scan(&item.ID, &item.Name, &item.Kind, &item.Category, pq.Array(&item.Ecosystems), &item.Enabled, &item.UpdateIntervalSecs, &started, &finished, &exported, &item.LastStatus, &item.LastError, &item.RecordCount, &item.UpdatedAt); err != nil {
			return nil, err
		}
		if started.Valid {
			item.LastSyncStartedAt = &started.Time
		}
		if finished.Valid {
			item.LastSyncFinishedAt = &finished.Time
		}
		if exported.Valid {
			item.LastExportedAt = &exported.Time
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

type securitySourceRegistryMeta struct {
	name       string
	category   string
	ecosystems []string
}

func securitySourceRegistryMetadata(source string) securitySourceRegistryMeta {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "osv":
		return securitySourceRegistryMeta{name: "OSV.dev", category: "code-library", ecosystems: []string{"PyPI", "npm", "Go", "Maven", "crates.io", "NuGet", "RubyGems", "Packagist", "Hex", "Pub", "SwiftURL", "Hackage", "CRAN", "opam", "VSCode", "GitHub Actions", "Alpine", "Debian", "Ubuntu", "SUSE", "openSUSE", "AlmaLinux", "Red Hat", "Rocky Linux", "Azure Linux", "Wolfi", "Chainguard", "openEuler", "Mageia", "Android"}}
	case "nvd":
		return securitySourceRegistryMeta{name: "NVD CVE 2.0", category: "general-cve", ecosystems: []string{}}
	case "trivy":
		return securitySourceRegistryMeta{name: "Trivy vulnerability DB", category: "os-package", ecosystems: []string{"Debian", "Ubuntu", "Alpine", "RHEL", "SUSE", "Amazon Linux", "Wolfi"}}
	case "cisa-kev":
		return securitySourceRegistryMeta{name: "CISA Known Exploited Vulnerabilities", category: "priority-exploit", ecosystems: []string{}}
	case "epss":
		return securitySourceRegistryMeta{name: "FIRST EPSS", category: "priority-risk", ecosystems: []string{}}
	default:
		display := strings.ToUpper(strings.TrimSpace(source))
		if display == "" {
			display = "Custom CVE Source"
		}
		return securitySourceRegistryMeta{name: display, category: "custom", ecosystems: []string{}}
	}
}

func (db *DB) SyncEPSSPriorityColumns(ctx context.Context) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	count, err := db.SyncEPSSPriorityColumnsTx(ctx, tx)
	if err != nil {
		return 0, err
	}
	return count, tx.Commit()
}

func (db *DB) SyncEPSSPriorityColumnsTx(ctx context.Context, tx *sql.Tx) (int, error) {
	clearRes, err := tx.ExecContext(ctx, `
		UPDATE cve_database c
		SET epss_score = 0,
		    epss_percentile = 0
		WHERE c.source != 'epss'
		  AND (c.epss_score != 0 OR c.epss_percentile != 0)
		  AND NOT EXISTS (
			SELECT 1
			FROM cve_database epss
			WHERE epss.source = 'epss'
			  AND epss.vulnerability_id = c.vulnerability_id
			  AND (epss.epss_score > 0 OR epss.epss_percentile > 0)
		  )`)
	if err != nil {
		return 0, err
	}
	setRes, err := tx.ExecContext(ctx, `
		WITH latest_epss AS (
			SELECT DISTINCT ON (vulnerability_id)
			       vulnerability_id, epss_score, epss_percentile
			FROM cve_database
			WHERE source = 'epss'
			  AND (epss_score > 0 OR epss_percentile > 0)
			ORDER BY vulnerability_id, updated_at DESC, epss_score DESC, epss_percentile DESC
		)
		UPDATE cve_database c
		SET epss_score = latest_epss.epss_score,
		    epss_percentile = latest_epss.epss_percentile
		FROM latest_epss
		WHERE c.source != 'epss'
		  AND c.vulnerability_id = latest_epss.vulnerability_id
		  AND (c.epss_score IS DISTINCT FROM latest_epss.epss_score
		       OR c.epss_percentile IS DISTINCT FROM latest_epss.epss_percentile)`)
	if err != nil {
		return 0, err
	}
	clearN, _ := clearRes.RowsAffected()
	setN, _ := setRes.RowsAffected()
	return int(clearN + setN), nil
}

func (db *DB) SearchCveDatabase(ctx context.Context, query, referenceKey, severity, source string, minCVSS, minEPSS, minEPSSPercentile float64, matchableOnly, includePrioritySources bool, sortBy, sortOrder string, limit, offset int) ([]models.CveEntry, int, error) {
	baseQ := `FROM cve_database WHERE 1=1`
	args := []any{}
	argN := 1

	query = strings.TrimSpace(query)
	if query != "" {
		if filter, vals, ok := cveReferenceKeyWhereFromSearchQuery(query, argN); ok {
			baseQ += " AND " + filter
			args = append(args, vals...)
			argN += len(vals)
		} else {
			baseQ += fmt.Sprintf(` AND id IN (
			SELECT search_cve.id FROM cve_database search_cve WHERE search_cve.vulnerability_id ILIKE $%d
			UNION
			SELECT search_cve.id FROM cve_database search_cve WHERE search_cve.title ILIKE $%d
			UNION
			SELECT search_cve.id FROM cve_database search_cve WHERE search_cve.description ILIKE $%d
			UNION
			SELECT cap.cve_id FROM cve_affected_packages cap WHERE cap.package_name ILIKE $%d
			UNION
			SELECT cap.cve_id FROM cve_affected_packages cap WHERE cap.ecosystem ILIKE $%d
			UNION
			SELECT cap.cve_id FROM cve_affected_packages cap WHERE cap.fixed_version ILIKE $%d
		)`, argN, argN, argN, argN, argN, argN)
			args = append(args, "%"+query+"%")
			argN++
		}
	}
	if referenceKey != "" {
		filter, vals, ok := cveReferenceKeyWhere(referenceKey, argN)
		if ok {
			baseQ += " AND " + filter
			args = append(args, vals...)
			argN += len(vals)
		}
	}
	if severity != "" {
		baseQ += fmt.Sprintf(" AND severity=$%d", argN)
		args = append(args, severity)
		argN++
	}
	if source != "" {
		baseQ += fmt.Sprintf(" AND source=$%d", argN)
		args = append(args, source)
		argN++
	} else if !includePrioritySources {
		baseQ += " AND source NOT IN ('cisa-kev', 'epss')"
	}
	if minCVSS > 0 {
		baseQ += fmt.Sprintf(" AND cvss_score>=$%d", argN)
		args = append(args, minCVSS)
		argN++
	}
	if minEPSS > 0 {
		baseQ += fmt.Sprintf(" AND epss_score>=$%d", argN)
		args = append(args, minEPSS)
		argN++
	}
	if minEPSSPercentile > 0 {
		baseQ += fmt.Sprintf(" AND epss_percentile>=$%d", argN)
		args = append(args, minEPSSPercentile)
		argN++
	}
	if matchableOnly {
		baseQ += " AND EXISTS (SELECT 1 FROM cve_affected_packages cap_matchable WHERE cap_matchable.cve_id = cve_database.id)"
	}

	var total int
	countArgs := make([]any, len(args))
	copy(countArgs, args)
	if err := db.QueryRowContext(ctx, "SELECT count(*) "+baseQ, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	sortCol := "cvss_score"
	switch sortBy {
	case "vulnerability_id", "severity", "cvss_score", "epss_score", "epss_percentile", "source", "title", "published_date":
		sortCol = sortBy
	}
	sortDir := "DESC"
	if sortOrder == "asc" {
		sortDir = "ASC"
	}
	nullHandling := ""
	if sortCol == "cvss_score" || sortCol == "epss_score" || sortCol == "epss_percentile" {
		nullHandling = " NULLS LAST"
	}
	dataQ := fmt.Sprintf("SELECT %s ", CveCols) + baseQ + fmt.Sprintf(" ORDER BY %s %s%s LIMIT $%d OFFSET $%d", sortCol, sortDir, nullHandling, argN, argN+1)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, dataQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []models.CveEntry
	for rows.Next() {
		var e models.CveEntry
		if err := ScanCveEntry(rows, &e); err != nil {
			return nil, 0, err
		}
		e.MatchableAffected = cveEntryMatchableAffectedCount(e.AffectedProducts, e.Ecosystem)
		e.Matchable = e.MatchableAffected > 0
		e.MatchabilityReason = cveEntryMatchabilityReason(e.AffectedProducts, e.Ecosystem)
		e.ReferenceKeys = cveReferenceKeys(e)
		entries = append(entries, e)
	}
	if err := db.enrichCveReferenceGroupCounts(ctx, entries); err != nil {
		log.Printf("WARNING: CVE reference group summary enrichment skipped: %v", err)
		markCveReferenceGroupStatus(entries, "unavailable")
	}
	return entries, total, nil
}

type cveReferenceGroupCounts struct {
	Total     int
	Matchable int
	Sources   int
}

func (db *DB) enrichCveReferenceGroupCounts(ctx context.Context, entries []models.CveEntry) error {
	entryKeys := make([]string, len(entries))
	keys := []string{}
	for i := range entries {
		key := preferredReferenceGroupKey(entries[i].ReferenceKeys)
		if key != "" {
			entryKeys[i] = key
			keys = appendUnique(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	timeout := time.Duration(envPositiveInt("BONGSU_CVE_GROUP_SUMMARY_TIMEOUT_MS", 1500)) * time.Millisecond
	groupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	matchablePredicate := cveSourceMatchablePredicateSQL("CASE WHEN jsonb_typeof(c.affected_products) = 'array' THEN c.affected_products ELSE '[]'::jsonb END", "c.ecosystem")
	rows, err := db.QueryContext(groupCtx, fmt.Sprintf(`
WITH keys AS (SELECT unnest($1::text[]) AS reference_key)
SELECT k.reference_key,
	count(c.id),
	count(c.id) FILTER (WHERE %s),
	count(DISTINCT NULLIF(c.source, ''))
FROM keys k
JOIN cve_reference_keys crk ON crk.reference_key = k.reference_key
JOIN cve_database c ON c.id = crk.cve_id
GROUP BY k.reference_key`, matchablePredicate), pq.Array(keys))
	if err != nil {
		return err
	}
	defer rows.Close()
	counts := map[string]cveReferenceGroupCounts{}
	for rows.Next() {
		var key string
		var c cveReferenceGroupCounts
		if err := rows.Scan(&key, &c.Total, &c.Matchable, &c.Sources); err != nil {
			return err
		}
		counts[key] = c
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range entries {
		c, ok := counts[entryKeys[i]]
		if !ok {
			continue
		}
		entries[i].ReferenceGroupKey = entryKeys[i]
		entries[i].ReferenceGroupTotal = c.Total
		entries[i].ReferenceGroupMatchable = c.Matchable
		entries[i].ReferenceGroupSources = c.Sources
		entries[i].ReferenceGroupStatus = "ok"
	}
	return nil
}

func preferredReferenceGroupKey(keys []string) string {
	for _, prefix := range []string{"cve:", "debian:", "ghsa:", "rustsec:", "pysec:", "go:", "mal:", "alma:", "suse:", "drupal:", "dtsa:", "osv:", "gsd:", "repo:", "vendor:"} {
		for _, key := range keys {
			if strings.HasPrefix(key, prefix) {
				return key
			}
		}
	}
	return ""
}

func markCveReferenceGroupStatus(entries []models.CveEntry, status string) {
	for i := range entries {
		if key := preferredReferenceGroupKey(entries[i].ReferenceKeys); key != "" {
			entries[i].ReferenceGroupKey = key
			entries[i].ReferenceGroupStatus = status
		}
	}
}

func (db *DB) GetCveReferenceGroupSummary(ctx context.Context, key string, limit int) (CveReferenceGroupSummary, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	filter, args, ok := cveReferenceKeyWhere(key, 1)
	if !ok {
		return CveReferenceGroupSummary{}, ErrInvalidCveReferenceKey
	}
	summary := CveReferenceGroupSummary{Key: strings.TrimSpace(key)}
	baseQ := "FROM cve_database WHERE " + filter
	if err := db.QueryRowContext(ctx, "SELECT count(*), count(*) FILTER (WHERE "+cveSourceMatchablePredicateSQL("CASE WHEN jsonb_typeof(affected_products) = 'array' THEN affected_products ELSE '[]'::jsonb END", "ecosystem")+") "+baseQ, args...).Scan(&summary.Total, &summary.Matchable); err != nil {
		return summary, err
	}
	var err error
	if summary.Sources, err = db.cveReferenceGroupBuckets(ctx, "source", baseQ, args); err != nil {
		return summary, err
	}
	if summary.Categories, err = db.cveReferenceGroupBuckets(ctx, "COALESCE(NULLIF(category, ''), '(uncategorized)')", baseQ, args); err != nil {
		return summary, err
	}
	if summary.Ecosystems, err = db.cveReferenceGroupBuckets(ctx, "COALESCE(NULLIF(ecosystem, ''), '(unknown)')", baseQ, args); err != nil {
		return summary, err
	}
	if summary.SourceGroups, err = db.cveReferenceGroupBuckets(ctx, "COALESCE(NULLIF(source, ''), '(unknown)') || ' / ' || COALESCE(NULLIF(category, ''), '(uncategorized)') || ' / ' || COALESCE(NULLIF(ecosystem, ''), '(unknown)')", baseQ, args); err != nil {
		return summary, err
	}
	if summary.AffectedPackages, summary.AffectedPackageTotal, err = db.cveReferenceGroupAffectedPackages(ctx, baseQ, args, limit); err != nil {
		return summary, err
	}
	dataArgs := append([]any{}, args...)
	dataArgs = append(dataArgs, limit)
	rows, err := db.QueryContext(ctx, fmt.Sprintf("SELECT %s %s ORDER BY cvss_score DESC NULLS LAST, updated_at DESC LIMIT $%d", CveCols, baseQ, len(dataArgs)), dataArgs...)
	if err != nil {
		return summary, err
	}
	defer rows.Close()
	for rows.Next() {
		var e models.CveEntry
		if err := ScanCveEntry(rows, &e); err != nil {
			return summary, err
		}
		e.MatchableAffected = cveEntryMatchableAffectedCount(e.AffectedProducts, e.Ecosystem)
		e.Matchable = e.MatchableAffected > 0
		e.MatchabilityReason = cveEntryMatchabilityReason(e.AffectedProducts, e.Ecosystem)
		e.ReferenceKeys = cveReferenceKeys(e)
		for _, refKey := range e.ReferenceKeys {
			summary.ReferenceKeys = appendUnique(summary.ReferenceKeys, refKey)
		}
		summary.Items = append(summary.Items, e)
	}
	return summary, rows.Err()
}

func (db *DB) cveReferenceGroupBuckets(ctx context.Context, expr, baseQ string, args []any) ([]CveReferenceGroupBucket, error) {
	rows, err := db.QueryContext(ctx, fmt.Sprintf(`SELECT %s AS name, count(*)
		%s
		GROUP BY name
		ORDER BY count(*) DESC, name
		LIMIT 20`, expr, baseQ), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CveReferenceGroupBucket{}
	for rows.Next() {
		var b CveReferenceGroupBucket
		if err := rows.Scan(&b.Name, &b.Count); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (db *DB) cveReferenceGroupAffectedPackages(ctx context.Context, baseQ string, args []any, limit int) ([]CveAffectedPackage, int, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	countQ := "SELECT count(*) FROM cve_affected_packages cap JOIN cve_database c ON c.id = cap.cve_id WHERE " + strings.TrimPrefix(baseQ, "FROM cve_database WHERE ")
	var total int
	if err := db.QueryRowContext(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	dataArgs := append([]any{}, args...)
	dataArgs = append(dataArgs, limit)
	rows, err := db.QueryContext(ctx, fmt.Sprintf(`
SELECT cap.cve_id, cap.vulnerability_id, cap.source, cap.package_name, cap.ecosystem, cap.fixed_version, cap.affected_product::text, cap.updated_at
FROM cve_affected_packages cap
JOIN cve_database c ON c.id = cap.cve_id
WHERE %s
ORDER BY cap.package_name, cap.ecosystem, cap.fixed_version, cap.source, cap.vulnerability_id
LIMIT $%d`, strings.TrimPrefix(baseQ, "FROM cve_database WHERE "), len(dataArgs)), dataArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []CveAffectedPackage{}
	for rows.Next() {
		var item CveAffectedPackage
		if err := rows.Scan(&item.CveID, &item.VulnerabilityID, &item.Source, &item.PackageName, &item.Ecosystem, &item.FixedVersion, &item.AffectedProduct, &item.UpdatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func cveReferenceKeys(e models.CveEntry) []string {
	keys := []string{}
	text := strings.Join([]string{e.VulnerabilityID, e.Title, e.Description, e.References, e.RawData}, "\n")
	addRegexKeys := func(prefix string, re *regexp.Regexp, upper bool) {
		for _, match := range re.FindAllString(text, -1) {
			match = strings.TrimSpace(match)
			if upper {
				match = strings.ToUpper(match)
			}
			keys = appendUnique(keys, prefix+match)
		}
	}
	addRegexKeys("cve:", cveReferenceKeyRe, true)
	addRegexKeys("ghsa:", ghsaReferenceKeyRe, true)
	addRegexKeys("rustsec:", rustsecReferenceKeyRe, true)
	addRegexKeys("pysec:", pysecReferenceKeyRe, true)
	addRegexKeys("go:", goReferenceKeyRe, true)
	addRegexKeys("debian:", debianAdvisoryKeyRe, true)
	addRegexKeys("mal:", malwareAdvisoryKeyRe, true)
	addRegexKeys("alma:", almaAdvisoryKeyRe, true)
	addRegexKeys("suse:", suseAdvisoryKeyRe, false)
	addRegexKeys("drupal:", drupalAdvisoryKeyRe, true)
	addRegexKeys("dtsa:", dtsaAdvisoryKeyRe, true)
	addRegexKeys("osv:", osvAdvisoryKeyRe, true)
	addRegexKeys("gsd:", gsdAdvisoryKeyRe, true)
	if isDebianSecurityEntry(e) {
		keys = appendUnique(keys, "vendor:debian")
	}

	for _, raw := range referenceURLs(e.References) {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		host := strings.ToLower(strings.TrimPrefix(u.Host, "www."))
		path := strings.Trim(u.Path, "/")
		parts := strings.Split(path, "/")
		if host == "github.com" && len(parts) >= 2 {
			owner := strings.ToLower(parts[0])
			repo := strings.ToLower(strings.TrimSuffix(parts[1], ".git"))
			if githubRepoPartRe.MatchString(owner) && githubRepoPartRe.MatchString(repo) {
				keys = appendUnique(keys, "repo:github.com/"+owner+"/"+repo)
			}
			continue
		}
		if strings.Contains(host, "debian.org") {
			keys = appendUnique(keys, "vendor:debian")
		} else if strings.Contains(host, "ubuntu.com") {
			keys = appendUnique(keys, "vendor:ubuntu")
		} else if strings.Contains(host, "redhat.com") {
			keys = appendUnique(keys, "vendor:redhat")
		}
	}
	return keys
}

func isDebianSecurityEntry(e models.CveEntry) bool {
	eco := strings.ToLower(strings.TrimSpace(e.Ecosystem))
	if eco == "debian" || strings.HasPrefix(eco, "debian:") {
		return true
	}
	vulnID := strings.ToUpper(strings.TrimSpace(e.VulnerabilityID))
	return strings.HasPrefix(vulnID, "DEBIAN-CVE-") || debianAdvisoryKeyRe.MatchString(vulnID)
}

func cveReferenceKeyFilter(referenceKey string) (string, []string) {
	key := strings.TrimSpace(referenceKey)
	if key == "" {
		return "", nil
	}
	lower := strings.ToLower(key)
	indexFilter := `EXISTS (SELECT 1 FROM cve_reference_keys crk WHERE crk.cve_id = id AND crk.reference_key = $%d)`
	switch {
	case strings.HasPrefix(lower, "cve:"):
		cve := strings.ToUpper(strings.TrimSpace(key[len("cve:"):]))
		if !cveReferenceKeyRe.MatchString(cve) {
			return "", nil
		}
		return indexFilter, []string{"cve:" + cve}
	case strings.HasPrefix(lower, "ghsa:"):
		ghsa := strings.ToUpper(strings.TrimSpace(key[len("ghsa:"):]))
		if !ghsaReferenceKeyRe.MatchString(ghsa) {
			return "", nil
		}
		return indexFilter, []string{"ghsa:" + ghsa}
	case strings.HasPrefix(lower, "rustsec:"):
		id := strings.ToUpper(strings.TrimSpace(key[len("rustsec:"):]))
		if !rustsecReferenceKeyRe.MatchString(id) {
			return "", nil
		}
		return indexFilter, []string{"rustsec:" + id}
	case strings.HasPrefix(lower, "pysec:"):
		id := strings.ToUpper(strings.TrimSpace(key[len("pysec:"):]))
		if !pysecReferenceKeyRe.MatchString(id) {
			return "", nil
		}
		return indexFilter, []string{"pysec:" + id}
	case strings.HasPrefix(lower, "go:"):
		id := strings.ToUpper(strings.TrimSpace(key[len("go:"):]))
		if !goReferenceKeyRe.MatchString(id) {
			return "", nil
		}
		return indexFilter, []string{"go:" + id}
	case strings.HasPrefix(lower, "debian:"):
		id := strings.ToUpper(strings.TrimSpace(key[len("debian:"):]))
		if !debianAdvisoryKeyRe.MatchString(id) {
			return "", nil
		}
		return indexFilter, []string{"debian:" + id}
	case strings.HasPrefix(lower, "mal:"):
		id := strings.ToUpper(strings.TrimSpace(key[len("mal:"):]))
		if !malwareAdvisoryKeyRe.MatchString(id) {
			return "", nil
		}
		return indexFilter, []string{"mal:" + id}
	case strings.HasPrefix(lower, "alma:"):
		id := strings.ToUpper(strings.TrimSpace(key[len("alma:"):]))
		if !almaAdvisoryKeyRe.MatchString(id) {
			return "", nil
		}
		return indexFilter, []string{"alma:" + id}
	case strings.HasPrefix(lower, "suse:"):
		id := strings.TrimSpace(key[len("suse:"):])
		if !suseAdvisoryKeyRe.MatchString(id) {
			return "", nil
		}
		return indexFilter, []string{"suse:" + id}
	case strings.HasPrefix(lower, "drupal:"):
		id := strings.ToUpper(strings.TrimSpace(key[len("drupal:"):]))
		if !drupalAdvisoryKeyRe.MatchString(id) {
			return "", nil
		}
		return indexFilter, []string{"drupal:" + id}
	case strings.HasPrefix(lower, "dtsa:"):
		id := strings.ToUpper(strings.TrimSpace(key[len("dtsa:"):]))
		if !dtsaAdvisoryKeyRe.MatchString(id) {
			return "", nil
		}
		return indexFilter, []string{"dtsa:" + id}
	case strings.HasPrefix(lower, "osv:"):
		id := strings.ToUpper(strings.TrimSpace(key[len("osv:"):]))
		if !osvAdvisoryKeyRe.MatchString(id) {
			return "", nil
		}
		return indexFilter, []string{"osv:" + id}
	case strings.HasPrefix(lower, "gsd:"):
		id := strings.ToUpper(strings.TrimSpace(key[len("gsd:"):]))
		if !gsdAdvisoryKeyRe.MatchString(id) {
			return "", nil
		}
		return indexFilter, []string{"gsd:" + id}
	case strings.HasPrefix(lower, "repo:"):
		repo := strings.TrimSpace(strings.TrimPrefix(lower, "repo:"))
		if !strings.HasPrefix(repo, "github.com/") || strings.Count(repo, "/") < 2 {
			return "", nil
		}
		return indexFilter, []string{"repo:" + repo}
	case lower == "vendor:debian":
		return indexFilter, []string{"vendor:debian"}
	case lower == "vendor:ubuntu":
		return indexFilter, []string{"vendor:ubuntu"}
	case lower == "vendor:redhat":
		return indexFilter, []string{"vendor:redhat"}
	default:
		return "", nil
	}
}

func cveReferenceKeyFilterForSearchQuery(query string) (string, []string) {
	if filter, vals := cveReferenceKeyFilter(query); filter != "" {
		return filter, vals
	}
	key := strings.TrimSpace(query)
	if key == "" || strings.ContainsAny(key, " \t\r\n") {
		return "", nil
	}
	if exactReferenceMatch(cveReferenceKeyRe, key) {
		return cveReferenceKeyFilter("cve:" + strings.ToUpper(key))
	}
	if exactReferenceMatch(ghsaReferenceKeyRe, key) {
		return cveReferenceKeyFilter("ghsa:" + strings.ToUpper(key))
	}
	if exactReferenceMatch(rustsecReferenceKeyRe, key) {
		return cveReferenceKeyFilter("rustsec:" + strings.ToUpper(key))
	}
	if exactReferenceMatch(pysecReferenceKeyRe, key) {
		return cveReferenceKeyFilter("pysec:" + strings.ToUpper(key))
	}
	if exactReferenceMatch(goReferenceKeyRe, key) {
		return cveReferenceKeyFilter("go:" + strings.ToUpper(key))
	}
	if exactReferenceMatch(debianAdvisoryKeyRe, key) {
		return cveReferenceKeyFilter("debian:" + strings.ToUpper(key))
	}
	if exactReferenceMatch(malwareAdvisoryKeyRe, key) {
		return cveReferenceKeyFilter("mal:" + strings.ToUpper(key))
	}
	if exactReferenceMatch(almaAdvisoryKeyRe, key) {
		return cveReferenceKeyFilter("alma:" + strings.ToUpper(key))
	}
	if exactReferenceMatch(suseAdvisoryKeyRe, key) {
		return cveReferenceKeyFilter("suse:" + key)
	}
	if exactReferenceMatch(drupalAdvisoryKeyRe, key) {
		return cveReferenceKeyFilter("drupal:" + strings.ToUpper(key))
	}
	if exactReferenceMatch(dtsaAdvisoryKeyRe, key) {
		return cveReferenceKeyFilter("dtsa:" + strings.ToUpper(key))
	}
	if exactReferenceMatch(osvAdvisoryKeyRe, key) {
		return cveReferenceKeyFilter("osv:" + strings.ToUpper(key))
	}
	if exactReferenceMatch(gsdAdvisoryKeyRe, key) {
		return cveReferenceKeyFilter("gsd:" + strings.ToUpper(key))
	}
	return "", nil
}

func exactReferenceMatch(re *regexp.Regexp, s string) bool {
	match := re.FindString(s)
	return match != "" && len(match) == len(s)
}

func cveReferenceKeyWhere(referenceKey string, start int) (string, []any, bool) {
	filter, vals := cveReferenceKeyFilter(referenceKey)
	if filter == "" {
		return "", nil, false
	}
	args := make([]any, 0, len(vals))
	for _, val := range vals {
		args = append(args, val)
	}
	return fmt.Sprintf(filter, placeholderRange(start, len(args))...), args, true
}

func cveReferenceKeyWhereFromSearchQuery(query string, start int) (string, []any, bool) {
	filter, vals := cveReferenceKeyFilterForSearchQuery(query)
	if filter == "" {
		return "", nil, false
	}
	args := make([]any, 0, len(vals))
	for _, val := range vals {
		args = append(args, val)
	}
	return fmt.Sprintf(filter, placeholderRange(start, len(args))...), args, true
}

func placeholderRange(start, count int) []any {
	out := make([]any, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, start+i)
	}
	return out
}

func referenceURLs(refs string) []string {
	type refEntry struct {
		URL string `json:"url"`
	}
	out := []string{}
	var entries []refEntry
	if refs != "" && json.Unmarshal([]byte(refs), &entries) == nil {
		for _, entry := range entries {
			if strings.TrimSpace(entry.URL) != "" {
				out = append(out, strings.TrimSpace(entry.URL))
			}
		}
		return out
	}
	if strings.TrimSpace(refs) != "" {
		out = append(out, strings.Fields(refs)...)
	}
	return out
}

func calcCvssScore(vector string) float64 {
	if vector == "" {
		return 0
	}
	prefix := ""
	if strings.HasPrefix(vector, "CVSS:") {
		idx := strings.Index(vector, "/")
		if idx <= 0 {
			return 0
		}
		prefix = vector[:idx+1]
		vector = vector[idx+1:]
	}

	parts := strings.Split(vector, "/")
	kv := make(map[string]string)
	for _, p := range parts {
		if sep := strings.Index(p, ":"); sep > 0 {
			kv[p[:sep]] = p[sep+1:]
		}
	}

	if strings.HasPrefix(prefix, "CVSS:4.0") {
		return calcCvss40(kv)
	}
	if strings.HasPrefix(prefix, "CVSS:3") {
		return calcCvss3x(kv)
	}
	if strings.HasPrefix(prefix, "CVSS:2") || kv["Au"] != "" {
		return calcCvss2(kv)
	}
	return 0
}

func calcCvss2(kv map[string]string) float64 {
	av := map[string]float64{"L": 0.395, "A": 0.646, "N": 1.0}
	ac := map[string]float64{"H": 0.35, "M": 0.61, "L": 0.71}
	au := map[string]float64{"M": 0.45, "S": 0.56, "N": 0.704}
	cia := map[string]float64{"N": 0.0, "P": 0.275, "C": 0.66}
	avVal, ok := av[kv["AV"]]
	if !ok {
		return 0
	}
	acVal, ok := ac[kv["AC"]]
	if !ok {
		return 0
	}
	auVal, ok := au[kv["Au"]]
	if !ok {
		return 0
	}
	cVal, ok := cia[kv["C"]]
	if !ok {
		return 0
	}
	iVal, ok := cia[kv["I"]]
	if !ok {
		return 0
	}
	aVal, ok := cia[kv["A"]]
	if !ok {
		return 0
	}
	impact := 10.41 * (1 - (1-cVal)*(1-iVal)*(1-aVal))
	exploit := 20 * avVal * acVal * auVal
	if impact == 0 {
		return 0
	}
	fImpact := 1.176
	return roundup1(((0.6 * impact) + (0.4 * exploit) - 1.5) * fImpact)
}

func calcCvss3x(kv map[string]string) float64 {
	avW := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	acW := map[string]float64{"L": 0.77, "H": 0.44}
	prWU := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	prWC := map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	uiW := map[string]float64{"N": 0.85, "R": 0.62}
	cW := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	iW := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	aW := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}

	scopeChanged := kv["S"] == "C"

	pr := prWU[kv["PR"]]
	if scopeChanged {
		pr = prWC[kv["PR"]]
	}

	iss := 1 - (1-cW[kv["C"]])*(1-iW[kv["I"]])*(1-aW[kv["A"]])
	if iss <= 0 {
		return 0
	}

	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = iss * 6.42
	}
	if impact <= 0 {
		return 0
	}

	exploitability := 8.22 * avW[kv["AV"]] * acW[kv["AC"]] * pr * uiW[kv["UI"]]

	var base float64
	if scopeChanged {
		base = math.Min(1.08*(impact+exploitability), 10)
	} else {
		base = math.Min(impact+exploitability, 10)
	}
	return math.Round(base*10) / 10
}

var cvss40Lookup = map[string]float64{
	// EQ1=0, EQ2=0
	"000000": 10, "000001": 9.9, "000010": 9.8, "000011": 9.5, "000020": 9.5, "000021": 9.2,
	"000100": 10, "000101": 9.6, "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1,
	"000200": 9.3, "000201": 9, "000210": 8.9, "000211": 8, "000220": 8.1, "000221": 6.8,
	"001000": 9.8, "001001": 9.5, "001010": 9.5, "001011": 9.2, "001020": 9, "001021": 8.4,
	"001100": 9.3, "001101": 9.2, "001110": 8.9, "001111": 8.1, "001120": 8.1, "001121": 6.5,
	"001200": 8.8, "001201": 8, "001210": 7.8, "001211": 7, "001220": 6.9, "001221": 4.8,
	"002001": 9.2, "002011": 8.2, "002021": 7.2,
	"002101": 7.9, "002111": 6.9, "002121": 5,
	"002201": 6.9, "002211": 5.5, "002221": 2.7,
	// EQ1=0, EQ2=1
	"010000": 9.9, "010001": 9.7, "010010": 9.5, "010011": 9.2, "010020": 9.2, "010021": 8.5,
	"010100": 9.5, "010101": 9.1, "010110": 9, "010111": 8.3, "010120": 8.4, "010121": 7.1,
	"010200": 9.2, "010201": 8.1, "010210": 8.2, "010211": 7.1, "010220": 7.2, "010221": 5.3,
	"011000": 9.5, "011001": 9.3, "011010": 9.2, "011011": 8.5, "011020": 8.5, "011021": 7.3,
	"011100": 9.2, "011101": 8.2, "011110": 8, "011111": 7.2, "011120": 7, "011121": 5.9,
	"011200": 8.4, "011201": 7, "011210": 7.1, "011211": 5.2, "011220": 5, "011221": 3,
	"012001": 8.6, "012011": 7.5, "012021": 5.2,
	"012101": 7.1, "012111": 5.2, "012121": 2.9,
	"012201": 6.3, "012211": 2.9, "012221": 1.7,
	// EQ1=1, EQ2=0
	"100000": 9.8, "100001": 9.5, "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1,
	"100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4, "100120": 7.7, "100121": 6.4,
	"100200": 8.7, "100201": 7.5, "100210": 7.4, "100211": 6.3, "100220": 6.3, "100221": 4.9,
	"101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7, "101020": 7.6, "101021": 6.7,
	"101100": 8.6, "101101": 7.6, "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5,
	"101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2, "101220": 5.2, "101221": 2.5,
	"102001": 8.3, "102011": 7, "102021": 5.4,
	"102101": 6.5, "102111": 5.8, "102121": 2.6,
	"102201": 5.3, "102211": 2.1, "102221": 1.3,
	// EQ1=1, EQ2=1
	"110000": 9.5, "110001": 9, "110010": 8.8, "110011": 7.6, "110020": 7.6, "110021": 7,
	"110100": 9, "110101": 7.7, "110110": 7.5, "110111": 6.2, "110120": 6.1, "110121": 5.3,
	"110200": 7.7, "110201": 6.6, "110210": 6.8, "110211": 5.9, "110220": 5.2, "110221": 3,
	"111000": 8.9, "111001": 7.8, "111010": 7.6, "111011": 6.7, "111020": 6.2, "111021": 5.8,
	"111100": 7.4, "111101": 5.9, "111110": 5.7, "111111": 5.7, "111120": 4.7, "111121": 2.3,
	"111200": 6.1, "111201": 5.2, "111210": 5.7, "111211": 2.9, "111220": 2.4, "111221": 1.6,
	"112001": 7.1, "112011": 5.9, "112021": 3,
	"112101": 5.8, "112111": 2.6, "112121": 1.5,
	"112201": 2.3, "112211": 1.3, "112221": 0.6,
	// EQ1=2, EQ2=0
	"200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2, "200020": 7.5, "200021": 5.8,
	"200100": 8.6, "200101": 7.4, "200110": 7.4, "200111": 6.1, "200120": 5.6, "200121": 3.4,
	"200200": 7, "200201": 5.4, "200210": 5.2, "200211": 4, "200220": 4, "200221": 2.2,
	"201000": 8.5, "201001": 7.5, "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1,
	"201100": 7.2, "201101": 5.7, "201110": 5.5, "201111": 4.1, "201120": 4.6, "201121": 1.9,
	"201200": 5.3, "201201": 3.6, "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8,
	"202001": 6.4, "202011": 5.1, "202021": 2,
	"202101": 4.7, "202111": 2.1, "202121": 1.1,
	"202201": 2.4, "202211": 0.9, "202221": 0.4,
	// EQ1=2, EQ2=1
	"210000": 8.8, "210001": 7.5, "210010": 7.3, "210011": 5.3, "210020": 6, "210021": 5,
	"210100": 7.3, "210101": 5.5, "210110": 5.9, "210111": 4, "210120": 4.1, "210121": 2,
	"210200": 5.4, "210201": 4.3, "210210": 4.5, "210211": 2.2, "210220": 2, "210221": 1.1,
	"211000": 7.5, "211001": 5.5, "211010": 5.8, "211011": 4.5, "211020": 4, "211021": 2.1,
	"211100": 6.1, "211101": 5.1, "211110": 4.8, "211111": 1.8, "211120": 2, "211121": 0.9,
	"211200": 4.6, "211201": 1.8, "211210": 1.7, "211211": 0.7, "211220": 0.8, "211221": 0.2,
	"212001": 5.3, "212011": 2.4, "212021": 1.4,
	"212101": 2.4, "212111": 1.2, "212121": 0.5,
	"212201": 1, "212211": 0.3, "212221": 0.1,
}

func calcCvss40(kv map[string]string) float64 {
	// EQ1: AV/PR/UI (Table 24)
	avN := kv["AV"] == "N"
	prN := kv["PR"] == "N"
	uiN := kv["UI"] == "N"
	var eq1 int
	if avN && prN && uiN {
		eq1 = 0
	} else if (avN && prN && (kv["UI"] == "A" || kv["UI"] == "P")) ||
		(avN && kv["PR"] == "L" && uiN) ||
		(kv["AV"] == "A" && prN && uiN) {
		eq1 = 1
	} else {
		eq1 = 2
	}

	// EQ2: AC/AT (Table 25)
	var eq2 int
	if kv["AC"] == "L" && kv["AT"] == "N" {
		eq2 = 0
	} else {
		eq2 = 1
	}

	// EQ3: VC/VI/VA (Table 26)
	var eq3 int
	if kv["VC"] == "H" || kv["VI"] == "H" || kv["VA"] == "H" {
		eq3 = 0
	} else if kv["VC"] == "L" || kv["VI"] == "L" || kv["VA"] == "L" {
		eq3 = 1
	} else {
		eq3 = 2
	}

	// EQ4: SC/SI/SA (Table 27)
	var eq4 int
	if kv["SC"] == "H" || kv["SI"] == "H" || kv["SA"] == "H" {
		eq4 = 0
	} else if kv["SC"] == "L" || kv["SI"] == "L" || kv["SA"] == "L" {
		eq4 = 1
	} else {
		eq4 = 2
	}

	// EQ5: E (Table 28)
	e := kv["E"]
	if e == "" {
		e = "X"
	}
	var eq5 int
	switch e {
	case "A":
		eq5 = 0
	case "P":
		eq5 = 1
	default: // U or X
		eq5 = 2
	}

	// EQ6: VC+CR / VI+IR / VA+AR (Table 29)
	// CR/IR/AR default to X (Not Defined), treated as H for EQ6
	cr := kv["CR"]
	if cr == "" {
		cr = "X"
	}
	ir := kv["IR"]
	if ir == "" {
		ir = "X"
	}
	ar := kv["AR"]
	if ar == "" {
		ar = "X"
	}
	eq6 := 1
	if (kv["VC"] == "H" && (cr == "H" || cr == "X")) ||
		(kv["VI"] == "H" && (ir == "H" || ir == "X")) ||
		(kv["VA"] == "H" && (ar == "H" || ar == "X")) {
		eq6 = 0
	}

	key := fmt.Sprintf("%d%d%d%d%d%d", eq1, eq2, eq3, eq4, eq5, eq6)
	if score, ok := cvss40Lookup[key]; ok {
		return score
	}
	return 0
}

func severityFromScore(score float64) string {
	if score >= 9.0 {
		return "CRITICAL"
	} else if score >= 7.0 {
		return "HIGH"
	} else if score >= 4.0 {
		return "MEDIUM"
	} else if score >= 0.1 {
		return "LOW"
	}
	return ""
}

func (db *DB) NormalizeVulnSeverity(ctx context.Context) (int, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE vulnerabilities
		SET severity = CASE
			WHEN cvss_score >= 9.0 THEN 'CRITICAL'
			WHEN cvss_score >= 7.0 THEN 'HIGH'
			WHEN cvss_score >= 4.0 THEN 'MEDIUM'
			WHEN cvss_score >= 0.1 THEN 'LOW'
			ELSE severity
		END
		WHERE cvss_score > 0 AND severity != CASE
			WHEN cvss_score >= 9.0 THEN 'CRITICAL'
			WHEN cvss_score >= 7.0 THEN 'HIGH'
			WHEN cvss_score >= 4.0 THEN 'MEDIUM'
			WHEN cvss_score >= 0.1 THEN 'LOW'
			ELSE ''
		END`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (db *DB) CalcCvssScores(ctx context.Context) (int, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, cvss_vector FROM cve_database WHERE cvss_vector LIKE 'CVSS:4%' OR (cvss_vector != '' AND cvss_score = 0)`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	type update struct {
		id       string
		score    float64
		severity string
	}
	var updates []update

	for rows.Next() {
		var id, vector string
		if err := rows.Scan(&id, &vector); err != nil {
			continue
		}
		score := calcCvssScore(vector)
		severity := severityFromScore(score)
		updates = append(updates, update{id: id, score: score, severity: severity})
	}

	if len(updates) == 0 {
		return 0, nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `UPDATE cve_database SET cvss_score=$1, severity=CASE WHEN $2 != '' THEN $2 ELSE severity END WHERE id=$3`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	for _, u := range updates {
		if _, err := stmt.ExecContext(ctx, u.score, u.severity, u.id); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(updates), nil
}

func (db *DB) GetCveSources(ctx context.Context) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT source FROM cve_database WHERE source != '' ORDER BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sources []string
	for rows.Next() {
		var s string
		rows.Scan(&s)
		sources = append(sources, s)
	}
	return sources, nil
}

type CveSourceStats struct {
	Source           string     `json:"source"`
	Count            int        `json:"count"`
	Matchable        int        `json:"matchable"`
	MatchablePercent float64    `json:"matchable_percent"`
	WithEcosystem    int        `json:"with_ecosystem"`
	WithFixed        int        `json:"with_fixed"`
	WithRanges       int        `json:"with_ranges"`
	WithCVSS         int        `json:"with_cvss"`
	LastUpdate       *time.Time `json:"last_update"`
}

type CveOsvEcosystemStats struct {
	Ecosystem         string     `json:"ecosystem"`
	IndexedRows       int        `json:"indexed_rows"`
	MatchableCVEs     int        `json:"matchable_cves"`
	RawRecords        int        `json:"raw_records"`
	LastUpdate        *time.Time `json:"last_update"`
	RawLastUpdate     *time.Time `json:"raw_last_update"`
	IndexedLastUpdate *time.Time `json:"indexed_last_update"`
}

type CveSourceFreshnessStats struct {
	Source     string     `json:"source"`
	Count      int        `json:"count"`
	LastUpdate *time.Time `json:"last_update"`
}

type CveReferenceGroupBucket struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type CveReferenceGroupSummary struct {
	Key                  string                    `json:"key"`
	Total                int                       `json:"total"`
	Matchable            int                       `json:"matchable"`
	Sources              []CveReferenceGroupBucket `json:"sources"`
	Categories           []CveReferenceGroupBucket `json:"categories"`
	Ecosystems           []CveReferenceGroupBucket `json:"ecosystems"`
	SourceGroups         []CveReferenceGroupBucket `json:"source_groups"`
	ReferenceKeys        []string                  `json:"reference_keys"`
	Items                []models.CveEntry         `json:"items"`
	AffectedPackageTotal int                       `json:"affected_package_total"`
	AffectedPackages     []CveAffectedPackage      `json:"affected_packages"`
}

type CveAffectedPackageIndexStats struct {
	Count                   int        `json:"count"`
	SourceCount             int        `json:"source_count"`
	IndexedCVEs             int        `json:"indexed_cves"`
	MatchableCVEs           int        `json:"matchable_cves"`
	CoveragePercent         float64    `json:"coverage_percent"`
	MissingMatchableSources []string   `json:"missing_matchable_sources"`
	LastUpdate              *time.Time `json:"last_update"`
	LatestMatchableUpdate   *time.Time `json:"latest_matchable_update"`
	Stale                   bool       `json:"stale"`
	Orphans                 int        `json:"orphans"`
}

type CveReferenceKeyIndexStats struct {
	Count           int        `json:"count"`
	IndexedCVEs     int        `json:"indexed_cves"`
	TotalCVEs       int        `json:"total_cves"`
	CanonicalCVEs   int        `json:"canonical_cves"`
	VendorKeys      int        `json:"vendor_keys"`
	RepositoryKeys  int        `json:"repository_keys"`
	CoveragePercent float64    `json:"coverage_percent"`
	LastUpdate      *time.Time `json:"last_update"`
	LatestCVEUpdate *time.Time `json:"latest_cve_update"`
	Stale           bool       `json:"stale"`
	Orphans         int        `json:"orphans"`
}

type CveAffectedPackage struct {
	CveID           string    `json:"cve_id"`
	VulnerabilityID string    `json:"vulnerability_id"`
	Source          string    `json:"source"`
	PackageName     string    `json:"package_name"`
	Ecosystem       string    `json:"ecosystem"`
	FixedVersion    string    `json:"fixed_version"`
	AffectedProduct string    `json:"affected_product"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type CveEPSSMergeStats struct {
	EPSSRecords              int     `json:"epss_records"`
	EPSSCVEs                 int     `json:"epss_cves"`
	MatchedCVEs              int     `json:"matched_cves"`
	UnmatchedCVEs            int     `json:"unmatched_cves"`
	NonEPSSCVEs              int     `json:"non_epss_cves"`
	NonEPSSCVEsWithEPSS      int     `json:"non_epss_cves_with_epss"`
	NonEPSSCoveragePercent   float64 `json:"non_epss_coverage_percent"`
	EnrichedRecords          int     `json:"enriched_records"`
	EnrichedCVEs             int     `json:"enriched_cves"`
	EnrichedSourceCount      int     `json:"enriched_source_count"`
	EPSSUniverseMatchPercent float64 `json:"epss_universe_match_percent"`
	MergeCoveragePercent     float64 `json:"merge_coverage_percent"`
}

type CvePlaceholderStats struct {
	TemporaryPlaceholders int `json:"temporary_placeholders"`
	EmptyVulnerabilityIDs int `json:"empty_vulnerability_ids"`
	EmptySources          int `json:"empty_sources"`
}

func (db *DB) GetCvePlaceholderStats(ctx context.Context) (*CvePlaceholderStats, error) {
	var stats CvePlaceholderStats
	err := db.QueryRowContext(ctx, `
SELECT
	count(*) FILTER (
		WHERE upper(trim(vulnerability_id)) LIKE 'TEMP-%'
		   OR upper(trim(id)) LIKE 'TEMP-%'
		   OR upper(trim(vulnerability_id)) LIKE 'CVD-%'
		   OR upper(trim(id)) LIKE 'CVD-%'
	),
	count(*) FILTER (WHERE trim(vulnerability_id) = ''),
	count(*) FILTER (WHERE trim(source) = '')
FROM cve_database`).Scan(&stats.TemporaryPlaceholders, &stats.EmptyVulnerabilityIDs, &stats.EmptySources)
	if err != nil {
		return nil, err
	}
	return &stats, nil
}

func (db *DB) GetCveAffectedPackageIndexStats(ctx context.Context) (*CveAffectedPackageIndexStats, error) {
	var stats CveAffectedPackageIndexStats
	err := db.QueryRowContext(ctx, `
WITH affected_index AS (
	SELECT
		count(*) AS count,
		count(DISTINCT source) FILTER (WHERE source != '') AS source_count,
		count(DISTINCT cve_id) AS indexed_cves,
		max(updated_at) AS last_update
	FROM cve_affected_packages
),
indexed_source_freshness AS (
	SELECT max(updated_at) AS latest_matchable_update
	FROM cve_affected_packages
	WHERE source != ''
)
SELECT
	COALESCE(ai.count, 0),
	COALESCE(ai.source_count, 0),
	COALESCE(ai.indexed_cves, 0),
	COALESCE(ai.indexed_cves, 0),
	ai.last_update,
	isf.latest_matchable_update,
	0,
	ARRAY[]::text[]
FROM affected_index ai
CROSS JOIN indexed_source_freshness isf`).Scan(
		&stats.Count, &stats.SourceCount, &stats.IndexedCVEs, &stats.MatchableCVEs, &stats.LastUpdate, &stats.LatestMatchableUpdate, &stats.Orphans, pq.Array(&stats.MissingMatchableSources))
	if err != nil {
		return nil, err
	}
	if stats.MatchableCVEs > 0 {
		stats.CoveragePercent = math.Round(float64(stats.IndexedCVEs)*1000/float64(stats.MatchableCVEs)) / 10
	}
	stats.Stale = stats.MatchableCVEs > 0 && (stats.LastUpdate == nil || stats.LatestMatchableUpdate == nil || stats.LastUpdate.Before(*stats.LatestMatchableUpdate))
	if stats.MissingMatchableSources == nil {
		stats.MissingMatchableSources = []string{}
	}
	return &stats, nil
}

func (db *DB) GetCveAffectedPackageIndexHealthStats(ctx context.Context) (map[string]any, error) {
	var count, sourceCount, indexedCVEs int
	var lastUpdate *time.Time
	err := db.QueryRowContext(ctx, `
SELECT
	(SELECT count(*) FROM cve_affected_packages),
	(SELECT count(DISTINCT source) FROM cve_affected_packages WHERE source != ''),
	(SELECT count(DISTINCT cve_id) FROM cve_affected_packages),
	(SELECT max(updated_at) FROM cve_affected_packages)`).Scan(
		&count, &sourceCount, &indexedCVEs, &lastUpdate)
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"summary_mode": "indexed-only",
		"count":        count,
		"source_count": sourceCount,
		"indexed_cves": indexedCVEs,
		"orphans":      0,
	}
	if lastUpdate != nil {
		out["last_update"] = lastUpdate
	}
	return out, nil
}

func (db *DB) GetCveReferenceKeyIndexStats(ctx context.Context) (*CveReferenceKeyIndexStats, error) {
	var stats CveReferenceKeyIndexStats
	err := db.QueryRowContext(ctx, `
SELECT
	(SELECT count(*) FROM cve_reference_keys),
	(SELECT count(DISTINCT cve_id) FROM cve_reference_keys),
	(SELECT count(*) FROM cve_database),
	(SELECT count(DISTINCT cve_id) FROM cve_reference_keys WHERE reference_key LIKE 'cve:%'),
	(SELECT count(*) FROM cve_reference_keys WHERE reference_key LIKE 'vendor:%'),
	(SELECT count(*) FROM cve_reference_keys WHERE reference_key LIKE 'repo:%'),
	(SELECT max(updated_at) FROM cve_reference_keys),
	(SELECT max(updated_at) FROM cve_database),
	(SELECT count(*) FROM cve_reference_keys crk WHERE NOT EXISTS (SELECT 1 FROM cve_database c WHERE c.id = crk.cve_id))`).Scan(
		&stats.Count, &stats.IndexedCVEs, &stats.TotalCVEs, &stats.CanonicalCVEs, &stats.VendorKeys, &stats.RepositoryKeys,
		&stats.LastUpdate, &stats.LatestCVEUpdate, &stats.Orphans)
	if err != nil {
		return nil, err
	}
	if stats.TotalCVEs > 0 {
		stats.CoveragePercent = math.Round(float64(stats.IndexedCVEs)*1000/float64(stats.TotalCVEs)) / 10
	}
	stats.Stale = stats.TotalCVEs > 0 && (stats.LastUpdate == nil || stats.LatestCVEUpdate == nil || stats.LastUpdate.Before(*stats.LatestCVEUpdate))
	return &stats, nil
}

func (db *DB) GetCveReferenceKeyIndexHealthStats(ctx context.Context) (map[string]any, error) {
	var count, indexedCVEs int
	var lastUpdate *time.Time
	err := db.QueryRowContext(ctx, `
SELECT
	(SELECT count(*) FROM cve_reference_keys),
	(SELECT count(DISTINCT cve_id) FROM cve_reference_keys),
	(SELECT max(updated_at) FROM cve_reference_keys)`).Scan(
		&count, &indexedCVEs, &lastUpdate)
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"summary_mode":    "indexed-only",
		"count":           count,
		"indexed_cves":    indexedCVEs,
		"canonical_cves":  0,
		"vendor_keys":     0,
		"repository_keys": 0,
		"orphans":         0,
	}
	if lastUpdate != nil {
		out["last_update"] = lastUpdate
	}
	return out, nil
}

func (db *DB) ListCveAffectedPackages(ctx context.Context, cveID string, limit, offset int) ([]CveAffectedPackage, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	var total int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM cve_affected_packages WHERE cve_id=$1`, cveID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.QueryContext(ctx, `
SELECT cve_id, vulnerability_id, source, package_name, ecosystem, fixed_version, affected_product::text, updated_at
FROM cve_affected_packages
WHERE cve_id=$1
ORDER BY package_name, ecosystem, fixed_version
LIMIT $2 OFFSET $3`, cveID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []CveAffectedPackage{}
	for rows.Next() {
		var item CveAffectedPackage
		if err := rows.Scan(&item.CveID, &item.VulnerabilityID, &item.Source, &item.PackageName, &item.Ecosystem, &item.FixedVersion, &item.AffectedProduct, &item.UpdatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (db *DB) GetCveEPSSMergeStats(ctx context.Context) (*CveEPSSMergeStats, error) {
	var stats CveEPSSMergeStats
	err := db.QueryRowContext(ctx, `
WITH epss AS (
	SELECT vulnerability_id, count(*) AS records
	FROM cve_database
	WHERE source = 'epss'
	  AND vulnerability_id != ''
	  AND (epss_score > 0 OR epss_percentile > 0)
	GROUP BY vulnerability_id
),
non_epss AS (
	SELECT
		vulnerability_id,
		count(*) FILTER (WHERE epss_score > 0 OR epss_percentile > 0) AS enriched_records
	FROM cve_database
	WHERE source != 'epss'
	  AND vulnerability_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
	GROUP BY vulnerability_id
)
SELECT
	COALESCE((SELECT sum(records) FROM epss), 0),
	(SELECT count(*) FROM epss),
	count(n.vulnerability_id),
	count(*) - count(n.vulnerability_id),
	(SELECT count(*) FROM non_epss),
	count(n.vulnerability_id),
	COALESCE(sum(n.enriched_records), 0),
	count(n.vulnerability_id) FILTER (WHERE n.enriched_records > 0),
	COALESCE((SELECT count(DISTINCT source) FROM cve_database WHERE source != 'epss' AND vulnerability_id != '' AND (epss_score > 0 OR epss_percentile > 0)), 0)
FROM epss e
LEFT JOIN non_epss n ON n.vulnerability_id = e.vulnerability_id`).Scan(
		&stats.EPSSRecords, &stats.EPSSCVEs, &stats.MatchedCVEs, &stats.UnmatchedCVEs,
		&stats.NonEPSSCVEs, &stats.NonEPSSCVEsWithEPSS, &stats.EnrichedRecords, &stats.EnrichedCVEs, &stats.EnrichedSourceCount)
	if err != nil {
		return nil, err
	}
	if stats.EPSSCVEs > 0 {
		stats.EPSSUniverseMatchPercent = math.Round(float64(stats.MatchedCVEs)*1000/float64(stats.EPSSCVEs)) / 10
		stats.MergeCoveragePercent = stats.EPSSUniverseMatchPercent
	}
	if stats.NonEPSSCVEs > 0 {
		stats.NonEPSSCoveragePercent = math.Round(float64(stats.NonEPSSCVEsWithEPSS)*1000/float64(stats.NonEPSSCVEs)) / 10
	}
	return &stats, nil
}

func (db *DB) GetCveSourceStats(ctx context.Context) ([]CveSourceStats, error) {
	rows, err := db.QueryContext(ctx, `
WITH base AS (
	SELECT
		source,
		count(*) AS count,
		count(*) FILTER (
			WHERE COALESCE(ecosystem, '') != ''
			   OR jsonb_path_exists(CASE WHEN jsonb_typeof(affected_products) = 'array' THEN affected_products ELSE '[]'::jsonb END, '$[*].ecosystem ? (@ != "")')
		) AS with_ecosystem,
		count(*) FILTER (
			WHERE jsonb_path_exists(CASE WHEN jsonb_typeof(affected_products) = 'array' THEN affected_products ELSE '[]'::jsonb END, '$[*].fixed ? (@ != "")')
		) AS with_fixed,
		count(*) FILTER (
			WHERE jsonb_path_exists(CASE WHEN jsonb_typeof(affected_products) = 'array' THEN affected_products ELSE '[]'::jsonb END, '$[*].ranges')
		) AS with_ranges,
		count(*) FILTER (WHERE cvss_score > 0 OR COALESCE(cvss_vector, '') != '') AS with_cvss,
		max(updated_at) AS last_update
	FROM cve_database
	WHERE source != ''
	GROUP BY source
),
matchable AS (
	SELECT
		source,
		count(DISTINCT cve_id) AS matchable
	FROM cve_affected_packages
	WHERE source != ''
	GROUP BY source
)
SELECT
	base.source,
	base.count,
	COALESCE(matchable.matchable, 0) AS matchable,
	base.with_ecosystem,
	GREATEST(base.with_fixed, COALESCE(matchable.matchable, 0)) AS with_fixed,
	base.with_ranges,
	base.with_cvss,
	GREATEST(COALESCE(s.last_sync_finished_at, base.last_update), base.last_update) AS last_update
FROM base
LEFT JOIN matchable ON matchable.source = base.source
LEFT JOIN security_sources s ON s.id = base.source
ORDER BY base.source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var stats []CveSourceStats
	for rows.Next() {
		var s CveSourceStats
		if err := rows.Scan(&s.Source, &s.Count, &s.Matchable, &s.WithEcosystem, &s.WithFixed, &s.WithRanges, &s.WithCVSS, &s.LastUpdate); err != nil {
			return nil, err
		}
		if s.Count > 0 {
			s.MatchablePercent = math.Round(float64(s.Matchable)*1000/float64(s.Count)) / 10
		}
		stats = append(stats, s)
	}
	return stats, nil
}

func (db *DB) GetCveOsvEcosystemStats(ctx context.Context, limit int) ([]CveOsvEcosystemStats, error) {
	if limit <= 0 || limit > 100 {
		limit = 40
	}
	rows, err := db.QueryContext(ctx, `
WITH raw AS (
	SELECT
		lower(split_part(ecosystem, ':', 1)) AS ecosystem,
		count(*) AS raw_records,
		max(updated_at) AS raw_last_update
	FROM cve_database
	WHERE source = 'osv'
	  AND trim(ecosystem) != ''
	GROUP BY lower(split_part(ecosystem, ':', 1))
),
indexed AS (
	SELECT
		lower(split_part(ecosystem, ':', 1)) AS ecosystem,
		count(*) AS indexed_rows,
		count(DISTINCT vulnerability_id) AS matchable_cves,
		max(updated_at) AS indexed_last_update
	FROM cve_affected_packages
	WHERE source = 'osv'
	  AND trim(ecosystem) != ''
	GROUP BY lower(split_part(ecosystem, ':', 1))
	ORDER BY indexed_rows DESC, ecosystem
	LIMIT $1
),
fallback_raw AS (
	SELECT
		i.ecosystem,
		count(DISTINCT c.id) AS raw_records,
		max(c.updated_at) AS raw_last_update
	FROM indexed i
	JOIN cve_affected_packages cap ON cap.source = 'osv'
	  AND lower(split_part(cap.ecosystem, ':', 1)) = i.ecosystem
	JOIN cve_database c ON c.id = cap.cve_id
	LEFT JOIN raw r ON r.ecosystem = i.ecosystem
	WHERE r.ecosystem IS NULL
	GROUP BY i.ecosystem
)
SELECT
	i.ecosystem,
	COALESCE(i.indexed_rows, 0) AS indexed_rows,
	COALESCE(i.matchable_cves, 0) AS matchable_cves,
	COALESCE(r.raw_records, fr.raw_records, 0) AS raw_records,
	COALESCE(r.raw_last_update, fr.raw_last_update, i.indexed_last_update) AS last_update,
	COALESCE(r.raw_last_update, fr.raw_last_update) AS raw_last_update,
	i.indexed_last_update
FROM indexed i
LEFT JOIN raw r ON r.ecosystem = i.ecosystem
LEFT JOIN fallback_raw fr ON fr.ecosystem = i.ecosystem
ORDER BY i.indexed_rows DESC, raw_records DESC, i.ecosystem`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var stats []CveOsvEcosystemStats
	for rows.Next() {
		var s CveOsvEcosystemStats
		if err := rows.Scan(&s.Ecosystem, &s.IndexedRows, &s.MatchableCVEs, &s.RawRecords, &s.LastUpdate, &s.RawLastUpdate, &s.IndexedLastUpdate); err != nil {
			return nil, err
		}
		stats = append(stats, s)
	}
	return stats, rows.Err()
}

func (db *DB) GetCveSourceFreshnessStats(ctx context.Context) ([]CveSourceFreshnessStats, error) {
	rows, err := db.QueryContext(ctx, `
WITH cve_sources AS (
	SELECT source, count(*) AS count, MAX(updated_at) AS raw_last_update
	FROM cve_database
	WHERE source != ''
	GROUP BY source
)
SELECT c.source, c.count, COALESCE(s.last_sync_finished_at, c.raw_last_update) AS last_update
FROM cve_sources c
LEFT JOIN security_sources s ON s.id = c.source
ORDER BY c.source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	stats := []CveSourceFreshnessStats{}
	for rows.Next() {
		var s CveSourceFreshnessStats
		if err := rows.Scan(&s.Source, &s.Count, &s.LastUpdate); err != nil {
			return nil, err
		}
		stats = append(stats, s)
	}
	return stats, rows.Err()
}

func (db *DB) GetCveSourceDataUpdateStats(ctx context.Context) ([]CveSourceFreshnessStats, error) {
	rows, err := db.QueryContext(ctx, `
SELECT source, count(*) AS count, MAX(updated_at) AS last_update
FROM cve_database
WHERE source != ''
GROUP BY source
ORDER BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	stats := []CveSourceFreshnessStats{}
	for rows.Next() {
		var s CveSourceFreshnessStats
		if err := rows.Scan(&s.Source, &s.Count, &s.LastUpdate); err != nil {
			return nil, err
		}
		stats = append(stats, s)
	}
	return stats, rows.Err()
}

func (db *DB) GetSecurityDBRevision(ctx context.Context) (string, error) {
	rows, err := db.QueryContext(ctx, `
WITH indexed AS (
	SELECT source, count(DISTINCT cve_id) AS matchable
	FROM cve_affected_packages
	GROUP BY source
)
SELECT c.source, count(*) AS records, COALESCE(i.matchable, 0) AS matchable, MAX(c.updated_at) AS last_update
FROM cve_database c
LEFT JOIN indexed i ON i.source = c.source
WHERE c.source != ''
GROUP BY c.source, i.matchable
ORDER BY c.source`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	type revisionSource struct {
		source     string
		count      int
		matchable  int
		lastUpdate *time.Time
	}
	stats := []revisionSource{}
	for rows.Next() {
		var s revisionSource
		if err := rows.Scan(&s.source, &s.count, &s.matchable, &s.lastUpdate); err != nil {
			return "", err
		}
		stats = append(stats, s)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if len(stats) == 0 {
		return "empty", nil
	}
	h := sha256.New()
	for _, s := range stats {
		lastUpdate := ""
		if s.lastUpdate != nil {
			lastUpdate = s.lastUpdate.UTC().Format(time.RFC3339Nano)
		}
		fmt.Fprintf(h, "%s\t%d\t%d\t%s\n", s.source, s.count, s.matchable, lastUpdate)
	}
	return hex.EncodeToString(h.Sum(nil))[:16], nil
}

type RematchResult struct {
	Matched                 int                       `json:"matched"`
	NewVulns                int                       `json:"new_vulns"`
	Updated                 int                       `json:"updated"`
	Skipped                 int                       `json:"skipped"`
	ScannedCandidates       int                       `json:"scanned_candidates"`
	CandidateLimit          int                       `json:"candidate_limit"`
	Limited                 bool                      `json:"limited"`
	SecurityDBRevision      string                    `json:"security_db_revision,omitempty"`
	SecurityDBRevisionError string                    `json:"security_db_revision_error,omitempty"`
	EligibleSources         int                       `json:"eligible_sources,omitempty"`
	ExcludedSources         int                       `json:"excluded_sources,omitempty"`
	SourcePolicy            map[string]map[string]any `json:"source_policy,omitempty"`
}

type RematchOptions struct {
	Sources                   []string
	MinSourceMatchablePercent float64
	ScanID                    string
	CandidateLimit            int
}

const (
	DefaultRematchCandidateLimit = 50000
	MaxRematchCandidateLimit     = 1000000
)

func cveSourceFixedPredicateSQL() string {
	return fmt.Sprintf(`(jsonb_typeof(ap->'fixed') = 'array' AND jsonb_array_length(ap->'fixed') = 1 AND %s)
		OR EXISTS (
			SELECT 1
			FROM jsonb_array_elements(CASE WHEN jsonb_typeof(ap->'ranges') = 'array' THEN ap->'ranges' ELSE '[]'::jsonb END) r
			JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(r->'events') = 'array' THEN r->'events' ELSE '[]'::jsonb END) ev ON true
			WHERE %s
		)`, fixedVersionValuePredicateSQL("ap->'fixed'->>0"), fixedVersionValuePredicateSQL("ev->>'fixed'"))
}

func cveSourceMatchablePredicateSQL(affectedProductsExpr, ecosystemExpr string) string {
	return fmt.Sprintf(`EXISTS (
		SELECT 1
		FROM jsonb_array_elements(%s) ap
		WHERE COALESCE(ap->>'name', '') != ''
		  AND COALESCE(NULLIF(ap->>'ecosystem', ''), NULLIF(%s, '')) IS NOT NULL
		  AND (%s)
		)`, affectedProductsExpr, ecosystemExpr, cveSourceFixedPredicateSQL())
}

func cvePackageMatchablePredicateSQL(affectedProductsExpr, ecosystemExpr, packageNameExpr, packageEcosystemExpr string) string {
	effectiveEcosystem := normalizeEcosystemSQL(fmt.Sprintf("lower(COALESCE(NULLIF(ap->>'ecosystem', ''), NULLIF(%s, '')))", ecosystemExpr))
	packageEcosystem := normalizeEcosystemSQL(fmt.Sprintf("lower(%s)", packageEcosystemExpr))
	return fmt.Sprintf(`EXISTS (
		SELECT 1
		FROM jsonb_array_elements(%s) ap
		WHERE lower(COALESCE(ap->>'name', '')) = lower(%s)
		  AND COALESCE(NULLIF(ap->>'ecosystem', ''), NULLIF(%s, '')) IS NOT NULL
		  AND %s = %s
		  AND (%s)
	)`, affectedProductsExpr, packageNameExpr, ecosystemExpr, effectiveEcosystem, packageEcosystem, cveSourceFixedPredicateSQL())
}

func cveEntryHasMatchableAffectedProduct(affectedProducts, ecosystem string) bool {
	return cveEntryMatchableAffectedCount(affectedProducts, ecosystem) > 0
}

func cveEntryMatchabilityReason(affectedProducts, ecosystem string) string {
	var products []affectedProduct
	if strings.TrimSpace(affectedProducts) == "" {
		return "no affected packages"
	}
	if json.Unmarshal([]byte(affectedProducts), &products) != nil {
		return "invalid affected_products"
	}
	if len(products) == 0 {
		return "no affected packages"
	}
	cveEco := normalizeEcosystem(ecosystem)
	hasName := false
	hasEcosystem := false
	hasFixedEvidence := false
	hasAmbiguousFixed := false
	for _, p := range products {
		if strings.TrimSpace(p.Name) == "" {
			continue
		}
		hasName = true
		effectiveEco := normalizeEcosystem(p.Ecosystem)
		if effectiveEco == "" {
			effectiveEco = cveEco
		}
		if effectiveEco == "" {
			continue
		}
		hasEcosystem = true
		if hasSafeFixedEvidence(p) {
			hasFixedEvidence = true
			return "matchable"
		}
		if len(uniqueFixedVersions(p.Fixed)) > 1 {
			hasAmbiguousFixed = true
		}
	}
	switch {
	case !hasName:
		return "missing package name"
	case !hasEcosystem:
		return "missing ecosystem"
	case hasAmbiguousFixed:
		return "ambiguous fixed versions"
	case !hasFixedEvidence:
		return "missing fixed version"
	default:
		return "not matchable"
	}
}

func cveEntryMatchableAffectedCount(affectedProducts, ecosystem string) int {
	var products []affectedProduct
	if affectedProducts == "" || json.Unmarshal([]byte(affectedProducts), &products) != nil {
		return 0
	}
	cveEco := normalizeEcosystem(ecosystem)
	count := 0
	for _, p := range products {
		if strings.TrimSpace(p.Name) == "" {
			continue
		}
		effectiveEco := normalizeEcosystem(p.Ecosystem)
		if effectiveEco == "" {
			effectiveEco = cveEco
		}
		if effectiveEco == "" {
			continue
		}
		if !hasSafeFixedEvidence(p) {
			continue
		}
		count++
	}
	return count
}

func (db *DB) RematchCVEs(ctx context.Context, opts RematchOptions) (*RematchResult, error) {
	if opts.CandidateLimit <= 0 {
		opts.CandidateLimit = DefaultRematchCandidateLimit
	}
	if opts.CandidateLimit > MaxRematchCandidateLimit {
		opts.CandidateLimit = MaxRematchCandidateLimit
	}
	args := []any{}
	filters := ""
	qualityCTE := ""
	qualityJoin := ""
	if len(opts.Sources) > 0 {
		args = append(args, pq.Array(opts.Sources))
		filters += fmt.Sprintf(" AND c.source = ANY($%d)", len(args))
	}
	if opts.MinSourceMatchablePercent > 0 {
		affectedProducts := `CASE WHEN jsonb_typeof(affected_products) = 'array' THEN affected_products ELSE '[]'::jsonb END`
		qualityCTE = fmt.Sprintf(`WITH source_quality AS (
			SELECT
				source,
				COUNT(*) AS total,
				COUNT(*) FILTER (
					WHERE %s
				) AS matchable
			FROM cve_database
			WHERE source != ''
			GROUP BY source
		)`, cveSourceMatchablePredicateSQL(affectedProducts, "ecosystem"))
		qualityJoin = "JOIN source_quality sq ON sq.source = c.source"
		args = append(args, opts.MinSourceMatchablePercent)
		filters += fmt.Sprintf(" AND (100.0 * sq.matchable / NULLIF(sq.total, 0)) >= $%d", len(args))
	}
	scanJoin := fmt.Sprintf("JOIN (%s) ls ON p.scan_id = ls.id", latestScansSub)
	if opts.ScanID != "" {
		args = append(args, opts.ScanID)
		filters += fmt.Sprintf(" AND p.scan_id = $%d", len(args))
		scanJoin = ""
	}
	rowLimit := opts.CandidateLimit * 100
	if rowLimit < opts.CandidateLimit+1 {
		rowLimit = opts.CandidateLimit + 1
	}
	if rowLimit > MaxRematchCandidateLimit+1 {
		rowLimit = MaxRematchCandidateLimit + 1
	}
	args = append(args, rowLimit)
	limitPlaceholder := fmt.Sprintf("$%d", len(args))

	query := fmt.Sprintf(`
		%s
		SELECT p.id, p.name, p.version, p.host_id, p.scan_id, p.container, p.file_path,
		       p.pkg_type, p.ecosystem,
		       c.vulnerability_id, c.severity, c.cvss_score, c.cvss_vector,
		       c.title, c.description, c.refs, c.category, c.ecosystem, c.affected_products
		FROM packages p
		%s
		JOIN cve_affected_packages cap
		  ON cap.package_name = lower(p.name)
		 AND cap.ecosystem = %s
		JOIN cve_database c ON c.id = cap.cve_id
		%s
		WHERE 1=1%s
		LIMIT %s
	`, qualityCTE, scanJoin, packageEcosystemSQL("p"), qualityJoin, filters, limitPlaceholder)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("match query: %w", err)
	}
	defer rows.Close()

	type match struct {
		pkgID, pkgName, version, hostID, scanID, container, filePath string
		pkgType, pkgEco                                              string
		vulnID, severity, title, description, refs                   string
		category, cveEco, affectedProducts                           string
		cvssScore                                                    float64
		cvssVector                                                   string
	}
	var matches []match

	for rows.Next() {
		var m match
		if err := rows.Scan(&m.pkgID, &m.pkgName, &m.version, &m.hostID, &m.scanID,
			&m.container, &m.filePath, &m.pkgType, &m.pkgEco,
			&m.vulnID, &m.severity, &m.cvssScore, &m.cvssVector,
			&m.title, &m.description, &m.refs, &m.category, &m.cveEco, &m.affectedProducts); err != nil {
			continue
		}
		matches = append(matches, m)
	}

	result := &RematchResult{ScannedCandidates: len(matches), CandidateLimit: opts.CandidateLimit}
	if len(matches) >= rowLimit {
		result.Limited = true
	}
	var newVulns []models.Vulnerability
	pending := map[string]int{}
	compatible := 0

	for _, m := range matches {
		affected, ok := compatibleSecurityCandidate(m.pkgName, m.pkgType, m.pkgEco, m.version, m.category, m.cveEco, m.affectedProducts)
		if !ok {
			result.Skipped++
			continue
		}
		compatible++
		if compatible > opts.CandidateLimit {
			result.Limited = true
			break
		}
		result.Matched++
		var exists bool
		if err := db.QueryRowContext(ctx,
			"SELECT EXISTS(SELECT 1 FROM vulnerabilities WHERE package_id=$1 AND vulnerability_id=$2 AND scan_id=$3)",
			m.pkgID, m.vulnID, m.scanID).Scan(&exists); err != nil || exists {
			result.Skipped++
			continue
		}

		primaryURL := ""
		var refList []struct {
			URL string `json:"url"`
		}
		if json.Unmarshal([]byte(m.refs), &refList) == nil {
			for _, r := range refList {
				if r.URL != "" {
					primaryURL = r.URL
					break
				}
			}
		}

		sev := m.severity
		if m.cvssScore >= 9.0 {
			sev = "CRITICAL"
		} else if m.cvssScore >= 7.0 {
			sev = "HIGH"
		} else if m.cvssScore >= 4.0 {
			sev = "MEDIUM"
		} else if m.cvssScore > 0 {
			sev = "LOW"
		}

		v := models.Vulnerability{
			ID: uuid.New().String(), PackageID: m.pkgID, ScanID: m.scanID, HostID: m.hostID,
			VulnerabilityID: m.vulnID, Severity: sev, Title: truncate(m.title, 500),
			Description: truncate(m.description, 2000), PkgName: m.pkgName, PkgPath: m.filePath,
			InstalledVer: m.version, FixedVersion: fixedVersions(affected)[0], CVSSScore: m.cvssScore, CVSSVector: m.cvssVector,
			PrimaryURL: primaryURL, Container: m.container, FindingSource: "cve-db",
		}
		key := rematchVulnerabilityKey(v)
		if idx, ok := pending[key]; ok {
			if betterRematchVulnerability(v, newVulns[idx]) {
				newVulns[idx] = v
			}
			result.Skipped++
			continue
		}
		pending[key] = len(newVulns)
		newVulns = append(newVulns, v)
	}

	if len(newVulns) > 0 {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()

		stmt, err := tx.PrepareContext(ctx, `INSERT INTO vulnerabilities
(id, package_id, scan_id, host_id, vulnerability_id, severity, title, description,
 pkg_name, pkg_path, installed_version, fixed_version, cvss_score, cvss_vector,
 primary_url, container, layer_id, finding_source, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,now())
ON CONFLICT (package_id, scan_id, vulnerability_id) DO NOTHING`)
		if err != nil {
			return nil, fmt.Errorf("prepare: %w", err)
		}
		defer stmt.Close()

		for _, v := range newVulns {
			res, err := stmt.ExecContext(ctx, v.ID, v.PackageID, v.ScanID, v.HostID,
				v.VulnerabilityID, v.Severity, v.Title, v.Description,
				v.PkgName, v.PkgPath, v.InstalledVer, v.FixedVersion,
				v.CVSSScore, v.CVSSVector, v.PrimaryURL, v.Container, "", v.FindingSource)
			if err != nil {
				continue
			}
			if affected, _ := res.RowsAffected(); affected > 0 {
				result.NewVulns++
			} else {
				result.Skipped++
			}
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func rematchVulnerabilityKey(v models.Vulnerability) string {
	return v.PackageID + "\x00" + v.ScanID + "\x00" + v.VulnerabilityID
}

// cpeProductVariants expands a CPE product to the spelling variants seen in NVD
// data, so the coarse SQL containment filter doesn't miss e.g. node.js vs nodejs
// or jre vs jdk. The Go matcher (compatibleCPECandidate) does the precise,
// version-gated decision afterward.
func cpeProductVariants(product string) []string {
	switch strings.ToLower(strings.TrimSpace(product)) {
	case "nodejs", "node", "node.js":
		return []string{"nodejs", "node.js", "node"}
	case "jdk", "jre", "openjdk", "java":
		return []string{"jdk", "jre", "openjdk", "java", "java_se"}
	case "go", "golang":
		return []string{"go", "golang"}
	default:
		return []string{strings.ToLower(strings.TrimSpace(product))}
	}
}

// RematchCPE matches detected runtimes (pkg_type='runtime', keyed by CPE
// product) against NVD CPE advisories, gated by version range so a runtime is
// flagged only when its version falls inside an affected range — never on
// vendor+product alone. Scoped to opts.ScanID when set, else the latest scans.
func (db *DB) RematchCPE(ctx context.Context, opts RematchOptions) (*RematchResult, error) {
	if opts.CandidateLimit <= 0 {
		opts.CandidateLimit = DefaultRematchCandidateLimit
	}
	// Pull the distinct runtime products present so we only scan NVD for those.
	scanFilter := ""
	prodArgs := []any{}
	if opts.ScanID != "" {
		scanFilter = " AND p.scan_id = $1"
		prodArgs = append(prodArgs, opts.ScanID)
	} else {
		scanFilter = fmt.Sprintf(" AND p.scan_id IN (SELECT id FROM %s)", latestScansSub)
	}
	prodRows, err := db.QueryContext(ctx, `SELECT DISTINCT lower(ecosystem) FROM packages p
		WHERE p.pkg_type='runtime' AND ecosystem<>''`+scanFilter, prodArgs...)
	if err != nil {
		return nil, fmt.Errorf("cpe product scan: %w", err)
	}
	productSet := map[string]bool{}
	for prodRows.Next() {
		var prod string
		if prodRows.Scan(&prod) == nil && prod != "" {
			for _, v := range cpeProductVariants(prod) {
				productSet[v] = true
			}
		}
	}
	prodRows.Close()
	result := &RematchResult{CandidateLimit: opts.CandidateLimit}
	if len(productSet) == 0 {
		return result, nil
	}
	variants := make([]string, 0, len(productSet))
	for v := range productSet {
		variants = append(variants, v)
	}

	// Coarse filter: NVD CVEs whose affected_products contain any of the
	// products. The @> containment uses the affected_products GIN index.
	containment := make([]byte, 0, 64)
	containment = append(containment, '[')
	for i, v := range variants {
		if i > 0 {
			containment = append(containment, ',')
		}
		obj, _ := json.Marshal(map[string]string{"product": v})
		containment = append(containment, obj...)
	}
	containment = append(containment, ']')

	// Join runtime packages to candidate NVD CVEs by product (coarse), then gate
	// precisely in Go with compatibleCPECandidate.
	q := `
WITH cands AS (
	SELECT vulnerability_id, severity, cvss_score, cvss_vector, title, description, refs, affected_products::text AS ap
	FROM cve_database
	WHERE source='nvd'
	  AND jsonb_typeof(affected_products)='array'
	  AND EXISTS (
		SELECT 1 FROM jsonb_array_elements(affected_products) e
		WHERE lower(e->>'product') = ANY($1)
	  )
)
SELECT p.id, p.name, p.version, p.host_id, p.scan_id, p.container, p.file_path, lower(p.ecosystem),
       c.vulnerability_id, c.severity, c.cvss_score, c.cvss_vector, c.title, c.description, c.refs, c.ap
FROM packages p
JOIN cands c ON c.ap ILIKE '%' || lower(p.ecosystem) || '%'
WHERE p.pkg_type='runtime' AND p.ecosystem<>''` + scanFilterFor("p", opts.ScanID, "$2")

	args := []any{pq.Array(variants)}
	if opts.ScanID != "" {
		args = append(args, opts.ScanID)
	}
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("cpe match query: %w", err)
	}
	defer rows.Close()

	type match struct {
		pkgID, pkgName, version, hostID, scanID, container, filePath, product string
		vulnID, severity, title, description, refs, ap                        string
		cvssScore                                                             float64
		cvssVector                                                            string
	}
	var matches []match
	for rows.Next() {
		var m match
		if err := rows.Scan(&m.pkgID, &m.pkgName, &m.version, &m.hostID, &m.scanID, &m.container, &m.filePath, &m.product,
			&m.vulnID, &m.severity, &m.cvssScore, &m.cvssVector, &m.title, &m.description, &m.refs, &m.ap); err != nil {
			continue
		}
		matches = append(matches, m)
	}
	result.ScannedCandidates = len(matches)

	var newVulns []models.Vulnerability
	pending := map[string]int{}
	for _, m := range matches {
		affected, ok := compatibleCPECandidate(m.product, m.version, m.ap)
		if !ok {
			result.Skipped++
			continue
		}
		result.Matched++
		primaryURL := ""
		var refList []struct {
			URL string `json:"url"`
		}
		if json.Unmarshal([]byte(m.refs), &refList) == nil {
			for _, r := range refList {
				if r.URL != "" {
					primaryURL = r.URL
					break
				}
			}
		}
		sev := m.severity
		if m.cvssScore >= 9.0 {
			sev = "CRITICAL"
		} else if m.cvssScore >= 7.0 {
			sev = "HIGH"
		} else if m.cvssScore >= 4.0 {
			sev = "MEDIUM"
		} else if m.cvssScore > 0 {
			sev = "LOW"
		}
		fixed := cpeFixedVersion(affected)
		v := models.Vulnerability{
			ID: uuid.New().String(), PackageID: m.pkgID, ScanID: m.scanID, HostID: m.hostID,
			VulnerabilityID: m.vulnID, Severity: sev, Title: truncate(m.title, 500),
			Description: truncate(m.description, 2000), PkgName: m.pkgName, PkgPath: m.filePath,
			InstalledVer: m.version, FixedVersion: fixed, CVSSScore: m.cvssScore, CVSSVector: m.cvssVector,
			PrimaryURL: primaryURL, Container: m.container, FindingSource: "cve-db",
		}
		key := rematchVulnerabilityKey(v)
		if _, ok := pending[key]; ok {
			result.Skipped++
			continue
		}
		pending[key] = len(newVulns)
		newVulns = append(newVulns, v)
	}

	if len(newVulns) > 0 {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		stmt, err := tx.PrepareContext(ctx, `INSERT INTO vulnerabilities
(id, package_id, scan_id, host_id, vulnerability_id, severity, title, description,
 pkg_name, pkg_path, installed_version, fixed_version, cvss_score, cvss_vector,
 primary_url, container, layer_id, finding_source, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,now())
ON CONFLICT (package_id, scan_id, vulnerability_id) DO NOTHING`)
		if err != nil {
			return nil, fmt.Errorf("prepare: %w", err)
		}
		defer stmt.Close()
		for _, v := range newVulns {
			res, err := stmt.ExecContext(ctx, v.ID, v.PackageID, v.ScanID, v.HostID,
				v.VulnerabilityID, v.Severity, v.Title, v.Description,
				v.PkgName, v.PkgPath, v.InstalledVer, v.FixedVersion,
				v.CVSSScore, v.CVSSVector, v.PrimaryURL, v.Container, "", v.FindingSource)
			if err != nil {
				continue
			}
			if affected, _ := res.RowsAffected(); affected > 0 {
				result.NewVulns++
			} else {
				result.Skipped++
			}
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// cpeFixedVersion picks the most informative "fixed" hint from a CPE range: the
// exclusive upper bound is the first unaffected version, i.e. the fix.
func cpeFixedVersion(p affectedProduct) string {
	if v := strings.TrimSpace(p.VersionEndExcluding); v != "" {
		return v
	}
	if v := strings.TrimSpace(p.VersionEndIncluding); v != "" {
		return v
	}
	return ""
}

func scanFilterFor(alias, scanID, placeholder string) string {
	if scanID != "" {
		return fmt.Sprintf(" AND %s.scan_id = %s", alias, placeholder)
	}
	return fmt.Sprintf(" AND %s.scan_id IN (SELECT id FROM %s)", alias, latestScansSub)
}

func betterRematchVulnerability(candidate, current models.Vulnerability) bool {
	if candidate.CVSSScore != current.CVSSScore {
		return candidate.CVSSScore > current.CVSSScore
	}
	if severityRank(candidate.Severity) != severityRank(current.Severity) {
		return severityRank(candidate.Severity) > severityRank(current.Severity)
	}
	if (candidate.FixedVersion != "") != (current.FixedVersion != "") {
		return candidate.FixedVersion != ""
	}
	if (candidate.Title != "") != (current.Title != "") {
		return candidate.Title != ""
	}
	return candidate.PrimaryURL != "" && current.PrimaryURL == ""
}

func severityRank(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// CVSS 3.x base score calculator
func calcCVSS3BaseScore(vector string) float64 {
	parts := map[string]string{}
	for _, seg := range splitCVSS(vector) {
		kv := splitCVSSKV(seg)
		if len(kv) == 2 {
			parts[kv[0]] = kv[1]
		}
	}

	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	ac := map[string]float64{"L": 0.77, "H": 0.44}
	ui := map[string]float64{"N": 0.85, "R": 0.62}
	cia := map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}

	avVal, ok := av[parts["AV"]]
	if !ok {
		return 0
	}
	acVal, ok := ac[parts["AC"]]
	if !ok {
		return 0
	}
	uiVal, ok := ui[parts["UI"]]
	if !ok {
		return 0
	}
	cVal := cia[parts["C"]]
	iVal := cia[parts["I"]]
	aVal := cia[parts["A"]]

	scopeChanged := parts["S"] == "C"

	prVal := 0.0
	switch parts["PR"] {
	case "N":
		prVal = 0.85
	case "L":
		if scopeChanged {
			prVal = 0.68
		} else {
			prVal = 0.62
		}
	case "H":
		if scopeChanged {
			prVal = 0.50
		} else {
			prVal = 0.27
		}
	default:
		return 0
	}

	iss := 1 - ((1 - cVal) * (1 - iVal) * (1 - aVal))
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*pow15(iss-0.02)
	} else {
		impact = 6.42 * iss
	}

	if impact <= 0 {
		return 0
	}

	exploit := 8.22 * avVal * acVal * prVal * uiVal

	var base float64
	if scopeChanged {
		base = 1.08 * (impact + exploit)
	} else {
		base = impact + exploit
	}
	if base > 10 {
		base = 10
	}
	return roundup1(base)
}

func pow15(x float64) float64 { y := x * x; y = y * y; return y * y * x }

func roundup1(x float64) float64 { return float64(int(x*10+0.95)) / 10 }

func splitCVSS(v string) []string {
	var res []string
	for _, s := range stringsSplit(v, "/") {
		if len(s) >= 5 && s[:5] == "CVSS:" {
			continue
		}
		res = append(res, s)
	}
	return res
}

func splitCVSSKV(s string) []string {
	for i, c := range s {
		if c == ':' {
			return []string{s[:i], s[i+1:]}
		}
	}
	return nil
}

func stringsSplit(s, sep string) []string {
	var res []string
	for {
		i := indexOfStr(s, sep)
		if i < 0 {
			res = append(res, s)
			break
		}
		res = append(res, s[:i])
		s = s[i+len(sep):]
	}
	return res
}

func indexOfStr(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func (db *DB) RecalcCVSSFromVectors(ctx context.Context) (int, error) {
	return db.CalcCvssScores(ctx)
}
