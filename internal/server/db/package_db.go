package db

import (
	"context"
	"fmt"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

const pkgCols = `p.id, p.scan_id, p.host_id, p.asset_type, p.asset_id, p.source, p.container, p.container_id, p.image_name, p.image_id, p.name, p.version, p.arch, p.pkg_type, p.ecosystem, p.purl, p.src_name, p.file_path, p.layer_id, p.target, p.created_at`

var pkgVulnJoin = ` LEFT JOIN (
	SELECT v.package_id, MAX(v.cvss_score) as max_cvss, COUNT(*) as vuln_count
	FROM vulnerabilities v
	JOIN packages vp ON vp.id = v.package_id
	` + vulnTriageJoin + `
	WHERE ` + currentActionableVulnSQLForPackage("v", "vp") + `
	GROUP BY v.package_id
) vx ON vx.package_id = p.id`

const pkgVulnSelect = `, COALESCE(vx.max_cvss, 0), COALESCE(vx.vuln_count, 0)`

const pkgInsertCols = `id, scan_id, host_id, asset_type, asset_id, source, container, container_id, image_name, image_id, name, version, arch, pkg_type, ecosystem, purl, src_name, file_path, layer_id, target`

func scanPkg(scanner interface{ Scan(...interface{}) error }, p *models.Package) error {
	return scanner.Scan(&p.ID, &p.ScanID, &p.HostID, &p.AssetType, &p.AssetID, &p.Source, &p.Container,
		&p.ContainerID, &p.ImageName, &p.ImageID, &p.Name, &p.Version, &p.Arch, &p.PkgType, &p.Ecosystem, &p.PURL, &p.SrcName,
		&p.FilePath, &p.LayerID, &p.Target, &p.CreatedAt,
		&p.MaxCVSS, &p.VulnCount)
}

func (db *DB) InsertPackages(ctx context.Context, pkgs []models.Package) error {
	if len(pkgs) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	q := fmt.Sprintf(`INSERT INTO packages (%s, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,now())`, pkgInsertCols)
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range pkgs {
		_, err := stmt.ExecContext(ctx,
			pkgs[i].ID, pkgs[i].ScanID, pkgs[i].HostID,
			defaultString(pkgs[i].AssetType, "host"), pkgs[i].AssetID,
			pkgs[i].Source, pkgs[i].Container, pkgs[i].ContainerID, pkgs[i].ImageName, pkgs[i].ImageID,
			pkgs[i].Name, pkgs[i].Version, pkgs[i].Arch, pkgs[i].PkgType, pkgs[i].Ecosystem, pkgs[i].PURL,
			pkgs[i].SrcName, pkgs[i].FilePath, pkgs[i].LayerID, pkgs[i].Target,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) GetLatestPackages(ctx context.Context, hostID string, limit, offset int) ([]models.Package, int, error) {
	countQ := fmt.Sprintf(`SELECT count(*) FROM packages p JOIN %s ls ON p.scan_id = ls.id WHERE p.host_id=$1`, latestScansSub)
	dataQ := fmt.Sprintf(`SELECT %s%s FROM packages p JOIN %s ls ON p.scan_id = ls.id%s WHERE p.host_id=$1 ORDER BY p.name LIMIT $2 OFFSET $3`, pkgCols, pkgVulnSelect, latestScansSub, pkgVulnJoin)

	var total int
	if err := db.QueryRowContext(ctx, countQ, hostID).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := db.QueryContext(ctx, dataQ, hostID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var pkgs []models.Package
	for rows.Next() {
		var p models.Package
		if err := scanPkg(rows, &p); err != nil {
			return nil, 0, err
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, total, nil
}

func (db *DB) GetLatestPackagesForSBOM(ctx context.Context, hostID string) ([]models.Package, error) {
	q := fmt.Sprintf(`SELECT %s%s FROM packages p JOIN %s ls ON p.scan_id = ls.id%s WHERE p.host_id=$1 ORDER BY p.asset_type, p.container, p.name, p.version`,
		pkgCols, pkgVulnSelect, latestScansSub, pkgVulnJoin)
	rows, err := db.QueryContext(ctx, q, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var pkgs []models.Package
	for rows.Next() {
		var p models.Package
		if err := scanPkg(rows, &p); err != nil {
			return nil, err
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, rows.Err()
}

type PackageFilter struct {
	HostID     string
	HostIDs    []string
	Container  string
	PkgType    string
	Source     string
	NameSearch string
	SortBy     string
	SortDesc   bool
	Limit      int
	Offset     int
}

func (db *DB) SearchPackages(ctx context.Context, f PackageFilter) ([]models.Package, int, error) {
	baseQ := `FROM packages p`
	args := []any{}
	n := 1

	baseQ += ` JOIN ` + latestScansSub + ` ls ON p.scan_id = ls.id`

	baseQ += ` WHERE 1=1`

	if f.HostID != "" {
		baseQ += fmt.Sprintf(" AND p.host_id=$%d", n)
		args = append(args, f.HostID)
		n++
	} else if len(f.HostIDs) > 0 {
		baseQ += fmt.Sprintf(" AND p.host_id = ANY($%d)", n)
		args = append(args, pqStringArray(f.HostIDs))
		n++
	}
	if f.Container != "" {
		if f.Container == "(host)" {
			baseQ += " AND (p.container = '' OR p.container IS NULL)"
		} else {
			baseQ += fmt.Sprintf(" AND p.container=$%d", n)
			args = append(args, f.Container)
			n++
		}
	}
	if f.PkgType != "" {
		baseQ += fmt.Sprintf(" AND p.pkg_type=$%d", n)
		args = append(args, f.PkgType)
		n++
	}
	if f.Source != "" {
		baseQ += fmt.Sprintf(" AND p.source=$%d", n)
		args = append(args, f.Source)
		n++
	}
	if f.NameSearch != "" {
		baseQ += fmt.Sprintf(" AND p.name ILIKE $%d", n)
		args = append(args, "%"+f.NameSearch+"%")
		n++
	}

	var total int
	countArgs := make([]any, len(args))
	copy(countArgs, args)
	if err := db.QueryRowContext(ctx, "SELECT count(*) "+baseQ, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	dataQ := ""
	if packageSortNeedsVulnAggregate(f.SortBy) {
		dataQ = fmt.Sprintf(`
WITH visible AS NOT MATERIALIZED (
	SELECT %s
	%s
),
vuln_counts AS (
	SELECT v.package_id, MAX(v.cvss_score) AS max_cvss, COUNT(*) AS vuln_count
	FROM vulnerabilities v
	JOIN visible p ON p.id = v.package_id
	%s
	WHERE %s
	GROUP BY v.package_id
)
SELECT %s%s
FROM visible p
LEFT JOIN vuln_counts vx ON vx.package_id = p.id
ORDER BY %s
LIMIT $%d OFFSET $%d`,
			pkgCols, baseQ,
			vulnTriageJoin, currentActionableVulnSQLForPackage("v", "p"),
			pkgCols, pkgVulnSelect, pkgSortExpr(f.SortBy, f.SortDesc), n, n+1)
	} else {
		dataQ = fmt.Sprintf(`
WITH page AS (
	SELECT %s
	%s
	ORDER BY %s
	LIMIT $%d OFFSET $%d
),
vuln_counts AS (
	SELECT v.package_id, MAX(v.cvss_score) AS max_cvss, COUNT(*) AS vuln_count
	FROM vulnerabilities v
	JOIN page p ON p.id = v.package_id
	%s
	WHERE %s
	GROUP BY v.package_id
)
SELECT %s%s
FROM page p
LEFT JOIN vuln_counts vx ON vx.package_id = p.id
ORDER BY %s`,
			pkgCols, baseQ, pkgSortExpr(f.SortBy, f.SortDesc), n, n+1,
			vulnTriageJoin, currentActionableVulnSQLForPackage("v", "p"),
			pkgCols, pkgVulnSelect, pkgSortExpr(f.SortBy, f.SortDesc))
	}
	args = append(args, f.Limit, f.Offset)

	rows, err := db.QueryContext(ctx, dataQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var pkgs []models.Package
	for rows.Next() {
		var p models.Package
		if err := scanPkg(rows, &p); err != nil {
			return nil, 0, err
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, total, nil
}

func packageSortNeedsVulnAggregate(sortBy string) bool {
	switch sortBy {
	case "max_cvss", "vuln_count":
		return true
	default:
		return false
	}
}

func (db *DB) GetPackageHostID(ctx context.Context, packageID string) (string, error) {
	var hostID string
	err := db.QueryRowContext(ctx, `SELECT host_id FROM packages WHERE id=$1`, packageID).Scan(&hostID)
	return hostID, err
}

func pkgSortExpr(col string, desc bool) string {
	allowed := map[string]string{
		"name": "p.name", "version": "p.version", "pkg_type": "p.pkg_type",
		"container": "p.container", "source": "p.source", "file_path": "p.file_path",
		"asset_type": "p.asset_type", "ecosystem": "p.ecosystem", "image_name": "p.image_name",
		"max_cvss": "COALESCE(vx.max_cvss, 0)", "vuln_count": "COALESCE(vx.vuln_count, 0)",
	}
	expr, ok := allowed[col]
	if !ok {
		expr = "p.name"
	}
	dir := "ASC"
	if desc {
		dir = "DESC"
	}
	return expr + " " + dir + " NULLS LAST"
}
