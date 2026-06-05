package db

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

func (db *DB) InsertContainers(ctx context.Context, containers []models.ContainerAsset) error {
	if len(containers) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	q := `INSERT INTO container_assets (id, scan_id, host_id, runtime, container_id, name, image_name, image_id, image_digest, state, labels, started_at, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,now())`
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range containers {
		labels := defaultString(containers[i].Labels, "{}")
		_, err := stmt.ExecContext(ctx,
			containers[i].ID, containers[i].ScanID, containers[i].HostID,
			defaultString(containers[i].Runtime, "docker"), containers[i].ContainerID,
			containers[i].Name, containers[i].ImageName, containers[i].ImageID,
			containers[i].ImageDigest, containers[i].State, labels, containers[i].StartedAt,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

type ContainerFilter struct {
	HostID     string
	HostIDs    []string
	Runtime    string
	State      string
	ImageName  string
	NameSearch string
	SortBy     string
	SortDesc   bool
	Limit      int
	Offset     int
}

func (db *DB) SearchContainers(ctx context.Context, f ContainerFilter) ([]models.ContainerAsset, int, error) {
	baseQ := `FROM container_assets c JOIN ` + latestScansSub + ` ls ON c.scan_id = ls.id WHERE 1=1`
	args := []any{}
	n := 1

	if f.HostID != "" {
		baseQ += fmt.Sprintf(" AND c.host_id=$%d", n)
		args = append(args, f.HostID)
		n++
	} else if len(f.HostIDs) > 0 {
		baseQ += fmt.Sprintf(" AND c.host_id = ANY($%d)", n)
		args = append(args, pqStringArray(f.HostIDs))
		n++
	}
	if f.Runtime != "" {
		baseQ += fmt.Sprintf(" AND c.runtime=$%d", n)
		args = append(args, f.Runtime)
		n++
	}
	if f.State != "" {
		baseQ += fmt.Sprintf(" AND c.state=$%d", n)
		args = append(args, f.State)
		n++
	}
	if f.ImageName != "" {
		baseQ += fmt.Sprintf(" AND c.image_name ILIKE $%d", n)
		args = append(args, "%"+f.ImageName+"%")
		n++
	}
	if f.NameSearch != "" {
		baseQ += fmt.Sprintf(" AND (c.name ILIKE $%d OR c.container_id ILIKE $%d OR c.image_id ILIKE $%d)", n, n, n)
		args = append(args, "%"+f.NameSearch+"%")
		n++
	}

	var total int
	countArgs := make([]any, len(args))
	copy(countArgs, args)
	if err := db.QueryRowContext(ctx, "SELECT count(*) "+baseQ, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	q := `SELECT c.id, c.scan_id, c.host_id, c.runtime, c.container_id, c.name, c.image_name, c.image_id, c.image_digest, c.state, c.labels::text, c.started_at,
		(SELECT count(*) FROM packages p WHERE p.scan_id=c.scan_id AND (p.container_id=c.container_id OR p.container=c.name))::int AS package_count,
		(SELECT count(*) FROM vulnerabilities v ` + vulnTriageJoin + ` WHERE v.scan_id=c.scan_id AND v.container=c.name AND ` + currentActionableVulnSQL() + `)::int AS vulnerability_count,
		(SELECT count(*) FROM vulnerabilities v ` + vulnTriageJoin + ` WHERE v.scan_id=c.scan_id AND v.container=c.name AND v.severity='CRITICAL' AND ` + currentActionableVulnSQL() + `)::int AS critical_count,
		(SELECT count(*) FROM vulnerabilities v ` + vulnTriageJoin + ` WHERE v.scan_id=c.scan_id AND v.container=c.name AND v.severity='HIGH' AND ` + currentActionableVulnSQL() + `)::int AS high_count,
		COALESCE((SELECT max(v.cvss_score) FROM vulnerabilities v ` + vulnTriageJoin + ` WHERE v.scan_id=c.scan_id AND v.container=c.name AND ` + currentActionableVulnSQL() + `), 0)::float AS max_cvss,
		c.created_at ` +
		baseQ + fmt.Sprintf(" ORDER BY %s LIMIT $%d OFFSET $%d", containerSortExpr(f.SortBy, f.SortDesc), n, n+1)
	args = append(args, f.Limit, f.Offset)

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []models.ContainerAsset
	for rows.Next() {
		var c models.ContainerAsset
		var started sql.NullTime
		if err := rows.Scan(
			&c.ID, &c.ScanID, &c.HostID, &c.Runtime, &c.ContainerID, &c.Name, &c.ImageName, &c.ImageID, &c.ImageDigest, &c.State, &c.Labels, &started,
			&c.PackageCount, &c.VulnerabilityCount, &c.CriticalCount, &c.HighCount, &c.MaxCVSS, &c.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		if started.Valid {
			c.StartedAt = &started.Time
		}
		c.LatestScanID = c.ScanID
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func containerSortExpr(col string, desc bool) string {
	allowed := map[string]string{
		"name":                "c.name",
		"image_name":          "c.image_name",
		"state":               "c.state",
		"runtime":             "c.runtime",
		"started_at":          "c.started_at",
		"created_at":          "c.created_at",
		"container_id":        "c.container_id",
		"package_count":       "(SELECT count(*) FROM packages p WHERE p.scan_id=c.scan_id AND (p.container_id=c.container_id OR p.container=c.name))",
		"vulnerability_count": "(SELECT count(*) FROM vulnerabilities v " + vulnTriageJoin + " WHERE v.scan_id=c.scan_id AND v.container=c.name AND " + currentActionableVulnSQL() + ")",
		"critical_count":      "(SELECT count(*) FROM vulnerabilities v " + vulnTriageJoin + " WHERE v.scan_id=c.scan_id AND v.container=c.name AND v.severity='CRITICAL' AND " + currentActionableVulnSQL() + ")",
		"high_count":          "(SELECT count(*) FROM vulnerabilities v " + vulnTriageJoin + " WHERE v.scan_id=c.scan_id AND v.container=c.name AND v.severity='HIGH' AND " + currentActionableVulnSQL() + ")",
		"max_cvss":            "COALESCE((SELECT max(v.cvss_score) FROM vulnerabilities v " + vulnTriageJoin + " WHERE v.scan_id=c.scan_id AND v.container=c.name AND " + currentActionableVulnSQL() + "), 0)",
	}
	expr, ok := allowed[col]
	if !ok {
		expr = "c.created_at"
	}
	dir := "ASC"
	if desc {
		dir = "DESC"
	}
	return expr + " " + dir + " NULLS LAST"
}
