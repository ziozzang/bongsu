package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

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

	q := `INSERT INTO container_assets (id, scan_id, host_id, runtime, container_id, name, image_name, image_id, image_digest, state, labels, facts, started_at, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13,now())`
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range containers {
		labels := defaultString(containers[i].Labels, "{}")
		facts := strings.TrimSpace(string(containers[i].Facts))
		if facts == "" {
			facts = "{}"
		}
		_, err := stmt.ExecContext(ctx,
			containers[i].ID, containers[i].ScanID, containers[i].HostID,
			defaultString(containers[i].Runtime, "docker"), containers[i].ContainerID,
			containers[i].Name, containers[i].ImageName, containers[i].ImageID,
			containers[i].ImageDigest, containers[i].State, labels, facts, containers[i].StartedAt,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

type ContainerFilter struct {
	HostID        string
	HostIDs       []string
	Runtime       string
	State         string
	ImageName     string
	NameSearch    string
	IncludeLabels bool
	SortBy        string
	SortDesc      bool
	Limit         int
	Offset        int
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

	q := `WITH filtered AS (
		SELECT c.id, c.scan_id, c.host_id, c.runtime, c.container_id, c.name, c.image_name, c.image_id, c.image_digest, c.state, c.labels::text AS labels, c.started_at, c.created_at ` + baseQ + `
	),
	package_counts AS (
		SELECT f.id, count(p.id)::int AS package_count
		FROM filtered f
		LEFT JOIN packages p ON p.scan_id=f.scan_id AND (p.container_id=f.container_id OR p.container=f.name)
		GROUP BY f.id
	),
	vuln_counts AS (
		SELECT f.id,
			count(v.id) FILTER (WHERE ` + currentActionableVulnSQL() + `)::int AS vulnerability_count,
			count(v.id) FILTER (WHERE v.severity='CRITICAL' AND ` + currentActionableVulnSQL() + `)::int AS critical_count,
			count(v.id) FILTER (WHERE v.severity='HIGH' AND ` + currentActionableVulnSQL() + `)::int AS high_count,
			COALESCE(max(v.cvss_score) FILTER (WHERE ` + currentActionableVulnSQL() + `), 0)::float AS max_cvss
		FROM filtered f
		LEFT JOIN vulnerabilities v ON v.scan_id=f.scan_id AND v.container=f.name
		` + vulnTriageJoin + `
		GROUP BY f.id
	)
	SELECT f.id, f.scan_id, f.host_id, f.runtime, f.container_id, f.name, f.image_name, f.image_id, f.image_digest, f.state, f.labels, f.started_at,
		COALESCE(pc.package_count, 0)::int AS package_count,
		COALESCE(vc.vulnerability_count, 0)::int AS vulnerability_count,
		COALESCE(vc.critical_count, 0)::int AS critical_count,
		COALESCE(vc.high_count, 0)::int AS high_count,
		COALESCE(vc.max_cvss, 0)::float AS max_cvss,
		f.created_at
	FROM filtered f
	LEFT JOIN package_counts pc ON pc.id=f.id
	LEFT JOIN vuln_counts vc ON vc.id=f.id` +
		fmt.Sprintf(" ORDER BY %s LIMIT $%d OFFSET $%d", containerSortExpr(f.SortBy, f.SortDesc), n, n+1)
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
		var labels string
		if err := rows.Scan(
			&c.ID, &c.ScanID, &c.HostID, &c.Runtime, &c.ContainerID, &c.Name, &c.ImageName, &c.ImageID, &c.ImageDigest, &c.State, &labels, &started,
			&c.PackageCount, &c.VulnerabilityCount, &c.CriticalCount, &c.HighCount, &c.MaxCVSS, &c.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		c.LabelCount = containerLabelCount(labels)
		if f.IncludeLabels {
			c.Labels = labels
		} else if c.LabelCount > 0 {
			c.LabelsRedacted = true
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

func containerLabelCount(labels string) int {
	if labels == "" {
		return 0
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(labels), &m); err != nil {
		return 0
	}
	return len(m)
}

func containerSortExpr(col string, desc bool) string {
	allowed := map[string]string{
		"name":                "f.name",
		"image_name":          "f.image_name",
		"state":               "f.state",
		"runtime":             "f.runtime",
		"started_at":          "f.started_at",
		"created_at":          "f.created_at",
		"container_id":        "f.container_id",
		"package_count":       "package_count",
		"vulnerability_count": "vulnerability_count",
		"critical_count":      "critical_count",
		"high_count":          "high_count",
		"max_cvss":            "max_cvss",
	}
	expr, ok := allowed[col]
	if !ok {
		expr = "f.created_at"
	}
	dir := "ASC"
	if desc {
		dir = "DESC"
	}
	return expr + " " + dir + " NULLS LAST"
}
