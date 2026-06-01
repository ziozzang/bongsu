package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

func (db *DB) UpsertHost(ctx context.Context, h *models.Host) error {
	return db.UpsertHostWithAgentToken(ctx, h, "")
}

func (db *DB) UpsertHostWithAgentToken(ctx context.Context, h *models.Host, tokenHash string) error {
	q := `INSERT INTO hosts (id, hostname, ip_address, os_name, os_version, kernel, arch, cpu_model, cpu_cores, memory_mb, agent_version, api_key_hash, agent_token_hash, last_seen, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, '', $12, now(), now(), now())
ON CONFLICT (id) DO UPDATE SET hostname=$2, ip_address=$3, os_name=$4, os_version=$5, kernel=$6, arch=$7, cpu_model=$8, cpu_cores=$9, memory_mb=$10, agent_version=$11, agent_token_hash=CASE WHEN hosts.agent_token_hash='' THEN $12 ELSE hosts.agent_token_hash END, last_seen=now(), updated_at=now()
WHERE $12='' OR hosts.agent_token_hash='' OR hosts.agent_token_hash=$12`
	res, err := db.ExecContext(ctx, q,
		h.ID, h.Hostname, h.IPAddress, h.OSName, h.OSVersion,
		h.Kernel, h.Arch, h.CPUModel, h.CPUCores, h.MemoryMB, h.AgentVersion, tokenHash,
	)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrAgentHostTokenMismatch
	}
	return nil
}

func (db *DB) VerifyOrBindHostAgentToken(ctx context.Context, hostID, tokenHash string) error {
	if hostID == "" || tokenHash == "" {
		return ErrAgentHostTokenMismatch
	}
	res, err := db.ExecContext(ctx, `UPDATE hosts
SET agent_token_hash=CASE WHEN agent_token_hash='' THEN $2 ELSE agent_token_hash END
WHERE id=$1 AND (agent_token_hash='' OR agent_token_hash=$2)`, hostID, tokenHash)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrAgentHostTokenMismatch
	}
	return nil
}

func (db *DB) ResetHostAgentToken(ctx context.Context, hostID string) error {
	res, err := db.ExecContext(ctx, `UPDATE hosts SET agent_token_hash='', updated_at=now() WHERE id=$1`, hostID)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}


const hostCols = `id, hostname, ip_address, os_name, os_version, kernel, arch, cpu_model, cpu_cores, memory_mb, agent_version, agent_token_hash <> '' AS agent_token_set, owner, team, environment, criticality, tags::text, last_seen, created_at`

func scanHost(scanner interface{ Scan(...interface{}) error }, h *models.Host) error {
	return scanner.Scan(&h.ID, &h.Hostname, &h.IPAddress, &h.OSName, &h.OSVersion,
		&h.Kernel, &h.Arch, &h.CPUModel, &h.CPUCores, &h.MemoryMB, &h.AgentVersion,
		&h.AgentTokenSet, &h.Owner, &h.Team, &h.Environment, &h.Criticality, &h.Tags, &h.LastSeen, &h.CreatedAt)
}

func (db *DB) ListHosts(ctx context.Context) ([]models.Host, error) {
	q := `SELECT ` + hostCols + ` FROM hosts ORDER BY hostname`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []models.Host
	for rows.Next() {
		var h models.Host
		if err := scanHost(rows, &h); err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}

type HostInventorySummary struct {
	ScanID         string     `json:"latest_scan_id,omitempty"`
	ScanStatus     string     `json:"latest_scan_status,omitempty"`
	ScannedAt      *time.Time `json:"latest_scan_at,omitempty"`
	PackageCount   int        `json:"latest_package_count"`
	VulnCount      int        `json:"latest_vulnerability_count"`
	ContainerCount int        `json:"latest_container_count"`
}

func (db *DB) GetHostInventorySummaries(ctx context.Context) (map[string]HostInventorySummary, error) {
	q := `SELECT
		s.host_id,
		s.id,
		s.status,
		s.finished_at,
		(SELECT count(*) FROM packages p WHERE p.scan_id=s.id)::int AS package_count,
		(SELECT count(*) FROM vulnerabilities v WHERE v.scan_id=s.id)::int AS vulnerability_count,
		(SELECT count(*) FROM container_assets c WHERE c.scan_id=s.id)::int AS container_count
	FROM scans s
	JOIN ` + latestScansSub + ` ls ON ls.id=s.id`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]HostInventorySummary{}
	for rows.Next() {
		var hostID string
		var s HostInventorySummary
		if err := rows.Scan(&hostID, &s.ScanID, &s.ScanStatus, &s.ScannedAt, &s.PackageCount, &s.VulnCount, &s.ContainerCount); err != nil {
			return nil, err
		}
		out[hostID] = s
	}
	return out, rows.Err()
}

func (db *DB) GetHost(ctx context.Context, id string) (*models.Host, error) {
	q := `SELECT ` + hostCols + ` FROM hosts WHERE id=$1`
	var h models.Host
	err := scanHost(db.QueryRowContext(ctx, q, id), &h)
	if err != nil {
		return nil, err
	}
	return &h, nil
}

func (db *DB) UpdateHostMetadata(ctx context.Context, id, owner, team, environment, criticality, tags string) error {
	if tags == "" {
		tags = "{}"
	}
	res, err := db.ExecContext(ctx, `UPDATE hosts
SET owner=$2, team=$3, environment=$4, criticality=$5, tags=$6::jsonb, updated_at=now()
WHERE id=$1`, id, owner, team, environment, criticality, tags)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
