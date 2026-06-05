package db

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

func (db *DB) CreateScan(ctx context.Context, s *models.Scan) error {
	q := `INSERT INTO scans (id, host_id, scan_type, status, security_db_revision, scan_request_id, started_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, now())`
	_, err := db.ExecContext(ctx, q, s.ID, s.HostID, s.ScanType, s.Status, s.SecurityDBRevision, s.ScanRequestID, s.StartedAt)
	return err
}

func (db *DB) CompleteScan(ctx context.Context, id, status, errorSummary string) error {
	if status == "" {
		status = "completed"
	}
	if status != "completed" && status != "degraded" {
		return fmt.Errorf("invalid scan status: %s", status)
	}
	q := `UPDATE scans SET status=$2, error_summary=$3, finished_at=now() WHERE id=$1`
	_, err := db.ExecContext(ctx, q, id, status, errorSummary)
	return err
}

func (db *DB) DeleteScan(ctx context.Context, id string, force bool) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if !force {
		var latest bool
		if err := tx.QueryRowContext(ctx, deleteScanLatestInventorySQL(), id).Scan(&latest); err != nil {
			return fmt.Errorf("check latest inventory scan: %w", err)
		}
		if latest {
			return ErrLatestInventoryScan
		}
	}

	tables := []string{"vulnerabilities", "packages", "container_assets", "user_accounts", "process_snapshots", "port_info"}
	for _, t := range tables {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE scan_id=$1", t), id); err != nil {
			return fmt.Errorf("delete from %s: %w", t, err)
		}
	}
	res, err := tx.ExecContext(ctx, "DELETE FROM scans WHERE id=$1", id)
	if err != nil {
		return fmt.Errorf("delete scan: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrScanNotFound
	}
	return tx.Commit()
}

func deleteScanLatestInventorySQL() string {
	return `SELECT EXISTS(
		SELECT 1
		FROM scans s
		JOIN ` + latestScansSub + ` ls ON ls.id = s.id
		WHERE s.id = $1
		  AND s.status IN ('completed','degraded')
	)`
}

func (db *DB) InsertUserAccounts(ctx context.Context, users []models.UserAccount) error {
	if len(users) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	q := `INSERT INTO user_accounts (id, scan_id, host_id, username, uid, gid, home_dir, shell) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range users {
		_, err := stmt.ExecContext(ctx,
			users[i].ID, users[i].ScanID, users[i].HostID,
			users[i].Username, users[i].UID, users[i].GID, users[i].HomeDir, users[i].Shell,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) InsertProcessSnapshots(ctx context.Context, procs []models.ProcessSnapshot) error {
	if len(procs) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	q := `INSERT INTO process_snapshots (id, scan_id, host_id, pid, name, cmdline, user_name, cpu_usage, mem_usage) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range procs {
		_, err := stmt.ExecContext(ctx,
			procs[i].ID, procs[i].ScanID, procs[i].HostID,
			procs[i].PID, procs[i].Name, procs[i].Cmdline, procs[i].User,
			procs[i].CPUUsage, procs[i].MemUsage,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) InsertPorts(ctx context.Context, ports []models.PortInfo) error {
	if len(ports) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	q := `INSERT INTO port_info (id, scan_id, host_id, name, port, protocol, address, pid) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range ports {
		_, err := stmt.ExecContext(ctx,
			ports[i].ID, ports[i].ScanID, ports[i].HostID,
			ports[i].Name, ports[i].Port, ports[i].Protocol, ports[i].Address, ports[i].PID,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) GetLatestUserAccounts(ctx context.Context, hostID string, limit, offset int) ([]models.UserAccount, int, error) {
	countQ := `SELECT count(*) FROM user_accounts u JOIN ` + latestScansSub + ` ls ON u.scan_id = ls.id WHERE u.host_id=$1`
	dataQ := `SELECT u.id, u.scan_id, u.host_id, u.username, u.uid, u.gid, u.home_dir, u.shell
FROM user_accounts u JOIN ` + latestScansSub + ` ls ON u.scan_id = ls.id
WHERE u.host_id=$1
ORDER BY u.uid, u.username
LIMIT $2 OFFSET $3`
	var total int
	if err := db.QueryRowContext(ctx, countQ, hostID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.QueryContext(ctx, dataQ, hostID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var users []models.UserAccount
	for rows.Next() {
		var u models.UserAccount
		if err := rows.Scan(&u.ID, &u.ScanID, &u.HostID, &u.Username, &u.UID, &u.GID, &u.HomeDir, &u.Shell); err != nil {
			return nil, 0, err
		}
		users = append(users, u)
	}
	return users, total, rows.Err()
}

func (db *DB) GetLatestProcessSnapshots(ctx context.Context, hostID string, limit, offset int) ([]models.ProcessSnapshot, int, error) {
	countQ := `SELECT count(*) FROM process_snapshots p JOIN ` + latestScansSub + ` ls ON p.scan_id = ls.id WHERE p.host_id=$1`
	dataQ := `SELECT p.id, p.scan_id, p.host_id, p.pid, p.name, p.cmdline, p.user_name, p.cpu_usage, p.mem_usage
FROM process_snapshots p JOIN ` + latestScansSub + ` ls ON p.scan_id = ls.id
WHERE p.host_id=$1
ORDER BY p.cpu_usage DESC, p.mem_usage DESC, p.pid
LIMIT $2 OFFSET $3`
	var total int
	if err := db.QueryRowContext(ctx, countQ, hostID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.QueryContext(ctx, dataQ, hostID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var procs []models.ProcessSnapshot
	for rows.Next() {
		var p models.ProcessSnapshot
		if err := rows.Scan(&p.ID, &p.ScanID, &p.HostID, &p.PID, &p.Name, &p.Cmdline, &p.User, &p.CPUUsage, &p.MemUsage); err != nil {
			return nil, 0, err
		}
		procs = append(procs, p)
	}
	return procs, total, rows.Err()
}

func (db *DB) GetLatestPorts(ctx context.Context, hostID string, limit, offset int) ([]models.PortInfo, int, error) {
	countQ := `SELECT count(*) FROM port_info p JOIN ` + latestScansSub + ` ls ON p.scan_id = ls.id WHERE p.host_id=$1`
	dataQ := `SELECT p.id, p.scan_id, p.host_id, p.name, p.port, p.protocol, p.address, p.pid
FROM port_info p JOIN ` + latestScansSub + ` ls ON p.scan_id = ls.id
WHERE p.host_id=$1
ORDER BY p.port, p.protocol, p.address
LIMIT $2 OFFSET $3`
	var total int
	if err := db.QueryRowContext(ctx, countQ, hostID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.QueryContext(ctx, dataQ, hostID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var ports []models.PortInfo
	for rows.Next() {
		var p models.PortInfo
		if err := rows.Scan(&p.ID, &p.ScanID, &p.HostID, &p.Name, &p.Port, &p.Protocol, &p.Address, &p.PID); err != nil {
			return nil, 0, err
		}
		ports = append(ports, p)
	}
	return ports, total, rows.Err()
}

func (db *DB) ListScans(ctx context.Context, hostID string, hostIDs []string, limit, offset int) ([]models.Scan, int, error) {
	baseWhere := ` WHERE 1=1`
	args := []any{}
	n := 1

	if hostID != "" {
		baseWhere += fmt.Sprintf(" AND host_id=$%d", n)
		args = append(args, hostID)
		n++
	} else if len(hostIDs) > 0 {
		baseWhere += fmt.Sprintf(" AND host_id = ANY($%d)", n)
		args = append(args, pqStringArray(hostIDs))
		n++
	}

	var total int
	countArgs := make([]any, len(args))
	copy(countArgs, args)
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM scans`+baseWhere, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	dataQ := fmt.Sprintf(`
WITH page_scans AS (
	SELECT id, host_id, scan_type, status, error_summary, security_db_revision, scan_request_id, started_at, finished_at, created_at
	FROM scans
	%s
	ORDER BY created_at DESC
	LIMIT $%d OFFSET $%d
),
scan_prev AS (
	SELECT s.*,
		(SELECT ps.id FROM scans ps
		 WHERE ps.host_id=s.host_id AND ps.status IN ('completed','degraded') AND ps.created_at < s.created_at
		 ORDER BY ps.created_at DESC LIMIT 1) AS prev_scan_id
	FROM page_scans s
)
SELECT
	s.id, s.host_id, s.scan_type, s.status, s.error_summary, s.security_db_revision, s.scan_request_id,
	(SELECT count(*) FROM packages p WHERE p.scan_id=s.id)::int AS package_count,
	(SELECT count(*) FROM vulnerabilities v WHERE v.scan_id=s.id)::int AS vulnerability_count,
	(SELECT count(*) FROM container_assets c WHERE c.scan_id=s.id)::int AS container_count,
	(SELECT count(*) FROM packages cp
	 WHERE cp.scan_id=s.id AND s.prev_scan_id IS NOT NULL
	   AND NOT EXISTS (
		SELECT 1 FROM packages pp
		WHERE pp.scan_id=s.prev_scan_id AND %s
	   ))::int AS packages_added,
	(SELECT count(*) FROM packages pp
	 WHERE pp.scan_id=s.prev_scan_id AND s.prev_scan_id IS NOT NULL
	   AND NOT EXISTS (
		SELECT 1 FROM packages cp
		WHERE cp.scan_id=s.id AND %s
	   ))::int AS packages_removed,
	(SELECT count(*) FROM packages cp
	 WHERE cp.scan_id=s.id AND s.prev_scan_id IS NOT NULL
	   AND EXISTS (
		SELECT 1 FROM packages pp
		WHERE pp.scan_id=s.prev_scan_id AND %s
		  AND COALESCE(pp.version, '') != COALESCE(cp.version, '')
	   ))::int AS packages_changed,
	s.started_at, s.finished_at, s.created_at
FROM scan_prev s
ORDER BY s.created_at DESC`, baseWhere, n, n+1, packageIdentitySQL("cp", "pp"), packageIdentitySQL("cp", "pp"), packageIdentitySQL("cp", "pp"))
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, dataQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var scans []models.Scan
	for rows.Next() {
		var s models.Scan
		if err := rows.Scan(&s.ID, &s.HostID, &s.ScanType, &s.Status, &s.ErrorSummary, &s.SecurityDBRevision, &s.ScanRequestID, &s.PackageCount, &s.VulnCount, &s.ContainerCount, &s.PackagesAdded, &s.PackagesRemoved, &s.PackagesChanged, &s.StartedAt, &s.FinishedAt, &s.CreatedAt); err != nil {
			return nil, 0, err
		}
		scans = append(scans, s)
	}
	return scans, total, nil
}

func packageIdentitySQL(a, b string) string {
	cols := []string{"asset_type", "asset_id", "source", "container", "container_id", "image_name", "name", "arch", "pkg_type", "ecosystem", "purl", "src_name", "file_path", "target"}
	parts := make([]string, 0, len(cols))
	for _, col := range cols {
		parts = append(parts, fmt.Sprintf("COALESCE(%s.%s, '') = COALESCE(%s.%s, '')", a, col, b, col))
	}
	return strings.Join(parts, " AND ")
}

func (db *DB) CreateScanRequest(ctx context.Context, req *models.ScanRequest) error {
	if req.ID == "" {
		req.ID = uuid.New().String()
	}
	if req.ScanType == "" {
		req.ScanType = "manual"
	}
	if req.Status == "" {
		req.Status = "pending"
	}
	_, err := db.ExecContext(ctx, `INSERT INTO scan_requests (id, host_id, requested_by, scan_type, packages_only, reason, security_db_revision, status, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())`,
		req.ID, req.HostID, req.RequestedBy, req.ScanType, req.PackagesOnly, req.Reason, req.SecurityDBRevision, req.Status)
	return err
}

type SecurityDBRescanQueueResult struct {
	Eligible       int
	Queued         int
	AlreadyPending int
}

type StaleScanRequestRequeueResult struct {
	Requeued            int
	CancelledDuplicates int
}

func (db *DB) QueueSecurityDBRescans(ctx context.Context, requestedBy, reason, securityDBRevision string, lastSeenAfter time.Time) (*SecurityDBRescanQueueResult, error) {
	q := `SELECT id FROM hosts`
	args := []any{}
	if !lastSeenAfter.IsZero() {
		q += ` WHERE last_seen >= $1`
		args = append(args, lastSeenAfter)
	}
	q += ` ORDER BY hostname`

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	result := &SecurityDBRescanQueueResult{}
	for rows.Next() {
		var hostID string
		if err := rows.Scan(&hostID); err != nil {
			return result, err
		}
		result.Eligible++
		var inserted bool
		if err := tx.QueryRowContext(ctx, queueSecurityDBRescanInsertSQL(), uuid.New().String(), hostID, requestedBy, reason, securityDBRevision).Scan(&inserted); err != nil {
			return result, err
		}
		if inserted {
			result.Queued++
		} else {
			result.AlreadyPending++
		}
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	return result, tx.Commit()
}

func queueSecurityDBRescanInsertSQL() string {
	return `
INSERT INTO scan_requests (id, host_id, requested_by, scan_type, packages_only, reason, security_db_revision, status, created_at)
VALUES ($1,$2,$3,'security-db-update',true,$4,$5,'pending',now())
ON CONFLICT (host_id) WHERE host_id <> '' AND scan_type='security-db-update' AND status='pending'
DO UPDATE SET
	requested_by=EXCLUDED.requested_by,
	reason=EXCLUDED.reason,
	security_db_revision=EXCLUDED.security_db_revision,
	error_message=''
RETURNING (xmax = 0) AS inserted`
}

func (db *DB) ListScanRequests(ctx context.Context, hostID string, hostIDs []string, status, scanType, securityDBRevision string, staleOnly bool, timeoutSeconds int64, limit, offset int) ([]models.ScanRequest, int, error) {
	baseQ := `FROM scan_requests WHERE 1=1`
	args := []any{}
	n := 1
	if hostID != "" {
		baseQ += fmt.Sprintf(" AND host_id=$%d", n)
		args = append(args, hostID)
		n++
	} else if len(hostIDs) > 0 {
		baseQ += fmt.Sprintf(" AND host_id = ANY($%d)", n)
		args = append(args, pqStringArray(hostIDs))
		n++
	}
	if status != "" {
		baseQ += fmt.Sprintf(" AND status=$%d", n)
		args = append(args, status)
		n++
	}
	if scanType != "" {
		baseQ += fmt.Sprintf(" AND scan_type=$%d", n)
		args = append(args, scanType)
		n++
	}
	if securityDBRevision != "" {
		baseQ += fmt.Sprintf(" AND security_db_revision=$%d", n)
		args = append(args, securityDBRevision)
		n++
	}
	if staleOnly {
		baseQ += fmt.Sprintf(" AND ((status='pending' AND created_at < now() - ($%d::bigint * interval '1 second')) OR (status='claimed' AND claimed_at IS NOT NULL AND claimed_at < now() - ($%d::bigint * interval '1 second')))", n, n)
		args = append(args, timeoutSeconds)
		n++
	}
	var total int
	if err := db.QueryRowContext(ctx, "SELECT count(*) "+baseQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := `SELECT id, host_id, requested_by, scan_type, packages_only, reason, security_db_revision, status, error_message, claimed_by_host_id, claimed_at, completed_at, created_at,
		EXTRACT(EPOCH FROM (now() - created_at))::bigint AS request_age_seconds,
		CASE WHEN claimed_at IS NULL THEN 0 ELSE EXTRACT(EPOCH FROM (now() - claimed_at))::bigint END AS claim_age_seconds ` + baseQ + fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", n, n+1)
	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []models.ScanRequest
	for rows.Next() {
		var r models.ScanRequest
		if err := rows.Scan(&r.ID, &r.HostID, &r.RequestedBy, &r.ScanType, &r.PackagesOnly, &r.Reason, &r.SecurityDBRevision, &r.Status, &r.ErrorMessage, &r.ClaimedByHostID, &r.ClaimedAt, &r.CompletedAt, &r.CreatedAt, &r.RequestAgeS, &r.ClaimAgeS); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, nil
}

func (db *DB) GetScanRequest(ctx context.Context, id string) (*models.ScanRequest, error) {
	var r models.ScanRequest
	err := db.QueryRowContext(ctx, `SELECT id, host_id, requested_by, scan_type, packages_only, reason, security_db_revision, status, error_message, claimed_by_host_id, claimed_at, completed_at, created_at,
	EXTRACT(EPOCH FROM (now() - created_at))::bigint AS request_age_seconds,
	CASE WHEN claimed_at IS NULL THEN 0 ELSE EXTRACT(EPOCH FROM (now() - claimed_at))::bigint END AS claim_age_seconds
FROM scan_requests
WHERE id=$1`, id).Scan(&r.ID, &r.HostID, &r.RequestedBy, &r.ScanType, &r.PackagesOnly, &r.Reason, &r.SecurityDBRevision, &r.Status, &r.ErrorMessage, &r.ClaimedByHostID, &r.ClaimedAt, &r.CompletedAt, &r.CreatedAt, &r.RequestAgeS, &r.ClaimAgeS)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (db *DB) CountScanRequestsByStatus(ctx context.Context, hostIDs []string, includeGlobal bool) (map[string]int, error) {
	q := `SELECT status, count(*) FROM scan_requests`
	args := []any{}
	where := []string{}
	if len(hostIDs) > 0 {
		if includeGlobal {
			where = append(where, `(host_id='' OR host_id = ANY($1))`)
		} else {
			where = append(where, `host_id = ANY($1)`)
		}
		args = append(args, pqStringArray(hostIDs))
	} else if !includeGlobal {
		where = append(where, `false`)
	}
	if len(where) > 0 {
		q += ` WHERE ` + strings.Join(where, " AND ")
	}
	q += ` GROUP BY status`

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		out[status] = count
	}
	return out, rows.Err()
}

func (db *DB) CountStaleScanRequestsByState(ctx context.Context, hostIDs []string, includeGlobal bool, timeoutSeconds int64) (map[string]int, error) {
	q := `SELECT stale_state, count(*) FROM (
		SELECT CASE
			WHEN status='pending' AND created_at < now() - ($1::bigint * interval '1 second') THEN 'pending'
		WHEN status='claimed' AND claimed_at IS NOT NULL AND claimed_at < now() - ($1::bigint * interval '1 second') THEN 'claimed'
		ELSE ''
	END AS stale_state
	FROM scan_requests
	WHERE status IN ('pending','claimed')`
	args := []any{timeoutSeconds}
	if len(hostIDs) > 0 {
		if includeGlobal {
			q += ` AND (host_id='' OR host_id = ANY($2))`
		} else {
			q += ` AND host_id = ANY($2)`
		}
		args = append(args, pqStringArray(hostIDs))
	} else if !includeGlobal {
		q += ` AND false`
	}
	q += `) stale_requests WHERE stale_state <> '' GROUP BY stale_state`

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var state string
		var count int
		if err := rows.Scan(&state, &count); err != nil {
			return nil, err
		}
		out[state] = count
	}
	return out, rows.Err()
}

func (db *DB) CountStaleSecurityDBRescanRequestsByState(ctx context.Context, hostIDs []string, includeGlobal bool, revision string, timeoutSeconds int64) (map[string]int, error) {
	q := `SELECT stale_state, count(*) FROM (
		SELECT CASE
			WHEN status='pending' AND created_at < now() - ($2::bigint * interval '1 second') THEN 'pending'
			WHEN status='claimed' AND claimed_at IS NOT NULL AND claimed_at < now() - ($2::bigint * interval '1 second') THEN 'claimed'
			ELSE ''
		END AS stale_state
		FROM scan_requests
		WHERE scan_type='security-db-update'
		  AND security_db_revision=$1
		  AND status IN ('pending','claimed')`
	args := []any{revision, timeoutSeconds}
	if len(hostIDs) > 0 {
		if includeGlobal {
			q += ` AND (host_id='' OR host_id = ANY($3))`
		} else {
			q += ` AND host_id = ANY($3)`
		}
		args = append(args, pqStringArray(hostIDs))
	} else if !includeGlobal {
		q += ` AND false`
	}
	q += `) stale_requests WHERE stale_state <> '' GROUP BY stale_state`

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var state string
		var count int
		if err := rows.Scan(&state, &count); err != nil {
			return nil, err
		}
		out[state] = count
	}
	return out, rows.Err()
}

func (db *DB) CountSecurityDBRescanRequestsByStatus(ctx context.Context, hostIDs []string, includeGlobal bool, revision string) (map[string]int, error) {
	q := `SELECT status, count(*) FROM scan_requests WHERE scan_type='security-db-update' AND security_db_revision=$1`
	args := []any{revision}
	if len(hostIDs) > 0 {
		if includeGlobal {
			q += ` AND (host_id='' OR host_id = ANY($2))`
		} else {
			q += ` AND host_id = ANY($2)`
		}
		args = append(args, pqStringArray(hostIDs))
	} else if !includeGlobal {
		q += ` AND false`
	}
	q += ` GROUP BY status`

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		out[status] = count
	}
	return out, rows.Err()
}

type SecurityDBScanCoverage struct {
	Revision        string  `json:"revision"`
	TotalHosts      int     `json:"total_hosts"`
	CurrentHosts    int     `json:"current_hosts"`
	StaleHosts      int     `json:"stale_hosts"`
	UnknownHosts    int     `json:"unknown_hosts"`
	NoScanHosts     int     `json:"no_scan_hosts"`
	CoveragePercent float64 `json:"coverage_percent"`
}

func (db *DB) GetSecurityDBScanCoverage(ctx context.Context, hostIDs []string, includeGlobal bool, revision string) (*SecurityDBScanCoverage, error) {
	q := `
SELECT
	count(*)::int,
	count(*) FILTER (WHERE latest.security_db_revision=$1)::int,
	count(*) FILTER (WHERE latest.id IS NOT NULL AND latest.security_db_revision <> '' AND latest.security_db_revision <> $1)::int,
	count(*) FILTER (WHERE latest.id IS NOT NULL AND latest.security_db_revision = '')::int,
	count(*) FILTER (WHERE latest.id IS NULL)::int
FROM hosts h
LEFT JOIN LATERAL (
	SELECT id, security_db_revision
	FROM scans s
	WHERE s.host_id=h.id AND s.status IN ('completed','degraded')
	ORDER BY s.created_at DESC
	LIMIT 1
) latest ON true`
	args := []any{revision}
	if len(hostIDs) > 0 {
		q += ` WHERE h.id = ANY($2)`
		args = append(args, pqStringArray(hostIDs))
	} else if !includeGlobal {
		q += ` WHERE false`
	}
	stats := &SecurityDBScanCoverage{Revision: revision}
	if err := db.QueryRowContext(ctx, q, args...).Scan(&stats.TotalHosts, &stats.CurrentHosts, &stats.StaleHosts, &stats.UnknownHosts, &stats.NoScanHosts); err != nil {
		return nil, err
	}
	if stats.TotalHosts > 0 {
		stats.CoveragePercent = math.Round(float64(stats.CurrentHosts)*1000/float64(stats.TotalHosts)) / 10
	}
	return stats, nil
}

func (db *DB) RequeueStaleScanRequests(ctx context.Context, timeout time.Duration) (*StaleScanRequestRequeueResult, error) {
	if timeout <= 0 {
		timeout = time.Hour
	}
	cutoff := time.Now().Add(-timeout)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	result := &StaleScanRequestRequeueResult{}
	cancelled, err := cancelStaleSecurityDBDuplicates(ctx, tx, cutoff)
	if err != nil {
		return result, err
	}
	result.CancelledDuplicates = cancelled
	res, err := tx.ExecContext(ctx, `UPDATE scan_requests
SET status='pending', claimed_at=NULL, claimed_by_host_id='', error_message='requeued after claim timeout'
WHERE status='claimed' AND claimed_at < $1`, cutoff)
	if err != nil {
		return result, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return result, err
	}
	result.Requeued = int(n)
	return result, tx.Commit()
}

func (db *DB) ClaimScanRequest(ctx context.Context, hostID string, timeout time.Duration) (*models.ScanRequest, *StaleScanRequestRequeueResult, error) {
	if timeout <= 0 {
		timeout = time.Hour
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()

	cutoff := time.Now().Add(-timeout)
	result := &StaleScanRequestRequeueResult{}
	cancelled, err := cancelStaleSecurityDBDuplicates(ctx, tx, cutoff)
	if err != nil {
		return nil, result, err
	}
	result.CancelledDuplicates = cancelled
	requeued, err := tx.ExecContext(ctx, `UPDATE scan_requests
SET status='pending', claimed_at=NULL, claimed_by_host_id='', error_message='requeued after claim timeout'
WHERE status='claimed' AND claimed_at < $1`, cutoff)
	if err != nil {
		return nil, result, err
	}
	requeuedCount, err := requeued.RowsAffected()
	if err != nil {
		return nil, result, err
	}
	result.Requeued = int(requeuedCount)

	q := `UPDATE scan_requests
SET status='claimed', claimed_at=now(), claimed_by_host_id=$1, error_message=''
WHERE id = (
	SELECT id FROM scan_requests
	WHERE status='pending' AND (host_id='' OR host_id=$1)
	ORDER BY created_at ASC
	FOR UPDATE SKIP LOCKED
	LIMIT 1
)
RETURNING id, host_id, requested_by, scan_type, packages_only, reason, security_db_revision, status, error_message, claimed_by_host_id, claimed_at, completed_at, created_at`
	var r models.ScanRequest
	err = tx.QueryRowContext(ctx, q, hostID).Scan(&r.ID, &r.HostID, &r.RequestedBy, &r.ScanType, &r.PackagesOnly, &r.Reason, &r.SecurityDBRevision, &r.Status, &r.ErrorMessage, &r.ClaimedByHostID, &r.ClaimedAt, &r.CompletedAt, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, result, tx.Commit()
	}
	if err != nil {
		return nil, result, err
	}
	return &r, result, tx.Commit()
}

func cancelStaleSecurityDBDuplicates(ctx context.Context, tx *sql.Tx, cutoff time.Time) (int, error) {
	res, err := tx.ExecContext(ctx, `WITH stale AS (
	SELECT
		sr.id,
		row_number() OVER (PARTITION BY sr.host_id ORDER BY sr.claimed_at DESC, sr.created_at DESC, sr.id DESC) AS rn,
		EXISTS (
			SELECT 1 FROM scan_requests pending
			WHERE pending.host_id=sr.host_id
			  AND pending.scan_type='security-db-update'
			  AND pending.status='pending'
		) AS has_pending
	FROM scan_requests sr
	WHERE sr.status='claimed'
	  AND sr.claimed_at < $1
	  AND sr.host_id <> ''
	  AND sr.scan_type='security-db-update'
)
UPDATE scan_requests sr
SET status='cancelled',
	completed_at=now(),
	error_message='cancelled stale duplicate security-db-update request because a newer pending or claimed request exists'
FROM stale
WHERE sr.id=stale.id
  AND (stale.has_pending OR stale.rn > 1)`, cutoff)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func (db *DB) CompleteScanRequest(ctx context.Context, id, status, message string) error {
	if status != "completed" && status != "degraded" && status != "failed" && status != "cancelled" {
		return fmt.Errorf("%w: %s", ErrInvalidScanRequestStatus, status)
	}
	res, err := db.ExecContext(ctx, `UPDATE scan_requests
SET status=$2, error_message=$3, completed_at=now()
WHERE id=$1 AND status IN ('pending','claimed')`, id, status, message)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected > 0 {
		return nil
	}
	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM scan_requests WHERE id=$1)`, id).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrScanRequestNotFound
	}
	return ErrScanRequestNotActive
}

func (db *DB) RequeueScanRequest(ctx context.Context, id, message string) error {
	if message == "" {
		message = "requeued by admin"
	}
	res, err := db.ExecContext(ctx, `UPDATE scan_requests
SET status='pending', error_message=$2, claimed_at=NULL, claimed_by_host_id='', completed_at=NULL
WHERE id=$1
  AND status IN ('failed','degraded','cancelled')
  AND NOT EXISTS (
	SELECT 1 FROM scan_requests pending
	WHERE pending.id <> scan_requests.id
	  AND pending.host_id=scan_requests.host_id
	  AND pending.host_id <> ''
	  AND pending.scan_type='security-db-update'
	  AND pending.status='pending'
	  AND scan_requests.scan_type='security-db-update'
  )`, id, message)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected > 0 {
		return nil
	}
	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM scan_requests WHERE id=$1)`, id).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrScanRequestNotFound
	}
	return ErrScanRequestNotRetryable
}

func (db *DB) RequeueScanRequestsByFilter(ctx context.Context, hostID string, status string, scanType string, securityDBRevision string, message string) (int, error) {
	if message == "" {
		message = "bulk requeued by admin"
	}
	where := []string{"status IN ('failed','degraded','cancelled')"}
	args := []any{message}
	n := 2
	if hostID != "" {
		where = append(where, fmt.Sprintf("host_id=$%d", n))
		args = append(args, hostID)
		n++
	}
	if status != "" {
		where = append(where, fmt.Sprintf("status=$%d", n))
		args = append(args, status)
		n++
	}
	if scanType != "" {
		where = append(where, fmt.Sprintf("scan_type=$%d", n))
		args = append(args, scanType)
		n++
	}
	if securityDBRevision != "" {
		where = append(where, fmt.Sprintf("security_db_revision=$%d", n))
		args = append(args, securityDBRevision)
	}
	q := `UPDATE scan_requests
SET status='pending', error_message=$1, claimed_at=NULL, claimed_by_host_id='', completed_at=NULL
WHERE ` + strings.Join(where, " AND ") + `
  AND NOT EXISTS (
	SELECT 1 FROM scan_requests pending
	WHERE pending.id <> scan_requests.id
	  AND pending.host_id=scan_requests.host_id
	  AND pending.host_id <> ''
	  AND pending.scan_type='security-db-update'
	  AND pending.status='pending'
	  AND scan_requests.scan_type='security-db-update'
  )`
	res, err := db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(affected), nil
}

func (db *DB) CompleteClaimedScanRequest(ctx context.Context, id, hostID, status, message string) error {
	if hostID == "" {
		return ErrScanRequestClaimMismatch
	}
	if status != "completed" && status != "degraded" && status != "failed" {
		return fmt.Errorf("%w: %s", ErrInvalidScanRequestStatus, status)
	}
	res, err := db.ExecContext(ctx, `UPDATE scan_requests
SET status=$2, error_message=$3, completed_at=now()
WHERE id=$1 AND status='claimed' AND claimed_by_host_id=$4`, id, status, message, hostID)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected > 0 {
		return nil
	}
	var exists, active bool
	var claimedBy string
	if err := db.QueryRowContext(ctx, `SELECT true, status='claimed', claimed_by_host_id FROM scan_requests WHERE id=$1`, id).Scan(&exists, &active, &claimedBy); err != nil {
		if err == sql.ErrNoRows {
			return ErrScanRequestNotFound
		}
		return err
	}
	if !exists {
		return ErrScanRequestNotFound
	}
	if !active {
		return ErrScanRequestNotActive
	}
	if claimedBy != hostID {
		return ErrScanRequestClaimMismatch
	}
	return ErrScanRequestNotActive
}
