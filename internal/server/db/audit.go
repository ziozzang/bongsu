package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

type AuditLogFilter struct {
	ActorType    string
	ActorID      string
	Action       string
	ResourceType string
	ResourceID   string
	Status       string
	CreatedFrom  *time.Time
	CreatedTo    *time.Time
}

func (db *DB) RecordAuditLog(ctx context.Context, logEntry *models.AuditLog) error {
	if logEntry.ID == "" {
		logEntry.ID = uuid.New().String()
	}
	if logEntry.Status == "" {
		logEntry.Status = "ok"
	}
	if len(logEntry.Metadata) == 0 {
		logEntry.Metadata = json.RawMessage(`{}`)
	}
	_, err := db.ExecContext(ctx, `INSERT INTO audit_logs
(id, actor_type, actor_id, action, resource_type, resource_id, status, ip_address, user_agent, metadata, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now())`,
		logEntry.ID, logEntry.ActorType, logEntry.ActorID, logEntry.Action, logEntry.ResourceType, logEntry.ResourceID,
		logEntry.Status, logEntry.IPAddress, logEntry.UserAgent, logEntry.Metadata)
	return err
}

func (db *DB) ListAuditLogs(ctx context.Context, f AuditLogFilter, limit, offset int) ([]models.AuditLog, int, error) {
	baseQ := `FROM audit_logs WHERE 1=1`
	args := []any{}
	n := 1
	add := func(col, value string) {
		if value == "" {
			return
		}
		baseQ += fmt.Sprintf(" AND %s=$%d", col, n)
		args = append(args, value)
		n++
	}
	add("actor_type", f.ActorType)
	add("actor_id", f.ActorID)
	add("action", f.Action)
	add("resource_type", f.ResourceType)
	add("resource_id", f.ResourceID)
	add("status", f.Status)
	if f.CreatedFrom != nil {
		baseQ += fmt.Sprintf(" AND created_at >= $%d", n)
		args = append(args, *f.CreatedFrom)
		n++
	}
	if f.CreatedTo != nil {
		baseQ += fmt.Sprintf(" AND created_at <= $%d", n)
		args = append(args, *f.CreatedTo)
		n++
	}

	var total int
	if err := db.QueryRowContext(ctx, "SELECT count(*) "+baseQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := `SELECT id, actor_type, actor_id, action, resource_type, resource_id, status, ip_address, user_agent, metadata, created_at ` + baseQ + fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", n, n+1)
	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []models.AuditLog
	for rows.Next() {
		var item models.AuditLog
		if err := rows.Scan(&item.ID, &item.ActorType, &item.ActorID, &item.Action, &item.ResourceType, &item.ResourceID, &item.Status, &item.IPAddress, &item.UserAgent, &item.Metadata, &item.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (db *DB) GetLatestAuditLog(ctx context.Context, f AuditLogFilter, excludedStatuses []string) (*models.AuditLog, error) {
	baseQ := `FROM audit_logs WHERE 1=1`
	args := []any{}
	n := 1
	add := func(col, value string) {
		if value == "" {
			return
		}
		baseQ += fmt.Sprintf(" AND %s=$%d", col, n)
		args = append(args, value)
		n++
	}
	add("actor_type", f.ActorType)
	add("actor_id", f.ActorID)
	add("action", f.Action)
	add("resource_type", f.ResourceType)
	add("resource_id", f.ResourceID)
	add("status", f.Status)
	if f.CreatedFrom != nil {
		baseQ += fmt.Sprintf(" AND created_at >= $%d", n)
		args = append(args, *f.CreatedFrom)
		n++
	}
	if f.CreatedTo != nil {
		baseQ += fmt.Sprintf(" AND created_at <= $%d", n)
		args = append(args, *f.CreatedTo)
		n++
	}
	if len(excludedStatuses) > 0 {
		baseQ += fmt.Sprintf(" AND NOT (status = ANY($%d))", n)
		args = append(args, pq.Array(excludedStatuses))
		n++
	}
	q := `SELECT id, actor_type, actor_id, action, resource_type, resource_id, status, ip_address, user_agent, metadata, created_at ` + baseQ + ` ORDER BY created_at DESC LIMIT 1`
	var item models.AuditLog
	err := db.QueryRowContext(ctx, q, args...).Scan(&item.ID, &item.ActorType, &item.ActorID, &item.Action, &item.ResourceType, &item.ResourceID, &item.Status, &item.IPAddress, &item.UserAgent, &item.Metadata, &item.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

