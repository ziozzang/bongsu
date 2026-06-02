package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type NotificationRule struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Enabled      bool            `json:"enabled"`
	TriggerEvent string          `json:"trigger_event"`
	MinSeverity  string          `json:"min_severity"`
	MinRiskLevel string          `json:"min_risk_level"`
	ExploitedOnly bool           `json:"exploited_only"`
	HostFilter   string          `json:"host_filter"`
	ChannelType  string          `json:"channel_type"`
	ChannelConfig json.RawMessage `json:"channel_config"`
	LastTriggered *time.Time     `json:"last_triggered"`
	TriggerCount int             `json:"trigger_count"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

type NotificationLog struct {
	ID           string          `json:"id"`
	RuleID       string          `json:"rule_id"`
	TriggerEvent string          `json:"trigger_event"`
	Status       string          `json:"status"`
	Payload      json.RawMessage `json:"payload"`
	ErrorMessage string          `json:"error_message"`
	Attempts     int             `json:"attempts"`
	CreatedAt    time.Time       `json:"created_at"`
}

const notificationRuleCols = `id, name, enabled, trigger_event, min_severity, min_risk_level, exploited_only, host_filter, channel_type, channel_config, last_triggered, trigger_count, created_at, updated_at`

func (db *DB) CreateNotificationRule(ctx context.Context, r *NotificationRule) error {
	if r.ID == "" {
		r.ID = uuid.New().String()
	}
	cfg := r.ChannelConfig
	if cfg == nil {
		cfg = json.RawMessage(`{}`)
	}
	_, err := db.ExecContext(ctx,
		`INSERT INTO notification_rules (id, name, enabled, trigger_event, min_severity, min_risk_level, exploited_only, host_filter, channel_type, channel_config, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now(), now())`,
		r.ID, r.Name, r.Enabled, r.TriggerEvent, r.MinSeverity, r.MinRiskLevel, r.ExploitedOnly, r.HostFilter, r.ChannelType, cfg)
	if err != nil {
		return fmt.Errorf("create notification rule: %w", err)
	}
	return nil
}

func (db *DB) GetNotificationRule(ctx context.Context, id string) (*NotificationRule, error) {
	var r NotificationRule
	var lastTrig *time.Time
	q := `SELECT ` + notificationRuleCols + ` FROM notification_rules WHERE id = $1`
	err := db.QueryRowContext(ctx, q, id).Scan(&r.ID, &r.Name, &r.Enabled, &r.TriggerEvent, &r.MinSeverity, &r.MinRiskLevel, &r.ExploitedOnly, &r.HostFilter, &r.ChannelType, &r.ChannelConfig, &lastTrig, &r.TriggerCount, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get notification rule: %w", err)
	}
	r.LastTriggered = lastTrig
	return &r, nil
}

func (db *DB) ListNotificationRules(ctx context.Context) ([]NotificationRule, error) {
	q := `SELECT ` + notificationRuleCols + ` FROM notification_rules ORDER BY name`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list notification rules: %w", err)
	}
	defer rows.Close()
	var out []NotificationRule
	for rows.Next() {
		var r NotificationRule
		var lastTrig *time.Time
		if err := rows.Scan(&r.ID, &r.Name, &r.Enabled, &r.TriggerEvent, &r.MinSeverity, &r.MinRiskLevel, &r.ExploitedOnly, &r.HostFilter, &r.ChannelType, &r.ChannelConfig, &lastTrig, &r.TriggerCount, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.LastTriggered = lastTrig
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) UpdateNotificationRule(ctx context.Context, r *NotificationRule) error {
	cfg := r.ChannelConfig
	if cfg == nil {
		cfg = json.RawMessage(`{}`)
	}
	res, err := db.ExecContext(ctx,
		`UPDATE notification_rules SET name=$2, enabled=$3, trigger_event=$4, min_severity=$5, min_risk_level=$6, exploited_only=$7, host_filter=$8, channel_type=$9, channel_config=$10, updated_at=now() WHERE id=$1`,
		r.ID, r.Name, r.Enabled, r.TriggerEvent, r.MinSeverity, r.MinRiskLevel, r.ExploitedOnly, r.HostFilter, r.ChannelType, cfg)
	if err != nil {
		return fmt.Errorf("update notification rule: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("notification rule not found")
	}
	return nil
}

func (db *DB) DeleteNotificationRule(ctx context.Context, id string) error {
	res, err := db.ExecContext(ctx, `DELETE FROM notification_rules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete notification rule: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("notification rule not found")
	}
	return nil
}

func (db *DB) GetEnabledRulesForEvent(ctx context.Context, event string) ([]NotificationRule, error) {
	q := `SELECT ` + notificationRuleCols + ` FROM notification_rules WHERE enabled = true AND trigger_event = $1 ORDER BY name`
	rows, err := db.QueryContext(ctx, q, event)
	if err != nil {
		return nil, fmt.Errorf("get enabled rules: %w", err)
	}
	defer rows.Close()
	var out []NotificationRule
	for rows.Next() {
		var r NotificationRule
		var lastTrig *time.Time
		if err := rows.Scan(&r.ID, &r.Name, &r.Enabled, &r.TriggerEvent, &r.MinSeverity, &r.MinRiskLevel, &r.ExploitedOnly, &r.HostFilter, &r.ChannelType, &r.ChannelConfig, &lastTrig, &r.TriggerCount, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.LastTriggered = lastTrig
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) RecordNotificationLog(ctx context.Context, l *NotificationLog) error {
	if l.ID == "" {
		l.ID = uuid.New().String()
	}
	payload := l.Payload
	if payload == nil {
		payload = json.RawMessage(`{}`)
	}
	_, err := db.ExecContext(ctx,
		`INSERT INTO notification_log (id, rule_id, trigger_event, status, payload, error_message, attempts, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, now())`,
		l.ID, l.RuleID, l.TriggerEvent, l.Status, payload, l.ErrorMessage, l.Attempts)
	return err
}

func (db *DB) ListNotificationLog(ctx context.Context, ruleID string, limit, offset int) ([]NotificationLog, int, error) {
	countQ := `SELECT count(*)::int FROM notification_log`
	dataQ := `SELECT id, rule_id, trigger_event, status, payload, error_message, attempts, created_at FROM notification_log`
	args := []any{}
	if ruleID != "" {
		countQ += ` WHERE rule_id = $1`
		dataQ += ` WHERE rule_id = $1`
		args = append(args, ruleID)
	}
	dataQ += ` ORDER BY created_at DESC`
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	dataQ += fmt.Sprintf(` LIMIT %d OFFSET %d`, limit, offset)
	var total int
	if err := db.QueryRowContext(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.QueryContext(ctx, dataQ, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list notification log: %w", err)
	}
	defer rows.Close()
	var out []NotificationLog
	for rows.Next() {
		var l NotificationLog
		if err := rows.Scan(&l.ID, &l.RuleID, &l.TriggerEvent, &l.Status, &l.Payload, &l.ErrorMessage, &l.Attempts, &l.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, l)
	}
	return out, total, rows.Err()
}

func (db *DB) TouchNotificationRuleTrigger(ctx context.Context, ruleID string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE notification_rules SET last_triggered = now(), trigger_count = trigger_count + 1, updated_at = now() WHERE id = $1`,
		ruleID)
	return err
}

func (db *DB) CleanupOldNotificationLogs(ctx context.Context) error {
	days := envInt("BONGSU_NOTIFICATION_LOG_RETENTION_DAYS", 30)
	if days < 1 {
		days = 30
	}
	_, err := db.ExecContext(ctx, `DELETE FROM notification_log WHERE created_at < now() - $1 * interval '1 day'`, days)
	return err
}
