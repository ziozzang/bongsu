package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// AIApproval is a queued AI-proposed action awaiting human approval.
type AIApproval struct {
	ID         string          `json:"id"`
	ActionType string          `json:"action_type"`
	Subject    string          `json:"subject"`
	Proposed   json.RawMessage `json:"proposed"`
	Context    json.RawMessage `json:"context"`
	Confidence float64         `json:"confidence"`
	Rule       string          `json:"rule"`
	Reason     string          `json:"reason"`
	Status     string          `json:"status"`
	CreatedAt  time.Time       `json:"created_at"`
	DecidedAt  *time.Time      `json:"decided_at,omitempty"`
	DecidedBy  string          `json:"decided_by,omitempty"`
}

// CreateAIApproval enqueues a pending approval. If an identical pending approval
// already exists (same action_type + subject) it is updated, not duplicated.
func (db *DB) CreateAIApproval(ctx context.Context, a *AIApproval) error {
	if len(a.Proposed) == 0 {
		a.Proposed = json.RawMessage("{}")
	}
	if len(a.Context) == 0 {
		a.Context = json.RawMessage("{}")
	}
	_, err := db.ExecContext(ctx, `
INSERT INTO ai_action_approvals (action_type, subject, proposed, context, confidence, rule, reason, status)
VALUES ($1,$2,$3,$4,$5,$6,$7,'pending')
ON CONFLICT (action_type, subject) WHERE status='pending'
DO UPDATE SET proposed=EXCLUDED.proposed, context=EXCLUDED.context, confidence=EXCLUDED.confidence,
              rule=EXCLUDED.rule, reason=EXCLUDED.reason, created_at=now()`,
		a.ActionType, a.Subject, []byte(a.Proposed), []byte(a.Context), a.Confidence, a.Rule, a.Reason)
	if err != nil {
		return fmt.Errorf("create ai approval: %w", err)
	}
	return nil
}

// ListAIApprovals returns approvals, optionally filtered by status, newest first.
func (db *DB) ListAIApprovals(ctx context.Context, status string, limit int) ([]AIApproval, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	args := []any{}
	filter := ""
	if status != "" {
		args = append(args, status)
		filter = " WHERE status=$1"
	}
	rows, err := db.QueryContext(ctx, `
SELECT id, action_type, subject, proposed, context, confidence, rule, reason, status, created_at, decided_at, decided_by
FROM ai_action_approvals`+filter+`
ORDER BY (status='pending') DESC, created_at DESC
LIMIT `+fmt.Sprintf("%d", limit), args...)
	if err != nil {
		return nil, fmt.Errorf("list ai approvals: %w", err)
	}
	defer rows.Close()
	out := []AIApproval{}
	for rows.Next() {
		a := AIApproval{}
		var proposed, contextJSON []byte
		if err := rows.Scan(&a.ID, &a.ActionType, &a.Subject, &proposed, &contextJSON, &a.Confidence,
			&a.Rule, &a.Reason, &a.Status, &a.CreatedAt, &a.DecidedAt, &a.DecidedBy); err != nil {
			return nil, err
		}
		a.Proposed = proposed
		a.Context = contextJSON
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetAIApproval fetches one approval by id.
func (db *DB) GetAIApproval(ctx context.Context, id string) (*AIApproval, error) {
	a := AIApproval{}
	var proposed, contextJSON []byte
	err := db.QueryRowContext(ctx, `
SELECT id, action_type, subject, proposed, context, confidence, rule, reason, status, created_at, decided_at, decided_by
FROM ai_action_approvals WHERE id=$1`, id).Scan(
		&a.ID, &a.ActionType, &a.Subject, &proposed, &contextJSON, &a.Confidence,
		&a.Rule, &a.Reason, &a.Status, &a.CreatedAt, &a.DecidedAt, &a.DecidedBy)
	if err != nil {
		return nil, err
	}
	a.Proposed = proposed
	a.Context = contextJSON
	return &a, nil
}

// ClaimAIApprovalForApproval atomically transitions a PENDING approval to
// 'approved' and returns its action_type + proposed payload, so the caller can
// execute the action knowing it won exclusively. Returns claimed=false if the
// approval was not pending (already decided / not found / lost the race) — this
// closes the double-execution window where two approvers both read 'pending'
// before either updates. On execution failure the caller reverts with
// RevertAIApproval.
func (db *DB) ClaimAIApprovalForApproval(ctx context.Context, id, decidedBy string) (claimed bool, actionType string, proposed json.RawMessage, err error) {
	var raw []byte
	e := db.QueryRowContext(ctx,
		`UPDATE ai_action_approvals SET status='approved', decided_at=now(), decided_by=$2
		 WHERE id=$1 AND status='pending' RETURNING action_type, proposed`,
		id, decidedBy).Scan(&actionType, &raw)
	if e == sql.ErrNoRows {
		return false, "", nil, nil
	}
	if e != nil {
		return false, "", nil, fmt.Errorf("claim ai approval: %w", e)
	}
	return true, actionType, json.RawMessage(raw), nil
}

// RevertAIApproval rolls a just-claimed approval back to pending when the action
// it represents failed to execute.
func (db *DB) RevertAIApproval(ctx context.Context, id string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE ai_action_approvals SET status='pending', decided_at=NULL, decided_by='' WHERE id=$1 AND status='approved'`, id)
	return err
}

// RejectAIApproval atomically transitions a pending approval to 'rejected'.
// Returns false if it was not pending.
func (db *DB) RejectAIApproval(ctx context.Context, id, decidedBy string) (bool, error) {
	res, err := db.ExecContext(ctx,
		`UPDATE ai_action_approvals SET status='rejected', decided_at=now(), decided_by=$2 WHERE id=$1 AND status='pending'`,
		decidedBy, id)
	if err != nil {
		return false, fmt.Errorf("reject ai approval: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// CountAIApprovalsByStatus returns counts grouped by status (for metrics/UI).
func (db *DB) CountAIApprovalsByStatus(ctx context.Context) (map[string]int, error) {
	rows, err := db.QueryContext(ctx, `SELECT status, count(*) FROM ai_action_approvals GROUP BY status`)
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
