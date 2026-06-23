package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// OutboxEvent is one durable pipeline event awaiting (or undergoing) delivery.
type OutboxEvent struct {
	ID          string
	EventType   string
	Payload     json.RawMessage
	Status      string
	Attempts    int
	MaxAttempts int
	DedupKey    string
}

// outboxEnqueuer is satisfied by both *sql.DB and *sql.Tx, so an event can be
// enqueued either standalone or — the point of a transactional outbox — inside
// the same transaction as the work that produced it, so the event and its cause
// commit or roll back together.
type outboxEnqueuer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

const outboxInsertSQL = `INSERT INTO event_outbox (event_type, payload, dedup_key, next_attempt_at)
VALUES ($1, $2, $3, now())
ON CONFLICT (dedup_key) WHERE dedup_key <> '' AND status IN ('pending','processing') DO NOTHING`

// EnqueueEventTx enqueues an event inside an existing transaction. A non-empty
// dedupKey coalesces with any already-live event of the same key (no duplicate
// row is created). Returns whether a new row was inserted.
func (db *DB) EnqueueEventTx(ctx context.Context, tx *sql.Tx, eventType string, payload any, dedupKey string) (bool, error) {
	return enqueueEvent(ctx, tx, eventType, payload, dedupKey)
}

// EnqueueEvent enqueues an event on its own connection.
func (db *DB) EnqueueEvent(ctx context.Context, eventType string, payload any, dedupKey string) (bool, error) {
	return enqueueEvent(ctx, db.DB, eventType, payload, dedupKey)
}

func enqueueEvent(ctx context.Context, q outboxEnqueuer, eventType string, payload any, dedupKey string) (bool, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("marshal outbox payload: %w", err)
	}
	if len(raw) == 0 || string(raw) == "null" {
		raw = []byte("{}")
	}
	res, err := q.ExecContext(ctx, outboxInsertSQL, eventType, raw, dedupKey)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ClaimDueOutboxEvents atomically claims up to limit pending events whose backoff
// has elapsed, marking them 'processing' under workerID. FOR UPDATE SKIP LOCKED
// makes concurrent dispatchers (or future multi-instance deployments) claim
// disjoint sets without blocking each other.
func (db *DB) ClaimDueOutboxEvents(ctx context.Context, workerID string, limit int) ([]OutboxEvent, error) {
	if limit <= 0 {
		limit = 1
	}
	const q = `UPDATE event_outbox SET status='processing', locked_by=$1, locked_at=now(), attempts=attempts+1, updated_at=now()
WHERE id IN (
	SELECT id FROM event_outbox
	WHERE status='pending' AND next_attempt_at <= now()
	ORDER BY next_attempt_at ASC
	FOR UPDATE SKIP LOCKED
	LIMIT $2
)
RETURNING id, event_type, payload, attempts, max_attempts, dedup_key`
	rows, err := db.QueryContext(ctx, q, workerID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OutboxEvent
	for rows.Next() {
		var e OutboxEvent
		if err := rows.Scan(&e.ID, &e.EventType, &e.Payload, &e.Attempts, &e.MaxAttempts, &e.DedupKey); err != nil {
			return nil, err
		}
		e.Status = "processing"
		out = append(out, e)
	}
	return out, rows.Err()
}

// CompleteOutboxEvent marks a claimed event delivered.
func (db *DB) CompleteOutboxEvent(ctx context.Context, id string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE event_outbox SET status='done', locked_by='', locked_at=NULL, last_error='', updated_at=now() WHERE id=$1`, id)
	return err
}

// RetryOutboxEvent records a failed delivery attempt: the event goes back to
// 'pending' with an exponential-backoff next_attempt_at, unless it has reached
// max_attempts, in which case it is dead-lettered. attempts was already
// incremented at claim time. Returns true if the event was dead-lettered.
func (db *DB) RetryOutboxEvent(ctx context.Context, id string, attempts, maxAttempts int, cause string) (bool, error) {
	if attempts >= maxAttempts {
		_, err := db.ExecContext(ctx,
			`UPDATE event_outbox SET status='dead', locked_by='', locked_at=NULL, last_error=$2, updated_at=now() WHERE id=$1`,
			id, cause)
		return true, err
	}
	backoff := outboxBackoff(attempts)
	_, err := db.ExecContext(ctx,
		`UPDATE event_outbox SET status='pending', locked_by='', locked_at=NULL, last_error=$2,
		 next_attempt_at = now() + ($3 || ' seconds')::interval, updated_at=now() WHERE id=$1`,
		id, cause, int(backoff.Seconds()))
	return false, err
}

// outboxBackoff returns the delay before the next attempt: exponential (base 2s)
// capped at 1 hour. attempt is the number of attempts already made (>=1).
func outboxBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := 2 * time.Second
	for i := 1; i < attempt && d < time.Hour; i++ {
		d *= 2
	}
	if d > time.Hour {
		d = time.Hour
	}
	return d
}

// ReclaimStuckOutboxEvents returns events stuck in 'processing' (a dispatcher
// died mid-delivery) older than the timeout back to 'pending' so another worker
// retries them. Returns the number reclaimed.
func (db *DB) ReclaimStuckOutboxEvents(ctx context.Context, timeout time.Duration) (int64, error) {
	cutoff := time.Now().Add(-timeout)
	res, err := db.ExecContext(ctx,
		`UPDATE event_outbox SET status='pending', locked_by='', locked_at=NULL,
		 last_error='reclaimed after processing timeout', updated_at=now()
		 WHERE status='processing' AND locked_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
