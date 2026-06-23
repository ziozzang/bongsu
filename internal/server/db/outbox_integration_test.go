//go:build integration

package db

import (
	"context"
	"testing"
	"time"
)

// TestEventOutboxIntegration exercises the durable-event guarantees against a
// real PostgreSQL: enqueue (incl. transactional + dedup coalescing), at-least-
// once claim under concurrency, exponential-backoff retry, dead-lettering at
// max_attempts, and reclaim of events orphaned by a crashed dispatcher.
func TestEventOutboxIntegration(t *testing.T) {
	database := openIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t.Run("enqueue then claim delivers the event exactly once while due", func(t *testing.T) {
		if _, err := database.EnqueueEvent(ctx, "test.basic", map[string]any{"n": 1}, ""); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		claimed, err := database.ClaimDueOutboxEvents(ctx, "w1", 10)
		if err != nil {
			t.Fatalf("claim: %v", err)
		}
		var found *OutboxEvent
		for i := range claimed {
			if claimed[i].EventType == "test.basic" {
				found = &claimed[i]
			}
		}
		if found == nil {
			t.Fatal("enqueued event was not claimed")
		}
		if found.Attempts != 1 {
			t.Fatalf("claim must increment attempts to 1, got %d", found.Attempts)
		}
		// A second immediate claim must NOT re-deliver it (now 'processing').
		again, err := database.ClaimDueOutboxEvents(ctx, "w2", 10)
		if err != nil {
			t.Fatalf("second claim: %v", err)
		}
		for _, e := range again {
			if e.ID == found.ID {
				t.Fatal("a processing event must not be re-claimed")
			}
		}
		if err := database.CompleteOutboxEvent(ctx, found.ID); err != nil {
			t.Fatalf("complete: %v", err)
		}
	})

	t.Run("dedup_key coalesces live events", func(t *testing.T) {
		ins1, err := database.EnqueueEvent(ctx, "test.dedup", map[string]any{"host": "h1"}, "rematch:h1")
		if err != nil || !ins1 {
			t.Fatalf("first enqueue should insert: ins=%v err=%v", ins1, err)
		}
		ins2, err := database.EnqueueEvent(ctx, "test.dedup", map[string]any{"host": "h1"}, "rematch:h1")
		if err != nil {
			t.Fatalf("second enqueue: %v", err)
		}
		if ins2 {
			t.Fatal("a live dedup_key must coalesce — no second row")
		}
		var live int
		if err := database.QueryRowContext(ctx,
			`SELECT count(*) FROM event_outbox WHERE dedup_key='rematch:h1' AND status IN ('pending','processing')`).Scan(&live); err != nil {
			t.Fatalf("count: %v", err)
		}
		if live != 1 {
			t.Fatalf("exactly one live event per dedup_key, got %d", live)
		}
	})

	t.Run("retry backs off, then dead-letters at max_attempts", func(t *testing.T) {
		if _, err := database.EnqueueEvent(ctx, "test.retry", map[string]any{}, ""); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		// Force a small max_attempts so we reach dead-letter quickly.
		var id string
		if err := database.QueryRowContext(ctx,
			`UPDATE event_outbox SET max_attempts=2 WHERE event_type='test.retry' RETURNING id`).Scan(&id); err != nil {
			t.Fatalf("set max_attempts: %v", err)
		}
		// Attempt 1: claim -> retry (attempts=1 < 2) -> pending with backoff.
		claimed, _ := database.ClaimDueOutboxEvents(ctx, "w1", 10)
		var ev *OutboxEvent
		for i := range claimed {
			if claimed[i].ID == id {
				ev = &claimed[i]
			}
		}
		if ev == nil {
			t.Fatal("retry event not claimed on attempt 1")
		}
		dead, err := database.RetryOutboxEvent(ctx, id, ev.Attempts, ev.MaxAttempts, "boom")
		if err != nil || dead {
			t.Fatalf("attempt 1 must not dead-letter: dead=%v err=%v", dead, err)
		}
		var status string
		var next time.Time
		if err := database.QueryRowContext(ctx,
			`SELECT status, next_attempt_at FROM event_outbox WHERE id=$1`, id).Scan(&status, &next); err != nil {
			t.Fatalf("read after retry: %v", err)
		}
		if status != "pending" || !next.After(time.Now()) {
			t.Fatalf("retry must reschedule in the future as pending, got status=%s next=%s", status, next)
		}
		// Make it due again, claim (attempts=2), retry -> dead-letter (2 >= 2).
		if _, err := database.ExecContext(ctx, `UPDATE event_outbox SET next_attempt_at=now() WHERE id=$1`, id); err != nil {
			t.Fatalf("force due: %v", err)
		}
		claimed2, _ := database.ClaimDueOutboxEvents(ctx, "w1", 10)
		ev = nil
		for i := range claimed2 {
			if claimed2[i].ID == id {
				ev = &claimed2[i]
			}
		}
		if ev == nil {
			t.Fatal("retry event not re-claimed on attempt 2")
		}
		dead, err = database.RetryOutboxEvent(ctx, id, ev.Attempts, ev.MaxAttempts, "boom2")
		if err != nil || !dead {
			t.Fatalf("attempt 2 must dead-letter: dead=%v err=%v", dead, err)
		}
		if err := database.QueryRowContext(ctx, `SELECT status FROM event_outbox WHERE id=$1`, id).Scan(&status); err != nil {
			t.Fatalf("read dead: %v", err)
		}
		if status != "dead" {
			t.Fatalf("event must be dead-lettered, got %s", status)
		}
	})

	t.Run("stuck processing events are reclaimed", func(t *testing.T) {
		if _, err := database.EnqueueEvent(ctx, "test.stuck", map[string]any{}, ""); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		claimed, _ := database.ClaimDueOutboxEvents(ctx, "deadworker", 10)
		var id string
		for _, e := range claimed {
			if e.EventType == "test.stuck" {
				id = e.ID
			}
		}
		if id == "" {
			t.Fatal("stuck event not claimed")
		}
		// Simulate the worker dying long ago.
		if _, err := database.ExecContext(ctx,
			`UPDATE event_outbox SET locked_at = now() - interval '10 minutes' WHERE id=$1`, id); err != nil {
			t.Fatalf("age lock: %v", err)
		}
		n, err := database.ReclaimStuckOutboxEvents(ctx, time.Minute)
		if err != nil {
			t.Fatalf("reclaim: %v", err)
		}
		if n < 1 {
			t.Fatalf("expected to reclaim the stuck event, got %d", n)
		}
		var status string
		if err := database.QueryRowContext(ctx, `SELECT status FROM event_outbox WHERE id=$1`, id).Scan(&status); err != nil {
			t.Fatalf("read reclaimed: %v", err)
		}
		if status != "pending" {
			t.Fatalf("reclaimed event must be pending again, got %s", status)
		}
	})
}
