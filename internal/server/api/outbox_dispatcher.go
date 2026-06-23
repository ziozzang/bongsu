package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ziozzang/bongsu/internal/server/db"
)

// permanentError marks a handler failure that retrying cannot fix (e.g. an
// undecodable payload). process() dead-letters it immediately instead of
// burning the retry budget, and — unlike a silent success — it stays visible in
// the dead-letter queue for forensics.
type permanentError struct{ err error }

func (e permanentError) Error() string { return e.err.Error() }
func permanent(err error) error        { return permanentError{err} }

// Event types carried by the outbox.
const (
	eventNotification = "notification.event"
)

// notificationEventPayload is the durable form of a notification trigger. The
// rendered event name + data are persisted so a matching rule's webhook/email
// can be (re)delivered by the dispatcher long after the originating request, and
// survive a process crash.
type notificationEventPayload struct {
	Event string         `json:"event"`
	Data  map[string]any `json:"data"`
}

// outboxHandler delivers one event. Returning an error causes the event to be
// retried with backoff (and eventually dead-lettered); nil marks it done.
type outboxHandler func(ctx context.Context, payload json.RawMessage) error

// OutboxDispatcher drains event_outbox at-least-once and routes each event to a
// registered handler. One instance runs per server process; ClaimDueOutboxEvents
// uses FOR UPDATE SKIP LOCKED so it is already safe to run several (or, later,
// multiple instances) concurrently.
type OutboxDispatcher struct {
	server   *Server
	workerID string
	handlers map[string]outboxHandler
	interval time.Duration
	batch    int
	stuckTTL time.Duration
}

// StartOutboxDispatcher runs the event-outbox dispatcher loop until ctx is
// cancelled. Intended to be called as `go server.StartOutboxDispatcher(bgCtx)`.
func (s *Server) StartOutboxDispatcher(ctx context.Context) {
	newOutboxDispatcher(s, outboxWorkerID()).Run(ctx)
}

// outboxWorkerID identifies this dispatcher in event_outbox.locked_by for
// debugging/forensics. Stable per process; uniqueness across instances is not
// required for correctness (claims are row-locked).
func outboxWorkerID() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return "dispatcher@" + h
	}
	return "dispatcher"
}

func newOutboxDispatcher(s *Server, workerID string) *OutboxDispatcher {
	d := &OutboxDispatcher{
		server:   s,
		workerID: workerID,
		handlers: map[string]outboxHandler{},
		interval: time.Duration(envInt("BONGSU_OUTBOX_POLL_SECONDS", 5)) * time.Second,
		batch:    envInt("BONGSU_OUTBOX_BATCH", 20),
		stuckTTL: time.Duration(envInt("BONGSU_OUTBOX_STUCK_SECONDS", 300)) * time.Second,
	}
	d.handlers[eventNotification] = d.handleNotificationEvent
	return d
}

func (d *OutboxDispatcher) handleNotificationEvent(ctx context.Context, payload json.RawMessage) error {
	var p notificationEventPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		// A malformed payload will never become valid: dead-letter it (visible for
		// forensics) rather than retrying forever or silently dropping it.
		return permanent(fmt.Errorf("decode notification payload: %w", err))
	}
	return d.server.ruleNotifier.evaluateAndDispatch(ctx, p.Event, p.Data)
}

// Run polls the outbox until ctx is cancelled, reclaiming stuck events on each
// tick before draining due ones.
func (d *OutboxDispatcher) Run(ctx context.Context) {
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	log.Printf("outbox dispatcher started (worker=%s, interval=%s)", d.workerID, d.interval)
	for {
		select {
		case <-ctx.Done():
			log.Printf("outbox dispatcher stopping")
			return
		case <-ticker.C:
			if n, err := d.server.db.ReclaimStuckOutboxEvents(ctx, d.stuckTTL); err != nil {
				log.Printf("outbox reclaim: %v", err)
			} else if n > 0 {
				log.Printf("outbox reclaimed %d stuck event(s)", n)
			}
			d.drain(ctx)
		}
	}
}

// drain claims and processes due events until a batch comes back empty or the
// context is cancelled.
func (d *OutboxDispatcher) drain(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		events, err := d.server.db.ClaimDueOutboxEvents(ctx, d.workerID, d.batch)
		if err != nil {
			log.Printf("outbox claim: %v", err)
			return
		}
		if len(events) == 0 {
			return
		}
		for i := range events {
			d.process(ctx, &events[i])
		}
	}
}

func (d *OutboxDispatcher) process(ctx context.Context, e *db.OutboxEvent) {
	handler, ok := d.handlers[e.EventType]
	if !ok {
		// Unknown type: dead-letter rather than spin, so a deploy that removed a
		// handler doesn't loop forever.
		if _, err := d.server.db.RetryOutboxEvent(ctx, e.ID, e.MaxAttempts, e.MaxAttempts, "no handler for "+e.EventType); err != nil {
			log.Printf("outbox dead-letter unknown type %s: %v", e.EventType, err)
		}
		return
	}
	if err := handler(ctx, e.Payload); err != nil {
		// A permanent error can never succeed on retry — dead-letter it now by
		// passing attempts==maxAttempts to the retry bookkeeping.
		attempts := e.Attempts
		var perm permanentError
		if errors.As(err, &perm) {
			attempts = e.MaxAttempts
		}
		dead, rerr := d.server.db.RetryOutboxEvent(ctx, e.ID, attempts, e.MaxAttempts, err.Error())
		if rerr != nil {
			log.Printf("outbox retry bookkeeping for %s: %v", e.ID, rerr)
		} else if dead {
			log.Printf("outbox event %s (%s) dead-lettered after %d attempts: %v", e.ID, e.EventType, e.Attempts, err)
		}
		return
	}
	if err := d.server.db.CompleteOutboxEvent(ctx, e.ID); err != nil {
		log.Printf("outbox complete %s: %v", e.ID, err)
	}
}
