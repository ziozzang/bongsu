-- Phase B: transactional outbox for the ingest -> match -> notify pipeline.
--
-- Notifications were fire-and-forget: notification_log was written and the send
-- happened in a detached goroutine with no persistence or retry, so a process
-- crash or a failing webhook lost the event irrecoverably. CVE rematch ran
-- synchronously inside the agent report request. The outbox makes both durable:
-- an event is enqueued (ideally in the same transaction as the work that produced
-- it), and a background dispatcher delivers it at-least-once with exponential
-- backoff and a dead-letter terminal state.

CREATE TABLE IF NOT EXISTS event_outbox (
    id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    event_type      TEXT NOT NULL,                       -- e.g. 'notification.event', 'scan.rematch'
    payload         JSONB NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'processing', 'done', 'dead')),
    attempts        INT NOT NULL DEFAULT 0,
    max_attempts    INT NOT NULL DEFAULT 10,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_by       TEXT NOT NULL DEFAULT '',
    locked_at       TIMESTAMPTZ,
    last_error      TEXT NOT NULL DEFAULT '',
    dedup_key       TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Claim path: pending events whose backoff has elapsed, oldest first.
CREATE INDEX IF NOT EXISTS idx_event_outbox_due
    ON event_outbox (next_attempt_at)
    WHERE status = 'pending';

-- Coalescing: at most one LIVE (pending/processing) event per dedup_key, so e.g.
-- a flood of "rematch host X" triggers collapses to a single pending job. A blank
-- dedup_key opts out of coalescing (every enqueue is its own row).
CREATE UNIQUE INDEX IF NOT EXISTS uq_event_outbox_dedup
    ON event_outbox (dedup_key)
    WHERE dedup_key <> '' AND status IN ('pending', 'processing');

-- Retention / dead-letter inspection.
CREATE INDEX IF NOT EXISTS idx_event_outbox_status_created
    ON event_outbox (status, created_at);
