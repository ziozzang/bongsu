package db

import (
	"testing"
	"time"
)

func TestOutboxBackoff(t *testing.T) {
	// Exponential from a 2s base, monotonic non-decreasing, capped at 1h.
	prev := time.Duration(0)
	for attempt := 1; attempt <= 20; attempt++ {
		d := outboxBackoff(attempt)
		if d < prev {
			t.Fatalf("backoff must be non-decreasing: attempt %d -> %s < prev %s", attempt, d, prev)
		}
		if d > time.Hour {
			t.Fatalf("backoff must be capped at 1h, attempt %d -> %s", attempt, d)
		}
		prev = d
	}
	if got := outboxBackoff(1); got != 2*time.Second {
		t.Fatalf("first attempt backoff should be the 2s base, got %s", got)
	}
	// A few attempts in, it should be well above the base and at/under the cap.
	if got := outboxBackoff(20); got != time.Hour {
		t.Fatalf("deep attempts should saturate at the 1h cap, got %s", got)
	}
	// Defensive: attempt < 1 must not panic or under-delay.
	if got := outboxBackoff(0); got != 2*time.Second {
		t.Fatalf("attempt 0 should clamp to the base, got %s", got)
	}
}
