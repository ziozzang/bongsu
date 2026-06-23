//go:build integration

package db

import (
	"context"
	"testing"
	"time"
)

// TestInsertAuthEvent verifies the 067 migration applies and an auth audit record
// round-trips, including the JSONB presented/decisions payloads.
func TestInsertAuthEvent(t *testing.T) {
	database := openIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ev := AuthEvent{
		RequestID:     "req-abc",
		RemoteAddr:    "10.0.0.5:4444",
		Method:        "GET",
		Path:          "/api/vulnerabilities",
		FinalKind:     "session",
		FinalID:       "user:alice",
		FinalAdmin:    false,
		FinalIdentity: "user:alice",
		Rejected:      true,
		RejectReason:  "multiple distinct identity credentials presented",
		MultiIdentity: true,
		Enriched:      false,
		Presented: []map[string]any{
			{"kind": "session", "decision": "selected"},
			{"kind": "trusted", "decision": "rejected_identity_mismatch"},
		},
		Decisions: []map[string]any{
			{"kind": "session", "decision": "selected"},
			{"kind": "trusted", "decision": "rejected_identity_mismatch", "reason": "identity_mismatch"},
		},
	}
	if err := database.InsertAuthEvent(ctx, ev); err != nil {
		t.Fatalf("InsertAuthEvent: %v", err)
	}

	var (
		gotKind, gotReason string
		rejected, multi    bool
		decisionsLen       int
	)
	err := database.QueryRowContext(ctx,
		`SELECT final_kind, reject_reason, rejected, multi_identity, jsonb_array_length(decisions)
		   FROM auth_events WHERE request_id=$1`, "req-abc").
		Scan(&gotKind, &gotReason, &rejected, &multi, &decisionsLen)
	if err != nil {
		t.Fatalf("read back auth_event: %v", err)
	}
	if gotKind != "session" || !rejected || !multi || gotReason == "" || decisionsLen != 2 {
		t.Fatalf("auth_event round-trip wrong: kind=%s rejected=%v multi=%v reason=%q decisions=%d",
			gotKind, rejected, multi, gotReason, decisionsLen)
	}

	// The partial reject index must be usable for "recent rejects" queries.
	var rejectCount int
	if err := database.QueryRowContext(ctx,
		`SELECT count(*) FROM auth_events WHERE rejected`).Scan(&rejectCount); err != nil {
		t.Fatalf("count rejects: %v", err)
	}
	if rejectCount < 1 {
		t.Fatalf("expected at least one rejected auth_event, got %d", rejectCount)
	}
}
