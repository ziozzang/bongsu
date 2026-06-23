package db

import (
	"context"
	"encoding/json"
	"fmt"
)

// AuthEvent is one persisted credential-resolution audit record. It is written
// only for non-trivial resolutions (reject / enrich / multi-identity); see
// migrations/067_auth_events.sql. Presented and Decisions are arbitrary JSON
// (the api layer's []SourceMatch / []AuthDecision) serialized verbatim.
type AuthEvent struct {
	RequestID     string
	RemoteAddr    string
	Method        string
	Path          string
	FinalKind     string
	FinalID       string
	FinalAdmin    bool
	FinalIdentity string
	Rejected      bool
	RejectReason  string
	MultiIdentity bool
	Enriched      bool
	Presented     any
	Decisions     any
}

const authEventInsertSQL = `INSERT INTO auth_events
(request_id, remote_addr, method, path, final_kind, final_id, final_admin, final_identity_key,
 rejected, reject_reason, multi_identity, enriched, presented, decisions)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`

// InsertAuthEvent persists one auth audit record. Callers treat failures as
// non-fatal (best-effort audit); the structured stderr log is the fallback.
func (db *DB) InsertAuthEvent(ctx context.Context, e AuthEvent) error {
	presented := marshalJSONArray(e.Presented)
	decisions := marshalJSONArray(e.Decisions)
	_, err := db.ExecContext(ctx, authEventInsertSQL,
		e.RequestID, e.RemoteAddr, e.Method, e.Path, e.FinalKind, e.FinalID, e.FinalAdmin, e.FinalIdentity,
		e.Rejected, e.RejectReason, e.MultiIdentity, e.Enriched, presented, decisions)
	if err != nil {
		return fmt.Errorf("insert auth_event: %w", err)
	}
	return nil
}

// marshalJSONArray serializes v to JSON, defaulting to an empty array on nil or
// error so the NOT NULL jsonb columns always receive valid JSON.
func marshalJSONArray(v any) []byte {
	if v == nil {
		return []byte("[]")
	}
	raw, err := json.Marshal(v)
	if err != nil || len(raw) == 0 || string(raw) == "null" {
		return []byte("[]")
	}
	return raw
}
