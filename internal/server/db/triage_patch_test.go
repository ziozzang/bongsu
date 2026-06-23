package db

import (
	"strings"
	"testing"
)

// The triage partial-update mask must never drop a previously-stored field that
// the caller did not send. This locks in the fix for the assignee/reason clobber
// where a status-only update wiped them.
func TestTriageUpdateSetClauses(t *testing.T) {
	has := func(clauses []string, col string) bool {
		for _, c := range clauses {
			if strings.HasPrefix(c, col+"=") {
				return true
			}
		}
		return false
	}

	t.Run("nil mask replaces every mutable field (full upsert)", func(t *testing.T) {
		c := triageUpdateSetClauses(nil)
		for _, col := range []string{"status", "reason", "comment", "assignee", "expires_at", "updated_by"} {
			if !has(c, col) {
				t.Fatalf("full upsert must set %s: %v", col, c)
			}
		}
	})

	t.Run("status-only patch preserves assignee/reason/comment/expiry", func(t *testing.T) {
		// Caller sent only a status change: mask is empty (no mutable fields present).
		c := triageUpdateSetClauses(map[string]bool{})
		// status + updated_by + updated_at are always applied.
		for _, col := range []string{"status", "updated_by", "updated_at"} {
			if !has(c, col) {
				t.Fatalf("status patch must still set %s: %v", col, c)
			}
		}
		// The masked-out fields must NOT appear, so EXCLUDED (= the empty/zero
		// values from the INSERT row) never overwrites the stored value.
		for _, col := range []string{"reason", "comment", "assignee", "expires_at"} {
			if has(c, col) {
				t.Fatalf("status-only patch must NOT clobber %s: %v", col, c)
			}
		}
	})

	t.Run("assignee-only patch updates assignee but not reason/comment", func(t *testing.T) {
		c := triageUpdateSetClauses(map[string]bool{TriageFieldAssignee: true})
		if !has(c, "assignee") {
			t.Fatalf("assignee patch must set assignee: %v", c)
		}
		for _, col := range []string{"reason", "comment", "expires_at"} {
			if has(c, col) {
				t.Fatalf("assignee patch must not touch %s: %v", col, c)
			}
		}
	})

	t.Run("explicit empty value still clears when present in the mask", func(t *testing.T) {
		// Sending "assignee":"" marks it present -> the clause IS emitted, so the
		// stored assignee is set to '' (explicit clear, distinct from omit).
		c := triageUpdateSetClauses(map[string]bool{TriageFieldAssignee: true})
		if !has(c, "assignee") {
			t.Fatalf("present assignee (even empty) must be settable: %v", c)
		}
	})
}
