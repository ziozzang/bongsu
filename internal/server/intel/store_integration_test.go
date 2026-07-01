//go:build integration

package intel

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/server/db"
)

func openIntelDB(t *testing.T) *db.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("BONGSU_TEST_DB"))
	if dsn == "" {
		t.Skip("BONGSU_TEST_DB not set; skipping intel store integration test")
	}
	if u, err := url.Parse(dsn); err == nil {
		if name := strings.TrimPrefix(u.Path, "/"); !strings.HasSuffix(name, "_test") {
			t.Fatalf("refusing non-test database %q", name)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	database, err := db.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	// RunMigrations reads the relative migrations/ dir, so run it from repo root.
	runMigrationsFromRoot(t, ctx, database)
	// Start each intel integration test from a clean slate (these tests use fixed
	// ids, so leftover rows from a prior run would collide).
	if _, err := database.ExecContext(ctx, `TRUNCATE intel_tool_calls, intel_runs, intel_verifications, vulnerabilities,
		package_dependencies, packages, scans, hosts, access_policies, access_subjects,
		cve_kev, cve_epss, cve_affected_packages, cve_database,
		exposure_catalog_entries, exposure_catalog_sources, scan_sboms RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return database
}

func runMigrationsFromRoot(t *testing.T, ctx context.Context, database *db.DB) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := orig
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(root + "/migrations"); err == nil {
			break
		}
		root = root + "/.."
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir root: %v", err)
	}
	defer func() { _ = os.Chdir(orig) }()
	if err := database.RunMigrations(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
}

// TestStoreRunLifecycleAndAudit verifies migration 073 applies, a run
// round-trips through create -> tool calls -> finish, and the async audit writer
// persists every queued tool call.
func TestStoreRunLifecycleAndAudit(t *testing.T) {
	database := openIntelDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	st := NewStore(database, 64)

	runID, err := st.CreateRun(ctx, RunRecord{
		Scenario:       "triage",
		Goal:           "is CVE-2024-1 reachable",
		PrincipalID:    "user:alice",
		PrincipalScope: map[string]any{"admin": false, "subjects": []string{"user:alice"}},
		ToolsInjected:  []string{"query_vulns", "dependents_of"},
	})
	if err != nil || runID == "" {
		t.Fatalf("CreateRun: id=%q err=%v", runID, err)
	}

	st.RecordToolCall(runID, 1, "query_vulns", []byte(`{"host":"h1"}`), []byte(`{"count":3}`), false, 12*time.Millisecond, "")
	st.RecordToolCall(runID, 2, "dependents_of", []byte(`{"pkg":"lodash"}`), []byte(`{"dependents":["app"]}`), true, 5*time.Millisecond, "")

	if err := st.FinishRun(ctx, runID, "completed",
		map[string]any{"verdict": "reachable"}, map[string]any{"total_tokens": 16040}, ""); err != nil {
		t.Fatalf("FinishRun: %v", err)
	}
	st.Close() // drains the audit channel

	var status, verdict string
	if err := database.QueryRowContext(ctx,
		`SELECT status, COALESCE(output->>'verdict','') FROM intel_runs WHERE id=$1`, runID).Scan(&status, &verdict); err != nil {
		t.Fatalf("read run: %v", err)
	}
	if status != "completed" || verdict != "reachable" {
		t.Fatalf("run state wrong: status=%s verdict=%s", status, verdict)
	}

	var calls, truncated int
	if err := database.QueryRowContext(ctx,
		`SELECT count(*), count(*) FILTER (WHERE output_truncated) FROM intel_tool_calls WHERE run_id=$1`, runID).
		Scan(&calls, &truncated); err != nil {
		t.Fatalf("read tool calls: %v", err)
	}
	if calls != 2 || truncated != 1 {
		t.Fatalf("audit rows = %d (truncated %d), want 2 (1 truncated)", calls, truncated)
	}

	var toolsLen int
	if err := database.QueryRowContext(ctx,
		`SELECT array_length(tools_injected,1) FROM intel_runs WHERE id=$1`, runID).Scan(&toolsLen); err != nil {
		t.Fatalf("read tools_injected: %v", err)
	}
	if toolsLen != 2 {
		t.Fatalf("tools_injected length = %d, want 2", toolsLen)
	}
}

// TestStoreAuditDropCounter verifies a saturated audit buffer drops events and
// records the loss on the run rather than blocking.
func TestStoreAuditDropCounter(t *testing.T) {
	database := openIntelDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Buffer of 1, and we never start draining until after we overflow it by not
	// giving the writer a chance — push many quickly.
	st := NewStore(database, 1)
	runID, err := st.CreateRun(ctx, RunRecord{Scenario: "nl_query", PrincipalID: "user:bob"})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	// Flood: most will not fit the size-1 buffer before the writer drains them,
	// so at least some drops are expected; the exact number is timing-dependent,
	// but the counter must be persisted and tool calls must not exceed what was
	// enqueued.
	for i := 0; i < 500; i++ {
		st.RecordToolCall(runID, i, "query_vulns", []byte(`{}`), []byte(`{}`), false, 0, "")
	}
	if err := st.FinishRun(ctx, runID, "completed", nil, nil, ""); err != nil {
		t.Fatalf("FinishRun: %v", err)
	}
	st.Close()

	var dropped, calls int
	if err := database.QueryRowContext(ctx, `SELECT dropped_audits FROM intel_runs WHERE id=$1`, runID).Scan(&dropped); err != nil {
		t.Fatalf("read dropped: %v", err)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM intel_tool_calls WHERE run_id=$1`, runID).Scan(&calls); err != nil {
		t.Fatalf("count calls: %v", err)
	}
	if dropped+calls != 500 {
		t.Fatalf("dropped(%d) + persisted(%d) = %d, want 500 (no audit double-counted or lost)", dropped, calls, dropped+calls)
	}
}
