package secdb

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestUpdateNowCallsHookAfterSuccessfulSync(t *testing.T) {
	m := NewManager("printf sync-ok", time.Hour)
	called := make(chan string, 1)
	m.SetUpdateHook(func(reason string) {
		called <- reason
	})

	if err := m.UpdateNowWithReason(context.Background(), "manual test"); err != nil {
		t.Fatalf("UpdateNowWithReason failed: %v", err)
	}

	select {
	case got := <-called:
		if got != "manual test" {
			t.Fatalf("hook reason = %q", got)
		}
	default:
		t.Fatal("expected update hook after successful sync")
	}
	status := m.Status()
	if status["status"] != "ok" {
		t.Fatalf("status = %#v", status)
	}
	if status["last_output"] != "sync-ok" {
		t.Fatalf("last output = %#v", status["last_output"])
	}
	if ts, ok := status["last_attempt"].(time.Time); !ok || ts.IsZero() {
		t.Fatalf("last attempt should be recorded after successful sync: %#v", status["last_attempt"])
	}
	if ts, ok := status["last_sync"].(time.Time); !ok || ts.IsZero() {
		t.Fatalf("last sync should be recorded after successful sync: %#v", status["last_sync"])
	}
}

func TestUpdateNowDoesNotCallHookAfterFailedSync(t *testing.T) {
	m := NewManager("printf sync-failed >&2; exit 7", time.Hour)
	called := make(chan string, 1)
	failed := make(chan string, 1)
	m.SetUpdateHook(func(reason string) {
		called <- reason
	})
	m.SetFailureHook(func(reason string, err error) {
		failed <- reason + ": " + err.Error()
	})

	if err := m.UpdateNowWithReason(context.Background(), "failed test"); err == nil {
		t.Fatal("expected sync failure")
	}

	select {
	case got := <-called:
		t.Fatalf("hook should not be called after failed sync, got %q", got)
	default:
	}
	select {
	case got := <-failed:
		if !strings.Contains(got, "failed test:") || !strings.Contains(got, "sync-failed") {
			t.Fatalf("failure hook should include reason and bounded output, got %q", got)
		}
	default:
		t.Fatal("expected failure hook after failed sync")
	}
	status := m.Status()
	if status["status"] != "failed" {
		t.Fatalf("status = %#v", status)
	}
	if status["last_output"] != "sync-failed" {
		t.Fatalf("last output = %#v", status["last_output"])
	}
	if got, _ := status["last_error"].(string); !strings.Contains(got, "sync-failed") {
		t.Fatalf("last error should include command output, got %q", got)
	}
	if ts, ok := status["last_attempt"].(time.Time); !ok || ts.IsZero() {
		t.Fatalf("last attempt should be recorded after failed sync: %#v", status["last_attempt"])
	}
	publicStatus := m.PublicStatus()
	if _, ok := publicStatus["last_output"]; ok {
		t.Fatalf("public status must not expose command output: %#v", publicStatus)
	}
	if _, ok := publicStatus["last_error"]; ok {
		t.Fatalf("public status must not expose command errors: %#v", publicStatus)
	}
	if _, ok := publicStatus["last_attempt"].(time.Time); !ok {
		t.Fatalf("public status should expose last attempt timestamp: %#v", publicStatus)
	}
}

func TestUpdateNowFailureHookCoversConfigurationErrors(t *testing.T) {
	m := NewManager("", time.Hour)
	failed := make(chan string, 1)
	m.SetFailureHook(func(reason string, err error) {
		failed <- reason + ": " + err.Error()
	})

	if err := m.UpdateNowWithReason(context.Background(), "manual test"); err == nil {
		t.Fatal("expected configuration error")
	}

	select {
	case got := <-failed:
		if !strings.Contains(got, "manual test") || !strings.Contains(got, "not configured") {
			t.Fatalf("failure hook = %q", got)
		}
	default:
		t.Fatal("expected failure hook for configuration error")
	}
}

func TestStartRunsStartupSyncWhenEnabled(t *testing.T) {
	m := NewManager("printf startup-ok", 0)
	m.SetSyncOnStart(true)
	called := make(chan string, 1)
	m.SetUpdateHook(func(reason string) {
		called <- reason
	})

	m.Start(context.Background())

	select {
	case got := <-called:
		if got != "security-db startup sync" {
			t.Fatalf("startup hook reason = %q", got)
		}
	default:
		t.Fatal("expected startup sync hook")
	}
	status := m.Status()
	if status["status"] != "ok" || status["last_output"] != "startup-ok" {
		t.Fatalf("startup sync status = %#v", status)
	}
}

func TestStartSkipsStartupSyncWhenDisabled(t *testing.T) {
	m := NewManager("printf startup-ok", 0)
	called := make(chan string, 1)
	m.SetUpdateHook(func(reason string) {
		called <- reason
	})

	m.Start(context.Background())

	select {
	case got := <-called:
		t.Fatalf("startup sync should be disabled by default, got %q", got)
	default:
	}
	if status := m.Status(); status["status"] != "never" {
		t.Fatalf("status = %#v", status)
	}
}

func TestStartExposesNextPeriodicSync(t *testing.T) {
	m := NewManager("printf periodic-ok", time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		m.Start(ctx)
		close(done)
	}()

	deadline := time.Now().Add(time.Second)
	for {
		status := m.Status()
		if next, ok := status["next_sync"].(time.Time); ok && !next.IsZero() {
			cancel()
			<-done
			return
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("next periodic sync was not recorded: %#v", status)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestStartUsesPersistedLastSyncHintForInitialPeriodicSchedule(t *testing.T) {
	m := NewManager("printf periodic-ok", time.Hour)
	m.SetLastSyncHint(time.Now().Add(-2 * time.Hour))
	called := make(chan string, 1)
	m.SetUpdateHook(func(reason string) {
		called <- reason
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		m.Start(ctx)
		close(done)
	}()

	select {
	case got := <-called:
		if got != "security-db periodic sync" {
			t.Fatalf("periodic hook reason = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("expected immediate periodic sync for expired persisted freshness")
	}
	cancel()
	<-done
}

func TestStartKeepsFuturePersistedLastSyncSchedule(t *testing.T) {
	m := NewManager("printf periodic-ok", time.Hour)
	hint := time.Now().Add(-30 * time.Minute)
	m.SetLastSyncHint(hint)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		m.Start(ctx)
		close(done)
	}()

	deadline := time.Now().Add(time.Second)
	for {
		status := m.Status()
		if next, ok := status["next_sync"].(time.Time); ok && !next.IsZero() {
			cancel()
			<-done
			if next.Before(hint.Add(time.Hour).Add(-100*time.Millisecond)) || next.After(hint.Add(time.Hour).Add(100*time.Millisecond)) {
				t.Fatalf("next sync = %v, want near %v", next, hint.Add(time.Hour))
			}
			return
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("next periodic sync was not recorded: %#v", status)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSyncOutputIsTailTruncated(t *testing.T) {
	t.Setenv("BONGSU_SECURITY_DB_SYNC_OUTPUT_MAX_BYTES", "6")
	if got := trimCommandOutput("0123456789", maxSyncOutputBytes()); got != "456789" {
		t.Fatalf("trimmed output = %q", got)
	}
}
