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
}

func TestUpdateNowDoesNotCallHookAfterFailedSync(t *testing.T) {
	m := NewManager("printf sync-failed >&2; exit 7", time.Hour)
	called := make(chan string, 1)
	m.SetUpdateHook(func(reason string) {
		called <- reason
	})

	if err := m.UpdateNowWithReason(context.Background(), "failed test"); err == nil {
		t.Fatal("expected sync failure")
	}

	select {
	case got := <-called:
		t.Fatalf("hook should not be called after failed sync, got %q", got)
	default:
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
	publicStatus := m.PublicStatus()
	if _, ok := publicStatus["last_output"]; ok {
		t.Fatalf("public status must not expose command output: %#v", publicStatus)
	}
	if _, ok := publicStatus["last_error"]; ok {
		t.Fatalf("public status must not expose command errors: %#v", publicStatus)
	}
}

func TestSyncOutputIsTailTruncated(t *testing.T) {
	t.Setenv("BONGSU_SECURITY_DB_SYNC_OUTPUT_MAX_BYTES", "6")
	if got := trimCommandOutput("0123456789", maxSyncOutputBytes()); got != "456789" {
		t.Fatalf("trimmed output = %q", got)
	}
}
