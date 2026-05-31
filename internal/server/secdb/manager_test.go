package secdb

import (
	"context"
	"testing"
	"time"
)

func TestUpdateNowCallsHookAfterSuccessfulSync(t *testing.T) {
	m := NewManager("true", time.Hour)
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
}

func TestUpdateNowDoesNotCallHookAfterFailedSync(t *testing.T) {
	m := NewManager("false", time.Hour)
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
}
