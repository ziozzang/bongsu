package live

import (
	"bytes"
	"strings"
	"testing"
)

func TestClientFilterMatch(t *testing.T) {
	global := &Event{Type: EventKPISnapshot}
	hostA := &Event{Type: EventScanCompleted, Payload: map[string]any{"host_id": "A"}}
	hostB := &Event{Type: EventScanCompleted, Payload: map[string]any{"host_id": "B"}}

	t.Run("all-hosts sees everything", func(t *testing.T) {
		f := ClientFilter{AllHosts: true}
		if !f.Match(global) || !f.Match(hostA) || !f.Match(hostB) {
			t.Fatal("admin/all-hosts filter must match every event")
		}
	})

	t.Run("host-scoped sees only allowed hosts + globals", func(t *testing.T) {
		f := ClientFilter{HostIDs: map[string]bool{"A": true}}
		if !f.Match(global) {
			t.Fatal("global (host-less) events must reach a scoped viewer")
		}
		if !f.Match(hostA) {
			t.Fatal("allowed host event must match")
		}
		if f.Match(hostB) {
			t.Fatal("a host outside the scope must NOT match")
		}
	})

	t.Run("type filter narrows", func(t *testing.T) {
		f := ClientFilter{AllHosts: true, Types: map[EventType]bool{EventScanCompleted: true}}
		if f.Match(global) {
			t.Fatal("kpi.snapshot must be filtered out when only scan.completed is requested")
		}
		if !f.Match(hostA) {
			t.Fatal("scan.completed must pass the type filter")
		}
	})
}

func TestHubPublishAndFilter(t *testing.T) {
	h := NewHub(100, 0)
	admin := NewClient(ClientFilter{AllHosts: true}, 8)
	scoped := NewClient(ClientFilter{HostIDs: map[string]bool{"A": true}}, 8)
	if !h.Subscribe(admin) || !h.Subscribe(scoped) {
		t.Fatal("subscribe failed")
	}

	id := h.Publish(&Event{Type: EventScanCompleted, Payload: map[string]any{"host_id": "B"}})
	if id != 1 {
		t.Fatalf("first event id must be 1, got %d", id)
	}
	// admin receives the host-B event; scoped (only host A) does not.
	select {
	case e := <-admin.C():
		if e.ID != 1 {
			t.Fatalf("admin got wrong event id %d", e.ID)
		}
	default:
		t.Fatal("admin must receive the host-B event")
	}
	select {
	case e := <-scoped.C():
		t.Fatalf("scoped viewer must NOT receive a host-B event, got %+v", e)
	default:
	}

	// a global event reaches both
	h.Publish(&Event{Type: EventKPISnapshot})
	if len(admin.C()) != 1 || len(scoped.C()) != 1 {
		t.Fatalf("global event must reach both clients (admin=%d scoped=%d)", len(admin.C()), len(scoped.C()))
	}
}

func TestHubDropsOnFullBuffer(t *testing.T) {
	h := NewHub(100, 0)
	slow := NewClient(ClientFilter{AllHosts: true}, 2) // tiny buffer, never drained
	h.Subscribe(slow)
	for i := 0; i < 5; i++ {
		h.Publish(&Event{Type: EventKPISnapshot})
	}
	if slow.Dropped() == 0 {
		t.Fatal("a client that never drains must accumulate drops, not block the hub")
	}
	if got := h.Metrics().EventsDropped; got == 0 {
		t.Fatalf("hub must count drops, got %d", got)
	}
}

func TestHubReplay(t *testing.T) {
	h := NewHub(100, 0)
	for i := 0; i < 5; i++ {
		h.Publish(&Event{Type: EventKPISnapshot})
	}
	// reconnect having seen id 2 -> replay 3,4,5
	got := h.Replay(2, ClientFilter{AllHosts: true}, 500)
	if len(got) != 3 || got[0].ID != 3 || got[2].ID != 5 {
		t.Fatalf("replay since 2 must return events 3..5, got %+v", got)
	}
	// replay respects the filter
	h.Publish(&Event{Type: EventScanCompleted, Payload: map[string]any{"host_id": "B"}})
	scoped := h.Replay(0, ClientFilter{HostIDs: map[string]bool{"A": true}}, 500)
	for _, e := range scoped {
		if e.Type == EventScanCompleted {
			t.Fatal("replay must apply the host scope filter")
		}
	}
}

func TestHubConnectionCap(t *testing.T) {
	h := NewHub(100, 1)
	if !h.Subscribe(NewClient(ClientFilter{AllHosts: true}, 8)) {
		t.Fatal("first subscribe under the cap must succeed")
	}
	if h.Subscribe(NewClient(ClientFilter{AllHosts: true}, 8)) {
		t.Fatal("subscribe past the cap must be rejected")
	}
}

func TestWriteEventSSEFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteEvent(&buf, &Event{ID: 7, Type: EventScanCompleted, Payload: map[string]any{"host_id": "A"}}); err != nil {
		t.Fatalf("write: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"id: 7\n", "event: scan.completed\n", "data: {", "\"host_id\":\"A\"", "\n\n"} {
		if !strings.Contains(out, want) {
			t.Fatalf("SSE output missing %q in:\n%s", want, out)
		}
	}
}
