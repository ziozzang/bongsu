// Package live implements the dynamic-monitoring substrate: an in-memory
// broadcaster Hub that fans events out to connected SSE clients, the event
// taxonomy, and the SSE wire encoding. It is deliberately decoupled from the api
// package — clients carry a ClientFilter (resolved from a Principal by the api
// layer), not the Principal itself, so there is no import cycle.
package live

import "time"

// EventType enumerates the live monitoring events. Names mirror the notification
// trigger events where they overlap.
type EventType string

const (
	EventScanStarted    EventType = "scan.started"
	EventScanCompleted  EventType = "scan.completed"
	EventScanFailed     EventType = "scan.failed"
	EventFindingNewCrit EventType = "finding.new_critical"
	EventFindingNewHigh EventType = "finding.new_high"
	EventAgentOnline    EventType = "agent.online"
	EventAgentOffline   EventType = "agent.offline"
	EventSecDBUpdated   EventType = "secdb.updated"
	EventRescanProgress EventType = "rescan.progress"
	EventSLABreach      EventType = "sla.breach"
	EventKPISnapshot    EventType = "kpi.snapshot"
)

// Severity levels for an event (used for UI emphasis/toasts).
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Event is one live monitoring event. ID is a monotonic per-process sequence the
// Hub assigns at publish time; clients use it as the SSE id for Last-Event-ID
// replay. Payload is free-form; a "host_id" key (when present) scopes the event
// to a host for RBAC filtering.
type Event struct {
	ID         int64          `json:"id"`
	Type       EventType      `json:"type"`
	ScopeKey   string         `json:"scope_key,omitempty"`
	Payload    map[string]any `json:"payload,omitempty"`
	Severity   string         `json:"severity,omitempty"`
	OccurredAt time.Time      `json:"occurred_at"`
}

// hostID returns the event's host scope ("" if it is a global event).
func (e *Event) hostID() string {
	if e.Payload == nil {
		return ""
	}
	switch v := e.Payload["host_id"].(type) {
	case string:
		return v
	}
	return ""
}

// ClientFilter decides which events a subscriber receives. It is derived from the
// caller's Principal by the api layer. Admin (or all-host access) sees every
// event; otherwise host-scoped events are gated by HostIDs while global events
// (no host_id) are always visible to authenticated viewers. A non-empty Types
// set further narrows to the requested event types.
type ClientFilter struct {
	AllHosts bool
	HostIDs  map[string]bool
	Types    map[EventType]bool
}

// Match reports whether an event should be delivered to a client with this filter.
func (f ClientFilter) Match(e *Event) bool {
	if len(f.Types) > 0 && !f.Types[e.Type] {
		return false
	}
	if f.AllHosts {
		return true
	}
	if hid := e.hostID(); hid != "" {
		return f.HostIDs[hid]
	}
	// Global events (no host scope) are visible to any authenticated viewer.
	return true
}
