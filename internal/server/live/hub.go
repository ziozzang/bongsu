package live

import (
	"sync"
	"sync/atomic"
	"time"
)

// Client is one connected subscriber. Events are delivered on C; when the buffer
// is full the Hub drops (at-most-once for the live UI — a dropped client is
// resynced by the next kpi.snapshot) and bumps the drop counters.
type Client struct {
	Filter  ClientFilter
	ch      chan *Event
	dropped atomic.Uint64
}

// NewClient creates a subscriber with the given filter and channel buffer.
func NewClient(filter ClientFilter, buffer int) *Client {
	if buffer <= 0 {
		buffer = 64
	}
	return &Client{Filter: filter, ch: make(chan *Event, buffer)}
}

// C is the receive side of the client's event channel.
func (c *Client) C() <-chan *Event { return c.ch }

// Dropped reports how many events this client missed due to a full buffer.
func (c *Client) Dropped() uint64 { return c.dropped.Load() }

// Hub is the in-memory broadcaster. One per process; safe for concurrent use.
// It keeps a bounded ring of recent events so a reconnecting client can replay
// what it missed via Last-Event-ID.
type Hub struct {
	mu       sync.RWMutex
	clients  map[*Client]struct{}
	ring     []Event
	ringCap  int
	nextID   atomic.Int64
	maxConns int

	// metrics (exposed via accessors for the hand-rolled /metrics endpoint)
	active     atomic.Int64
	connsTotal atomic.Uint64
	sent       atomic.Uint64
	dropped    atomic.Uint64
	replayed   atomic.Uint64
	now        func() time.Time
}

// NewHub creates a hub retaining ringCap recent events and accepting at most
// maxConns concurrent clients (0 = unlimited).
func NewHub(ringCap, maxConns int) *Hub {
	if ringCap <= 0 {
		ringCap = 1000
	}
	return &Hub{
		clients:  map[*Client]struct{}{},
		ring:     make([]Event, 0, ringCap),
		ringCap:  ringCap,
		maxConns: maxConns,
		now:      time.Now,
	}
}

// Subscribe registers a client. It returns false if the connection cap is
// reached (the caller should reject with 503).
func (h *Hub) Subscribe(c *Client) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.maxConns > 0 && len(h.clients) >= h.maxConns {
		return false
	}
	h.clients[c] = struct{}{}
	h.active.Store(int64(len(h.clients)))
	h.connsTotal.Add(1)
	return true
}

// Unsubscribe removes a client and closes its channel.
func (h *Hub) Unsubscribe(c *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		close(c.ch)
		h.active.Store(int64(len(h.clients)))
	}
}

// Publish stamps an event with a monotonic ID + timestamp, records it in the
// replay ring, and fans it out to matching clients (non-blocking). It returns
// the assigned ID.
func (h *Hub) Publish(e *Event) int64 {
	id := h.nextID.Add(1)
	e.ID = id
	if e.OccurredAt.IsZero() {
		e.OccurredAt = h.now()
	}
	h.mu.Lock()
	if len(h.ring) >= h.ringCap {
		copy(h.ring, h.ring[1:])
		h.ring[len(h.ring)-1] = *e
	} else {
		h.ring = append(h.ring, *e)
	}
	clients := make([]*Client, 0, len(h.clients))
	for c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.Unlock()

	for _, c := range clients {
		if !c.Filter.Match(e) {
			continue
		}
		select {
		case c.ch <- e:
			h.sent.Add(1)
		default:
			c.dropped.Add(1)
			h.dropped.Add(1)
		}
	}
	return id
}

// Replay returns up to max events newer than sinceID that match the filter, for
// a reconnecting client. Events older than the ring are unavailable (the client
// resyncs via the next snapshot).
func (h *Hub) Replay(sinceID int64, f ClientFilter, max int) []Event {
	if max <= 0 {
		max = 500
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]Event, 0, 16)
	for i := range h.ring {
		e := h.ring[i]
		if e.ID <= sinceID {
			continue
		}
		if !f.Match(&e) {
			continue
		}
		out = append(out, e)
		if len(out) >= max {
			break
		}
	}
	h.replayed.Add(uint64(len(out)))
	return out
}

// LastID returns the highest event ID published so far.
func (h *Hub) LastID() int64 { return h.nextID.Load() }

// Metrics snapshots the hub counters for the /metrics endpoint.
func (h *Hub) Metrics() HubMetrics {
	return HubMetrics{
		ActiveConnections: h.active.Load(),
		ConnectionsTotal:  h.connsTotal.Load(),
		EventsSent:        h.sent.Load(),
		EventsDropped:     h.dropped.Load(),
		EventsReplayed:    h.replayed.Load(),
	}
}

// HubMetrics is a point-in-time snapshot of the hub's counters.
type HubMetrics struct {
	ActiveConnections int64
	ConnectionsTotal  uint64
	EventsSent        uint64
	EventsDropped     uint64
	EventsReplayed    uint64
}
