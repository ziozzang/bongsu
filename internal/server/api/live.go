package api

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ziozzang/bongsu/internal/server/live"
)

// writeLiveMetrics emits the live-monitoring channel gauges/counters into the
// hand-rolled /metrics exposition.
func (s *Server) writeLiveMetrics(b *strings.Builder) {
	if s.live == nil {
		return
	}
	m := s.live.Metrics()
	writePromGauge(b, "bongsu_live_connections_active", nil, float64(m.ActiveConnections))
	writePromCounter(b, "bongsu_live_connections_total", nil, float64(m.ConnectionsTotal))
	writePromCounter(b, "bongsu_live_events_sent_total", nil, float64(m.EventsSent))
	writePromCounter(b, "bongsu_live_events_dropped_total", nil, float64(m.EventsDropped))
	writePromCounter(b, "bongsu_live_events_replayed_total", nil, float64(m.EventsReplayed))
}

// handleEventStream serves the live monitoring feed as Server-Sent Events. The
// caller must be an authenticated viewer (or higher); the events delivered are
// filtered to the caller's RBAC host scope. A reconnecting browser resumes via
// Last-Event-ID; a ?types= filter narrows to specific event types.
func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	// EventSource cannot set request headers, so accept the caller's token via a
	// query parameter and inject it into the header slots the Principal resolver
	// reads (X-API-Key for API keys/DB tokens, Authorization for DB/session
	// tokens). Injected before the first s.principal() call so the per-request
	// cache resolves with it.
	if tok := strings.TrimSpace(r.URL.Query().Get("access_token")); tok != "" {
		if r.Header.Get("X-API-Key") == "" {
			r.Header.Set("X-API-Key", tok)
		}
		if r.Header.Get("Authorization") == "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
	}
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	if s.live == nil {
		writeError(w, http.StatusServiceUnavailable, "live monitoring disabled")
		return
	}

	filter := s.liveFilter(r)
	client := live.NewClient(filter, envInt("BONGSU_LIVE_BUFFER", 64))
	if !s.live.Subscribe(client) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusServiceUnavailable, "too many live connections")
		return
	}
	defer s.live.Unsubscribe(client)

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no") // disable proxy buffering (nginx)
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Replay anything missed since the client's last seen id.
	if since := liveSinceID(r); since > 0 {
		for _, e := range s.live.Replay(since, filter, envInt("BONGSU_LIVE_REPLAY_MAX", 500)) {
			ev := e
			if live.WriteEvent(w, &ev) != nil {
				return
			}
		}
		flusher.Flush()
	}

	ctx := r.Context()
	heartbeat := time.NewTicker(time.Duration(envInt("BONGSU_LIVE_HEARTBEAT_SECONDS", 15)) * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-client.C():
			if !ok {
				return // hub shut the client down
			}
			if live.WriteEvent(w, e) != nil {
				return
			}
			flusher.Flush()
		case <-heartbeat.C:
			if live.WriteHeartbeat(w) != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// liveFilter derives the client's event filter from its RBAC host scope and the
// optional ?types= query parameter.
func (s *Server) liveFilter(r *http.Request) live.ClientFilter {
	f := live.ClientFilter{}
	scope := s.accessScope(r)
	if scope.All {
		f.AllHosts = true
	} else {
		f.HostIDs = make(map[string]bool, len(scope.HostIDs))
		for _, id := range scope.HostIDs {
			f.HostIDs[id] = true
		}
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("types")); raw != "" {
		f.Types = map[live.EventType]bool{}
		for _, t := range strings.Split(raw, ",") {
			if t = strings.TrimSpace(t); t != "" {
				f.Types[live.EventType(t)] = true
			}
		}
	}
	return f
}

// liveSinceID reads the resume point from the Last-Event-ID header (browser
// reconnect) or an explicit ?since= query parameter.
func liveSinceID(r *http.Request) int64 {
	raw := r.Header.Get("Last-Event-ID")
	if raw == "" {
		raw = r.URL.Query().Get("since")
	}
	id, _ := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	return id
}

// publishLive emits a live event to subscribers, if the hub is running. Safe to
// call from request handlers and background loops; never blocks.
func (s *Server) publishLive(eventType live.EventType, severity string, payload map[string]any) {
	if s.live == nil {
		return
	}
	s.live.Publish(&live.Event{Type: eventType, Severity: severity, Payload: payload})
}

// StartLivenessMonitor polls host last-seen on an interval and emits an
// agent.online / agent.offline live event whenever a host's computed agent
// status transitions. The status is derived per request elsewhere; this loop
// turns the level into an edge so the dashboard can alert on the moment an agent
// goes dark (or recovers) without the client polling. Run as a background
// goroutine; returns when ctx is cancelled.
func (s *Server) StartLivenessMonitor(ctx context.Context) {
	interval := time.Duration(envInt("BONGSU_LIVENESS_POLL_SECONDS", 60)) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	prev := map[string]string{} // host ID -> last observed agent status
	primed := false             // skip emitting on the first sweep (no prior state)
	log.Printf("agent liveness monitor started (interval=%s)", interval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			hosts, err := s.db.ListHosts(ctx)
			if err != nil {
				log.Printf("liveness monitor list hosts: %v", err)
				continue
			}
			now := time.Now()
			for i := range hosts {
				h := &hosts[i]
				applyAgentStatus(h, now)
				old, seen := prev[h.ID]
				prev[h.ID] = h.AgentStatus
				if !primed || !seen || old == h.AgentStatus {
					continue
				}
				eventType, severity := live.EventAgentOffline, live.SeverityWarning
				if h.AgentStatus == "online" {
					eventType, severity = live.EventAgentOnline, live.SeverityInfo
				}
				s.publishLive(eventType, severity, map[string]any{
					"host_id":         h.ID,
					"hostname":        h.Hostname,
					"prev_status":     old,
					"new_status":      h.AgentStatus,
					"last_seen_age_s": h.LastSeenAgeS,
				})
			}
			primed = true
		}
	}
}
