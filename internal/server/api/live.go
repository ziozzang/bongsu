package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ziozzang/bongsu/internal/server/live"
)

// handleEventStream serves the live monitoring feed as Server-Sent Events. The
// caller must be an authenticated viewer (or higher); the events delivered are
// filtered to the caller's RBAC host scope. A reconnecting browser resumes via
// Last-Event-ID; a ?types= filter narrows to specific event types.
func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
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
