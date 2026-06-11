package api

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/ziozzang/bongsu/internal/server/db"
)

// handleGetScanActivity serves the per-day scan activity timeline for the
// dashboard (scans run, hosts reporting, packages ingested, status mix).
func (s *Server) handleGetScanActivity(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		if v, err := strconv.Atoi(d); err == nil && v > 0 {
			days = v
		}
	}
	if days > 365 {
		days = 365
	}
	activity, err := s.db.GetScanActivity(r.Context(), days)
	if err != nil {
		log.Printf("scan activity: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if activity == nil {
		activity = []db.ScanActivityRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"days": days, "items": activity})
}

func (s *Server) handleGetVulnTrends(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		if v, err := strconv.Atoi(d); err == nil && v > 0 {
			days = v
		}
	}
	if days > 365 {
		days = 365
	}
	hostID := r.URL.Query().Get("host_id")
	trends, err := s.db.GetVulnTrends(r.Context(), days, hostID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if trends == nil {
		trends = []db.VulnTrendRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": trends})
}

func (s *Server) handleGetVulnTrendSummary(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	summary, err := s.db.GetVulnTrendSummary(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) startVulnTrendSnapshotter() {
	interval := time.Duration(envInt("BONGSU_VULN_TREND_SNAPSHOT_INTERVAL_HOURS", 24)) * time.Hour
	if interval < time.Hour {
		interval = time.Hour
	}
	go func() {
		for {
			time.Sleep(interval)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			s.runTrendSnapshotAllHosts(ctx)
			s.db.CleanupOldTrendSnapshots(ctx)
			cancel()
		}
	}()
	log.Printf("Vuln trend snapshotter started (interval: %s)", interval)
}

func (s *Server) runTrendSnapshotAllHosts(ctx context.Context) {
	hosts, err := s.db.ListHosts(ctx)
	if err != nil {
		log.Printf("trend snapshot list hosts: %v", err)
		return
	}
	for _, h := range hosts {
		if err := s.db.RecordVulnTrendSnapshot(ctx, h.ID, ""); err != nil {
			log.Printf("trend snapshot host %s: %v", h.ID, err)
		}
	}
}
