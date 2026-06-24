package api

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/ziozzang/bongsu/internal/server/cvematch"
	"github.com/ziozzang/bongsu/internal/shared/models"
)

// handleExportHostVEX emits the host's analysis decisions as a CycloneDX VEX
// document, so suppressions/triage made in Bongsu are portable to other tools.
func (s *Server) handleExportHostVEX(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	hostID := r.PathValue("id")
	triages, err := s.db.ListVulnerabilityTriageForExport(r.Context(), hostID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	stmts := make([]cvematch.VEXStatement, 0, len(triages))
	for _, t := range triages {
		stmts = append(stmts, cvematch.VEXStatement{
			VulnerabilityID: t.VulnerabilityID,
			PkgName:         t.PkgName,
			Status:          t.Status,
			Reason:          t.Reason,
			Detail:          t.Comment,
		})
	}
	doc, err := cvematch.BuildCycloneDXVEX(stmts, cvematch.NowRFC3339())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not build VEX")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\"vex-"+hostID+".cdx.json\"")
	_, _ = w.Write(doc)
}

// handleImportVEX applies a CycloneDX VEX document's analysis decisions to
// Bongsu triage. Optional ?host=<id> scopes the decisions to one host;
// otherwise they are applied globally (host_id=”). Admin only.
func (s *Server) handleImportVEX(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAgentReportBytes())
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "vex too large")
			return
		}
		writeError(w, http.StatusBadRequest, "could not read body")
		return
	}
	stmts, err := cvematch.ParseCycloneDXVEX(data)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CycloneDX VEX: "+err.Error())
		return
	}
	hostID := strings.TrimSpace(r.URL.Query().Get("host"))
	actor := s.actorID(r)

	applied := 0
	var failures []string
	ctx := r.Context()
	for _, st := range stmts {
		pkgName := st.PkgName
		if pkgName == "" && st.ComponentPURL != "" {
			if name, _, _, _, _, ok := cvematch.ParsePURL(st.ComponentPURL); ok {
				pkgName = name
			}
		}
		t := &models.VulnerabilityTriage{
			ID:              uuid.New().String(),
			VulnerabilityID: st.VulnerabilityID,
			HostID:          hostID,
			PkgName:         pkgName,
			Status:          st.Status,
			Reason:          st.Reason,
			Comment:         st.Detail,
			UpdatedBy:       actor,
		}
		if err := s.db.UpsertVulnerabilityTriage(ctx, t); err != nil {
			failures = append(failures, st.VulnerabilityID+": "+err.Error())
			continue
		}
		applied++
	}
	s.audit(r, "vex.import", "host", hostID, "success", map[string]any{"applied": applied, "statements": len(stmts)})

	resp := map[string]any{"statements": len(stmts), "applied": applied}
	if len(failures) > 0 {
		resp["failures"] = failures
	}
	writeJSON(w, http.StatusOK, resp)
}
