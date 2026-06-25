package api

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/ziozzang/bongsu/internal/server/db"
)

// handleUploadExposureCatalog ingests a bumblebee-format exposure catalog
// (known-compromised package releases). The raw JSON body is the catalog;
// ?source=<name> identifies the replaceable source slot (defaults to the
// catalog's schema-derived name), ?display=<label> is a human label. Admin only.
func (s *Server) handleUploadExposureCatalog(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAgentReportBytes())
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "catalog too large")
			return
		}
		writeError(w, http.StatusBadRequest, "could not read body")
		return
	}
	cat, entries, err := db.ParseBumblebeeCatalog(data)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(entries) == 0 {
		writeError(w, http.StatusBadRequest, "catalog had no matchable entries (need entries with enumerated versions)")
		return
	}
	source := strings.TrimSpace(r.URL.Query().Get("source"))
	if source == "" {
		writeError(w, http.StatusBadRequest, "source query param required (the replaceable catalog slot name)")
		return
	}
	display := strings.TrimSpace(r.URL.Query().Get("display"))
	if display == "" {
		display = source
	}
	schemaVer := cat.SchemaVersion
	if schemaVer == "" {
		schemaVer = "0.1.0"
	}

	stored, err := s.db.UpsertExposureCatalog(r.Context(), source, display, s.actorID(r), schemaVer, data, entries)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not store catalog: "+err.Error())
		return
	}
	s.audit(r, "exposure_catalog.upload", "exposure_catalog", source, "success",
		map[string]any{"entries": stored, "raw_entries": len(cat.Entries)})
	writeJSON(w, http.StatusOK, map[string]any{
		"source":          source,
		"stored_entries":  stored,
		"catalog_entries": len(cat.Entries),
		"schema_version":  schemaVer,
	})
}

// handleListExposureCatalogs lists uploaded catalog sources.
func (s *Server) handleListExposureCatalogs(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	sources, err := s.db.ListExposureCatalogSources(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	if sources == nil {
		sources = []db.ExposureCatalogSource{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": sources})
}

// handleDeleteExposureCatalog removes a catalog source (and its entries). Admin only.
func (s *Server) handleDeleteExposureCatalog(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	ok, err := s.db.DeleteExposureCatalogSource(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "catalog not found")
		return
	}
	s.audit(r, "exposure_catalog.delete", "exposure_catalog", r.PathValue("id"), "success", nil)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}
