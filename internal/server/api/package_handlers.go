package api

import (
	"log"
	"net/http"

	"github.com/ziozzang/bongsu/internal/server/db"
	"github.com/ziozzang/bongsu/internal/shared/models"
)

func (s *Server) handlePackageVulns(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	pkgID := r.PathValue("id")
	ctx := r.Context()
	hostID, err := s.db.GetPackageHostID(ctx, pkgID)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !s.canReadHost(r, hostID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	vulns, err := s.db.GetVulnsByPackageID(ctx, pkgID)
	if err != nil {
		log.Printf("package vulns: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if vulns == nil {
		vulns = []models.Vulnerability{}
	}
	writeJSON(w, http.StatusOK, vulns)
}

func (s *Server) handleSearchPackages(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	scope := s.accessScope(r)
	if scope.Empty() {
		writeJSON(w, http.StatusOK, map[string]any{"items": []models.Package{}, "total": 0})
		return
	}
	hostID := r.URL.Query().Get("host_id")
	if hostID != "" && !scope.CanReadHost(hostID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	f := db.PackageFilter{
		HostID:     hostID,
		HostIDs:    scope.HostIDs,
		Container:  r.URL.Query().Get("container"),
		PkgType:    r.URL.Query().Get("pkg_type"),
		Source:     r.URL.Query().Get("source"),
		NameSearch: r.URL.Query().Get("q"),
		SortBy:     r.URL.Query().Get("sort_by"),
		SortDesc:   r.URL.Query().Get("sort_order") == "desc",
		Limit:      limitParam(r, 100),
		Offset:     offsetParam(r),
	}

	pkgs, total, err := s.db.SearchPackages(ctx, f)
	if err != nil {
		log.Printf("search packages: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items": pkgs,
		"total": total,
	})
}

func (s *Server) handleSearchContainers(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	scope := s.accessScope(r)
	if scope.Empty() {
		writeJSON(w, http.StatusOK, map[string]any{"items": []models.ContainerAsset{}, "total": 0})
		return
	}
	hostID := r.URL.Query().Get("host_id")
	if hostID != "" && !scope.CanReadHost(hostID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	f := db.ContainerFilter{
		HostID:     hostID,
		HostIDs:    scope.HostIDs,
		Runtime:    r.URL.Query().Get("runtime"),
		State:      r.URL.Query().Get("state"),
		ImageName:  r.URL.Query().Get("image"),
		NameSearch: r.URL.Query().Get("q"),
		SortBy:     r.URL.Query().Get("sort_by"),
		SortDesc:   r.URL.Query().Get("sort_order") == "desc",
		Limit:      limitParam(r, 100),
		Offset:     offsetParam(r),
	}

	containers, total, err := s.db.SearchContainers(ctx, f)
	if err != nil {
		log.Printf("search containers: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items": containers,
		"total": total,
	})
}

func (s *Server) handlePackageFilters(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	scope := s.accessScope(r)
	if scope.Empty() {
		writeJSON(w, http.StatusOK, &db.FilterOptions{})
		return
	}

	opts, err := s.db.GetFilterOptions(ctx, scopeHostFilter(scope, scope.HostIDs))
	if err != nil {
		log.Printf("filter options: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, opts)
}
