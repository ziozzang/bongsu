package api

import (
	"log"
	"net/http"
	"strings"

	"github.com/ziozzang/bongsu/internal/server/db"
)

// Asset knowledge graph API.
//
// Read-only, RBAC-scoped endpoints that expose the typed semantic graph derived
// from the live inventory + CVE tables (see internal/server/db/graph.go). The UI
// uses these for topology exploration and CVE blast-radius analysis.

// graphOntology is the static schema (node types + relation types) of the graph.
// It is returned verbatim to the UI so legends, colors, and edge semantics stay
// in one place and never drift from the backend's derivation logic.
type graphNodeTypeDoc struct {
	Type        string `json:"type"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

type graphRelDoc struct {
	Rel         string `json:"rel"`
	Src         string `json:"src"`
	Dst         string `json:"dst"`
	Description string `json:"description"`
}

var graphOntologyNodeTypes = []graphNodeTypeDoc{
	{Type: "host", Label: "Host", Description: "A scanned machine or VM (latest inventory)."},
	{Type: "container", Label: "Container", Description: "A container running on a host."},
	{Type: "package", Label: "Package", Description: "An installed software package on a host or container."},
	{Type: "service", Label: "Service", Description: "A listening network port/service on a host."},
	{Type: "cve", Label: "CVE", Description: "A vulnerability identifier from the security database."},
	{Type: "group", Label: "Asset Group", Description: "A static or dynamic grouping of hosts."},
}

var graphOntologyRelations = []graphRelDoc{
	{Rel: "runs", Src: "host", Dst: "container", Description: "Host runs the container."},
	{Rel: "installs", Src: "host", Dst: "package", Description: "Host has the package installed."},
	{Rel: "contains", Src: "container", Dst: "package", Description: "Container image contains the package."},
	{Rel: "exposes", Src: "host", Dst: "service", Description: "Host exposes the listening service."},
	{Rel: "member_of", Src: "host", Dst: "group", Description: "Host is a member of the asset group."},
	{Rel: "affected_by", Src: "package", Dst: "cve", Description: "Package is affected by the CVE."},
	{Rel: "exposed_to", Src: "host", Dst: "cve", Description: "Host is exposed to the CVE via an affected package."},
}

func (s *Server) handleGraphSchema(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"node_types": graphOntologyNodeTypes,
		"relations":  graphOntologyRelations,
	})
}

func (s *Server) handleGraphOverview(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	ov, err := s.db.GraphOverviewForScope(r.Context(), s.accessScope(r))
	if err != nil {
		log.Printf("graph overview: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, ov)
}

func (s *Server) handleGraphBlastRadius(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	vulnID := strings.TrimSpace(r.URL.Query().Get("vulnerability_id"))
	if vulnID == "" {
		writeError(w, http.StatusBadRequest, "vulnerability_id is required")
		return
	}
	scope := s.accessScope(r)
	if scope.Empty() {
		writeJSON(w, http.StatusOK, map[string]any{
			"graph":  emptyNeighborhood(db.NodeCVE, vulnID),
			"rollup": &db.BlastRadiusRollup{VulnerabilityID: vulnID, BySeverity: map[string]int{}, ByEnvironment: map[string]int{}, ByCriticality: map[string]int{}},
		})
		return
	}
	graph, rollup, err := s.db.BlastRadius(r.Context(), vulnID, scope, limitParam(r, 300))
	if err != nil {
		log.Printf("graph blast radius: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	s.enrichGraphCVENodes(r, graph)
	if rollup != nil {
		if sig, ok := graph.Root.Attrs["known_exploited"].(bool); ok {
			rollup.KnownExploited = sig
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"graph": graph, "rollup": rollup})
}

func (s *Server) handleGraphHost(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	hostID := strings.TrimSpace(r.PathValue("id"))
	if hostID == "" {
		writeError(w, http.StatusBadRequest, "host id is required")
		return
	}
	nh, err := s.db.HostNeighborhood(r.Context(), hostID, s.accessScope(r), limitParam(r, 100))
	if err != nil {
		log.Printf("graph host: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	if nh == nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	s.enrichGraphCVENodes(r, nh)
	writeJSON(w, http.StatusOK, nh)
}

func (s *Server) handleGraphGroup(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	groupID := strings.TrimSpace(r.PathValue("id"))
	if groupID == "" {
		writeError(w, http.StatusBadRequest, "group id is required")
		return
	}
	nh, err := s.db.GroupNeighborhood(r.Context(), groupID, s.accessScope(r), limitParam(r, 300))
	if err != nil {
		log.Printf("graph group: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	if nh == nil {
		writeJSON(w, http.StatusOK, emptyNeighborhood(db.NodeGroup, groupID))
		return
	}
	writeJSON(w, http.StatusOK, nh)
}

// enrichGraphCVENodes annotates every cve node (including the root if it is a
// cve) with known_exploited (CISA KEV) and epss_score in one batch query.
func (s *Server) enrichGraphCVENodes(r *http.Request, nh *db.GraphNeighborhood) {
	if nh == nil {
		return
	}
	vids := map[string]bool{}
	if nh.Root.Type == db.NodeCVE {
		vids[nh.Root.ID] = true
	}
	for _, n := range nh.Nodes {
		if n.Type == db.NodeCVE {
			vids[n.ID] = true
		}
	}
	if len(vids) == 0 {
		return
	}
	ids := make([]string, 0, len(vids))
	for v := range vids {
		ids = append(ids, v)
	}
	sigs, err := s.db.CVESignals(r.Context(), ids)
	if err != nil {
		return
	}
	apply := func(n *db.GraphNode) {
		if n.Type != db.NodeCVE {
			return
		}
		if sig, ok := sigs[n.ID]; ok {
			if n.Attrs == nil {
				n.Attrs = map[string]any{}
			}
			n.Attrs["known_exploited"] = sig.KnownExploited
			n.Attrs["epss_score"] = sig.EPSSScore
		}
	}
	apply(&nh.Root)
	for i := range nh.Nodes {
		apply(&nh.Nodes[i])
	}
}

func (s *Server) handleGraphExposure(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	rows, err := s.db.ExposedServices(r.Context(), s.accessScope(r), limitParam(r, 200))
	if err != nil {
		log.Printf("graph exposure: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": rows, "total": len(rows)})
}

func (s *Server) handleGraphImages(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	rows, err := s.db.Images(r.Context(), s.accessScope(r), limitParam(r, 200))
	if err != nil {
		log.Printf("graph images: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"images": rows, "total": len(rows)})
}

func (s *Server) handleGraphOrg(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	org, err := s.db.OrgExposure(r.Context(), s.accessScope(r))
	if err != nil {
		log.Printf("graph org: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, org)
}

func (s *Server) handleGraphRemediation(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	rows, err := s.db.Remediation(r.Context(), s.accessScope(r), limitParam(r, 100))
	if err != nil {
		log.Printf("graph remediation: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"remediations": rows, "total": len(rows)})
}

func (s *Server) handleGraphCVE(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateWeb(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	vid := strings.TrimSpace(r.PathValue("id"))
	if vid == "" {
		writeError(w, http.StatusBadRequest, "vulnerability id is required")
		return
	}
	sigs, err := s.db.CVESignals(r.Context(), []string{vid})
	if err != nil {
		log.Printf("graph cve signals: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	aliases, err := s.db.CVEAliases(r.Context(), vid)
	if err != nil {
		log.Printf("graph cve aliases: %v", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	if aliases == nil {
		aliases = []string{}
	}
	sig := sigs[vid]
	writeJSON(w, http.StatusOK, map[string]any{
		"vulnerability_id": vid,
		"known_exploited":  sig.KnownExploited,
		"epss_score":       sig.EPSSScore,
		"aliases":          aliases,
	})
}

func emptyNeighborhood(t db.GraphNodeType, id string) *db.GraphNeighborhood {
	return &db.GraphNeighborhood{
		Root:  db.GraphNode{Type: t, ID: id, Label: id},
		Nodes: []db.GraphNode{},
		Edges: []db.GraphEdge{},
	}
}
