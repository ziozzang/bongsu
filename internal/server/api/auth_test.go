package api

import (
	"net/http/httptest"
	"testing"
)

func TestAuthSeparation(t *testing.T) {
	s := &Server{
		apiKey:       "admin-key",
		agentKey:     "agent-key",
		installToken: "install-token",
		webAuth:      true,
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "admin-key")
	if !s.authenticateAdmin(req) {
		t.Fatal("admin key should authenticate admin")
	}
	if s.authenticateAgent(req) == false {
		t.Fatal("admin key should be accepted for agent compatibility")
	}

	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "agent-key")
	if !s.authenticateAgent(req) {
		t.Fatal("agent key should authenticate agent")
	}
	if s.authenticateAdmin(req) {
		t.Fatal("agent key must not authenticate admin")
	}

	req = httptest.NewRequest("GET", "/api/install.sh?token=install-token", nil)
	if !s.authenticateInstall(req) {
		t.Fatal("install token should authenticate installer")
	}

	req = httptest.NewRequest("GET", "/api/install.sh?api_key=admin-key", nil)
	if s.authenticateInstall(req) {
		t.Fatal("api_key query parameter must not authenticate installer")
	}
}

func TestWebAuthCanBeDisabledWithoutOpeningAdmin(t *testing.T) {
	s := &Server{apiKey: "admin-key", agentKey: "agent-key", webAuth: false}
	req := httptest.NewRequest("GET", "/", nil)
	if !s.authenticateWeb(req) {
		t.Fatal("web auth disabled should allow web reads")
	}
	if s.authenticateAdmin(req) {
		t.Fatal("web auth disabled must not open admin API")
	}
	if s.authenticateAgent(req) {
		t.Fatal("web auth disabled must not open agent API")
	}
}

func TestViewerKeys(t *testing.T) {
	keys := parseViewerKeys("viewer-key:alice, team-key:devops, malformed")
	if keys["viewer-key"] != "alice" {
		t.Fatalf("viewer-key subject = %q", keys["viewer-key"])
	}
	if keys["team-key"] != "devops" {
		t.Fatalf("team-key subject = %q", keys["team-key"])
	}

	s := &Server{apiKey: "admin-key", viewerKeys: keys, webAuth: true}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "viewer-key")
	if !s.authenticateWeb(req) {
		t.Fatal("viewer key should authenticate web")
	}
	if s.authenticateAdmin(req) {
		t.Fatal("viewer key must not authenticate admin")
	}
	if got := s.viewerSubject(req); got != "alice" {
		t.Fatalf("viewer subject = %q", got)
	}
}
