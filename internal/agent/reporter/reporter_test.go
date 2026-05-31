package reporter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

func TestReporterSendsAgentIdentityHeaders(t *testing.T) {
	seenToken := ""
	seenHostID := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenToken = r.Header.Get("X-Bongsu-Agent-Token")
		seenHostID = r.Header.Get("X-Bongsu-Host-ID")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	rep := New(srv.URL, "api-key", "agent-token")
	err := rep.Send(&models.ScanReport{Host: models.Host{ID: "host-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if seenToken != "agent-token" || seenHostID != "host-1" {
		t.Fatalf("headers = (%q, %q), want agent-token host-1", seenToken, seenHostID)
	}
}
