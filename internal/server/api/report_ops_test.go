package api

import (
	"strings"
	"testing"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

func TestScanFailedFromStatus(t *testing.T) {
	cases := []struct {
		name   string
		status string
		errs   []string
		want   bool
	}{
		{"completed clean", "completed", nil, false},
		{"degraded status", "degraded", nil, true},
		{"failed status", "failed", nil, true},
		{"completed with ingest errors", "completed", []string{"packages: boom"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scanFailedFromStatus(tc.status, tc.errs); got != tc.want {
				t.Fatalf("scanFailedFromStatus(%q, %v) = %v, want %v", tc.status, tc.errs, got, tc.want)
			}
		})
	}
}

func TestScanFailedPayloadCarriesIdentityAndErrors(t *testing.T) {
	report := &models.ScanReport{ScanID: "scan-1", ScanType: "inventory"}
	report.Host.ID = "host-1"
	report.Host.Hostname = "web01"
	errs := []string{"packages: boom", "users: nope"}
	data := scanFailedPayload(report, "degraded", "2 error(s): packages: boom; users: nope", errs)
	if data["host_id"] != "host-1" || data["hostname"] != "web01" {
		t.Fatalf("missing host identity: %#v", data)
	}
	if data["scan_status"] != "degraded" {
		t.Fatalf("scan_status = %v", data["scan_status"])
	}
	if data["ingest_error_count"] != len(errs) {
		t.Fatalf("ingest_error_count = %v, want %d", data["ingest_error_count"], len(errs))
	}
	if summary, _ := data["error_summary"].(string); !strings.Contains(summary, "packages: boom") {
		t.Fatalf("error_summary = %q", summary)
	}
}

func TestAutoAssignByOwnerDefaultsOn(t *testing.T) {
	if !autoAssignByOwnerEnabled() {
		t.Fatal("auto-assign by owner should default to enabled")
	}
	t.Setenv("BONGSU_AUTO_ASSIGN_BY_OWNER", "false")
	if autoAssignByOwnerEnabled() {
		t.Fatal("auto-assign by owner should honor disable flag")
	}
}

func TestScanFailedTriggerIsAccepted(t *testing.T) {
	if !validTriggerEvent("scan.failed") {
		t.Fatal("scan.failed must be an accepted trigger_event")
	}
	if !validTriggerEvent("scan.completed") {
		t.Fatal("scan.completed must remain an accepted trigger_event")
	}
	if validTriggerEvent("scan.bogus") {
		t.Fatal("unknown trigger_event should be rejected")
	}
}
