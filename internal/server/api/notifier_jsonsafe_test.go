package api

import (
	"encoding/json"
	"testing"

	"github.com/ziozzang/bongsu/internal/server/db"
)

// Notification event data is persisted to the outbox as JSON and decoded later,
// which turns map[string]int into map[string]float64 and int into float64. The
// condition matcher must read those values correctly or severity/risk filters
// would silently stop applying once a notification travels through the outbox.
func TestNotifCountMapAndIntSurviveJSONRoundTrip(t *testing.T) {
	orig := map[string]any{
		"severity_counts": map[string]int{"CRITICAL": 2, "LOW": 5},
		"exploited_count": 3,
	}
	raw, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	counts, ok := notifCountMap(decoded["severity_counts"])
	if !ok {
		t.Fatal("notifCountMap must read a JSON-decoded count map")
	}
	if counts["CRITICAL"] != 2 || counts["LOW"] != 5 {
		t.Fatalf("counts wrong after round trip: %+v", counts)
	}

	n, ok := notifInt(decoded["exploited_count"])
	if !ok || n != 3 {
		t.Fatalf("notifInt must read a JSON-decoded int, got %d ok=%v", n, ok)
	}

	// Native (non-round-tripped) shapes must still work for in-process calls.
	if c, ok := notifCountMap(map[string]int{"HIGH": 1}); !ok || c["HIGH"] != 1 {
		t.Fatalf("native map[string]int must still read: %+v ok=%v", c, ok)
	}
	if v, ok := notifInt(7); !ok || v != 7 {
		t.Fatalf("native int must still read: %d ok=%v", v, ok)
	}
}

// matchesConditions must apply a MinSeverity filter identically whether the data
// is native or has been through the outbox's JSON round trip.
func TestMatchesConditionsAfterOutboxRoundTrip(t *testing.T) {
	n := &ruleNotifier{}
	rule := &db.NotificationRule{MinSeverity: "HIGH", ChannelType: "log"}
	roundTrip := func(data map[string]any) map[string]any {
		raw, _ := json.Marshal(data)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		return out
	}

	// CRITICAL present, rule wants >= HIGH -> must match.
	hot := map[string]any{"severity_counts": map[string]int{"CRITICAL": 1}}
	if !n.matchesConditions(rule, hot) {
		t.Fatal("native: critical finding must satisfy a HIGH-min rule")
	}
	if !n.matchesConditions(rule, roundTrip(hot)) {
		t.Fatal("round-trip: critical finding must still satisfy a HIGH-min rule")
	}

	// Only LOW present, rule wants >= HIGH -> must NOT match (the regression we fix:
	// after a round trip this must still be filtered out).
	cold := map[string]any{"severity_counts": map[string]int{"LOW": 9}}
	if n.matchesConditions(rule, cold) {
		t.Fatal("native: low-only must not satisfy a HIGH-min rule")
	}
	if n.matchesConditions(rule, roundTrip(cold)) {
		t.Fatal("round-trip: low-only must still be filtered out by a HIGH-min rule")
	}
}
