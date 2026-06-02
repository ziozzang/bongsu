package api

import (
	"strings"
	"testing"
	"time"
)

func TestParseCronAcceptsValidExpressions(t *testing.T) {
	tests := []struct {
		expr string
	}{
		{"*/5 * * * *"},
		{"0 2 * * *"},
		{"30 4 1 * *"},
		{"0 0 * * 1"},
		{"0,30 * * * *"},
		{"0 0 1,15 * *"},
		{"0 0 * * 0,6"},
	}
	for _, tt := range tests {
		_, err := parseCron(tt.expr)
		if err != nil {
			t.Fatalf("parseCron(%q) error: %v", tt.expr, err)
		}
	}
}

func TestParseCronRejectsInvalidExpressions(t *testing.T) {
	tests := []string{
		"* * *",
		"* * * * * *",
		"60 * * * *",
		"* 25 * * *",
		"abc * * * *",
		"0-60 * * * *",
	}
	for _, expr := range tests {
		_, err := parseCron(expr)
		if err == nil {
			t.Fatalf("parseCron(%q) should have failed", expr)
		}
	}
}

func TestNextCronTimeEveryFiveMinutes(t *testing.T) {
	schedule, err := parseCron("*/5 * * * *")
	if err != nil {
		t.Fatal(err)
	}
	after := time.Date(2026, 6, 1, 10, 3, 0, 0, time.UTC)
	next := nextCronTime(schedule, after)
	want := time.Date(2026, 6, 1, 10, 5, 0, 0, time.UTC)
	if next != want {
		t.Fatalf("next = %v, want %v", next, want)
	}
}

func TestNextCronTimeDailyAt2AM(t *testing.T) {
	schedule, err := parseCron("0 2 * * *")
	if err != nil {
		t.Fatal(err)
	}
	after := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	next := nextCronTime(schedule, after)
	want := time.Date(2026, 6, 2, 2, 0, 0, 0, time.UTC)
	if next != want {
		t.Fatalf("next = %v, want %v", next, want)
	}
}

func TestComputeNextRunNeverPanics(t *testing.T) {
	tests := []string{
		"*/5 * * * *",
		"0 0 31 2 *",
		"0 0 29 2 *",
	}
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	for _, expr := range tests {
		next, err := computeNextRun(expr, now)
		if err != nil {
			t.Logf("computeNextRun(%q) error (expected for impossible dates): %v", expr, err)
			continue
		}
		if next.IsZero() {
			t.Fatalf("computeNextRun(%q) returned zero", expr)
		}
	}
}

func TestSchedulerIntervalFromEnv(t *testing.T) {
	t.Setenv("BONGSU_SCHEDULER_INTERVAL_SECONDS", "30")
	interval := time.Duration(envInt("BONGSU_SCHEDULER_INTERVAL_SECONDS", 60)) * time.Second
	if interval < 10*time.Second {
		t.Fatalf("interval = %v, should not be clamped", interval)
	}
	if interval != 30*time.Second {
		t.Fatalf("interval = %v, want 30s", interval)
	}
}

func TestSchedulerStartsBackgroundGoroutine(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		"startScheduler()",
		"BONGSU_SCHEDULER_INTERVAL_SECONDS",
		"BONGSU_SCHEDULER_DISABLED",
		"GetDueScheduledScans",
		"computeNextRun",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("scheduler missing %q", want)
		}
	}
}

func TestScheduledScanRoutesAreRegistered(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		`"GET /api/admin/schedules"`,
		`"POST /api/admin/schedules"`,
		`"GET /api/admin/schedules/{id}"`,
		`"PUT /api/admin/schedules/{id}"`,
		`"DELETE /api/admin/schedules/{id}"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("route missing %q", want)
		}
	}
}
