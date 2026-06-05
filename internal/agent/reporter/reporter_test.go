package reporter

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

func TestReporterSendsAgentIdentityHeaders(t *testing.T) {
	seenToken := ""
	seenHostID := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenToken = r.Header.Get("X-Bongsu-Agent-Token")
		seenHostID = r.Header.Get("X-Bongsu-Host-ID")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "scan_status": "degraded", "inventory_status": "degraded"})
	}))
	defer srv.Close()

	rep := New(srv.URL, "api-key", "agent-token")
	result, err := rep.Send(&models.ScanReport{Host: models.Host{ID: "host-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.ScanStatus != "degraded" || result.InventoryStatus != "degraded" {
		t.Fatalf("report result = %#v", result)
	}
	if seenToken != "agent-token" || seenHostID != "host-1" {
		t.Fatalf("headers = (%q, %q), want agent-token host-1", seenToken, seenHostID)
	}
}

func TestRetryConfigFromEnvDefaults(t *testing.T) {
	cfg := retryConfigFromEnv()
	if cfg.maxAttempts != 5 {
		t.Fatalf("default maxAttempts = %d, want 5", cfg.maxAttempts)
	}
	if cfg.maxBackoff != 30*time.Second {
		t.Fatalf("default maxBackoff = %v, want 30s", cfg.maxBackoff)
	}
}

func TestRetryConfigFromEnvCustom(t *testing.T) {
	t.Setenv("BONGSU_AGENT_RETRY_ATTEMPTS", "3")
	t.Setenv("BONGSU_AGENT_RETRY_MAX_BACKOFF_SECONDS", "10")
	cfg := retryConfigFromEnv()
	if cfg.maxAttempts != 3 {
		t.Fatalf("custom maxAttempts = %d, want 3", cfg.maxAttempts)
	}
	if cfg.maxBackoff != 10*time.Second {
		t.Fatalf("custom maxBackoff = %v, want 10s", cfg.maxBackoff)
	}
}

func TestRetryConfigFromEnvBounds(t *testing.T) {
	for _, v := range []string{"0", "-1", "invalid"} {
		t.Setenv("BONGSU_AGENT_RETRY_ATTEMPTS", v)
		cfg := retryConfigFromEnv()
		if cfg.maxAttempts != 5 {
			t.Fatalf("BONGSU_AGENT_RETRY_ATTEMPTS=%q gave %d, want 5", v, cfg.maxAttempts)
		}
	}
}

func TestShouldRetryHTTP(t *testing.T) {
	for _, code := range []int{500, 502, 503, 504, 429} {
		if !shouldRetryHTTP(code) {
			t.Fatalf("shouldRetryHTTP(%d) = false, want true", code)
		}
	}
	for _, code := range []int{200, 400, 401, 403, 404, 409} {
		if shouldRetryHTTP(code) {
			t.Fatalf("shouldRetryHTTP(%d) = true, want false", code)
		}
	}
}

func TestReporterRetriesOnServerError(t *testing.T) {
	t.Setenv("BONGSU_AGENT_RETRY_ATTEMPTS", "3")
	t.Setenv("BONGSU_AGENT_RETRY_MAX_BACKOFF_SECONDS", "1")
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	rep := New(srv.URL, "api-key")
	rep.sleep = func(time.Duration) {}
	_, err := rep.Send(&models.ScanReport{Host: models.Host{ID: "host-1"}})
	if err != nil {
		t.Fatalf("expected retry to succeed: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

func TestReporterDoesNotRetryClientError(t *testing.T) {
	t.Setenv("BONGSU_AGENT_RETRY_ATTEMPTS", "3")
	t.Setenv("BONGSU_AGENT_RETRY_MAX_BACKOFF_SECONDS", "1")
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	rep := New(srv.URL, "api-key")
	rep.sleep = func(time.Duration) {}
	_, err := rep.Send(&models.ScanReport{Host: models.Host{ID: "host-1"}})
	if err == nil {
		t.Fatal("expected error for 400")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1 (no retry on 4xx)", attempts)
	}
}

func TestReporterBoundsErrorResponseBodies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, strings.Repeat("x", maxErrorResponseBodyBytes+4096))
	}))
	defer srv.Close()

	rep := New(srv.URL, "api-key")
	_, err := rep.Send(&models.ScanReport{Host: models.Host{ID: "host-1"}})
	if err == nil {
		t.Fatal("expected error for oversized error body")
	}
	msg := err.Error()
	if !strings.Contains(msg, "...(truncated)") {
		t.Fatalf("error body was not marked truncated: len=%d err=%q", len(msg), msg)
	}
	if strings.Count(msg, "x") > maxErrorResponseBodyBytes {
		t.Fatalf("error body was not bounded: x count=%d", strings.Count(msg, "x"))
	}
}

func TestReporterRetryExhausted(t *testing.T) {
	t.Setenv("BONGSU_AGENT_RETRY_ATTEMPTS", "2")
	t.Setenv("BONGSU_AGENT_RETRY_MAX_BACKOFF_SECONDS", "1")
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	rep := New(srv.URL, "api-key")
	rep.sleep = func(time.Duration) {}
	_, err := rep.Send(&models.ScanReport{Host: models.Host{ID: "host-1"}})
	if err == nil {
		t.Fatal("expected error after retries exhausted")
	}
	if !strings.Contains(err.Error(), "after 2 attempts") {
		t.Fatalf("error = %q, want 'after 2 attempts'", err.Error())
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

func TestReporterHonorsRetryAfterHeader(t *testing.T) {
	t.Setenv("BONGSU_AGENT_RETRY_ATTEMPTS", "2")
	t.Setenv("BONGSU_AGENT_RETRY_MAX_BACKOFF_SECONDS", "30")
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	rep := New(srv.URL, "api-key")
	sleeps := []time.Duration{}
	rep.sleep = func(d time.Duration) { sleeps = append(sleeps, d) }
	_, err := rep.Send(&models.ScanReport{Host: models.Host{ID: "host-1"}})
	if err != nil {
		t.Fatalf("expected retry-after retry to succeed: %v", err)
	}
	if len(sleeps) != 1 || sleeps[0] != 3*time.Second {
		t.Fatalf("sleeps = %#v, want [3s]", sleeps)
	}
}

func TestReporterCapsRetryAfterHeader(t *testing.T) {
	t.Setenv("BONGSU_AGENT_RETRY_ATTEMPTS", "2")
	t.Setenv("BONGSU_AGENT_RETRY_MAX_BACKOFF_SECONDS", "1")
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	rep := New(srv.URL, "api-key")
	sleeps := []time.Duration{}
	rep.sleep = func(d time.Duration) { sleeps = append(sleeps, d) }
	_, err := rep.Send(&models.ScanReport{Host: models.Host{ID: "host-1"}})
	if err != nil {
		t.Fatalf("expected capped retry-after retry to succeed: %v", err)
	}
	if len(sleeps) != 1 || sleeps[0] != time.Second {
		t.Fatalf("sleeps = %#v, want [1s]", sleeps)
	}
}

func TestRetryAfterDelayParsesHTTPDate(t *testing.T) {
	now := time.Date(2026, 6, 5, 10, 0, 0, 0, time.UTC)
	header := now.Add(4 * time.Second).Format(http.TimeFormat)
	delay, ok := retryAfterDelay(header, now)
	if !ok || delay != 4*time.Second {
		t.Fatalf("retryAfterDelay = (%v, %v), want 4s true", delay, ok)
	}
	delay, ok = retryAfterDelay(now.Add(-time.Second).Format(http.TimeFormat), now)
	if !ok || delay != 0 {
		t.Fatalf("past retryAfterDelay = (%v, %v), want 0 true", delay, ok)
	}
	if _, ok := retryAfterDelay("-1", now); ok {
		t.Fatal("negative Retry-After seconds must be ignored")
	}
}

func TestReporterSendUsesExponentialBackoff(t *testing.T) {
	src, err := os.ReadFile("reporter.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	for _, want := range []string{
		"doWithRetry",
		"shouldRetryHTTP",
		"BONGSU_AGENT_RETRY_ATTEMPTS",
		"BONGSU_AGENT_RETRY_MAX_BACKOFF_SECONDS",
		"1<<uint(attempt-1)",
		"r.rng.Int63n",
		"Retry-After",
		"retryAfterDelay",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("reporter.go missing %q", want)
		}
	}
}

func TestReporterErrorBodiesUseBoundedReader(t *testing.T) {
	src, err := os.ReadFile("reporter.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	for _, want := range []string{
		"const maxErrorResponseBodyBytes",
		"io.LimitReader(body, maxErrorResponseBodyBytes+1)",
		"readBoundedErrorBody(resp.Body)",
		"...(truncated)",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("reporter bounded error body missing %q", want)
		}
	}
	if strings.Count(body, "io.ReadAll(") != 1 {
		t.Fatalf("reporter must only read HTTP error bodies through readBoundedErrorBody: %s", body)
	}
}
