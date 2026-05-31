package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWebhookNotifierSendsSignedPayload(t *testing.T) {
	received := make(chan webhookPayload, 1)
	results := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		mac := hmac.New(sha256.New, []byte("secret"))
		mac.Write(body)
		wantSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if got := r.Header.Get("X-Bongsu-Signature-256"); got != wantSig {
			t.Errorf("signature = %q, want %q", got, wantSig)
		}
		var payload webhookPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		received <- payload
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	n := &webhookNotifier{
		url:    server.URL,
		secret: "secret",
		client: server.Client(),
		onResult: func(event string, data map[string]any, status string, httpStatus int, errMsg string, attempts int) {
			results <- status
		},
	}
	n.Send("scan.completed", map[string]any{"scan_id": "scan-1"})

	select {
	case payload := <-received:
		if payload.Event != "scan.completed" {
			t.Fatalf("event = %q", payload.Event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook was not received")
	}
	select {
	case status := <-results:
		if status != "ok" {
			t.Fatalf("result status = %q", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook result was not reported")
	}
}

func TestWebhookNotifierReportsHTTPFailure(t *testing.T) {
	results := make(chan struct {
		status     string
		httpStatus int
		attempts   int
	}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	n := &webhookNotifier{
		url:    server.URL,
		client: server.Client(),
		onResult: func(event string, data map[string]any, status string, httpStatus int, errMsg string, attempts int) {
			results <- struct {
				status     string
				httpStatus int
				attempts   int
			}{status: status, httpStatus: httpStatus, attempts: attempts}
		},
		maxAttempts: 1,
	}
	n.Send("scan.completed", map[string]any{"scan_id": "scan-1"})
	select {
	case result := <-results:
		if result.status != "failed" || result.httpStatus != http.StatusBadGateway {
			t.Fatalf("result = %#v", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook failure result was not reported")
	}
}

func TestWebhookNotifierRetriesTransientFailures(t *testing.T) {
	var requests atomic.Int32
	results := make(chan struct {
		status   string
		attempts int
	}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	n := &webhookNotifier{
		url:         server.URL,
		client:      server.Client(),
		maxAttempts: 2,
		retryDelay:  time.Millisecond,
		onResult: func(event string, data map[string]any, status string, httpStatus int, errMsg string, attempts int) {
			results <- struct {
				status   string
				attempts int
			}{status: status, attempts: attempts}
		},
	}
	n.Send("scan.completed", map[string]any{"scan_id": "scan-1"})
	select {
	case result := <-results:
		if result.status != "ok" || result.attempts != 2 || requests.Load() != 2 {
			t.Fatalf("retry result=%#v requests=%d", result, requests.Load())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook retry result was not reported")
	}
}

func TestWebhookNotifierDoesNotRetryClientErrors(t *testing.T) {
	var requests atomic.Int32
	results := make(chan int, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	n := &webhookNotifier{
		url:         server.URL,
		client:      server.Client(),
		maxAttempts: 3,
		retryDelay:  time.Millisecond,
		onResult: func(event string, data map[string]any, status string, httpStatus int, errMsg string, attempts int) {
			results <- attempts
		},
	}
	n.Send("scan.completed", map[string]any{"scan_id": "scan-1"})
	select {
	case attempts := <-results:
		if attempts != 1 || requests.Load() != 1 {
			t.Fatalf("client error attempts=%d requests=%d", attempts, requests.Load())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook client error result was not reported")
	}
}

func TestWebhookRetryAttemptsFromEnv(t *testing.T) {
	t.Setenv("BONGSU_WEBHOOK_RETRY_ATTEMPTS", "0")
	if got := webhookRetryAttemptsFromEnv(); got != 1 {
		t.Fatalf("zero attempts clamp = %d, want 1", got)
	}
	t.Setenv("BONGSU_WEBHOOK_RETRY_ATTEMPTS", "11")
	if got := webhookRetryAttemptsFromEnv(); got != 10 {
		t.Fatalf("high attempts clamp = %d, want 10", got)
	}
	t.Setenv("BONGSU_WEBHOOK_RETRY_ATTEMPTS", "4")
	if got := webhookRetryAttemptsFromEnv(); got != 4 {
		t.Fatalf("attempts = %d, want 4", got)
	}
}

func TestWebhookSeverityThreshold(t *testing.T) {
	n := &webhookNotifier{url: "http://example.invalid", minSeverity: "HIGH"}
	if n.ShouldSendSeverity(map[string]int{"MEDIUM": 10}) {
		t.Fatal("medium should not pass high threshold")
	}
	if !n.ShouldSendSeverity(map[string]int{"HIGH": 1}) {
		t.Fatal("high should pass high threshold")
	}
	if !n.ShouldSendSeverity(map[string]int{"CRITICAL": 1}) {
		t.Fatal("critical should pass high threshold")
	}
	if severityRank(strings.ToLower("critical")) != 4 {
		t.Fatal("severity rank should be case-insensitive")
	}
}

func TestWebhookScanInventoryThreshold(t *testing.T) {
	n := &webhookNotifier{url: "http://example.invalid", minSeverity: "CRITICAL", inventoryStatuses: parseInventoryStatuses("empty,none")}
	if !n.ShouldSendScan(map[string]int{"LOW": 1}, "empty") {
		t.Fatal("empty inventory should trigger scan webhook")
	}
	if n.ShouldSendScan(map[string]int{"LOW": 1}, "healthy") {
		t.Fatal("healthy inventory below severity threshold should not trigger scan webhook")
	}
	if !n.ShouldSendScan(map[string]int{"CRITICAL": 1}, "healthy") {
		t.Fatal("critical finding should trigger scan webhook")
	}
}

func TestParseInventoryStatusesDefault(t *testing.T) {
	got := parseInventoryStatuses("")
	if !got["empty"] || got["healthy"] {
		t.Fatalf("default inventory statuses = %#v", got)
	}
	got = parseInventoryStatuses("empty, degraded, stale, invalid")
	if !got["empty"] || !got["degraded"] || !got["stale"] || got["invalid"] {
		t.Fatalf("parsed inventory statuses = %#v", got)
	}
}
