package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/server/db"
)

func TestNotificationRuleRoutesAreRegistered(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		`"GET /api/admin/notification-rules"`,
		`"POST /api/admin/notification-rules"`,
		`"GET /api/admin/notification-rules/{id}"`,
		`"PUT /api/admin/notification-rules/{id}"`,
		`"DELETE /api/admin/notification-rules/{id}"`,
		`"POST /api/admin/notification-rules/{id}/test"`,
		`"GET /api/admin/notification-log"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("route missing %q", want)
		}
	}
}

func TestNotificationRuleHandlersExist(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		"handleListNotificationRules",
		"handleCreateNotificationRule",
		"handleGetNotificationRule",
		"handleUpdateNotificationRule",
		"handleDeleteNotificationRule",
		"handleTestNotificationRule",
		"handleListNotificationLog",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q", want)
		}
	}
}

func TestNotificationRuleDBMethodsExist(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		"CreateNotificationRule",
		"GetNotificationRule",
		"ListNotificationRules",
		"UpdateNotificationRule",
		"DeleteNotificationRule",
		"GetEnabledRulesForEvent",
		"RecordNotificationLog",
		"ListNotificationLog",
		"TouchNotificationRuleTrigger",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q", want)
		}
	}
}

func TestNotificationRulesRequireAdminAuth(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, fn := range []string{"handleCreateNotificationRule", "handleDeleteNotificationRule", "handleTestNotificationRule"} {
		idx := strings.Index(out, "func (s *Server) "+fn)
		if idx < 0 {
			t.Fatalf("%s not found", fn)
		}
		body := extractFuncBody(out, idx)
		if !strings.Contains(body, "authenticateAdmin") {
			t.Fatalf("%s does not check authenticateAdmin", fn)
		}
	}
}

func TestNotificationEngineExists(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		"ruleNotifier",
		"newRuleNotifier",
		"evaluateAndDispatch",
		"matchesConditions",
		"dispatch",
		"dispatchTest",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q", want)
		}
	}
}

func TestNotificationEnvVarsPresent(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		"BONGSU_NOTIFICATION_DISABLED",
		"BONGSU_NOTIFICATION_TIMEOUT_SECONDS",
		"BONGSU_NOTIFICATION_RETRY_ATTEMPTS",
		"BONGSU_NOTIFICATION_RETRY_DELAY_MS",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing env var %q", want)
		}
	}
}

func TestNotificationEngineTriggeredAfterScan(t *testing.T) {
	out := readAllPackageGoFiles(t)
	// Notifications are now durable: the report handler enqueues a scan.completed
	// event to the transactional outbox, and the dispatcher delivers it by calling
	// the rule engine. Assert both ends of that path exist.
	if !strings.Contains(out, `eventNotification, notificationEventPayload{Event: "scan.completed"`) {
		t.Fatal("scan.completed must be enqueued to the event outbox after a scan")
	}
	if !strings.Contains(out, `evaluateAndDispatch(ctx, p.Event, p.Data)`) {
		t.Fatal("outbox dispatcher must deliver notification events via the rule engine")
	}
}

func TestNotificationRuleWebhookRetriesTransientFailures(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Setenv("BONGSU_NOTIFICATION_RETRY_ATTEMPTS", "3")
	t.Setenv("BONGSU_NOTIFICATION_RETRY_DELAY_MS", "1")
	rule := &db.NotificationRule{
		ID:            "rule-1",
		Name:          "retry rule",
		ChannelType:   "webhook",
		ChannelConfig: json.RawMessage(`{"url":"` + server.URL + `"}`),
	}
	notifier := &ruleNotifier{client: server.Client()}
	status, errMsg, attempts := notifier.sendWebhook(context.Background(), rule, "scan.completed", map[string]any{"event": "scan.completed"})
	if status != "sent" || errMsg != "" || attempts != 2 || requests.Load() != 2 {
		t.Fatalf("status=%q err=%q attempts=%d requests=%d", status, errMsg, attempts, requests.Load())
	}
}

func TestNotificationRuleWebhookDoesNotRetryClientErrors(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	t.Setenv("BONGSU_NOTIFICATION_RETRY_ATTEMPTS", "3")
	t.Setenv("BONGSU_NOTIFICATION_RETRY_DELAY_MS", "1")
	rule := &db.NotificationRule{
		ID:            "rule-1",
		Name:          "client-error rule",
		ChannelType:   "webhook",
		ChannelConfig: json.RawMessage(`{"url":"` + server.URL + `"}`),
	}
	notifier := &ruleNotifier{client: server.Client()}
	status, errMsg, attempts := notifier.sendWebhook(context.Background(), rule, "scan.completed", map[string]any{"event": "scan.completed"})
	if status != "failed" || errMsg != "HTTP 400" || attempts != 1 || requests.Load() != 1 {
		t.Fatalf("status=%q err=%q attempts=%d requests=%d", status, errMsg, attempts, requests.Load())
	}
}

func TestNotificationRuleWebhookSignsPayload(t *testing.T) {
	const secret = "notification-secret"
	received := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode payload: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, _ := json.Marshal(payload)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		wantSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if got := r.Header.Get("X-Bongsu-Signature-256"); got != wantSig {
			t.Errorf("signature = %q, want %q", got, wantSig)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if got := r.Header.Get("X-Bongsu-Rule-ID"); got != "rule-1" {
			t.Errorf("rule header = %q", got)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	rule := &db.NotificationRule{
		ID:            "rule-1",
		Name:          "signed rule",
		ChannelType:   "webhook",
		ChannelConfig: json.RawMessage(`{"url":"` + server.URL + `","secret":"` + secret + `"}`),
	}
	notifier := &ruleNotifier{client: server.Client()}
	status, errMsg, attempts := notifier.sendWebhook(context.Background(), rule, "test", map[string]any{"event": "test"})
	if status != "sent" || errMsg != "" || attempts != 1 {
		t.Fatalf("status=%q err=%q attempts=%d", status, errMsg, attempts)
	}
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("signed webhook was not received")
	}
}

func TestNotificationRetryEnvBounds(t *testing.T) {
	t.Setenv("BONGSU_NOTIFICATION_RETRY_ATTEMPTS", "0")
	if got := notificationRetryAttemptsFromEnv(); got != 1 {
		t.Fatalf("zero attempts clamp = %d, want 1", got)
	}
	t.Setenv("BONGSU_NOTIFICATION_RETRY_ATTEMPTS", "11")
	if got := notificationRetryAttemptsFromEnv(); got != 10 {
		t.Fatalf("high attempts clamp = %d, want 10", got)
	}
	t.Setenv("BONGSU_NOTIFICATION_RETRY_DELAY_MS", "0")
	if got := notificationRetryDelayFromEnv(); got != time.Second {
		t.Fatalf("zero delay clamp = %s, want 1s", got)
	}
	t.Setenv("BONGSU_NOTIFICATION_RETRY_DELAY_MS", "70000")
	if got := notificationRetryDelayFromEnv(); got != time.Minute {
		t.Fatalf("high delay clamp = %s, want 1m", got)
	}
}
