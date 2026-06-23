package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ziozzang/bongsu/internal/server/db"
)

type ruleNotifier struct {
	server *Server
	client *http.Client
}

func newRuleNotifier(s *Server) *ruleNotifier {
	timeout := time.Duration(envInt("BONGSU_NOTIFICATION_TIMEOUT_SECONDS", 15)) * time.Second
	if timeout < time.Second {
		timeout = 15 * time.Second
	}
	if timeout > 5*time.Minute {
		timeout = 5 * time.Minute
	}
	return &ruleNotifier{
		server: s,
		client: &http.Client{Timeout: timeout},
	}
}

// evaluateAndDispatch evaluates the enabled rules for an event and dispatches the
// matching ones. It returns an error if any matching rule's delivery ultimately
// failed, so a caller draining the event outbox can retry the whole event
// (at-least-once). Rule fetch failures are also returned so the event is retried
// rather than silently dropped.
func (n *ruleNotifier) evaluateAndDispatch(ctx context.Context, event string, data map[string]any) error {
	if envBool("BONGSU_NOTIFICATION_DISABLED", false) {
		return nil
	}
	rules, err := n.server.db.GetEnabledRulesForEvent(ctx, event)
	if err != nil {
		return fmt.Errorf("notification rules fetch: %w", err)
	}
	failed := 0
	for _, rule := range rules {
		if !n.matchesConditions(&rule, data) {
			continue
		}
		if !n.dispatch(ctx, &rule, event, data) {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d notification rule(s) failed delivery for event %s", failed, event)
	}
	return nil
}

// notifCountMap reads a {label: count} map from event data, tolerating both the
// native map[string]int (in-process call) and the map[string]float64/any shape
// that survives a JSON round-trip through the event outbox.
func notifCountMap(v any) (map[string]int, bool) {
	switch m := v.(type) {
	case map[string]int:
		return m, true
	case map[string]float64:
		out := make(map[string]int, len(m))
		for k, f := range m {
			out[k] = int(f)
		}
		return out, true
	case map[string]any:
		out := make(map[string]int, len(m))
		for k, raw := range m {
			n, _ := notifInt(raw)
			out[k] = n
		}
		return out, true
	}
	return nil, false
}

// notifInt reads an int from event data, tolerating the float64/json.Number a
// JSON round-trip produces.
func notifInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	}
	return 0, false
}

func (n *ruleNotifier) matchesConditions(rule *db.NotificationRule, data map[string]any) bool {
	if rule.MinSeverity != "" {
		if counts, ok := notifCountMap(data["severity_counts"]); ok {
			matched := false
			for sev, cnt := range counts {
				if cnt > 0 && severityRank(sev) >= severityRank(rule.MinSeverity) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}
	if rule.MinRiskLevel != "" {
		if counts, ok := notifCountMap(data["risk_level_counts"]); ok {
			matched := false
			for rl, cnt := range counts {
				if cnt > 0 && riskRank(rl) >= riskRank(rule.MinRiskLevel) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}
	if rule.ExploitedOnly {
		if exploited, ok := notifInt(data["exploited_count"]); ok && exploited == 0 {
			return false
		}
	}
	if rule.HostFilter != "" {
		hostID, _ := data["host_id"].(string)
		if hostID == "" {
			return false
		}
		found := false
		for _, f := range strings.Split(rule.HostFilter, ",") {
			if strings.TrimSpace(f) == hostID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// dispatch delivers one rule's notification and records the attempt. It returns
// true on successful delivery (or a non-retryable misconfiguration that should
// not block the event) and false when the send failed and the event should be
// retried from the outbox.
func (n *ruleNotifier) dispatch(ctx context.Context, rule *db.NotificationRule, event string, data map[string]any) bool {
	payload := map[string]any{
		"event":     event,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"rule_id":   rule.ID,
		"rule_name": rule.Name,
		"data":      data,
	}
	payloadJSON, _ := json.Marshal(payload)
	logEntry := &db.NotificationLog{
		RuleID:       rule.ID,
		TriggerEvent: event,
		Payload:      payloadJSON,
	}
	ok := true
	switch rule.ChannelType {
	case "webhook":
		cfg := map[string]string{}
		json.Unmarshal(rule.ChannelConfig, &cfg)
		if strings.TrimSpace(cfg["url"]) == "" {
			// Misconfiguration, not a transient failure — retrying won't help, so
			// don't wedge the event; surface it in the log instead.
			log.Printf("notification rule %s: no url in channel_config", rule.ID)
			return true
		}
		status, errMsg, attempts := n.sendWebhook(ctx, rule, event, payload)
		logEntry.Status = status
		logEntry.ErrorMessage = errMsg
		logEntry.Attempts = attempts
		ok = status == "sent"
	case "email":
		status, errMsg, attempts := n.sendEmail(ctx, rule, event, payload)
		logEntry.Status = status
		logEntry.ErrorMessage = errMsg
		logEntry.Attempts = attempts
		ok = status == "sent"
	case "log":
		log.Printf("[NOTIFICATION] rule=%s event=%s data=%s", rule.Name, event, string(payloadJSON))
		logEntry.Status = "sent"
		logEntry.Attempts = 1
	}
	if err := n.server.db.RecordNotificationLog(ctx, logEntry); err != nil {
		log.Printf("notification log record: %v", err)
	}
	n.server.db.TouchNotificationRuleTrigger(ctx, rule.ID)
	return ok
}

func (n *ruleNotifier) sendWebhook(ctx context.Context, rule *db.NotificationRule, event string, payload map[string]any) (string, string, int) {
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("notification rule %s marshal: %v", rule.ID, err)
		return "failed", err.Error(), 1
	}
	cfg := map[string]string{}
	json.Unmarshal(rule.ChannelConfig, &cfg)
	attempts := notificationRetryAttemptsFromEnv()
	delay := notificationRetryDelayFromEnv()
	client := n.client
	if client == nil {
		client = http.DefaultClient
	}
	var lastErr string
	for attempt := 1; attempt <= attempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(cfg["url"]), bytes.NewReader(body))
		if err != nil {
			log.Printf("notification rule %s request: %v", rule.ID, err)
			return "failed", err.Error(), attempt
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "bongsu-notification/0.1.0")
		req.Header.Set("X-Bongsu-Event", event)
		req.Header.Set("X-Bongsu-Rule-ID", rule.ID)
		if secret := cfg["secret"]; secret != "" {
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write(body)
			req.Header.Set("X-Bongsu-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err.Error()
			log.Printf("notification rule %s webhook attempt %d/%d: %v", rule.ID, attempt, attempts, err)
			if attempt < attempts {
				sleepWithContext(ctx, delay)
				continue
			}
			return "failed", lastErr, attempt
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return "sent", "", attempt
		}
		lastErr = fmt.Sprintf("HTTP %d", resp.StatusCode)
		log.Printf("notification rule %s webhook attempt %d/%d returned HTTP %d", rule.ID, attempt, attempts, resp.StatusCode)
		if !retryWebhookStatus(resp.StatusCode) || attempt == attempts {
			return "failed", lastErr, attempt
		}
		sleepWithContext(ctx, delay)
	}
	return "failed", lastErr, attempts
}

func (n *ruleNotifier) dispatchTest(ctx context.Context, rule *db.NotificationRule) error {
	testData := map[string]any{"test": true, "message": "Test notification from bongsu"}
	payload := map[string]any{
		"event":     "test",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"rule_id":   rule.ID,
		"rule_name": rule.Name,
		"data":      testData,
	}
	cfg := map[string]string{}
	json.Unmarshal(rule.ChannelConfig, &cfg)
	switch rule.ChannelType {
	case "webhook":
		if strings.TrimSpace(cfg["url"]) == "" {
			return fmt.Errorf("no url configured")
		}
		status, errMsg, _ := n.sendWebhook(ctx, rule, "test", payload)
		if status == "sent" {
			return nil
		}
		if errMsg == "" {
			errMsg = "webhook failed"
		}
		return fmt.Errorf("%s", errMsg)
	case "email":
		status, errMsg, _ := n.sendEmail(ctx, rule, "test", payload)
		if status == "sent" {
			return nil
		}
		if errMsg == "" {
			errMsg = "email send failed"
		}
		return fmt.Errorf("%s", errMsg)
	case "log":
		log.Printf("[NOTIFICATION TEST] rule=%s", rule.Name)
		return nil
	}
	return fmt.Errorf("unknown channel type: %s", rule.ChannelType)
}

func notificationRetryAttemptsFromEnv() int {
	attempts := envInt("BONGSU_NOTIFICATION_RETRY_ATTEMPTS", 3)
	if attempts < 1 {
		return 1
	}
	if attempts > 10 {
		return 10
	}
	return attempts
}

func notificationRetryDelayFromEnv() time.Duration {
	ms := envInt("BONGSU_NOTIFICATION_RETRY_DELAY_MS", 1000)
	if ms <= 0 {
		return time.Second
	}
	if ms > 60000 {
		return time.Minute
	}
	return time.Duration(ms) * time.Millisecond
}

func sleepWithContext(ctx context.Context, delay time.Duration) {
	if delay <= 0 {
		return
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
