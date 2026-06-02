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
	return &ruleNotifier{
		server: s,
		client: &http.Client{Timeout: timeout},
	}
}

func (n *ruleNotifier) evaluateAndDispatch(ctx context.Context, event string, data map[string]any) {
	if envBool("BONGSU_NOTIFICATION_DISABLED", false) {
		return
	}
	rules, err := n.server.db.GetEnabledRulesForEvent(ctx, event)
	if err != nil {
		log.Printf("notification rules fetch: %v", err)
		return
	}
	for _, rule := range rules {
		if !n.matchesConditions(&rule, data) {
			continue
		}
		n.dispatch(ctx, &rule, event, data)
	}
}

func (n *ruleNotifier) matchesConditions(rule *db.NotificationRule, data map[string]any) bool {
	if rule.MinSeverity != "" {
		if counts, ok := data["severity_counts"].(map[string]int); ok {
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
		if counts, ok := data["risk_level_counts"].(map[string]int); ok {
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
		if exploited, ok := data["exploited_count"].(int); ok && exploited == 0 {
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

func (n *ruleNotifier) dispatch(ctx context.Context, rule *db.NotificationRule, event string, data map[string]any) {
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
	switch rule.ChannelType {
	case "webhook":
		cfg := map[string]string{}
		json.Unmarshal(rule.ChannelConfig, &cfg)
		url := cfg["url"]
		if url == "" {
			log.Printf("notification rule %s: no url in channel_config", rule.ID)
			return
		}
		body, err := json.Marshal(payload)
		if err != nil {
			log.Printf("notification rule %s marshal: %v", rule.ID, err)
			return
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			log.Printf("notification rule %s request: %v", rule.ID, err)
			return
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
		resp, err := n.client.Do(req)
		if err != nil {
			logEntry.Status = "failed"
			logEntry.ErrorMessage = err.Error()
		} else {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				logEntry.Status = "sent"
			} else {
				logEntry.Status = "failed"
				logEntry.ErrorMessage = fmt.Sprintf("HTTP %d", resp.StatusCode)
			}
		}
	case "log":
		log.Printf("[NOTIFICATION] rule=%s event=%s data=%s", rule.Name, event, string(payloadJSON))
		logEntry.Status = "sent"
	}
	if err := n.server.db.RecordNotificationLog(ctx, logEntry); err != nil {
		log.Printf("notification log record: %v", err)
	}
	n.server.db.TouchNotificationRuleTrigger(ctx, rule.ID)
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
		url := cfg["url"]
		if url == "" {
			return fmt.Errorf("no url configured")
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "bongsu-notification/0.1.0")
		req.Header.Set("X-Bongsu-Event", "test")
		if secret := cfg["secret"]; secret != "" {
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write(body)
			req.Header.Set("X-Bongsu-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		}
		resp, err := n.client.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	case "log":
		log.Printf("[NOTIFICATION TEST] rule=%s", rule.Name)
		return nil
	}
	return fmt.Errorf("unknown channel type: %s", rule.ChannelType)
}
