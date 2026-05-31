package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type webhookNotifier struct {
	url               string
	secret            string
	minSeverity       string
	inventoryStatuses map[string]bool
	client            *http.Client
	maxAttempts       int
	retryDelay        time.Duration
	onResult          func(event string, data map[string]any, status string, httpStatus int, errMsg string, attempts int)
}

type webhookPayload struct {
	Event     string         `json:"event"`
	Timestamp string         `json:"timestamp"`
	Data      map[string]any `json:"data"`
}

func newWebhookNotifierFromEnv() *webhookNotifier {
	url := strings.TrimSpace(os.Getenv("BONGSU_WEBHOOK_URL"))
	if url == "" {
		return nil
	}
	return &webhookNotifier{
		url:               url,
		secret:            os.Getenv("BONGSU_WEBHOOK_SECRET"),
		minSeverity:       strings.ToUpper(strings.TrimSpace(os.Getenv("BONGSU_WEBHOOK_MIN_SEVERITY"))),
		inventoryStatuses: parseInventoryStatuses(os.Getenv("BONGSU_WEBHOOK_INVENTORY_STATUSES")),
		client:            &http.Client{Timeout: 10 * time.Second},
		maxAttempts:       webhookRetryAttemptsFromEnv(),
		retryDelay:        time.Duration(envInt("BONGSU_WEBHOOK_RETRY_DELAY_MS", 1000)) * time.Millisecond,
	}
}

func (n *webhookNotifier) Enabled() bool {
	return n != nil && n.url != ""
}

func (n *webhookNotifier) Send(event string, data map[string]any) {
	if !n.Enabled() {
		return
	}
	go func() {
		report := func(status string, httpStatus int, errMsg string, attempts int) {
			if n.onResult != nil {
				n.onResult(event, data, status, httpStatus, errMsg, attempts)
			}
		}
		payload := webhookPayload{
			Event:     event,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Data:      data,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			log.Printf("webhook marshal %s: %v", event, err)
			report("failed", 0, err.Error(), 1)
			return
		}
		attempts := n.maxAttempts
		if attempts <= 0 {
			attempts = 1
		}
		delay := n.retryDelay
		if delay <= 0 {
			delay = time.Second
		}
		client := n.client
		if client == nil {
			client = http.DefaultClient
		}
		var lastStatus int
		var lastErr string
		for attempt := 1; attempt <= attempts; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
			if err != nil {
				cancel()
				log.Printf("webhook request %s: %v", event, err)
				report("failed", 0, err.Error(), attempt)
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "bongsu-webhook/0.1.0")
			req.Header.Set("X-Bongsu-Event", event)
			if n.secret != "" {
				mac := hmac.New(sha256.New, []byte(n.secret))
				mac.Write(body)
				req.Header.Set("X-Bongsu-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
			}
			resp, err := client.Do(req)
			cancel()
			if err != nil {
				lastStatus = 0
				lastErr = err.Error()
				log.Printf("webhook send %s attempt %d/%d: %v", event, attempt, attempts, err)
				if attempt < attempts {
					time.Sleep(delay)
					continue
				}
				report("failed", lastStatus, lastErr, attempt)
				return
			}
			lastStatus = resp.StatusCode
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				report("ok", resp.StatusCode, "", attempt)
				return
			}
			lastErr = ""
			log.Printf("webhook send %s attempt %d/%d returned HTTP %d", event, attempt, attempts, resp.StatusCode)
			if !retryWebhookStatus(resp.StatusCode) || attempt == attempts {
				report("failed", resp.StatusCode, "", attempt)
				return
			}
			time.Sleep(delay)
		}
		report("failed", lastStatus, lastErr, attempts)
	}()
}

func retryWebhookStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

func webhookRetryAttemptsFromEnv() int {
	attempts := envInt("BONGSU_WEBHOOK_RETRY_ATTEMPTS", 3)
	if attempts < 1 {
		return 1
	}
	if attempts > 10 {
		return 10
	}
	return attempts
}

func (n *webhookNotifier) ShouldSendSeverity(counts map[string]int) bool {
	if !n.Enabled() {
		return false
	}
	if n.minSeverity == "" {
		return true
	}
	for sev, count := range counts {
		if count > 0 && severityRank(sev) >= severityRank(n.minSeverity) {
			return true
		}
	}
	return false
}

func (n *webhookNotifier) ShouldSendScan(counts map[string]int, inventoryStatus string) bool {
	if !n.Enabled() {
		return false
	}
	if n.ShouldSendSeverity(counts) {
		return true
	}
	if n.inventoryStatuses == nil {
		n.inventoryStatuses = parseInventoryStatuses("")
	}
	return n.inventoryStatuses[strings.ToLower(strings.TrimSpace(inventoryStatus))]
}

func parseInventoryStatuses(v string) map[string]bool {
	if strings.TrimSpace(v) == "" {
		v = "empty"
	}
	out := map[string]bool{}
	for _, part := range strings.Split(v, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		switch part {
		case "healthy", "degraded", "stale", "empty", "none":
			out[part] = true
		}
	}
	return out
}

func severityRank(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}
