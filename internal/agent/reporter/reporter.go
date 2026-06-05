package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

const maxErrorResponseBodyBytes = 16 << 10

type retryConfig struct {
	maxAttempts int
	maxBackoff  time.Duration
}

type Reporter struct {
	serverURL  string
	apiKey     string
	agentToken string
	client     *http.Client
	retry      retryConfig
	rng        *rand.Rand
	sleep      func(time.Duration)
}

type ReportResult struct {
	Status           string `json:"status"`
	ScanID           string `json:"scan_id"`
	ScanStatus       string `json:"scan_status"`
	InventoryStatus  string `json:"inventory_status"`
	IngestErrorCount int    `json:"ingest_error_count"`
	SkippedVulnCount int    `json:"skipped_vuln_count"`
}

func retryConfigFromEnv() retryConfig {
	attempts := 5
	if v := os.Getenv("BONGSU_AGENT_RETRY_ATTEMPTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			attempts = n
		}
	}
	maxBackoff := 30 * time.Second
	if v := os.Getenv("BONGSU_AGENT_RETRY_MAX_BACKOFF_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxBackoff = time.Duration(n) * time.Second
		}
	}
	return retryConfig{maxAttempts: attempts, maxBackoff: maxBackoff}
}

func shouldRetryHTTP(statusCode int) bool {
	return statusCode == http.StatusTooManyRequests || statusCode >= 500
}

func retryAfterDelay(header string, now time.Time) (time.Duration, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(header); err == nil {
		if seconds < 0 {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}
	when, err := http.ParseTime(header)
	if err != nil {
		return 0, false
	}
	delay := when.Sub(now)
	if delay < 0 {
		delay = 0
	}
	return delay, true
}

func (r *Reporter) boundedBackoff(delay time.Duration) time.Duration {
	if delay > r.retry.maxBackoff {
		return r.retry.maxBackoff
	}
	return delay
}

func (r *Reporter) exponentialBackoff(attempt int) time.Duration {
	if attempt <= 0 {
		attempt = 1
	}
	backoff := time.Duration(1<<uint(attempt-1)) * time.Second
	backoff = r.boundedBackoff(backoff)
	if backoff <= 0 {
		return 0
	}
	jitter := time.Duration(r.rng.Int63n(int64(backoff) / 2))
	return backoff + jitter
}

func (r *Reporter) retryDelay(attempt int, resp *http.Response) time.Duration {
	if resp != nil {
		if delay, ok := retryAfterDelay(resp.Header.Get("Retry-After"), time.Now()); ok {
			return r.boundedBackoff(delay)
		}
	}
	return r.exponentialBackoff(attempt)
}

func (r *Reporter) doWithRetry(fn func() (*http.Response, error)) (*http.Response, error) {
	var lastErr error
	delay := time.Duration(0)
	for attempt := 0; attempt < r.retry.maxAttempts; attempt++ {
		if attempt > 0 {
			r.sleep(delay)
		}
		resp, err := fn()
		if err != nil {
			lastErr = err
			delay = r.retryDelay(attempt+1, nil)
			continue
		}
		if shouldRetryHTTP(resp.StatusCode) {
			delay = r.retryDelay(attempt+1, resp)
			resp.Body.Close()
			lastErr = fmt.Errorf("server returned %d", resp.StatusCode)
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("after %d attempts: %w", r.retry.maxAttempts, lastErr)
}

func (r *Reporter) ClaimScanRequest(hostID string) (*models.ScanRequest, error) {
	req, err := http.NewRequest("POST", r.serverURL+"/api/agent/scan-requests/claim?host_id="+url.QueryEscape(hostID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", r.apiKey)
	r.setAgentIdentityHeaders(req, hostID)
	resp, err := r.doWithRetry(func() (*http.Response, error) {
		return r.client.Do(req.Clone(req.Context()))
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body := readBoundedErrorBody(resp.Body)
		return nil, fmt.Errorf("claim returned %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		Request *models.ScanRequest `json:"request"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Request, nil
}

func (r *Reporter) CompleteScanRequest(id, hostID, status, message string) error {
	body, _ := json.Marshal(map[string]string{"host_id": hostID, "status": status, "message": message})
	req, err := http.NewRequest("POST", r.serverURL+"/api/agent/scan-requests/"+id+"/complete", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", r.apiKey)
	r.setAgentIdentityHeaders(req, hostID)
	resp, err := r.doWithRetry(func() (*http.Response, error) {
		bodyBytes, _ := json.Marshal(map[string]string{"host_id": hostID, "status": status, "message": message})
		reqClone, cloneErr := http.NewRequest("POST", r.serverURL+"/api/agent/scan-requests/"+id+"/complete", bytes.NewReader(bodyBytes))
		if cloneErr != nil {
			return nil, cloneErr
		}
		reqClone.Header.Set("Content-Type", "application/json")
		reqClone.Header.Set("X-API-Key", r.apiKey)
		r.setAgentIdentityHeaders(reqClone, hostID)
		return r.client.Do(reqClone)
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody := readBoundedErrorBody(resp.Body)
		return fmt.Errorf("complete returned %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func New(serverURL, apiKey string, agentToken ...string) *Reporter {
	token := ""
	if len(agentToken) > 0 {
		token = agentToken[0]
	}
	return &Reporter{
		serverURL:  serverURL,
		apiKey:     apiKey,
		agentToken: token,
		client:     &http.Client{Timeout: 5 * time.Minute},
		retry:      retryConfigFromEnv(),
		rng:        rand.New(rand.NewSource(time.Now().UnixNano())),
		sleep:      time.Sleep,
	}
}

func (r *Reporter) setAgentIdentityHeaders(req *http.Request, hostID string) {
	if r.agentToken == "" {
		return
	}
	req.Header.Set("X-Bongsu-Agent-Token", r.agentToken)
	req.Header.Set("X-Bongsu-Host-ID", hostID)
}

func (r *Reporter) Send(report *models.ScanReport) (*ReportResult, error) {
	resp, err := r.doWithRetry(func() (*http.Response, error) {
		bodyBytes, marshalErr := json.Marshal(report)
		if marshalErr != nil {
			return nil, marshalErr
		}
		req, reqErr := http.NewRequest("POST", r.serverURL+"/api/report", bytes.NewReader(bodyBytes))
		if reqErr != nil {
			return nil, reqErr
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", r.apiKey)
		r.setAgentIdentityHeaders(req, report.Host.ID)
		return r.client.Do(req)
	})
	if err != nil {
		return nil, fmt.Errorf("send report: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody := readBoundedErrorBody(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result ReportResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode report response: %w", err)
	}
	if result.ScanStatus == "" {
		result.ScanStatus = "completed"
	}
	return &result, nil
}

func readBoundedErrorBody(body io.Reader) []byte {
	if body == nil {
		return nil
	}
	limited := io.LimitReader(body, maxErrorResponseBodyBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return []byte("failed to read error response")
	}
	if len(data) <= maxErrorResponseBodyBytes {
		return data
	}
	data = data[:maxErrorResponseBodyBytes]
	return append(data, []byte("...(truncated)")...)
}
