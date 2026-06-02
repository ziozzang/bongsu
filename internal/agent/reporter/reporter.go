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
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

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

func (r *Reporter) doWithRetry(fn func() (*http.Response, error)) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt < r.retry.maxAttempts; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			if backoff > r.retry.maxBackoff {
				backoff = r.retry.maxBackoff
			}
			jitter := time.Duration(r.rng.Int63n(int64(backoff) / 2))
			backoff += jitter
			time.Sleep(backoff)
		}
		resp, err := fn()
		if err != nil {
			lastErr = err
			continue
		}
		if shouldRetryHTTP(resp.StatusCode) {
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
		body, _ := io.ReadAll(resp.Body)
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
		respBody, _ := io.ReadAll(resp.Body)
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
		respBody, _ := io.ReadAll(resp.Body)
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
