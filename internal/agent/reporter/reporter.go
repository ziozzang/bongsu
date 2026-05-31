package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

type Reporter struct {
	serverURL  string
	apiKey     string
	agentToken string
	client     *http.Client
}

type ReportResult struct {
	Status           string `json:"status"`
	ScanID           string `json:"scan_id"`
	ScanStatus       string `json:"scan_status"`
	InventoryStatus  string `json:"inventory_status"`
	IngestErrorCount int    `json:"ingest_error_count"`
	SkippedVulnCount int    `json:"skipped_vuln_count"`
}

func (r *Reporter) ClaimScanRequest(hostID string) (*models.ScanRequest, error) {
	req, err := http.NewRequest("POST", r.serverURL+"/api/agent/scan-requests/claim?host_id="+url.QueryEscape(hostID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", r.apiKey)
	r.setAgentIdentityHeaders(req, hostID)
	resp, err := r.client.Do(req)
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
	resp, err := r.client.Do(req)
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
	body, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("marshal report: %w", err)
	}

	req, err := http.NewRequest("POST", r.serverURL+"/api/report", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", r.apiKey)
	r.setAgentIdentityHeaders(req, report.Host.ID)

	resp, err := r.client.Do(req)
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
