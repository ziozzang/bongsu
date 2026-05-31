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
	serverURL string
	apiKey    string
	client    *http.Client
}

func (r *Reporter) ClaimScanRequest(hostID string) (*models.ScanRequest, error) {
	req, err := http.NewRequest("POST", r.serverURL+"/api/agent/scan-requests/claim?host_id="+url.QueryEscape(hostID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", r.apiKey)
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

func New(serverURL, apiKey string) *Reporter {
	return &Reporter{
		serverURL: serverURL,
		apiKey:    apiKey,
		client:    &http.Client{Timeout: 5 * time.Minute},
	}
}

func (r *Reporter) Send(report *models.ScanReport) error {
	body, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}

	req, err := http.NewRequest("POST", r.serverURL+"/api/report", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", r.apiKey)

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("send report: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
