package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

type Reporter struct {
	serverURL string
	apiKey    string
	client    *http.Client
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
