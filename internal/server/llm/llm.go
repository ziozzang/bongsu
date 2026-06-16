// Package llm is a small, dependency-free client abstraction over LLM providers
// used for AI-assisted vulnerability analysis. It supports Anthropic and any
// OpenAI-compatible endpoint (OpenAI, Ollama, vLLM, LocalAI), so on-prem /
// air-gapped deployments can point at a local model and never send asset or
// vulnerability data to an external service. Disabled by default.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Provider string

const (
	ProviderNone      Provider = "none"
	ProviderAnthropic Provider = "anthropic"
	ProviderOpenAI    Provider = "openai" // also covers Ollama / vLLM / LocalAI (OpenAI-compatible)
)

// Config configures the LLM client. All fields come from BONGSU_LLM_* env vars
// (resolved by the caller); the package itself reads no globals.
type Config struct {
	Provider  Provider
	BaseURL   string // override; defaults to the provider's public endpoint
	Model     string
	APIKey    string
	MaxTokens int
	Timeout   time.Duration
}

// Client talks to the configured provider.
type Client struct {
	cfg  Config
	http *http.Client
}

func New(cfg Config) *Client {
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 1024
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}
	return &Client{cfg: cfg, http: &http.Client{Timeout: cfg.Timeout}}
}

// Enabled reports whether the client is configured to make calls.
func (c *Client) Enabled() bool {
	if c == nil {
		return false
	}
	switch c.cfg.Provider {
	case ProviderAnthropic, ProviderOpenAI:
		return strings.TrimSpace(c.cfg.Model) != ""
	default:
		return false
	}
}

func (c *Client) Provider() string {
	if c == nil {
		return string(ProviderNone)
	}
	return string(c.cfg.Provider)
}

func (c *Client) Model() string {
	if c == nil {
		return ""
	}
	return c.cfg.Model
}

// Complete sends a system + user prompt and returns the model's text reply. The
// caller is responsible for instructing a JSON response and parsing it (so the
// path works uniformly across providers, including local models without a
// structured-output mode).
func (c *Client) Complete(ctx context.Context, system, user string) (string, error) {
	if !c.Enabled() {
		return "", fmt.Errorf("llm: provider %q not enabled", c.cfg.Provider)
	}
	switch c.cfg.Provider {
	case ProviderAnthropic:
		return c.completeAnthropic(ctx, system, user)
	case ProviderOpenAI:
		return c.completeOpenAI(ctx, system, user)
	default:
		return "", fmt.Errorf("llm: unsupported provider %q", c.cfg.Provider)
	}
}

func (c *Client) completeAnthropic(ctx context.Context, system, user string) (string, error) {
	base := strings.TrimRight(c.cfg.BaseURL, "/")
	if base == "" {
		base = "https://api.anthropic.com"
	}
	body, _ := json.Marshal(map[string]any{
		"model":      c.cfg.Model,
		"max_tokens": c.cfg.MaxTokens,
		"system":     system,
		"messages":   []map[string]any{{"role": "user", "content": user}},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.cfg.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	raw, err := c.do(req)
	if err != nil {
		return "", err
	}
	var out struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("llm: decode anthropic response: %w", err)
	}
	if out.Error != nil {
		return "", fmt.Errorf("llm: anthropic error: %s", out.Error.Message)
	}
	var b strings.Builder
	for _, c := range out.Content {
		b.WriteString(c.Text)
	}
	return b.String(), nil
}

func (c *Client) completeOpenAI(ctx context.Context, system, user string) (string, error) {
	base := strings.TrimRight(c.cfg.BaseURL, "/")
	if base == "" {
		base = "https://api.openai.com/v1"
	}
	body, _ := json.Marshal(map[string]any{
		"model":       c.cfg.Model,
		"max_tokens":  c.cfg.MaxTokens,
		"temperature": 0,
		"messages": []map[string]any{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}
	raw, err := c.do(req)
	if err != nil {
		return "", err
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("llm: decode openai response: %w", err)
	}
	if out.Error != nil {
		return "", fmt.Errorf("llm: openai error: %s", out.Error.Message)
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("llm: empty openai response")
	}
	return out.Choices[0].Message.Content, nil
}

func (c *Client) do(req *http.Request) ([]byte, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("llm: request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("llm: provider returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}

// ExtractJSON returns the first balanced top-level JSON object in s. Models often
// wrap JSON in prose or code fences; this recovers the object robustly.
func ExtractJSON(s string) (json.RawMessage, error) {
	start := strings.IndexByte(s, '{')
	if start < 0 {
		return nil, fmt.Errorf("llm: no JSON object in response")
	}
	depth := 0
	inStr := false
	esc := false
	for i := start; i < len(s); i++ {
		ch := s[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case ch == '\\':
				esc = true
			case ch == '"':
				inStr = false
			}
			continue
		}
		switch ch {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return json.RawMessage(s[start : i+1]), nil
			}
		}
	}
	return nil, fmt.Errorf("llm: unbalanced JSON in response")
}
