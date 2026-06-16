package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExtractJSON(t *testing.T) {
	cases := []struct {
		in   string
		want string
		err  bool
	}{
		{`{"a":1}`, `{"a":1}`, false},
		{"prose before {\"a\":1,\"b\":\"}{\"} after", `{"a":1,"b":"}{"}`, false},
		{"```json\n{\"x\": {\"y\": 2}}\n```", `{"x": {"y": 2}}`, false},
		{"no json here", "", true},
		{`{"unbalanced": `, "", true},
	}
	for _, c := range cases {
		got, err := ExtractJSON(c.in)
		if c.err {
			if err == nil {
				t.Fatalf("ExtractJSON(%q) expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ExtractJSON(%q) error: %v", c.in, err)
		}
		if string(got) != c.want {
			t.Fatalf("ExtractJSON(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEnabled(t *testing.T) {
	if New(Config{Provider: ProviderNone}).Enabled() {
		t.Fatal("none must be disabled")
	}
	if New(Config{Provider: ProviderOpenAI}).Enabled() {
		t.Fatal("openai without a model must be disabled")
	}
	if !New(Config{Provider: ProviderOpenAI, Model: "m"}).Enabled() {
		t.Fatal("openai with a model must be enabled")
	}
	if !New(Config{Provider: ProviderAnthropic, Model: "claude"}).Enabled() {
		t.Fatal("anthropic with a model must be enabled")
	}
	var nilClient *Client
	if nilClient.Enabled() {
		t.Fatal("nil client must be disabled")
	}
}

func TestCompleteOpenAIRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer k" {
			t.Errorf("missing bearer auth, got %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		if req["model"] != "m" {
			t.Errorf("model not forwarded: %v", req["model"])
		}
		w.Write([]byte(`{"choices":[{"message":{"content":"hello"}}]}`))
	}))
	defer srv.Close()
	c := New(Config{Provider: ProviderOpenAI, BaseURL: srv.URL + "/v1", Model: "m", APIKey: "k"})
	got, err := c.Complete(context.Background(), "sys", "user")
	if err != nil {
		t.Fatal(err)
	}
	if got != "hello" {
		t.Fatalf("got %q", got)
	}
}

func TestCompleteAnthropicRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/messages") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != "k" || r.Header.Get("anthropic-version") == "" {
			t.Errorf("missing anthropic headers")
		}
		w.Write([]byte(`{"content":[{"text":"hi "},{"text":"there"}]}`))
	}))
	defer srv.Close()
	c := New(Config{Provider: ProviderAnthropic, BaseURL: srv.URL, Model: "claude", APIKey: "k"})
	got, err := c.Complete(context.Background(), "sys", "user")
	if err != nil {
		t.Fatal(err)
	}
	if got != "hi there" {
		t.Fatalf("got %q", got)
	}
}

func TestCompleteHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte(`{"error":{"message":"boom"}}`))
	}))
	defer srv.Close()
	c := New(Config{Provider: ProviderOpenAI, BaseURL: srv.URL + "/v1", Model: "m"})
	if _, err := c.Complete(context.Background(), "s", "u"); err == nil {
		t.Fatal("expected error on HTTP 500")
	}
}
