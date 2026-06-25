package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// echoTool is a trivial read-only tool: it returns its "msg" argument, and
// denies access to any resource owned by subjects the scope lacks.
type echoTool struct{ restrictedTo []string }

func (echoTool) Name() string        { return "echo" }
func (echoTool) Description() string { return "echo the msg argument" }
func (echoTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"msg":{"type":"string"}}}`)
}
func (e echoTool) Call(ctx context.Context, args map[string]any) (string, error) {
	if s := ScopeFromContext(ctx); !s.Allows(e.restrictedTo) {
		return "", ToolError("forbidden: caller scope may not access this resource")
	}
	return "echo:" + argString(args, "msg"), nil
}

func runMCP(t *testing.T, scope *Scope, reg *Registry, requests ...string) []map[string]any {
	t.Helper()
	in := strings.NewReader(strings.Join(requests, "\n") + "\n")
	var out bytes.Buffer
	var audited []string
	srv := NewMCPServer(reg, scope).WithAudit(func(seq int, tool string, args, result []byte, isErr bool, dur time.Duration) {
		audited = append(audited, tool)
	})
	if err := srv.Serve(context.Background(), in, &out); err != nil {
		t.Fatalf("serve: %v", err)
	}
	var resps []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("decode response %q: %v", line, err)
		}
		resps = append(resps, m)
	}
	return resps
}

func TestMCPInitializeAndList(t *testing.T) {
	reg := NewRegistry()
	reg.Register(echoTool{})
	resps := runMCP(t, &Scope{Admin: true}, reg,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
	)
	// initialize + tools/list reply; the notification gets no reply -> 2 responses.
	if len(resps) != 2 {
		t.Fatalf("want 2 responses (notification silent), got %d: %+v", len(resps), resps)
	}
	init := resps[0]["result"].(map[string]any)
	if init["protocolVersion"] != "2024-11-05" {
		t.Fatalf("initialize result wrong: %+v", init)
	}
	list := resps[1]["result"].(map[string]any)
	tools := list["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["name"] != "echo" {
		t.Fatalf("tools/list wrong: %+v", tools)
	}
}

func TestMCPToolCallScopeAllowed(t *testing.T) {
	reg := NewRegistry()
	reg.Register(echoTool{restrictedTo: []string{"user:alice"}})
	resps := runMCP(t, &Scope{Subjects: []string{"user:alice"}}, reg,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hi"}}}`,
	)
	res := resps[0]["result"].(map[string]any)
	if res["isError"].(bool) {
		t.Fatalf("authorized call must succeed: %+v", res)
	}
	content := res["content"].([]any)[0].(map[string]any)
	if content["text"] != "echo:hi" {
		t.Fatalf("tool output wrong: %+v", content)
	}
}

// The adversarial case: a caller whose scope does not cover the resource gets a
// model-visible forbidden error — the MCP server is the policy chokepoint.
func TestMCPToolCallScopeDenied(t *testing.T) {
	reg := NewRegistry()
	reg.Register(echoTool{restrictedTo: []string{"user:alice"}})
	resps := runMCP(t, &Scope{Subjects: []string{"user:bob"}}, reg,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hi"}}}`,
	)
	res := resps[0]["result"].(map[string]any)
	if !res["isError"].(bool) {
		t.Fatalf("out-of-scope call must be denied: %+v", res)
	}
	content := res["content"].([]any)[0].(map[string]any)
	if !strings.Contains(content["text"].(string), "forbidden") {
		t.Fatalf("denial must be model-visible: %+v", content)
	}
}

func TestMCPUnknownMethod(t *testing.T) {
	reg := NewRegistry()
	resps := runMCP(t, &Scope{Admin: true}, reg,
		`{"jsonrpc":"2.0","id":9,"method":"nonsense","params":{}}`,
	)
	if resps[0]["error"] == nil {
		t.Fatalf("unknown method must return an error: %+v", resps[0])
	}
}
