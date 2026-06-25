package intel

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// MCPServer exposes Bongsu's read-only intelligence tools over the Model Context
// Protocol (newline-delimited JSON-RPC 2.0 on stdio). The jikji agent loads it
// via `jikjictl ... --tools-from "bongsu intel-mcp --run-id <id>"` and calls the
// tools autonomously during a run. Every tools/call is scope-checked (the run's
// RBAC snapshot) and audited; tools are read-only. This is the single,
// centralized policy+audit chokepoint for the intelligence layer's data access.
type MCPServer struct {
	reg     *Registry
	scope   *Scope
	name    string
	version string
	// audit is called after every tools/call (nil = no audit sink). seq is a
	// per-server monotonic counter.
	audit    func(seq int, tool string, args, result []byte, isErr bool, dur time.Duration)
	seq      int
	maxBytes int
}

// NewMCPServer builds a server bound to a registry and the caller scope.
func NewMCPServer(reg *Registry, scope *Scope) *MCPServer {
	return &MCPServer{reg: reg, scope: scope, name: "bongsu", version: "0.1.0", maxBytes: 64 * 1024}
}

// WithAudit sets the audit sink and returns the server (chainable).
func (m *MCPServer) WithAudit(fn func(seq int, tool string, args, result []byte, isErr bool, dur time.Duration)) *MCPServer {
	m.audit = fn
	return m
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve runs the JSON-RPC stdio loop until the reader is exhausted or ctx is
// cancelled. Notifications (no id) get no reply; requests get exactly one.
func (m *MCPServer) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	enc := json.NewEncoder(w)
	for sc.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		resp, isNotification := m.dispatch(ctx, req)
		if isNotification {
			continue
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return sc.Err()
}

func (m *MCPServer) dispatch(ctx context.Context, req rpcRequest) (rpcResponse, bool) {
	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		resp.Result = map[string]any{
			"protocolVersion": "2024-11-05",
			"serverInfo":      map[string]string{"name": m.name, "version": m.version},
			"capabilities":    map[string]any{"tools": map[string]any{}},
		}
	case "notifications/initialized":
		return resp, true // notification, no reply
	case "tools/list":
		resp.Result = map[string]any{"tools": m.reg.Describe()}
	case "tools/call":
		resp.Result = m.handleToolCall(ctx, req.Params)
	default:
		if len(req.ID) == 0 {
			return resp, true // unknown notification
		}
		resp.Error = &rpcError{Code: -32601, Message: "method not found: " + req.Method}
	}
	return resp, false
}

// handleToolCall enforces scope, executes the tool, audits, and renders the MCP
// content result. An error becomes an isError text result (the model sees the
// failure) rather than a transport error.
func (m *MCPServer) handleToolCall(ctx context.Context, params json.RawMessage) map[string]any {
	var call struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(params, &call); err != nil {
		return errorContent("invalid tools/call params")
	}
	m.seq++
	seq := m.seq
	rawArgs, _ := json.Marshal(call.Arguments)

	start := time.Now()
	out, err := m.reg.Call(ctx, m.scope, call.Name, call.Arguments)
	dur := time.Since(start)

	isErr := err != nil
	text := out
	if isErr {
		text = err.Error()
	}
	if m.audit != nil {
		m.audit(seq, call.Name, rawArgs, []byte(text), isErr, dur)
	}
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isErr,
	}
}

func errorContent(msg string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": msg}},
		"isError": true,
	}
}

// ToolError is a sentinel a tool handler can return to signal a clean,
// model-visible failure (vs a transport error).
func ToolError(format string, a ...any) error { return fmt.Errorf(format, a...) }
