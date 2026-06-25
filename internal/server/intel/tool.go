package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Tool is one capability the intelligence layer can expose to a backbone agent
// run. The shape is MCP-aligned (name, description, JSON input schema, call) so
// the same registry can back either an in-process Bongsu agent loop or an
// external MCP server that jikji loads via --tools-from.
//
// Invariants every Tool must uphold:
//   - READ-ONLY: a tool never mutates state. The intelligence layer reasons over
//     Bongsu's data; it does not act on it without a separate, audited path.
//   - SCOPE-BOUND: a tool reads only what the caller's RBAC scope permits. The
//     scope rides in the context (ScopeFromContext); a tool that touches
//     host/asset data MUST filter by it, never widening access.
type Tool interface {
	Name() string
	Description() string
	// InputSchema is a JSON Schema object describing the tool's arguments.
	InputSchema() json.RawMessage
	// Call executes the tool. args is the decoded argument object; the return is
	// the tool result rendered as text (JSON or prose) for the model.
	Call(ctx context.Context, args map[string]any) (string, error)
}

// Scope is the caller's authorization context carried into tool calls. It mirrors
// the RBAC subjects/admin the API resolves per request, so a tool can constrain
// its reads to what the caller may see. A nil Scope means "no access" — tools
// must treat it as deny, not allow.
type Scope struct {
	Admin    bool
	Subjects []string
}

type scopeKey struct{}

// WithScope attaches the caller scope to a context for tool calls.
func WithScope(ctx context.Context, s *Scope) context.Context {
	return context.WithValue(ctx, scopeKey{}, s)
}

// ScopeFromContext returns the caller scope, or nil (deny) when absent.
func ScopeFromContext(ctx context.Context) *Scope {
	if s, ok := ctx.Value(scopeKey{}).(*Scope); ok {
		return s
	}
	return nil
}

// Allows reports whether the scope grants access to a resource owned by the
// given subjects. Admin sees everything; otherwise at least one subject must
// intersect. An empty resource-subject set is treated as unrestricted-read
// (catalog/reference data), not host data.
func (s *Scope) Allows(resourceSubjects []string) bool {
	if s == nil {
		return false
	}
	if s.Admin {
		return true
	}
	if len(resourceSubjects) == 0 {
		return true
	}
	have := make(map[string]bool, len(s.Subjects))
	for _, sub := range s.Subjects {
		have[strings.ToLower(strings.TrimSpace(sub))] = true
	}
	for _, rs := range resourceSubjects {
		if have[strings.ToLower(strings.TrimSpace(rs))] {
			return true
		}
	}
	return false
}

// Registry is a concurrency-safe set of tools keyed by name.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]Tool
}

// NewRegistry builds an empty registry.
func NewRegistry() *Registry { return &Registry{tools: map[string]Tool{}} }

// Register adds a tool, replacing any prior tool of the same name.
func (r *Registry) Register(t Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[t.Name()] = t
}

// Names returns the registered tool names, sorted.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.tools))
	for n := range r.tools {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ToolDescriptor is the wire description of a tool (MCP tools/list shape).
type ToolDescriptor struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// Describe returns the descriptors for all tools, sorted by name — the payload an
// MCP server or an in-process agent advertises to the model.
func (r *Registry) Describe() []ToolDescriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ToolDescriptor, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, ToolDescriptor{Name: t.Name(), Description: t.Description(), InputSchema: t.InputSchema()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Call dispatches to the named tool with the caller scope attached. A missing
// scope is a deny: the call fails rather than running unscoped.
func (r *Registry) Call(ctx context.Context, scope *Scope, name string, args map[string]any) (string, error) {
	if scope == nil {
		return "", fmt.Errorf("intel: tool %q called without a caller scope", name)
	}
	r.mu.RLock()
	t, ok := r.tools[name]
	r.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("intel: unknown tool %q", name)
	}
	return t.Call(WithScope(ctx, scope), args)
}

// argString is a helper for tool implementations to read a string argument.
func argString(args map[string]any, key string) string {
	if v, ok := args[key]; ok {
		if s, ok := v.(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}
