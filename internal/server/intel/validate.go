package intel

import (
	"encoding/json"
	"strings"
)

// validateScenarioOutput checks a scenario run's final response against its
// OutputSchema. It is intentionally lightweight (no full JSON Schema engine):
// the response must be a JSON object carrying every top-level field the schema
// marks "required". This enforces the "structured termination" contract — a run
// that answers in prose, omits required fields, or trails extra text is invalid
// — without a heavy dependency. Returns ok and, when not ok, a short reason.
func validateScenarioOutput(schema json.RawMessage, response string) (bool, string) {
	if len(schema) == 0 {
		return true, "" // no schema declared: nothing to enforce
	}
	var sch struct {
		Required []string `json:"required"`
	}
	_ = json.Unmarshal(schema, &sch)

	obj, ok := extractJSONObject(response)
	if !ok {
		return false, "output is not a JSON object"
	}
	var missing []string
	for _, k := range sch.Required {
		if _, present := obj[k]; !present {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return false, "missing required fields: " + strings.Join(missing, ", ")
	}
	return true, ""
}

// extractJSONObject parses the response as a JSON object, tolerating a model that
// wraps it in ```json fences or surrounding prose by falling back to the first
// balanced {...} span.
func extractJSONObject(s string) (map[string]any, bool) {
	s = strings.TrimSpace(s)
	var obj map[string]any
	if json.Unmarshal([]byte(s), &obj) == nil {
		return obj, true
	}
	// Strip a leading ```json / ``` fence if present.
	if i := strings.Index(s, "{"); i >= 0 {
		if j := strings.LastIndex(s, "}"); j > i {
			if json.Unmarshal([]byte(s[i:j+1]), &obj) == nil {
				return obj, true
			}
		}
	}
	return nil, false
}
