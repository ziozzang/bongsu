package intel

import (
	"encoding/json"
	"testing"
)

func TestValidateScenarioOutput(t *testing.T) {
	schema := json.RawMessage(`{"type":"object","required":["verdict","confidence"]}`)

	// valid object with required fields
	if ok, _ := validateScenarioOutput(schema, `{"verdict":"confirmed","confidence":0.9}`); !ok {
		t.Fatal("valid output must pass")
	}
	// missing a required field
	if ok, reason := validateScenarioOutput(schema, `{"verdict":"confirmed"}`); ok || reason == "" {
		t.Fatalf("missing field must fail with a reason, got ok=%v reason=%q", ok, reason)
	}
	// prose-wrapped / fenced JSON is extracted
	if ok, _ := validateScenarioOutput(schema, "Here is the result:\n```json\n{\"verdict\":\"rejected\",\"confidence\":0.1}\n```"); !ok {
		t.Fatal("fenced JSON must be extracted and pass")
	}
	// not JSON at all
	if ok, _ := validateScenarioOutput(schema, "I could not determine a verdict."); ok {
		t.Fatal("prose-only output must fail")
	}
	// no schema declared -> always valid
	if ok, _ := validateScenarioOutput(nil, "anything"); !ok {
		t.Fatal("no schema must pass")
	}
}
