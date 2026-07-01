package intel

import "testing"

// TestPipelineRegistry verifies the built-in pipelines register, describe, and
// resolve — and, critically, that every stage references a scenario that
// actually exists. A pipeline pointing at an unknown scenario would only fail at
// run time, so this guards the code-registered set at build/test time.
func TestPipelineRegistry(t *testing.T) {
	pl := NewPipelineRegistry()
	RegisterPipelines(pl)

	sc := NewScenarioRegistry()
	RegisterScenarios(sc)

	names := pl.Names()
	if len(names) == 0 {
		t.Fatal("expected built-in pipelines")
	}
	// "audit" is the canonical find -> verify -> report chain.
	audit, ok := pl.Get("audit")
	if !ok {
		t.Fatal("audit pipeline must be registered")
	}
	want := []string{"triage", "verify", "report"}
	if len(audit.Scenarios) != len(want) {
		t.Fatalf("audit stages = %v, want %v", audit.Scenarios, want)
	}
	for i, s := range want {
		if audit.Scenarios[i] != s {
			t.Fatalf("audit stage %d = %q, want %q", i, audit.Scenarios[i], s)
		}
	}

	// Every stage of every pipeline must reference a real scenario.
	for _, info := range pl.Describe() {
		if info.Description == "" {
			t.Errorf("pipeline %q has no description", info.Name)
		}
		if len(info.Scenarios) == 0 {
			t.Errorf("pipeline %q has no stages", info.Name)
		}
		if len(info.Scenarios) > maxPipelineStages {
			t.Errorf("pipeline %q exceeds %d stages", info.Name, maxPipelineStages)
		}
		for _, stage := range info.Scenarios {
			if _, ok := sc.Get(stage); !ok {
				t.Errorf("pipeline %q references unknown scenario %q", info.Name, stage)
			}
		}
	}

	// Unknown name resolves to not-found.
	if _, ok := pl.Get("does-not-exist"); ok {
		t.Fatal("unknown pipeline must not resolve")
	}
}

// TestRunNamedPipelineUnknown verifies the API-facing entrypoint rejects an
// unregistered pipeline name without touching the backbone.
func TestRunNamedPipelineUnknown(t *testing.T) {
	t.Setenv("BONGSU_INTEL_JIKJI_URL", "http://127.0.0.1:1") // enabled but unused
	svc := NewServiceFromEnv(nil)
	defer svc.Close()
	if _, err := svc.RunNamedPipeline(nil, "arbitrary-user-dag", nil, "u", &Scope{Admin: true}); err == nil {
		t.Fatal("unknown pipeline name must be rejected before any backbone call")
	}
}
