package api

import (
	"strings"
	"testing"
)

func TestValidateRuleExprAcceptsValid(t *testing.T) {
	tests := []string{
		"",
		"owner=alice",
		"environment=production",
		"criticality=critical",
		"team=platform",
		"owner=alice,environment=production",
		"tags:tier=frontend",
		"tags:env",
		"environment=staging,tags:tier=backend",
	}
	for _, expr := range tests {
		if err := validateRuleExpr(expr); err != nil {
			t.Fatalf("validateRuleExpr(%q) error: %v", expr, err)
		}
	}
}

func TestValidateRuleExprRejectsInvalid(t *testing.T) {
	tests := []struct {
		expr string
		msg  string
	}{
		{"foo=bar", "unknown field"},
		{"tags:", "empty tag"},
	}
	for _, tt := range tests {
		err := validateRuleExpr(tt.expr)
		if err == nil {
			t.Fatalf("validateRuleExpr(%q) should have failed", tt.expr)
		}
		if !strings.Contains(err.Error(), tt.msg) {
			t.Fatalf("validateRuleExpr(%q) error %q should contain %q", tt.expr, err.Error(), tt.msg)
		}
	}
}

func TestAssetGroupRoutesAreRegistered(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		`"GET /api/asset-groups"`,
		`"POST /api/asset-groups"`,
		`"GET /api/asset-groups/{id}"`,
		`"DELETE /api/asset-groups/{id}"`,
		`"POST /api/asset-groups/{id}/hosts"`,
		`"DELETE /api/asset-groups/{id}/hosts/{hostId}"`,
		`"POST /api/asset-groups/{id}/scan"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("route missing %q", want)
		}
	}
}

func TestAssetGroupHandlersExist(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		"handleListAssetGroups",
		"handleCreateAssetGroup",
		"handleGetAssetGroup",
		"handleDeleteAssetGroup",
		"handleAddHostToAssetGroup",
		"handleRemoveHostFromAssetGroup",
		"handleTriggerAssetGroupScan",
		"validateRuleExpr",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q", want)
		}
	}
}

func TestAssetGroupDBMethodsExist(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		"CreateAssetGroup",
		"GetAssetGroup",
		"ListAssetGroups",
		"DeleteAssetGroup",
		"AddHostToAssetGroup",
		"RemoveHostFromAssetGroup",
		"GetAssetGroupHostIDs",
		"ExpandDynamicGroup",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q", want)
		}
	}
}

func TestAssetGroupCreateRequiresAdminAuth(t *testing.T) {
	out := readAllPackageGoFiles(t)
	idx := strings.Index(out, "func (s *Server) handleCreateAssetGroup")
	if idx < 0 {
		t.Fatal("handleCreateAssetGroup not found")
	}
	body := extractFuncBody(out, idx)
	if !strings.Contains(body, "authenticateAdmin") {
		t.Fatal("handleCreateAssetGroup does not check authenticateAdmin")
	}
}

func TestAssetGroupAddHostRejectsDynamicGroups(t *testing.T) {
	out := readAllPackageGoFiles(t)
	idx := strings.Index(out, "func (s *Server) handleAddHostToAssetGroup")
	if idx < 0 {
		t.Fatal("handleAddHostToAssetGroup not found")
	}
	body := extractFuncBody(out, idx)
	if !strings.Contains(body, "static") {
		t.Fatal("handleAddHostToAssetGroup does not check for static rule type")
	}
}

func TestAssetGroupTriggerScanCreatesRequests(t *testing.T) {
	out := readAllPackageGoFiles(t)
	idx := strings.Index(out, "func (s *Server) handleTriggerAssetGroupScan")
	if idx < 0 {
		t.Fatal("handleTriggerAssetGroupScan not found")
	}
	body := extractFuncBody(out, idx)
	for _, want := range []string{"ExpandDynamicGroup", "GetAssetGroupHostIDs", "CreateScanRequest"} {
		if !strings.Contains(body, want) {
			t.Fatalf("handleTriggerAssetGroupScan missing %q", want)
		}
	}
}
