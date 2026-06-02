package api

import (
	"strings"
	"testing"
)

func TestNotificationRuleRoutesAreRegistered(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		`"GET /api/admin/notification-rules"`,
		`"POST /api/admin/notification-rules"`,
		`"GET /api/admin/notification-rules/{id}"`,
		`"PUT /api/admin/notification-rules/{id}"`,
		`"DELETE /api/admin/notification-rules/{id}"`,
		`"POST /api/admin/notification-rules/{id}/test"`,
		`"GET /api/admin/notification-log"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("route missing %q", want)
		}
	}
}

func TestNotificationRuleHandlersExist(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		"handleListNotificationRules",
		"handleCreateNotificationRule",
		"handleGetNotificationRule",
		"handleUpdateNotificationRule",
		"handleDeleteNotificationRule",
		"handleTestNotificationRule",
		"handleListNotificationLog",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q", want)
		}
	}
}

func TestNotificationRuleDBMethodsExist(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		"CreateNotificationRule",
		"GetNotificationRule",
		"ListNotificationRules",
		"UpdateNotificationRule",
		"DeleteNotificationRule",
		"GetEnabledRulesForEvent",
		"RecordNotificationLog",
		"ListNotificationLog",
		"TouchNotificationRuleTrigger",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q", want)
		}
	}
}

func TestNotificationRulesRequireAdminAuth(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, fn := range []string{"handleCreateNotificationRule", "handleDeleteNotificationRule", "handleTestNotificationRule"} {
		idx := strings.Index(out, "func (s *Server) "+fn)
		if idx < 0 {
			t.Fatalf("%s not found", fn)
		}
		body := extractFuncBody(out, idx)
		if !strings.Contains(body, "authenticateAdmin") {
			t.Fatalf("%s does not check authenticateAdmin", fn)
		}
	}
}

func TestNotificationEngineExists(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		"ruleNotifier",
		"newRuleNotifier",
		"evaluateAndDispatch",
		"matchesConditions",
		"dispatch",
		"dispatchTest",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q", want)
		}
	}
}

func TestNotificationEnvVarsPresent(t *testing.T) {
	out := readAllPackageGoFiles(t)
	for _, want := range []string{
		"BONGSU_NOTIFICATION_DISABLED",
		"BONGSU_NOTIFICATION_TIMEOUT_SECONDS",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing env var %q", want)
		}
	}
}

func TestNotificationEngineTriggeredAfterScan(t *testing.T) {
	out := readAllPackageGoFiles(t)
	if !strings.Contains(out, `evaluateAndDispatch(ctx, "scan.completed"`) {
		t.Fatal("notification engine not triggered after scan completion")
	}
}
