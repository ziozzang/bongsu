package main

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestEnvPositiveIntFallsBackForInvalidValues(t *testing.T) {
	for _, value := range []string{"", "0", "-1", "invalid"} {
		t.Setenv("BONGSU_TEST_POSITIVE_INT", value)
		if got := envPositiveInt("BONGSU_TEST_POSITIVE_INT", 10); got != 10 {
			t.Fatalf("envPositiveInt(%q) = %d, want 10", value, got)
		}
	}

	t.Setenv("BONGSU_TEST_POSITIVE_INT", "42")
	if got := envPositiveInt("BONGSU_TEST_POSITIVE_INT", 10); got != 42 {
		t.Fatalf("envPositiveInt valid = %d, want 42", got)
	}
}

func TestNewHTTPServerUsesConfiguredTimeoutsAndHeaderLimit(t *testing.T) {
	t.Setenv("BONGSU_HTTP_READ_HEADER_TIMEOUT_SECONDS", "3")
	t.Setenv("BONGSU_HTTP_READ_TIMEOUT_SECONDS", "31")
	t.Setenv("BONGSU_HTTP_WRITE_TIMEOUT_SECONDS", "121")
	t.Setenv("BONGSU_HTTP_IDLE_TIMEOUT_SECONDS", "122")
	t.Setenv("BONGSU_HTTP_MAX_HEADER_BYTES", "2048")

	srv := newHTTPServer(9090, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	if srv.Addr != ":9090" {
		t.Fatalf("addr = %q", srv.Addr)
	}
	if srv.ReadHeaderTimeout != 3*time.Second {
		t.Fatalf("read header timeout = %s", srv.ReadHeaderTimeout)
	}
	if srv.ReadTimeout != 31*time.Second {
		t.Fatalf("read timeout = %s", srv.ReadTimeout)
	}
	if srv.WriteTimeout != 121*time.Second {
		t.Fatalf("write timeout = %s", srv.WriteTimeout)
	}
	if srv.IdleTimeout != 122*time.Second {
		t.Fatalf("idle timeout = %s", srv.IdleTimeout)
	}
	if srv.MaxHeaderBytes != 2048 {
		t.Fatalf("max header bytes = %d", srv.MaxHeaderBytes)
	}
}

func TestValidateServerSecretsRejectsMissingRequiredSecrets(t *testing.T) {
	t.Setenv("BONGSU_ALLOW_WEAK_SECRETS", "false")

	if err := validateServerSecrets(); err == nil {
		t.Fatal("missing server secrets should be rejected")
	}
}

func TestValidateServerSecretsRejectsWeakPlaceholders(t *testing.T) {
	t.Setenv("BONGSU_API_KEY", "change-me-to-a-strong-random-string")
	t.Setenv("BONGSU_AGENT_API_KEY", "agent-key-0123456789")
	t.Setenv("BONGSU_INSTALL_TOKEN", "install-token-0123456789")
	t.Setenv("BONGSU_ALLOW_WEAK_SECRETS", "false")

	if err := validateServerSecrets(); err == nil {
		t.Fatal("placeholder secrets should be rejected")
	}
}

func TestValidateServerSecretsRejectsDuplicateAdminAndAgentKeys(t *testing.T) {
	shared := "bongsu-shared-key-0123456789"
	t.Setenv("BONGSU_API_KEY", shared)
	t.Setenv("BONGSU_AGENT_API_KEY", shared)
	t.Setenv("BONGSU_INSTALL_TOKEN", "bongsu-install-token-0123456789")
	t.Setenv("BONGSU_ALLOW_WEAK_SECRETS", "false")

	if err := validateServerSecrets(); err == nil {
		t.Fatal("agent key must be distinct from admin key")
	}
}

func TestValidateServerSecretsAllowsStrongDistinctKeys(t *testing.T) {
	t.Setenv("BONGSU_API_KEY", "bongsu-admin-0123456789abcdef")
	t.Setenv("BONGSU_AGENT_API_KEY", "bongsu-agent-0123456789abcdef")
	t.Setenv("BONGSU_INSTALL_TOKEN", "bongsu-install-0123456789abcdef")
	t.Setenv("BONGSU_ALLOW_WEAK_SECRETS", "false")

	if err := validateServerSecrets(); err != nil {
		t.Fatalf("strong distinct secrets rejected: %v", err)
	}
}

func TestValidateServerSecretsAllowsExplicitWeakOverride(t *testing.T) {
	t.Setenv("BONGSU_API_KEY", "change-me")
	t.Setenv("BONGSU_AGENT_API_KEY", "change-me")
	t.Setenv("BONGSU_INSTALL_TOKEN", "change-me")
	t.Setenv("BONGSU_ALLOW_WEAK_SECRETS", "true")

	if err := validateServerSecrets(); err != nil {
		t.Fatalf("explicit weak-secret override rejected: %v", err)
	}
}

func TestMainStartsHTTPListenerBeforeBackgroundSecuritySync(t *testing.T) {
	out, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		`net.Listen("tcp", httpServer.Addr)`,
		`httpServer.Serve(listener)`,
		`go secMgr.Start(bgCtx)`,
		`BONGSU_SECURITY_DB_SYNC_ON_START`,
		`BONGSU_DB_CONNECT_TIMEOUT_SECONDS`,
		`BONGSU_DB_MIGRATION_TIMEOUT_SECONDS`,
		`database.RunMigrations(migrationCtx)`,
		`BONGSU_CVE_AFFECTED_INDEX_REBUILD_TIMEOUT_SECONDS`,
		`database.EnsureCveAffectedPackages(indexCtx)`,
		`BONGSU_STARTUP_RECALC_TIMEOUT_SECONDS`,
		`database.EnrichVulnerabilities(recalcCtx)`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("startup ordering missing %q", want)
		}
	}
	if strings.Index(body, `httpServer.Serve(listener)`) > strings.Index(body, `go secMgr.Start(bgCtx)`) {
		t.Fatal("security DB startup sync must begin only after the HTTP listener is accepting requests")
	}
}
