package main

import "testing"

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
