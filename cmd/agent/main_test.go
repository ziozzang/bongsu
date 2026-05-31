package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestAppendCollectionErrorBoundsReportErrors(t *testing.T) {
	errs := []string{}
	longErr := strings.Repeat("x", maxCollectionErrorBytes+20)

	errs = appendCollectionError(errs, "users", nil)
	if len(errs) != 0 {
		t.Fatalf("nil error changed slice: %#v", errs)
	}

	errs = appendCollectionError(errs, "users", errors.New("permission denied"))
	if len(errs) != 1 || errs[0] != "users: permission denied" {
		t.Fatalf("plain error = %#v", errs)
	}

	errs = appendCollectionError(errs, "trivy_host", errors.New(longErr))
	if len(errs) != 2 {
		t.Fatalf("error count = %d, want 2", len(errs))
	}
	if !strings.HasPrefix(errs[1], "trivy_host: ") || !strings.HasSuffix(errs[1], "...(truncated)") {
		t.Fatalf("bounded error has unexpected shape: %q", errs[1])
	}

	errs = appendCollectionError(nil, "osquery", errors.New(strings.Repeat("한", maxCollectionErrorBytes)))
	if !utf8.ValidString(errs[0]) {
		t.Fatalf("truncated unicode error is not valid UTF-8: %q", errs[0])
	}

	for i := 0; i < maxCollectionErrors+5; i++ {
		errs = appendCollectionError(errs, "container", errors.New("scan failed"))
	}
	if len(errs) != maxCollectionErrors {
		t.Fatalf("error count = %d, want %d", len(errs), maxCollectionErrors)
	}
	if errs[maxCollectionErrors-1] != "additional collection errors omitted" {
		t.Fatalf("overflow marker missing: %q", errs[maxCollectionErrors-1])
	}
}

func TestLoadConfigReadsAgentToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("server_url: http://server\napi_key: key\nagent_token: token-123\nwork_dir: /tmp/bongsu\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentToken != "token-123" {
		t.Fatalf("agent token = %q", cfg.AgentToken)
	}
}

func TestEnsureAgentTokenPersistsToken(t *testing.T) {
	dir := t.TempDir()
	first, err := ensureAgentToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) < 32 {
		t.Fatalf("token too short: %q", first)
	}
	info, err := os.Stat(filepath.Join(dir, "agent.token"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("agent token mode = %v, want 0600", info.Mode().Perm())
	}
	second, err := ensureAgentToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatalf("token was not persisted: %q != %q", second, first)
	}
}
