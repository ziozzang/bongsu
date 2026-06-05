package collector

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestParseDelimitedPackagesSkipsInvalidRows(t *testing.T) {
	pkgs := parseDelimitedPackages([]byte("openssl\t3.0.17-1\tamd64\topenssl\nmissing-version\t\tamd64\t\nbad-row\n"), "dpkg")
	if len(pkgs) != 1 {
		t.Fatalf("packages = %d, want 1: %#v", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "openssl" || pkgs[0].Version != "3.0.17-1" || pkgs[0].Arch != "amd64" || pkgs[0].SrcName != "openssl" || pkgs[0].Source != "dpkg" || pkgs[0].PkgType != "os" {
		t.Fatalf("unexpected package: %#v", pkgs[0])
	}
}

func TestCollectOSQueryPackagesFallsBackToDpkgQuery(t *testing.T) {
	binDir := t.TempDir()
	dpkg := filepath.Join(binDir, "dpkg-query")
	if err := os.WriteFile(dpkg, []byte("#!/bin/sh\nprintf 'openssl\\t3.0.17-1\\tamd64\\topenssl\\n'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	c := New(t.TempDir())
	pkgs, err := c.CollectOSQueryPackages()
	if err != nil {
		t.Fatalf("CollectOSQueryPackages fallback failed: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "openssl" || pkgs[0].Source != "dpkg" {
		t.Fatalf("fallback packages = %#v", pkgs)
	}
}

func TestTrivyPackagesOnlyFlagsFollowSubcommand(t *testing.T) {
	c := New(t.TempDir())
	c.PackagesOnly = true
	cmd := c.trivyCommandContext(context.Background(), "image", "--format", "json", "alpine:latest")
	got := cmd.Args[1:]
	want := []string{"image", "--skip-db-update", "--skip-java-db-update", "--skip-version-check", "--offline-scan", "--scanners", "vuln", "--format", "json", "alpine:latest"}
	if len(got) != len(want) {
		t.Fatalf("args len = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q; all args %#v", i, got[i], want[i], got)
		}
	}
}

func TestTrivyDBRepositoryFlagFollowsSubcommand(t *testing.T) {
	c := New(t.TempDir())
	cmd := c.trivyCommandContext(context.Background(), "fs", "--format", "json", "/")
	got := cmd.Args[1:]
	want := []string{"fs", "--db-repository", defaultDBRepository, "--format", "json", "/"}
	if len(got) != len(want) {
		t.Fatalf("args len = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q; all args %#v", i, got[i], want[i], got)
		}
	}
}

func TestParseSSListeningPorts(t *testing.T) {
	out := []byte(`tcp LISTEN 0 4096 127.0.0.1:5677 0.0.0.0:* users:(("bongsu-server",pid=1674817,fd=7))
udp UNCONN 0 0 [::]:5353 [::]:*
tcp LISTEN 0 4096 [::1]:5678 [::]:* users:(("node",pid=1234,fd=21))
`)
	ports := parseSSListeningPorts(out)
	if len(ports) != 3 {
		t.Fatalf("ports = %d, want 3: %#v", len(ports), ports)
	}
	if ports[0].Protocol != "tcp" || ports[0].Address != "127.0.0.1" || ports[0].Port != 5677 || ports[0].Name != "bongsu-server" || ports[0].PID != 1674817 {
		t.Fatalf("unexpected tcp port: %#v", ports[0])
	}
	if ports[1].Protocol != "udp" || ports[1].Address != "::" || ports[1].Port != 5353 {
		t.Fatalf("unexpected udp port: %#v", ports[1])
	}
	if ports[2].Address != "::1" || ports[2].Name != "node" || ports[2].PID != 1234 {
		t.Fatalf("unexpected ipv6 process port: %#v", ports[2])
	}
}

func TestParseNetstatListeningPorts(t *testing.T) {
	out := []byte(`Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:5677          0.0.0.0:*               LISTEN      1674817/bongsu-server
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
tcp6       0      0 :::5678                 :::*                    LISTEN      1234/node
`)
	ports := parseNetstatListeningPorts(out)
	if len(ports) != 3 {
		t.Fatalf("ports = %d, want 3: %#v", len(ports), ports)
	}
	if ports[0].Protocol != "tcp" || ports[0].Address != "127.0.0.1" || ports[0].Port != 5677 || ports[0].Name != "bongsu-server" || ports[0].PID != 1674817 {
		t.Fatalf("unexpected tcp port: %#v", ports[0])
	}
	if ports[1].Protocol != "udp" || ports[1].Address != "0.0.0.0" || ports[1].Port != 68 || ports[1].Name != "" || ports[1].PID != 0 {
		t.Fatalf("unexpected udp port: %#v", ports[1])
	}
	if ports[2].Protocol != "tcp" || ports[2].Address != "::" || ports[2].Port != 5678 || ports[2].Name != "node" || ports[2].PID != 1234 {
		t.Fatalf("unexpected tcp6 port: %#v", ports[2])
	}
}
