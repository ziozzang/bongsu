package collector

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// parseApkPackages
//
// parseApkPackages splits on the LAST hyphen in the line:
//   "busybox-1.36.1-r0"  → name="busybox-1.36.1"  version="r0"
//   "musl-1.2.4-r2"      → name="musl-1.2.4"       version="r2"
// This mirrors the implementation (strings.LastIndex(line, "-")).
// ---------------------------------------------------------------------------

func TestParseApkPackages(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantLen     int
		wantName    string
		wantVersion string
		wantSource  string
	}{
		{
			// Last hyphen splits: "busybox-1.36.1" / "r0"
			name:        "typical alpine package",
			input:       "busybox-1.36.1-r0\n",
			wantLen:     1,
			wantName:    "busybox-1.36.1",
			wantVersion: "r0",
			wantSource:  "apk",
		},
		{
			// underscore in name — last hyphen still the only split point
			name:        "package with underscore in name",
			input:       "ssl_client-1.36.1-r0\n",
			wantLen:     1,
			wantName:    "ssl_client-1.36.1",
			wantVersion: "r0",
			wantSource:  "apk",
		},
		{
			// multiple hyphens — last one splits
			name:        "package with multiple hyphens",
			input:       "ca-certificates-bundle-20230506-r0\n",
			wantLen:     1,
			wantName:    "ca-certificates-bundle-20230506",
			wantVersion: "r0",
			wantSource:  "apk",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkgs := parseApkPackages([]byte(tc.input))
			if len(pkgs) != tc.wantLen {
				t.Fatalf("len = %d, want %d: %#v", len(pkgs), tc.wantLen, pkgs)
			}
			if tc.wantLen == 0 {
				return
			}
			p := pkgs[0]
			if p.Name != tc.wantName {
				t.Errorf("Name = %q, want %q", p.Name, tc.wantName)
			}
			if p.Version != tc.wantVersion {
				t.Errorf("Version = %q, want %q", p.Version, tc.wantVersion)
			}
			if p.Source != tc.wantSource {
				t.Errorf("Source = %q, want %q", p.Source, tc.wantSource)
			}
			if p.PkgType != "os" {
				t.Errorf("PkgType = %q, want %q", p.PkgType, "os")
			}
		})
	}
}

func TestParseApkPackages_MultipleLines(t *testing.T) {
	// Three packages; verify count and that Source/PkgType are set.
	input := "musl-1.2.4-r2\nbusybox-1.36.1-r0\nzlib-1.3.1-r0\n"
	pkgs := parseApkPackages([]byte(input))
	if len(pkgs) != 3 {
		t.Fatalf("len = %d, want 3: %#v", len(pkgs), pkgs)
	}
	for _, p := range pkgs {
		if p.Source != "apk" {
			t.Errorf("Source = %q, want %q", p.Source, "apk")
		}
		if p.PkgType != "os" {
			t.Errorf("PkgType = %q, want %q", p.PkgType, "os")
		}
	}
}

func TestParseApkPackages_EmptyInput(t *testing.T) {
	pkgs := parseApkPackages([]byte(""))
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages for empty input, got %d", len(pkgs))
	}
}

func TestParseApkPackages_SkipsMalformedLines(t *testing.T) {
	// "nohyphen" → no hyphen → skipped.
	// "-startshyphen" → idx==0 → skipped (idx <= 0 guard).
	// "trailinghyphen-" → hyphen at end → skipped (idx == len-1 guard).
	// "valid-r0" → idx>0, not at end → included.
	input := "nohyphen\n-startshyphen\ntrailinghyphen-\nvalid-r0\n"
	pkgs := parseApkPackages([]byte(input))
	if len(pkgs) != 1 {
		t.Fatalf("len = %d, want 1: %#v", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "valid" {
		t.Errorf("Name = %q, want %q", pkgs[0].Name, "valid")
	}
	if pkgs[0].Version != "r0" {
		t.Errorf("Version = %q, want %q", pkgs[0].Version, "r0")
	}
}

// ---------------------------------------------------------------------------
// normalizeSourcePackageName
// ---------------------------------------------------------------------------

func TestNormalizeSourcePackageName(t *testing.T) {
	tests := []struct {
		name   string
		src    string
		source string
		want   string
	}{
		{
			name:   "dpkg passthrough",
			src:    "openssl",
			source: "dpkg",
			want:   "openssl",
		},
		{
			name:   "rpm strips .src.rpm and release+version",
			src:    "openssl-3.0.7-18.el9_3.src.rpm",
			source: "rpm",
			want:   "openssl",
		},
		{
			name:   "rpm without .src.rpm extension strips last two dash-segments",
			src:    "bash-5.2.15-3.el9",
			source: "rpm",
			want:   "bash",
		},
		{
			name:   "rpm single hyphen still handled",
			src:    "kernel-6.1.0-1",
			source: "rpm",
			want:   "kernel",
		},
		{
			name:   "non-rpm source is unchanged",
			src:    "libssl3-3.0.7-1ubuntu1",
			source: "osquery",
			want:   "libssl3-3.0.7-1ubuntu1",
		},
		{
			name:   "rpm empty string stays empty",
			src:    "",
			source: "rpm",
			want:   "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeSourcePackageName(tc.src, tc.source)
			if got != tc.want {
				t.Errorf("normalizeSourcePackageName(%q, %q) = %q, want %q", tc.src, tc.source, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parsePort
// ---------------------------------------------------------------------------

func TestParsePort(t *testing.T) {
	tests := []struct {
		raw  string
		want int
	}{
		{"80", 80},
		{"443", 443},
		{"0", 0},
		{"65535", 65535},
		{"", 0},
		{"abc", 0},
		{" 8080 ", 8080},
	}
	for _, tc := range tests {
		got := parsePort(tc.raw)
		if got != tc.want {
			t.Errorf("parsePort(%q) = %d, want %d", tc.raw, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// normalizePortProtocol
// ---------------------------------------------------------------------------

func TestNormalizePortProtocol(t *testing.T) {
	tests := []struct {
		proto string
		want  string
	}{
		{"tcp", "tcp"},
		{"tcp6", "tcp"},
		{"TCP", "tcp"},
		{"TCP6", "tcp"},
		{"udp", "udp"},
		{"udp6", "udp"},
		{"UDP", "udp"},
		{"UDP6", "udp"},
		{"raw", ""},
		{"", ""},
		{"icmp", ""},
		{" tcp ", "tcp"},
	}
	for _, tc := range tests {
		got := normalizePortProtocol(tc.proto)
		if got != tc.want {
			t.Errorf("normalizePortProtocol(%q) = %q, want %q", tc.proto, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// parseAddressPort
// ---------------------------------------------------------------------------

func TestParseAddressPort(t *testing.T) {
	tests := []struct {
		endpoint    string
		wantAddress string
		wantPort    int
	}{
		// IPv4
		{"127.0.0.1:5677", "127.0.0.1", 5677},
		{"0.0.0.0:80", "0.0.0.0", 80},
		// IPv6 with brackets (ss format)
		{"[::]:5353", "::", 5353},
		{"[::1]:8080", "::1", 8080},
		{"[2001:db8::1]:443", "2001:db8::1", 443},
		// Bare * or empty
		{"*", "", 0},
		{"", "", 0},
		// No port
		{"127.0.0.1", "", 0},
		// Port at end after colon — just port
		{":::80", "::", 80},
	}
	for _, tc := range tests {
		addr, port := parseAddressPort(tc.endpoint)
		if addr != tc.wantAddress || port != tc.wantPort {
			t.Errorf("parseAddressPort(%q) = (%q, %d), want (%q, %d)",
				tc.endpoint, addr, port, tc.wantAddress, tc.wantPort)
		}
	}
}

// ---------------------------------------------------------------------------
// parseSSProcess
// ---------------------------------------------------------------------------

func TestParseSSProcess(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantProc string
		wantPID  int
	}{
		{
			name:     "single process",
			raw:      `users:(("bongsu-server",pid=1674817,fd=7))`,
			wantProc: "bongsu-server",
			wantPID:  1674817,
		},
		{
			name:     "short process name",
			raw:      `users:(("node",pid=1234,fd=21))`,
			wantProc: "node",
			wantPID:  1234,
		},
		{
			name:     "empty raw",
			raw:      "",
			wantProc: "",
			wantPID:  0,
		},
		{
			name:     "no process info (UDP UNCONN line)",
			raw:      "",
			wantProc: "",
			wantPID:  0,
		},
		{
			name:     "malformed — no pid= keyword",
			raw:      `users:(("nginx",1234,fd=5))`,
			wantProc: "",
			wantPID:  0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proc, pid := parseSSProcess(tc.raw)
			if proc != tc.wantProc || pid != tc.wantPID {
				t.Errorf("parseSSProcess(%q) = (%q, %d), want (%q, %d)",
					tc.raw, proc, pid, tc.wantProc, tc.wantPID)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseNetstatProcess
// ---------------------------------------------------------------------------

func TestParseNetstatProcess(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantProc string
		wantPID  int
	}{
		{
			name:     "pid/name format",
			raw:      "1674817/bongsu-server",
			wantProc: "bongsu-server",
			wantPID:  1674817,
		},
		{
			name:     "no process (dash)",
			raw:      "-",
			wantProc: "",
			wantPID:  0,
		},
		{
			name:     "empty string",
			raw:      "",
			wantProc: "",
			wantPID:  0,
		},
		{
			name:     "slash in name",
			raw:      "1234/my/process",
			wantProc: "my/process",
			wantPID:  1234,
		},
		{
			name:     "no slash — not pid/name format",
			raw:      "sshd",
			wantProc: "",
			wantPID:  0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proc, pid := parseNetstatProcess(tc.raw)
			if proc != tc.wantProc || pid != tc.wantPID {
				t.Errorf("parseNetstatProcess(%q) = (%q, %d), want (%q, %d)",
					tc.raw, proc, pid, tc.wantProc, tc.wantPID)
			}
		})
	}
}

func TestParseDelimitedPackagesSkipsInvalidRows(t *testing.T) {
	// dpkg rows carry a leading status word; only fully-installed entries count.
	in := "installed\topenssl\t3.0.17-1\tamd64\topenssl\n" +
		"config-files\tremoved-pkg\t1.0-1\tamd64\tremoved-pkg\n" + // removed, files purged
		"not-installed\tnever-pkg\t2.0\tamd64\t\n" + // recorded but absent
		"installed\tmissing-version\t\tamd64\t\n" +
		"installed\tbad-row\n"
	pkgs := parseDelimitedPackages([]byte(in), "dpkg")
	if len(pkgs) != 1 {
		t.Fatalf("packages = %d, want 1 (only installed): %#v", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "openssl" || pkgs[0].Version != "3.0.17-1" || pkgs[0].Arch != "amd64" || pkgs[0].SrcName != "openssl" || pkgs[0].Source != "dpkg" || pkgs[0].PkgType != "os" {
		t.Fatalf("unexpected package: %#v", pkgs[0])
	}
}

func TestCollectOSQueryPackagesFallsBackToDpkgQuery(t *testing.T) {
	binDir := t.TempDir()
	dpkg := filepath.Join(binDir, "dpkg-query")
	if err := os.WriteFile(dpkg, []byte("#!/bin/sh\nprintf 'installed\\topenssl\\t3.0.17-1\\tamd64\\topenssl\\n'\n"), 0755); err != nil {
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
