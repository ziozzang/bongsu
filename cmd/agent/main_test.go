package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ziozzang/bongsu/internal/agent/reporter"
	"github.com/ziozzang/bongsu/internal/shared/models"
)

func TestAgentVersionStringIncludesBuildMetadata(t *testing.T) {
	oldVersion, oldCommit, oldBuildDate := version, commit, buildDate
	t.Cleanup(func() {
		version, commit, buildDate = oldVersion, oldCommit, oldBuildDate
	})
	version = "1.2.3"
	commit = "abcdef1234567890"
	buildDate = "2026-06-01T00:00:00Z"
	got := agentVersionString()
	want := "1.2.3+abcdef123456+2026-06-01T00:00:00Z"
	if got != want {
		t.Fatalf("agent version = %q, want %q", got, want)
	}
	version, commit, buildDate = "", "", ""
	if got := agentVersionString(); got != "dev" {
		t.Fatalf("empty build metadata = %q, want dev", got)
	}
}

func TestReleaseBuildsInjectAgentMetadata(t *testing.T) {
	files := map[string][]string{
		"../../Makefile": {
			"BONGSU_COMMIT",
			"BONGSU_BUILD_DATE",
			"GO_BUILD_FLAGS ?= -trimpath",
			"go build $(GO_BUILD_FLAGS)",
			"-X main.version=$(BONGSU_VERSION)",
			"-X main.commit=$(BONGSU_COMMIT)",
			"-X main.buildDate=$(BONGSU_BUILD_DATE)",
		},
		"../../scripts/package.sh": {
			"COMMIT=",
			"BUILD_DATE=",
			"go build -trimpath",
			"-X main.version=${VERSION}",
			"-X main.commit=${COMMIT}",
			"-X main.buildDate=${BUILD_DATE}",
			`cp bin/bongsu-server-linux-amd64 "$STAGING/bin/bongsu-server"`,
			"download-nvd.sh",
			"download-osv.sh",
			"extract-trivy-cvedb.sh",
			"sync-all-cvedb.sh",
			"SHA256SUMS",
			"sha256sum -c SHA256SUMS",
		},
		"../../scripts/verify-static-binaries.sh": {
			`"$OUT_DIR/bongsu-agent" --version`,
			`"$OUT_DIR/bongsu-server" --version`,
			"${VERSION}+${COMMIT}+${BUILD_DATE}",
		},
		"../../deploy/Dockerfile.agent": {
			"ARG BONGSU_COMMIT",
			"ARG BONGSU_BUILD_DATE",
			"-X main.commit=${BONGSU_COMMIT}",
			"-X main.buildDate=${BONGSU_BUILD_DATE}",
		},
		"../../deploy/Dockerfile.server": {
			"ARG BONGSU_COMMIT",
			"ARG BONGSU_BUILD_DATE",
			"-X main.commit=${BONGSU_COMMIT}",
			"-X main.buildDate=${BONGSU_BUILD_DATE}",
		},
	}
	for path, wants := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		body := string(data)
		for _, want := range wants {
			if !strings.Contains(body, want) {
				t.Fatalf("%s missing build metadata %q", path, want)
			}
		}
	}
}

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

func TestContainerScanAnnotatesPackagesWithRuntimeIdentity(t *testing.T) {
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	start := strings.Index(body, "for idx := range containers")
	if start < 0 {
		t.Fatal("container scan loop not found")
	}
	end := strings.Index(body[start:], "// 6. OSQuery packages")
	if end < 0 {
		t.Fatal("container scan loop end not found")
	}
	loop := body[start : start+end]
	for _, want := range []string{
		`pkgs[i].AssetType = "container"`,
		"pkgs[i].AssetID = assetID",
		"pkgs[i].Container = c.Name",
		"pkgs[i].ContainerID = c.ContainerID",
		"pkgs[i].ImageName = c.ImageName",
		"pkgs[i].ImageID = c.ImageID",
		"vulns[i].Container = c.Name",
	} {
		if !strings.Contains(loop, want) {
			t.Fatalf("container package ontology annotation missing %q: %s", want, loop)
		}
	}
}

func TestAgentScanControlsAreConfigurable(t *testing.T) {
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	for _, want := range []string{
		`flag.String("scan-root"`,
		`flag.Duration("trivy-timeout"`,
		`flag.Duration("container-timeout"`,
		`flag.Duration("command-timeout"`,
		`flag.Bool("skip-containers"`,
		`flag.Int("max-containers"`,
		`BONGSU_AGENT_SCAN_ROOT`,
		`BONGSU_AGENT_TRIVY_TIMEOUT_SECONDS`,
		`BONGSU_AGENT_CONTAINER_TIMEOUT_SECONDS`,
		`BONGSU_AGENT_COMMAND_TIMEOUT_SECONDS`,
		`BONGSU_AGENT_SKIP_CONTAINERS`,
		`BONGSU_AGENT_MAX_CONTAINERS`,
		`cfg.ScanRoot`,
		`cfg.TrivyTimeoutSeconds`,
		`cfg.ContainerTimeoutSeconds`,
		`cfg.CommandTimeoutSeconds`,
		`cfg.SkipContainers`,
		`cfg.MaxContainers`,
		`applyAgentCommandTimeout(scanOpts.CommandTimeout)`,
		`coll.HostScanRoot = scanOpts.ScanRoot`,
		`coll.HostTimeout = scanOpts.TrivyTimeout`,
		`coll.ImageTimeout = scanOpts.ContainerTimeout`,
		`coll.CommandTimeout = scanOpts.CommandTimeout`,
		`if scanOpts.SkipContainers`,
		`len(containers) > scanOpts.MaxContainers`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("agent scan control wiring missing %q", want)
		}
	}
}

func TestCollectorUsesTrivyTimeoutsAndScanRoot(t *testing.T) {
	data, err := os.ReadFile("../../internal/agent/collector/collector.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	for _, want := range []string{
		`HostScanRoot`,
		`HostTimeout`,
		`ImageTimeout`,
		`CommandTimeout time.Duration`,
		`exec.CommandContext(ctx, c.trivy`,
		`exec.CommandContext(ctx, name, args...)`,
		`context.WithTimeout(ctx, c.HostTimeout)`,
		`context.WithTimeout(ctx, c.ImageTimeout)`,
		`context.WithTimeout(ctx, c.CommandTimeout)`,
		`trivy fs timed out after`,
		`trivy image %s timed out after`,
		`timed out after`,
		`scanRoot`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("collector scan control missing %q", want)
		}
	}
	if strings.Contains(body, `exec.Command(c.trivy, allArgs...)`) {
		t.Fatal("collector Trivy execution must use CommandContext")
	}
	for _, forbidden := range []string{
		`exec.Command("docker"`,
		`exec.Command(c.osquery`,
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("collector helper execution must use CommandContext, found %q", forbidden)
		}
	}
}

func TestSystemCollectorHelperCommandsAreBounded(t *testing.T) {
	data, err := os.ReadFile("../../internal/agent/system/system.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	for _, want := range []string{
		`BONGSU_AGENT_COMMAND_TIMEOUT_SECONDS`,
		`defaultCommandTimeout`,
		`context.WithTimeout(context.Background(), timeout)`,
		`exec.CommandContext(ctx, name, args...)`,
		`timed out after`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("system helper timeout wiring missing %q", want)
		}
	}
	if strings.Contains(body, `exec.Command(`) {
		t.Fatal("system helper execution must use CommandContext")
	}
}

func TestScanRequestCompletionFromReportPreservesDegradedScans(t *testing.T) {
	status, message := scanRequestCompletionFromReport(&reporter.ReportResult{
		ScanStatus:       "degraded",
		InventoryStatus:  "degraded",
		IngestErrorCount: 2,
		SkippedVulnCount: 3,
	})
	if status != "degraded" {
		t.Fatalf("status = %q, want degraded", status)
	}
	for _, want := range []string{"inventory_status=degraded", "ingest_errors=2", "skipped_vulns=3"} {
		if !strings.Contains(message, want) {
			t.Fatalf("degraded completion message missing %q: %q", want, message)
		}
	}

	status, message = scanRequestCompletionFromReport(&reporter.ReportResult{ScanStatus: "completed"})
	if status != "completed" || message != "" {
		t.Fatalf("clean completion = (%q, %q), want completed empty message", status, message)
	}
}

func TestLoadConfigReadsAgentTokenAndHostID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("server_url: http://server\napi_key: key\nagent_token: token-123\nwork_dir: /tmp/bongsu\nhost_id: host-override-1\nscan_root: /var/lib\ntrivy_timeout_seconds: 120\ncontainer_timeout_seconds: 30\ncommand_timeout_seconds: 15\nskip_containers: true\nmax_containers: 4\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentToken != "token-123" {
		t.Fatalf("agent token = %q", cfg.AgentToken)
	}
	if cfg.HostID != "host-override-1" {
		t.Fatalf("host id = %q", cfg.HostID)
	}
	if cfg.ScanRoot != "/var/lib" || cfg.TrivyTimeoutSeconds != 120 || cfg.ContainerTimeoutSeconds != 30 || cfg.CommandTimeoutSeconds != 15 || cfg.SkipContainers == nil || !*cfg.SkipContainers || cfg.MaxContainers != 4 {
		t.Fatalf("scan controls not parsed: %#v", cfg)
	}
}

func TestApplyHostIDOverride(t *testing.T) {
	host := &models.Host{ID: "derived"}
	applyHostIDOverride(host, " explicit-host ")
	if host.ID != "explicit-host" {
		t.Fatalf("host id = %q", host.ID)
	}
	applyHostIDOverride(host, " ")
	if host.ID != "explicit-host" {
		t.Fatalf("blank override changed host id to %q", host.ID)
	}
}

func TestCompleteScanRequestWithRetrySucceedsAfterFailure(t *testing.T) {
	t.Setenv("BONGSU_AGENT_RETRY_ATTEMPTS", "1")
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fail the first outer attempt, succeed on the second.
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rep := reporter.New(srv.URL, "api-key")
	// Avoid the real 2s backoff between outer attempts.
	oldBackoff := completeScanRequestBackoff
	completeScanRequestBackoff = time.Millisecond
	t.Cleanup(func() { completeScanRequestBackoff = oldBackoff })

	completeScanRequestWithRetry(rep, "req-1", "host-1", "failed", "boom")
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("server calls = %d, want 2", got)
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
