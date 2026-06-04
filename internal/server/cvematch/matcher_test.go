package cvematch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

func TestWriteTempSBOMUsesPrivateTempFile(t *testing.T) {
	path, err := writeTempSBOM([]byte(`{"bomFormat":"CycloneDX"}`))
	if err != nil {
		t.Fatalf("writeTempSBOM: %v", err)
	}
	defer os.Remove(path)

	if filepath.Dir(path) != os.TempDir() {
		t.Fatalf("temp file dir = %q, want %q", filepath.Dir(path), os.TempDir())
	}
	if !strings.HasPrefix(filepath.Base(path), "bongsu-sbom-") {
		t.Fatalf("temp file name = %q", filepath.Base(path))
	}
	if !strings.HasSuffix(filepath.Base(path), ".cdx.json") {
		t.Fatalf("temp file name should keep SBOM extension, got %q", filepath.Base(path))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat temp file: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("temp file mode = %v, want 0600", mode)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read temp file: %v", err)
	}
	if string(data) != `{"bomFormat":"CycloneDX"}` {
		t.Fatalf("temp file content = %q", data)
	}
}

func TestPackageMatchGroupsSeparateMixedOSPackageTypes(t *testing.T) {
	host := models.Host{ID: "host-1", Hostname: "node-1", OSName: "Ubuntu"}
	pkgs := []models.Package{
		{ID: "host-deb", AssetType: "host", Name: "openssl", Version: "3.0.13", PkgType: "deb", Ecosystem: "Ubuntu"},
		{ID: "container-apk", AssetType: "container", AssetID: "container-1", ContainerID: "container-1", ImageName: "alpine:3.20", Name: "busybox", Version: "1.36", PkgType: "apk", Ecosystem: "Alpine"},
	}

	groups := packageMatchGroups(pkgs, host)
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(groups))
	}
	keys := []string{groups[0].key, groups[1].key}
	joined := strings.Join(keys, "\n")
	for _, want := range []string{"host\x00host-1\x00deb", "container\x00container-1\x00apk"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("group keys missing %q: %q", want, joined)
		}
	}
}

func TestMatchKeepsSuccessfulAssetGroupsWhenOneTrivySBOMFails(t *testing.T) {
	dir := t.TempDir()
	trivy := filepath.Join(dir, "trivy")
	script := `#!/bin/sh
last=""
for arg in "$@"; do last="$arg"; done
if grep -q 'pkg:apk/' "$last"; then
  echo "apk fixture failed" >&2
  exit 7
fi
cat <<'JSON'
{"Results":[{"Target":"/","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-0001","Severity":"HIGH","PkgName":"openssl","InstalledVersion":"3.0.13","FixedVersion":"3.0.14","PrimaryURL":"https://example.test/CVE-2026-0001","CVSS":{"nvd":{"V3Score":7.5,"V3Vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}}]}]}
JSON
`
	if err := os.WriteFile(trivy, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake trivy: %v", err)
	}
	matcher := NewMatcher(trivy, dir, "")
	host := models.Host{ID: "host-1", Hostname: "node-1", OSName: "Ubuntu"}
	pkgs := []models.Package{
		{ID: "pkg-deb", AssetType: "host", HostID: "host-1", Name: "openssl", Version: "3.0.13", PkgType: "deb", Ecosystem: "Ubuntu", Target: "/"},
		{ID: "pkg-apk", AssetType: "container", AssetID: "container-1", ContainerID: "container-1", ImageName: "alpine:3.20", Name: "busybox", Version: "1.36", PkgType: "apk", Ecosystem: "Alpine", PURL: "pkg:apk/alpine/busybox@1.36", Target: "alpine:3.20"},
	}

	vulns, err := matcher.Match(t.Context(), pkgs, host)
	if err != nil {
		t.Fatalf("Match returned error despite one successful group: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("vulns = %d, want 1", len(vulns))
	}
	if vulns[0].PackageID != "pkg-deb" || vulns[0].VulnerabilityID != "CVE-2026-0001" {
		t.Fatalf("vulnerability = %+v, want deb package CVE", vulns[0])
	}
}
