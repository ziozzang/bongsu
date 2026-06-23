package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseDpkgStatus(t *testing.T) {
	const status = `Package: adduser
Status: install ok installed
Architecture: all
Source: shadow
Version: 3.137
Description: add and remove users and groups
 long folded
 description body

Package: half-removed-pkg
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0

Package: libc6
Status: install ok installed
Architecture: amd64
Version: 2.38-1
`
	dir := t.TempDir()
	p := filepath.Join(dir, "status")
	if err := os.WriteFile(p, []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := parseDpkgStatus(dir, p, "debian")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 installed packages, got %d: %+v", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "adduser" || pkgs[0].Version != "3.137" {
		t.Fatalf("unexpected first package: %+v", pkgs[0])
	}
	if pkgs[0].SrcName != "shadow" {
		t.Fatalf("source name = %q, want shadow", pkgs[0].SrcName)
	}
	if pkgs[0].PkgType != "debian" || pkgs[0].Ecosystem != "Debian" {
		t.Fatalf("pkg_type/ecosystem = %q/%q", pkgs[0].PkgType, pkgs[0].Ecosystem)
	}
	if pkgs[1].Name != "libc6" {
		t.Fatalf("second package should be libc6, got %q", pkgs[1].Name)
	}
}

// A dpkg status database routinely retains stanzas for packages that are NOT on
// disk ("not-installed" after purge) or only partly present ("half-installed").
// Their Status string contains the substring "installed", so a naive
// strings.Contains check reports them as installed — false-positive findings for
// software that isn't there. Only the exact status word "installed" must count.
func TestParseDpkgStatusSkipsNonInstalledStates(t *testing.T) {
	const status = `Package: real-pkg
Status: install ok installed
Version: 1.0
Architecture: amd64

Package: purged-pkg
Status: purge ok not-installed
Version: 2.0
Architecture: amd64

Package: broken-pkg
Status: install ok half-installed
Version: 3.0
Architecture: amd64

Package: unpacked-pkg
Status: install ok unpacked
Version: 4.0
Architecture: amd64

Package: configfiles-pkg
Status: deinstall ok config-files
Version: 5.0
Architecture: amd64
`
	dir := t.TempDir()
	p := filepath.Join(dir, "status")
	if err := os.WriteFile(p, []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := parseDpkgStatus(dir, p, "debian")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "real-pkg" {
		t.Fatalf("only the fully-installed package must be reported, got %+v", pkgs)
	}
}

func TestDpkgSourceWithVersion(t *testing.T) {
	const status = `Package: adb
Status: install ok installed
Architecture: amd64
Source: android-platform-tools (34.0.5-12)
Version: 1:34.0.5-12
`
	dir := t.TempDir()
	p := filepath.Join(dir, "status")
	os.WriteFile(p, []byte(status), 0o644)
	pkgs, _ := parseDpkgStatus(dir, p, "ubuntu")
	if len(pkgs) != 1 {
		t.Fatalf("want 1 pkg, got %d", len(pkgs))
	}
	if pkgs[0].SrcName != "android-platform-tools" {
		t.Fatalf("src name = %q, want android-platform-tools", pkgs[0].SrcName)
	}
	if pkgs[0].PkgType != "ubuntu" || pkgs[0].Ecosystem != "Ubuntu" {
		t.Fatalf("ubuntu mapping wrong: %q/%q", pkgs[0].PkgType, pkgs[0].Ecosystem)
	}
	if pkgs[0].PURL != "pkg:deb/adb@1:34.0.5-12?arch=amd64" {
		t.Fatalf("purl = %q", pkgs[0].PURL)
	}
}

func TestParseApkInstalled(t *testing.T) {
	const installed = `C:Q16vHLRZoP2NZ2lLj3reL8p+l/YE4=
P:alpine-baselayout
V:3.4.3-r2
A:x86_64
o:alpine-baselayout

C:Q1abc=
P:busybox
V:1.36.1-r5
A:x86_64
o:busybox
`
	dir := t.TempDir()
	p := filepath.Join(dir, "installed")
	os.WriteFile(p, []byte(installed), 0o644)
	pkgs, err := parseApkInstalled(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("want 2 apk pkgs, got %d", len(pkgs))
	}
	if pkgs[1].Name != "busybox" || pkgs[1].Version != "1.36.1-r5" {
		t.Fatalf("unexpected busybox parse: %+v", pkgs[1])
	}
	if pkgs[1].PkgType != "alpine" || pkgs[1].Ecosystem != "Alpine" {
		t.Fatalf("alpine mapping wrong: %q/%q", pkgs[1].PkgType, pkgs[1].Ecosystem)
	}
	if pkgs[0].PURL != "pkg:apk/alpine-baselayout@3.4.3-r2?arch=x86_64" {
		t.Fatalf("apk purl = %q", pkgs[0].PURL)
	}
}

func TestScanRootSelectsDpkg(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "var/lib/dpkg"), 0o755)
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "etc/os-release"), []byte(`ID=ubuntu`+"\n"), 0o644)
	os.WriteFile(filepath.Join(root, "var/lib/dpkg/status"),
		[]byte("Package: bash\nStatus: install ok installed\nVersion: 5.2\nArchitecture: amd64\n"), 0o644)
	res, err := ScanRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != "dpkg" || res.OSFamily != "ubuntu" {
		t.Fatalf("source/family = %q/%q", res.Source, res.OSFamily)
	}
	if len(res.Packages) != 1 || res.Packages[0].PkgType != "ubuntu" {
		t.Fatalf("expected 1 ubuntu pkg, got %+v", res.Packages)
	}
}

func TestScanRootEmptyWhenNoDB(t *testing.T) {
	res, err := ScanRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 0 || res.Source != "" {
		t.Fatalf("expected empty result, got %+v", res)
	}
}
