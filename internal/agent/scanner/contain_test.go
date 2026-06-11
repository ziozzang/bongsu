package scanner

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestScanRootRejectsAbsoluteSymlinkEscape verifies the core containment
// guarantee: an ABSOLUTE symlink inside an untrusted container rootfs that
// points at a HOST file must not leak that host content into the inventory.
// Here etc/os-release -> <outside>/secret (containing "HOST-SECRET"); the
// distro ID read must skip it, so dpkg packages fall back to "debian" (the
// non-ubuntu default) and no host bytes appear anywhere in the result.
func TestScanRootRejectsAbsoluteSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("ID=ubuntu\nHOST-SECRET\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	mkdir(t, filepath.Join(root, "etc"))
	// Absolute symlink → resolves against host fs → outside root → rejected.
	if err := os.Symlink(secret, filepath.Join(root, "etc", "os-release")); err != nil {
		t.Fatal(err)
	}
	mkdir(t, filepath.Join(root, "var/lib/dpkg"))
	mkfile(t, filepath.Join(root, "var/lib/dpkg/status"),
		"Package: bash\nStatus: install ok installed\nVersion: 5.2\nArchitecture: amd64\n")

	res, err := ScanRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	// os-release was skipped → distro defaults to debian, NOT ubuntu.
	if res.OSFamily != "debian" {
		t.Fatalf("OSFamily = %q, want debian (escaped os-release must be skipped)", res.OSFamily)
	}
	if distroIDFromRoot(root) != "" {
		t.Fatal("distroIDFromRoot followed an absolute symlink outside root")
	}
	// And the raw read helper must refuse it.
	if _, err := readFileWithinRoot(root, filepath.Join(root, "etc", "os-release")); err == nil {
		t.Fatal("readFileWithinRoot returned content for an escaping symlink")
	}
}

// TestRelativeInRootSymlinkIsRead verifies the accepted-tradeoff other half: a
// RELATIVE symlink that stays inside the rootfs is a legitimate distro layout
// (etc/os-release -> ../usr/lib/os-release) and MUST still be read.
func TestRelativeInRootSymlinkIsRead(t *testing.T) {
	root := t.TempDir()

	mkdir(t, filepath.Join(root, "usr/lib"))
	mkfile(t, filepath.Join(root, "usr/lib/os-release"), "ID=ubuntu\n")
	mkdir(t, filepath.Join(root, "etc"))
	// Relative symlink staying under root → allowed.
	if err := os.Symlink("../usr/lib/os-release", filepath.Join(root, "etc", "os-release")); err != nil {
		t.Fatal(err)
	}

	if got := distroIDFromRoot(root); got != "ubuntu" {
		t.Fatalf("distroIDFromRoot = %q, want ubuntu (in-root relative symlink should resolve)", got)
	}
	data, err := readFileWithinRoot(root, filepath.Join(root, "etc", "os-release"))
	if err != nil {
		t.Fatalf("readFileWithinRoot rejected an in-root relative symlink: %v", err)
	}
	if !strings.Contains(string(data), "ubuntu") {
		t.Fatalf("unexpected content: %q", data)
	}
}

// TestLangScanRejectsAbsoluteSymlinkEscape verifies the language walk applies
// the same containment: a package-lock.json that is an absolute symlink to an
// outside file must be skipped, so the outside package is not inventoried.
func TestLangScanRejectsAbsoluteSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	outLock := filepath.Join(outside, "package-lock.json")
	if err := os.WriteFile(outLock, []byte(
		`{"packages":{"node_modules/host-secret-pkg":{"version":"9.9.9"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	mkdir(t, filepath.Join(root, "opt/app"))
	if err := os.Symlink(outLock, filepath.Join(root, "opt/app/package-lock.json")); err != nil {
		t.Fatal(err)
	}

	pkgs := ScanLanguagePackages(root, 20)
	for _, p := range pkgs {
		if p.Name == "host-secret-pkg" {
			t.Fatal("language walk followed an absolute symlink outside root")
		}
	}
}

// TestLangScanReadsInRootRelativeSymlink confirms the language walk still reads
// a relative in-root symlinked lockfile (legit layout).
func TestLangScanReadsInRootRelativeSymlink(t *testing.T) {
	root := t.TempDir()

	mkdir(t, filepath.Join(root, "shared"))
	mkfile(t, filepath.Join(root, "shared/package-lock.json"),
		`{"packages":{"node_modules/lodash":{"version":"4.17.21"}}}`)
	mkdir(t, filepath.Join(root, "opt/app"))
	if err := os.Symlink("../../shared/package-lock.json",
		filepath.Join(root, "opt/app/package-lock.json")); err != nil {
		t.Fatal(err)
	}

	pkgs := ScanLanguagePackages(root, 20)
	var found bool
	for _, p := range pkgs {
		if p.Name == "lodash" && p.Version == "4.17.21" {
			found = true
		}
	}
	if !found {
		t.Fatal("in-root relative symlinked lockfile should have been read")
	}
}

// TestHostRootExemption verifies the root=="/" exemption: an absolute symlink is
// followed normally on a host scan (everything is within /), so behavior is
// identical to before the containment change.
func TestHostRootExemption(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("host-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	// With root "/", containment is skipped and the link resolves normally.
	data, err := readFileWithinRoot("/", link)
	if err != nil {
		t.Fatalf("host-root read failed: %v", err)
	}
	if !bytes.Equal(data, []byte("host-content")) {
		t.Fatalf("host-root read = %q, want host-content", data)
	}
	// Empty root is also treated as host root.
	if _, err := readFileWithinRoot("", link); err != nil {
		t.Fatalf("empty-root read failed: %v", err)
	}
}

// TestDpkgOversizedLineReturnsPartial verifies DEFECT 2: a status-file line over
// bufio.Scanner's 4MiB cap must NOT fail the whole scan — packages parsed before
// the offending line are returned, with no error.
func TestDpkgOversizedLineReturnsPartial(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("Package: first\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\n\n")
	// A single continuation line bigger than the 4MiB scanner cap.
	b.WriteString("Package: poison\nStatus: install ok installed\nVersion: 2.0\nDescription: x\n ")
	b.WriteString(strings.Repeat("A", 5*1024*1024))
	b.WriteString("\n\nPackage: third\nStatus: install ok installed\nVersion: 3.0\n")

	p := filepath.Join(dir, "status")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	pkgs, err := parseDpkgStatus(dir, p, "debian")
	if err != nil {
		t.Fatalf("oversized line must not fail the scan, got err: %v", err)
	}
	// "first" was fully parsed before the oversized line; assert it survives.
	var haveFirst bool
	for _, pk := range pkgs {
		if pk.Name == "first" && pk.Version == "1.0" {
			haveFirst = true
		}
	}
	if !haveFirst {
		t.Fatalf("expected partial result to include 'first', got %+v", pkgs)
	}
}
