package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// mkfile creates path with optional content, making parent dirs as needed.
func mkfile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

// findPkg returns the first package matching name, or zero value.
func findPkg(pkgs []models.Package, name string) (models.Package, bool) {
	for _, p := range pkgs {
		if p.Name == name {
			return p, true
		}
	}
	return models.Package{}, false
}

func TestScanRuntimes_PyenvPython(t *testing.T) {
	root := t.TempDir()
	mkfile(t, filepath.Join(root, ".pyenv/versions/3.12.1/bin/python3"), "")
	mkdir(t, filepath.Join(root, ".pyenv/versions/3.12.1/lib/python3.12"))

	pkgs := ScanRuntimes(root, 0)
	p, ok := findPkg(pkgs, "python")
	if !ok {
		t.Fatalf("python not detected; got %+v", pkgs)
	}
	if p.Version != "3.12.1" {
		t.Errorf("version = %q, want 3.12.1", p.Version)
	}
	if p.Ecosystem != "python" {
		t.Errorf("ecosystem = %q, want python", p.Ecosystem)
	}
	if p.PkgType != "runtime" {
		t.Errorf("pkg_type = %q, want runtime", p.PkgType)
	}
	if p.Source != "native-runtime" {
		t.Errorf("source = %q, want native-runtime", p.Source)
	}
	if p.PURL != "pkg:generic/python@3.12.1" {
		t.Errorf("purl = %q", p.PURL)
	}
	if p.FilePath == "" {
		t.Error("file_path empty")
	}
}

func TestScanRuntimes_NodeTarball(t *testing.T) {
	root := t.TempDir()
	prefix := filepath.Join(root, "opt/node-v20.11.0-linux-x64")
	mkfile(t, filepath.Join(prefix, "bin/node"), "")
	mkfile(t, filepath.Join(prefix, "lib/node_modules/npm/package.json"), `{"name":"npm","version":"10.2.4"}`)

	pkgs := ScanRuntimes(root, 0)
	p, ok := findPkg(pkgs, "node.js")
	if !ok {
		t.Fatalf("node.js not detected; got %+v", pkgs)
	}
	if p.Version != "20.11.0" {
		t.Errorf("version = %q, want 20.11.0", p.Version)
	}
	if p.Ecosystem != "nodejs" {
		t.Errorf("ecosystem = %q, want nodejs", p.Ecosystem)
	}
	if p.PkgType != "runtime" {
		t.Errorf("pkg_type = %q, want runtime", p.PkgType)
	}
}

func TestScanRuntimes_JDKRelease(t *testing.T) {
	root := t.TempDir()
	prefix := filepath.Join(root, "opt/jdk-21.0.2")
	mkfile(t, filepath.Join(prefix, "bin/java"), "")
	mkfile(t, filepath.Join(prefix, "release"),
		"JAVA_VERSION=\"21.0.2\"\nIMPLEMENTOR=\"Eclipse Adoptium\"\nOS_NAME=\"Linux\"\n")

	pkgs := ScanRuntimes(root, 0)
	p, ok := findPkg(pkgs, "openjdk")
	if !ok {
		t.Fatalf("openjdk not detected; got %+v", pkgs)
	}
	if p.Version != "21.0.2" {
		t.Errorf("version = %q, want 21.0.2", p.Version)
	}
	if p.Ecosystem != "jdk" {
		t.Errorf("ecosystem = %q, want jdk", p.Ecosystem)
	}
	if p.PkgType != "runtime" {
		t.Errorf("pkg_type = %q, want runtime", p.PkgType)
	}
}

func TestScanRuntimes_OracleJDK(t *testing.T) {
	root := t.TempDir()
	prefix := filepath.Join(root, "opt/oracle-jdk")
	mkfile(t, filepath.Join(prefix, "bin/java"), "")
	mkfile(t, filepath.Join(prefix, "release"),
		"JAVA_VERSION=\"17.0.9\"\nIMPLEMENTOR=\"Oracle Corporation\"\n")

	pkgs := ScanRuntimes(root, 0)
	p, ok := findPkg(pkgs, "jdk")
	if !ok {
		t.Fatalf("oracle jdk not detected; got %+v", pkgs)
	}
	if p.Version != "17.0.9" {
		t.Errorf("version = %q, want 17.0.9", p.Version)
	}
}

func TestScanRuntimes_PythonNoVersionSkipped(t *testing.T) {
	root := t.TempDir()
	// bin/python with no version-bearing prefix and no lib/pythonX.Y → skip.
	mkfile(t, filepath.Join(root, "usr/local/bin/python"), "")

	pkgs := ScanRuntimes(root, 0)
	if _, ok := findPkg(pkgs, "python"); ok {
		t.Fatalf("python should NOT be detected without a version; got %+v", pkgs)
	}
}

func TestScanRuntimes_GoSDK(t *testing.T) {
	root := t.TempDir()
	mkfile(t, filepath.Join(root, "usr/local/go/VERSION"), "go1.22.1\n")

	pkgs := ScanRuntimes(root, 0)
	p, ok := findPkg(pkgs, "go")
	if !ok {
		t.Fatalf("go not detected; got %+v", pkgs)
	}
	if p.Version != "go1.22.1" {
		t.Errorf("version = %q, want go1.22.1", p.Version)
	}
	if p.Ecosystem != "golang" {
		t.Errorf("ecosystem = %q, want golang", p.Ecosystem)
	}
}

func TestScanRuntimes_Ruby(t *testing.T) {
	root := t.TempDir()
	prefix := filepath.Join(root, ".rbenv/versions/3.3.0")
	mkfile(t, filepath.Join(prefix, "bin/ruby"), "")
	mkdir(t, filepath.Join(prefix, "lib/ruby/3.3.0"))

	pkgs := ScanRuntimes(root, 0)
	p, ok := findPkg(pkgs, "ruby")
	if !ok {
		t.Fatalf("ruby not detected; got %+v", pkgs)
	}
	if p.Version != "3.3.0" {
		t.Errorf("version = %q, want 3.3.0", p.Version)
	}
	if p.Ecosystem != "ruby" {
		t.Errorf("ecosystem = %q, want ruby", p.Ecosystem)
	}
}

func TestScanRuntimes_Dedup(t *testing.T) {
	root := t.TempDir()
	// Two symlink-style launchers in one bin dir, plus lib marker.
	prefix := filepath.Join(root, ".pyenv/versions/3.10.4")
	mkfile(t, filepath.Join(prefix, "bin/python"), "")
	mkfile(t, filepath.Join(prefix, "bin/python3"), "")
	mkfile(t, filepath.Join(prefix, "bin/python3.10"), "")
	mkdir(t, filepath.Join(prefix, "lib/python3.10"))

	pkgs := ScanRuntimes(root, 0)
	count := 0
	for _, p := range pkgs {
		if p.Name == "python" && p.Version == "3.10.4" {
			count++
		}
	}
	// Each launcher has a distinct FilePath, so all are kept (dedup is on
	// name+version+path). Ensure we at least detect and don't crash, and that
	// no exact (name,version,path) duplicate slips through.
	if count == 0 {
		t.Fatalf("expected python 3.10.4 detected; got %+v", pkgs)
	}
	seen := map[string]bool{}
	for _, p := range pkgs {
		key := p.Name + p.Version + p.FilePath
		if seen[key] {
			t.Errorf("duplicate (name,version,path) emitted: %s", key)
		}
		seen[key] = true
	}
}
