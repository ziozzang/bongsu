package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanLanguagePackagesAcrossNonStandardDirs(t *testing.T) {
	root := t.TempDir()
	// pyenv-style location, outside any system package dir
	writeFile(t, root, "home/dev/.pyenv/versions/3.12/lib/python3.12/site-packages/requests-2.31.0.dist-info/METADATA",
		"Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n\nbody")
	// nvm-style npm lockfile
	writeFile(t, root, "opt/app/package-lock.json",
		`{"packages":{"":{"version":"1.0.0"},"node_modules/lodash":{"version":"4.17.21"}}}`)
	// pinned requirements
	writeFile(t, root, "srv/svc/requirements.txt", "flask==3.0.0\n# comment\nunpinned-pkg>=1.0\nDjango[bcrypt]==4.2.0\n")
	// go.mod
	writeFile(t, root, "build/go.mod", "module x\n\nrequire (\n\tgithub.com/pkg/errors v0.9.1\n)\n")
	// Cargo.lock
	writeFile(t, root, "rust/Cargo.lock", "[[package]]\nname = \"serde\"\nversion = \"1.0.197\"\n")

	pkgs := ScanLanguagePackages(root, 20)
	byName := map[string]models.Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	checks := []struct{ name, version, eco string }{
		{"requests", "2.31.0", "PyPI"},
		{"lodash", "4.17.21", "npm"},
		{"flask", "3.0.0", "PyPI"},
		{"Django", "4.2.0", "PyPI"}, // extras suffix "[bcrypt]" stripped from the name
		{"github.com/pkg/errors", "0.9.1", "Go"},
		{"serde", "1.0.197", "crates.io"},
	}
	for _, c := range checks {
		p, ok := byName[c.name]
		if !ok {
			t.Fatalf("expected to find %q, got %v", c.name, byName)
		}
		if p.Version != c.version || p.Ecosystem != c.eco {
			t.Fatalf("%s: got %s/%s want %s/%s", c.name, p.Version, p.Ecosystem, c.version, c.eco)
		}
	}
	// unpinned requirement must be skipped (no resolved version)
	if _, ok := byName["unpinned-pkg"]; ok {
		t.Fatal("unpinned requirement should not be reported")
	}
}

func TestNpmLockCapturesDependencies(t *testing.T) {
	root := t.TempDir()
	// v2/v3 lockfile: each package entry carries its direct dependencies.
	writeFile(t, root, "app/package-lock.json", `{"packages":{
	  "":{"version":"1.0.0"},
	  "node_modules/express":{"version":"4.18.2","dependencies":{"lodash":"^4.17.0"}},
	  "node_modules/lodash":{"version":"4.17.21"}
	}}`)
	pkgs := ScanLanguagePackages(root, 20)
	var express *models.Package
	for i := range pkgs {
		if pkgs[i].Name == "express" {
			express = &pkgs[i]
		}
	}
	if express == nil {
		t.Fatalf("express not parsed: %+v", pkgs)
	}
	if len(express.Dependencies) != 1 || express.Dependencies[0] != "lodash" {
		t.Fatalf("express must record its dependency on lodash, got %v", express.Dependencies)
	}
}

func TestLanguageScanDepthBound(t *testing.T) {
	root := t.TempDir()
	deep := "a/b/c/d/e/f/g/h/requirements.txt"
	writeFile(t, root, deep, "deeppkg==1.0\n")
	pkgs := ScanLanguagePackages(root, 3) // shallower than the file
	for _, p := range pkgs {
		if p.Name == "deeppkg" {
			t.Fatal("file beyond max depth should not be scanned")
		}
	}
}
