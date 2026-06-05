package collector

import (
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
