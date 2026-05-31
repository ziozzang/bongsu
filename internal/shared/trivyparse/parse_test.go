package trivyparse

import "testing"

func TestExtractPackagesSetsEcosystemAndPURL(t *testing.T) {
	data := []byte(`{
	  "Results": [{
	    "Target": "package-lock.json",
	    "Type": "npm",
	    "Packages": [{"Name": "lodash", "Version": "4.17.20"}]
	  }]
	}`)

	pkgs, vulns, err := ExtractPackagesAndVulns(data, "trivy-host", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 0 {
		t.Fatalf("unexpected vulnerabilities: %d", len(vulns))
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1", len(pkgs))
	}
	if pkgs[0].Ecosystem != "npm" {
		t.Fatalf("ecosystem = %q, want npm", pkgs[0].Ecosystem)
	}
	if pkgs[0].PURL != "pkg:npm/lodash@4.17.20" {
		t.Fatalf("purl = %q", pkgs[0].PURL)
	}
}

func TestUbuntuPackagesKeepUbuntuEcosystem(t *testing.T) {
	data := []byte(`{
	  "Results": [{
	    "Target": "ubuntu:24.04",
	    "Type": "ubuntu",
	    "Packages": [{"Name": "openssl", "Version": "3.0.13-0ubuntu3.5", "Arch": "amd64"}]
	  }]
	}`)

	pkgs, _, err := ExtractPackagesAndVulns(data, "trivy-container", "api")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1", len(pkgs))
	}
	if pkgs[0].Ecosystem != "Ubuntu" {
		t.Fatalf("ecosystem = %q, want Ubuntu", pkgs[0].Ecosystem)
	}
	if pkgs[0].PURL != "pkg:deb/openssl@3.0.13-0ubuntu3.5?arch=amd64" {
		t.Fatalf("purl = %q", pkgs[0].PURL)
	}
}
