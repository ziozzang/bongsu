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

func TestVulnerabilitiesBindToPackageTarget(t *testing.T) {
	data := []byte(`{
	  "Results": [
	    {
	      "Target": "package-lock.json",
	      "Type": "npm",
	      "Packages": [{"Name": "debug", "Version": "4.3.0"}],
	      "Vulnerabilities": [{"VulnerabilityID": "CVE-2026-0001", "PkgName": "debug", "InstalledVersion": "4.3.0"}]
	    },
	    {
	      "Target": "requirements.txt",
	      "Type": "python-pkg",
	      "Packages": [{"Name": "debug", "Version": "1.0.0"}],
	      "Vulnerabilities": [{"VulnerabilityID": "CVE-2026-0002", "PkgName": "debug", "InstalledVersion": "1.0.0"}]
	    }
	  ]
	}`)

	pkgs, vulns, err := ExtractPackagesAndVulns(data, "trivy-host", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 || len(vulns) != 2 {
		t.Fatalf("packages=%d vulns=%d, want 2 each", len(pkgs), len(vulns))
	}
	idsByTarget := map[string]string{}
	for _, p := range pkgs {
		idsByTarget[p.Target] = p.ID
	}
	if vulns[0].PackageID != idsByTarget["package-lock.json"] {
		t.Fatalf("npm vuln package_id = %q, want %q", vulns[0].PackageID, idsByTarget["package-lock.json"])
	}
	if vulns[1].PackageID != idsByTarget["requirements.txt"] {
		t.Fatalf("python vuln package_id = %q, want %q", vulns[1].PackageID, idsByTarget["requirements.txt"])
	}
}
