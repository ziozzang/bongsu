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
