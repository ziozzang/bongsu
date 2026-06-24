package cvematch

import "testing"

func TestParsePURL(t *testing.T) {
	cases := []struct {
		purl                              string
		name, version, pkgType, eco, arch string
		ok                                bool
	}{
		{"pkg:deb/openssl@3.0.11-1?arch=amd64", "openssl", "3.0.11-1", "deb", "Debian", "amd64", true},
		{"pkg:rpm/openssl-libs@1:3.0.7-18.el9?arch=x86_64", "openssl-libs", "1:3.0.7-18.el9", "rpm", "RHEL", "x86_64", true},
		{"pkg:apk/musl@1.2.4-r2", "musl", "1.2.4-r2", "apk", "Alpine", "", true},
		{"pkg:pypi/django@4.2.0", "django", "4.2.0", "python-pkg", "PyPI", "", true},
		{"pkg:npm/lodash@4.17.21", "lodash", "4.17.21", "node-pkg", "npm", "", true},
		// npm scope: %40 -> @, namespace joins with "/"
		{"pkg:npm/%40angular/core@17.0.0", "@angular/core", "17.0.0", "node-pkg", "npm", "", true},
		// maven group/artifact -> group:artifact
		{"pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0", "com.fasterxml.jackson.core:jackson-databind", "2.13.0", "jar", "Maven", "", true},
		// golang full module path preserved
		{"pkg:golang/golang.org/x/net@0.17.0", "golang.org/x/net", "0.17.0", "golang", "Go", "", true},
		{"pkg:cargo/serde@1.0.197", "serde", "1.0.197", "rustbinary", "crates.io", "", true},
		// URL-encoded version
		{"pkg:deb/foo@1.0%2Bdfsg-1", "foo", "1.0+dfsg-1", "deb", "Debian", "", true},
		// unknown type -> passes through with empty ecosystem
		{"pkg:conda/numpy@1.0", "numpy", "1.0", "conda", "", "", true},
		// malformed
		{"openssl@3.0", "", "", "", "", "", false},
		{"pkg:deb", "", "", "", "", "", false},
	}
	for _, c := range cases {
		name, version, pkgType, eco, arch, ok := ParsePURL(c.purl)
		if ok != c.ok {
			t.Errorf("ParsePURL(%q) ok=%v want %v", c.purl, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if name != c.name || version != c.version || pkgType != c.pkgType || eco != c.eco || arch != c.arch {
			t.Errorf("ParsePURL(%q) = (%q,%q,%q,%q,%q) want (%q,%q,%q,%q,%q)",
				c.purl, name, version, pkgType, eco, arch, c.name, c.version, c.pkgType, c.eco, c.arch)
		}
	}
}

func TestParseSBOMCycloneDX(t *testing.T) {
	doc := `{
	  "bomFormat":"CycloneDX","specVersion":"1.5","serialNumber":"urn:uuid:abc","version":1,
	  "metadata":{"timestamp":"2026-06-24T00:00:00Z","component":{"type":"application","name":"myapp","version":"1.0"}},
	  "components":[
	    {"type":"library","name":"requests","version":"2.19.1","bom-ref":"ref-req","purl":"pkg:pypi/requests@2.19.1"},
	    {"type":"library","name":"lodash","version":"4.17.21","bom-ref":"ref-lodash","purl":"pkg:npm/lodash@4.17.21"},
	    {"type":"operating-system","name":"debian","version":"12","bom-ref":"ref-os"}
	  ],
	  "dependencies":[
	    {"ref":"ref-req","dependsOn":["ref-lodash"]}
	  ]
	}`
	pkgs, meta, err := ParseSBOM([]byte(doc))
	if err != nil {
		t.Fatalf("ParseSBOM: %v", err)
	}
	if meta.Format != "CycloneDX" || meta.ComponentName != "myapp" || meta.SpecVersion != "1.5" {
		t.Fatalf("meta wrong: %+v", meta)
	}
	// The operating-system component has no PURL -> filtered.
	if len(pkgs) != 2 {
		t.Fatalf("want 2 packages (os root filtered), got %d: %+v", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "requests" || pkgs[0].Ecosystem != "PyPI" || pkgs[0].Source != "sbom" {
		t.Fatalf("requests parse wrong: %+v", pkgs[0])
	}
	// dependency graph translated to purl edges
	deps := meta.Dependencies["pkg:pypi/requests@2.19.1"]
	if len(deps) != 1 || deps[0] != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("dependency edge wrong: %+v", meta.Dependencies)
	}
}

func TestParseSBOMSPDX(t *testing.T) {
	doc := `{
	  "SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3","name":"myapp-sbom",
	  "creationInfo":{"created":"2026-06-24T00:00:00Z","creators":["Tool: syft"]},
	  "packages":[
	    {"SPDXID":"SPDXRef-Package-requests","name":"requests","versionInfo":"2.19.1","downloadLocation":"NOASSERTION","packageUrl":"pkg:pypi/requests@2.19.1"},
	    {"SPDXID":"SPDXRef-Package-noeco","name":"mystery","versionInfo":"1.0","downloadLocation":"NOASSERTION"}
	  ]
	}`
	pkgs, meta, err := ParseSBOM([]byte(doc))
	if err != nil {
		t.Fatalf("ParseSBOM SPDX: %v", err)
	}
	if meta.Format != "SPDX" || meta.ComponentName != "myapp-sbom" {
		t.Fatalf("spdx meta wrong: %+v", meta)
	}
	// "mystery" has no purl -> no ecosystem -> filtered.
	if len(pkgs) != 1 || pkgs[0].Name != "requests" || pkgs[0].Ecosystem != "PyPI" {
		t.Fatalf("spdx packages wrong: %+v", pkgs)
	}
}

func TestParseSBOMRejectsUnknown(t *testing.T) {
	if _, _, err := ParseSBOM([]byte(`{"foo":"bar"}`)); err == nil {
		t.Fatal("unknown format must error")
	}
	if _, _, err := ParseSBOM([]byte(`not json`)); err == nil {
		t.Fatal("invalid JSON must error")
	}
}
