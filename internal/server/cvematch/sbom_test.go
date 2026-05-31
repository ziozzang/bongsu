package cvematch

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

func TestGenerateCycloneDXIncludesBongsuContext(t *testing.T) {
	host := models.Host{
		ID:        "host-1",
		Hostname:  "build-node-1",
		IPAddress: "192.0.2.10",
		OSName:    "Ubuntu",
		OSVersion: "24.04",
		Kernel:    "6.8.0",
		Arch:      "amd64",
		Owner:     "platform",
		Team:      "security",
	}
	pkgs := []models.Package{{
		ID:          "pkg-1",
		HostID:      "host-1",
		AssetType:   "container",
		AssetID:     "container-1",
		Source:      "trivy",
		Container:   "api",
		ContainerID: "sha256:abc",
		ImageName:   "example/api:1.0",
		Name:        "openssl",
		Version:     "3.0.13",
		Arch:        "amd64",
		PkgType:     "deb",
		Ecosystem:   "Ubuntu",
		FilePath:    "/usr/lib",
	}}

	data, err := GenerateCycloneDX(pkgs, host)
	if err != nil {
		t.Fatalf("GenerateCycloneDX: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal sbom: %v", err)
	}
	if doc["bomFormat"] != "CycloneDX" {
		t.Fatalf("bomFormat = %v", doc["bomFormat"])
	}
	components := doc["components"].([]any)
	if len(components) != 1 {
		t.Fatalf("components = %d", len(components))
	}
	component := components[0].(map[string]any)
	if component["purl"] == "" {
		t.Fatal("component purl is empty")
	}
	if component["bom-ref"] == component["purl"] {
		t.Fatal("CycloneDX bom-ref must be a bongsu-stable identity, not a potentially duplicated purl")
	}
	props := component["properties"].([]any)
	foundAsset := false
	for _, item := range props {
		prop := item.(map[string]any)
		if prop["name"] == "bongsu:asset_type" && prop["value"] == "container" {
			foundAsset = true
			break
		}
	}
	if !foundAsset {
		t.Fatal("bongsu asset context property missing")
	}
	metadata := doc["metadata"].(map[string]any)
	root := metadata["component"].(map[string]any)
	rootProps := root["properties"].([]any)
	foundOwner := false
	for _, item := range rootProps {
		prop := item.(map[string]any)
		if prop["name"] == "bongsu:owner" && prop["value"] == "platform" {
			foundOwner = true
			break
		}
	}
	if !foundOwner {
		t.Fatal("bongsu host owner property missing")
	}
	deps := doc["dependencies"].([]any)
	if len(deps) != 2 {
		t.Fatalf("dependencies = %d, want host plus package", len(deps))
	}
	rootDeps := deps[0].(map[string]any)
	if rootDeps["ref"] != root["bom-ref"] {
		t.Fatalf("root dependency ref = %v, want root bom-ref %v", rootDeps["ref"], root["bom-ref"])
	}
	dependsOn := rootDeps["dependsOn"].([]any)
	if len(dependsOn) != 1 || dependsOn[0] != component["bom-ref"] {
		t.Fatalf("root dependsOn = %#v, want package bom-ref %v", dependsOn, component["bom-ref"])
	}
}

func TestGenerateCycloneDXUsesUniqueBOMRefsForDuplicatePURLs(t *testing.T) {
	host := models.Host{ID: "host-1", Hostname: "node-1", OSName: "Ubuntu"}
	base := models.Package{
		HostID:      "host-1",
		AssetType:   "container",
		Source:      "trivy",
		Name:        "openssl",
		Version:     "3.0.13",
		PkgType:     "deb",
		Ecosystem:   "Ubuntu",
		Container:   "api",
		ContainerID: "container-a",
		ImageName:   "example/api:1.0",
	}
	other := base
	other.ID = "pkg-2"
	other.Container = "worker"
	other.ContainerID = "container-b"

	data, err := GenerateCycloneDX([]models.Package{base, other}, host)
	if err != nil {
		t.Fatalf("GenerateCycloneDX: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal sbom: %v", err)
	}
	components := doc["components"].([]any)
	if len(components) != 2 {
		t.Fatalf("components = %d, want 2", len(components))
	}
	refs := map[string]bool{}
	var purl string
	for _, item := range components {
		component := item.(map[string]any)
		ref := component["bom-ref"].(string)
		if refs[ref] {
			t.Fatalf("duplicate bom-ref %q", ref)
		}
		refs[ref] = true
		if purl == "" {
			purl = component["purl"].(string)
		} else if component["purl"].(string) != purl {
			t.Fatalf("test expected duplicate purls, got %q and %q", purl, component["purl"])
		}
	}
	deps := doc["dependencies"].([]any)
	rootDeps := deps[0].(map[string]any)["dependsOn"].([]any)
	if len(rootDeps) != 2 {
		t.Fatalf("root dependsOn = %#v, want both packages", rootDeps)
	}
}

func TestGenerateSPDXIncludesPackagePURLAndRelationships(t *testing.T) {
	host := models.Host{ID: "host-1", Hostname: "build-node-1", OSName: "Ubuntu", OSVersion: "24.04"}
	pkgs := []models.Package{{
		ID:        "pkg-1",
		HostID:    "host-1",
		AssetType: "host",
		AssetID:   "host-1",
		Source:    "trivy",
		Name:      "openssl",
		Version:   "3.0.13",
		Arch:      "amd64",
		PkgType:   "deb",
		Ecosystem: "Ubuntu",
	}}

	data, err := GenerateSPDX(pkgs, host)
	if err != nil {
		t.Fatalf("GenerateSPDX: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}
	if doc["spdxVersion"] != "SPDX-2.3" {
		t.Fatalf("spdxVersion = %v", doc["spdxVersion"])
	}
	packages := doc["packages"].([]any)
	if len(packages) != 2 {
		t.Fatalf("packages = %d", len(packages))
	}
	pkg := packages[1].(map[string]any)
	if pkg["packageUrl"] == "" {
		t.Fatal("SPDX packageUrl is empty")
	}
	for _, field := range []string{"licenseConcluded", "licenseDeclared", "copyrightText", "supplier"} {
		if pkg[field] == "" {
			t.Fatalf("SPDX package field %s is empty", field)
		}
	}
	code := pkg["packageVerificationCode"].(map[string]any)
	if got := code["packageVerificationCodeValue"]; got == "" {
		t.Fatal("SPDX package verification code is empty")
	}
	refs := pkg["externalRefs"].([]any)
	if len(refs) != 1 || refs[0].(map[string]any)["referenceType"] != "purl" {
		t.Fatalf("missing purl external ref: %#v", refs)
	}
	relationships := doc["relationships"].([]any)
	if len(relationships) < 2 {
		t.Fatalf("relationships = %d", len(relationships))
	}
}

func TestSPDXPackageVerificationCodeIgnoresRowIDs(t *testing.T) {
	base := models.Package{
		ID:        "pkg-row-1",
		HostID:    "host-row-1",
		AssetType: "container",
		AssetID:   "container-1",
		Source:    "trivy",
		Container: "api",
		ImageName: "example/api:1.0",
		Name:      "openssl",
		Version:   "3.0.13",
		Arch:      "amd64",
		PkgType:   "deb",
		Ecosystem: "Ubuntu",
		FilePath:  "/usr/lib",
	}
	next := base
	next.ID = "pkg-row-2"
	next.HostID = "host-row-2"

	got := spdxPackageVerificationCode(spdxPackageIdentity(base)...)
	want := spdxPackageVerificationCode(spdxPackageIdentity(next)...)
	if got != want {
		t.Fatalf("verification code changed with row IDs: got %s want %s", got, want)
	}
	next.Version = "3.0.14"
	changed := spdxPackageVerificationCode(spdxPackageIdentity(next)...)
	if changed == got {
		t.Fatal("verification code should change when package version changes")
	}
}

func TestGenerateSPDXSanitizesDocumentIdentity(t *testing.T) {
	host := models.Host{ID: "host/with spaces", Hostname: "build node/1", OSName: "Ubuntu"}
	pkgs := []models.Package{{Name: "openssl", Version: "3.0.13", PkgType: "deb"}}
	data, err := GenerateSPDX(pkgs, host)
	if err != nil {
		t.Fatalf("GenerateSPDX: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}
	name := doc["name"].(string)
	if strings.ContainsAny(name, " /") {
		t.Fatalf("document name is not sanitized: %q", name)
	}
	ns := doc["documentNamespace"].(string)
	if strings.Contains(ns, " ") {
		t.Fatalf("namespace contains a space: %q", ns)
	}
	if strings.Contains(ns, "host/with spaces") {
		t.Fatalf("namespace contains unsanitized host id: %q", ns)
	}
}
