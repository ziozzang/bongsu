package cvematch

import (
	"encoding/json"
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
