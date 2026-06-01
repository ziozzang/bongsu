package cvematch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteTempSBOMUsesPrivateTempFile(t *testing.T) {
	path, err := writeTempSBOM([]byte(`{"bomFormat":"CycloneDX"}`))
	if err != nil {
		t.Fatalf("writeTempSBOM: %v", err)
	}
	defer os.Remove(path)

	if filepath.Dir(path) != os.TempDir() {
		t.Fatalf("temp file dir = %q, want %q", filepath.Dir(path), os.TempDir())
	}
	if !strings.HasPrefix(filepath.Base(path), "bongsu-sbom-") {
		t.Fatalf("temp file name = %q", filepath.Base(path))
	}
	if !strings.HasSuffix(filepath.Base(path), ".cdx.json") {
		t.Fatalf("temp file name should keep SBOM extension, got %q", filepath.Base(path))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat temp file: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("temp file mode = %v, want 0600", mode)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read temp file: %v", err)
	}
	if string(data) != `{"bomFormat":"CycloneDX"}` {
		t.Fatalf("temp file content = %q", data)
	}
}
