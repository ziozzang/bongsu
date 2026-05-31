package trivydb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestWriteArchiveIncludesTrivyDB(t *testing.T) {
	cache := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cache, "db"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "db", "trivy.db"), []byte("db"), 0644); err != nil {
		t.Fatal(err)
	}

	m := NewManager("trivy", cache, "", 0)
	var buf bytes.Buffer
	if err := m.WriteArchive(&buf); err != nil {
		t.Fatal(err)
	}

	gz, err := gzip.NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Name == "db/trivy.db" {
			return
		}
	}
	t.Fatal("db/trivy.db not found in archive")
}

func TestDownloadArgsIncludeConfiguredDBRepository(t *testing.T) {
	m := NewManager("trivy", "/cache", "registry.local/aqua/trivy-db", 0)
	want := []string{
		"image",
		"--download-db-only",
		"--cache-dir", "/cache",
		"--db-repository", "registry.local/aqua/trivy-db",
	}
	if got := m.downloadArgs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("download args = %#v, want %#v", got, want)
	}
}

func TestIsSafePathRejectsTraversalAndPrefixSiblings(t *testing.T) {
	base := filepath.Join(t.TempDir(), "cache")
	tests := []struct {
		name string
		want bool
	}{
		{"db/trivy.db", true},
		{"../cache2/db/trivy.db", false},
		{"../cache/db/trivy.db", true},
		{"../../outside", false},
		{filepath.Join(base, "db/trivy.db"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSafePath(base, tt.name); got != tt.want {
				t.Fatalf("isSafePath(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestLoadFromFileDoesNotCorruptExistingDBOnInvalidArchive(t *testing.T) {
	cache := t.TempDir()
	dbDir := filepath.Join(cache, "db")
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(dbDir, "trivy.db")
	if err := os.WriteFile(existing, []byte("existing"), 0644); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(t.TempDir(), "invalid-trivy.tar.gz")
	if err := writeTrivyArchive(archive, map[string]string{"db/metadata.json": "{}"}); err != nil {
		t.Fatal(err)
	}
	m := NewManager("trivy", cache, "", 0)
	if err := m.LoadFromFile(archive); err == nil {
		t.Fatal("expected invalid archive to fail")
	}
	got, err := os.ReadFile(existing)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "existing" {
		t.Fatalf("existing db changed to %q", got)
	}
}

func TestLoadFromFileReplacesDBAfterStaging(t *testing.T) {
	cache := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cache, "db"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "db", "trivy.db"), []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(t.TempDir(), "valid-trivy.tar.gz")
	if err := writeTrivyArchive(archive, map[string]string{"db/trivy.db": "new"}); err != nil {
		t.Fatal(err)
	}
	m := NewManager("trivy", cache, "", 0)
	if err := m.LoadFromFile(archive); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(cache, "db", "trivy.db"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("db content = %q", got)
	}
}

func writeTrivyArchive(path string, files map[string]string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			return err
		}
	}
	return nil
}
