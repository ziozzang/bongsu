package trivydb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
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
