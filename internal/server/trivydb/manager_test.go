package trivydb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
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

func TestCacheMutationsAreSerialized(t *testing.T) {
	out, err := os.ReadFile("manager.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"opMu       sync.Mutex",
		"func (m *Manager) updateFromDownload",
		"m.opMu.Lock()",
		"defer m.opMu.Unlock()",
		"func (m *Manager) LoadFromFile",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("trivy DB manager cache mutation serialization missing %q", want)
		}
	}
	updateStart := strings.Index(body, "func (m *Manager) updateFromDownload")
	loadStart := strings.Index(body, "func (m *Manager) LoadFromFile")
	validateStart := strings.Index(body, "func (m *Manager) ValidateArchive")
	if updateStart < 0 || loadStart < 0 || validateStart < 0 {
		t.Fatal("expected manager methods not found")
	}
	updateFn := body[updateStart:loadStart]
	loadFn := body[loadStart:validateStart]
	if !strings.Contains(updateFn, "m.opMu.Lock()") || !strings.Contains(loadFn, "m.opMu.Lock()") {
		t.Fatal("download and load operations must both take opMu")
	}
}

func TestStatusTracksFailuresWithoutExposingErrorsPublicly(t *testing.T) {
	m := NewManager(filepath.Join(t.TempDir(), "missing-trivy"), t.TempDir(), "", 0)
	if err := m.UpdateNow(context.Background()); err == nil {
		t.Fatal("expected update to fail")
	}
	status := m.Status()
	if status["status"] != "failed" {
		t.Fatalf("status = %#v", status)
	}
	if got, _ := status["last_error"].(string); !strings.Contains(got, "trivy download-db") {
		t.Fatalf("last_error = %q, want download failure", got)
	}
	publicStatus := m.PublicStatus()
	if _, ok := publicStatus["last_error"]; ok {
		t.Fatalf("public status must not expose command errors: %#v", publicStatus)
	}
	if publicStatus["status"] != "failed" {
		t.Fatalf("public status = %#v", publicStatus)
	}
}

func TestStatusResetsAfterSuccessfulLoad(t *testing.T) {
	cache := t.TempDir()
	m := NewManager(filepath.Join(t.TempDir(), "missing-trivy"), cache, "", 0)
	if err := m.UpdateNow(context.Background()); err == nil {
		t.Fatal("expected update to fail")
	}
	archive := filepath.Join(t.TempDir(), "valid-trivy.tar.gz")
	if err := writeTrivyArchive(archive, map[string]string{"db/trivy.db": "db"}); err != nil {
		t.Fatal(err)
	}
	if err := m.LoadFromFile(archive); err != nil {
		t.Fatalf("load archive: %v", err)
	}
	status := m.Status()
	if status["status"] != "ok" || status["last_error"] != "" || status["ready"] != true {
		t.Fatalf("status not reset after load: %#v", status)
	}
}

func TestBoundedErrorKeepsUTF8Valid(t *testing.T) {
	got := boundedError(strings.Repeat("한", maxStatusErrorBytes), maxStatusErrorBytes)
	if !utf8.ValidString(got) {
		t.Fatalf("bounded error is not valid UTF-8: %q", got)
	}
	if !strings.HasSuffix(got, "...(truncated)") {
		t.Fatalf("bounded error missing truncation marker: %q", got)
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

func TestValidateArchiveDoesNotActivateDB(t *testing.T) {
	cache := t.TempDir()
	archive := filepath.Join(t.TempDir(), "valid-trivy.tar.gz")
	if err := writeTrivyArchive(archive, map[string]string{"db/trivy.db": "validated"}); err != nil {
		t.Fatal(err)
	}
	m := NewManager("trivy", cache, "", 0)
	if err := m.ValidateArchive(archive); err != nil {
		t.Fatalf("validate archive: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cache, "db", "trivy.db")); !os.IsNotExist(err) {
		t.Fatalf("validate should not activate db, stat err=%v", err)
	}
	if m.IsReady() {
		t.Fatal("validate should not mark manager ready")
	}
}

func TestLoadFromFileRejectsUnsupportedArchiveEntryTypes(t *testing.T) {
	cache := t.TempDir()
	archive := filepath.Join(t.TempDir(), "unsafe-trivy.tar.gz")
	if err := writeTrivyArchiveEntries(archive, []tarEntry{
		{name: "db/trivy.db", content: "db", typeflag: tar.TypeReg},
		{name: "db/link", typeflag: tar.TypeSymlink, linkname: "/tmp/outside"},
	}); err != nil {
		t.Fatal(err)
	}
	m := NewManager("trivy", cache, "", 0)
	if err := m.LoadFromFile(archive); err == nil {
		t.Fatal("expected unsupported archive entry to fail")
	}
	if _, err := os.Stat(filepath.Join(cache, "db", "trivy.db")); !os.IsNotExist(err) {
		t.Fatalf("unsafe archive should not activate db, stat err=%v", err)
	}
}

func TestLoadFromFileCreateErrorDoesNotCloseNilFile(t *testing.T) {
	out, err := os.ReadFile("manager.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	if strings.Contains(body, "if err != nil {\n\t\t\tout.Close()") {
		t.Fatal("os.Create error path must not close a nil file handle")
	}
}

func TestInvalidArchiveErrorsAreClassified(t *testing.T) {
	cache := t.TempDir()
	archive := filepath.Join(t.TempDir(), "invalid-trivy.tar.gz")
	if err := os.WriteFile(archive, []byte("not gzip"), 0644); err != nil {
		t.Fatal(err)
	}
	m := NewManager("trivy", cache, "", 0)
	if err := m.ValidateArchive(archive); !errors.Is(err, ErrInvalidArchive) {
		t.Fatalf("invalid archive error = %v, want ErrInvalidArchive", err)
	}
}

type tarEntry struct {
	name     string
	content  string
	typeflag byte
	linkname string
}

func writeTrivyArchive(path string, files map[string]string) error {
	entries := make([]tarEntry, 0, len(files))
	for name, content := range files {
		entries = append(entries, tarEntry{name: name, content: content, typeflag: tar.TypeReg})
	}
	return writeTrivyArchiveEntries(path, entries)
}

func writeTrivyArchiveEntries(path string, entries []tarEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		hdr := &tar.Header{
			Name:     entry.name,
			Mode:     0644,
			Size:     int64(len(entry.content)),
			Typeflag: typeflag,
			Linkname: entry.linkname,
		}
		if typeflag != tar.TypeReg && typeflag != tar.TypeRegA {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if hdr.Size > 0 {
			if _, err := tw.Write([]byte(entry.content)); err != nil {
				return err
			}
		}
	}
	return nil
}
