package system

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// parseKeyValueFile
// ---------------------------------------------------------------------------

func TestParseKeyValueFile_BasicPairs(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "os-release")
	if err := os.WriteFile(f, []byte("NAME=Ubuntu\nVERSION=22.04\n"), 0644); err != nil {
		t.Fatal(err)
	}
	m := parseKeyValueFile(f)
	if m["name"] != "Ubuntu" {
		t.Errorf("name = %q, want %q", m["name"], "Ubuntu")
	}
	if m["version"] != "22.04" {
		t.Errorf("version = %q, want %q", m["version"], "22.04")
	}
}

func TestParseKeyValueFile_CommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "os-release")
	content := "# This is a comment\n\nNAME=Debian\n# another comment\n\nVERSION_ID=12\n"
	if err := os.WriteFile(f, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	m := parseKeyValueFile(f)
	if len(m) != 2 {
		t.Errorf("len = %d, want 2: %v", len(m), m)
	}
	if m["name"] != "Debian" {
		t.Errorf("name = %q, want %q", m["name"], "Debian")
	}
	if m["version_id"] != "12" {
		t.Errorf("version_id = %q, want %q", m["version_id"], "12")
	}
}

func TestParseKeyValueFile_DoubleQuotedValues(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "os-release")
	if err := os.WriteFile(f, []byte(`NAME="Ubuntu 22.04 LTS"`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	m := parseKeyValueFile(f)
	if m["name"] != "Ubuntu 22.04 LTS" {
		t.Errorf("name = %q, want %q", m["name"], "Ubuntu 22.04 LTS")
	}
}

func TestParseKeyValueFile_SingleQuotedValues(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "os-release")
	if err := os.WriteFile(f, []byte("NAME='Alpine Linux'\n"), 0644); err != nil {
		t.Fatal(err)
	}
	m := parseKeyValueFile(f)
	if m["name"] != "Alpine Linux" {
		t.Errorf("name = %q, want %q", m["name"], "Alpine Linux")
	}
}

func TestParseKeyValueFile_ValueContainsEquals(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "os-release")
	// The value itself contains an '=' — only the first '=' splits key/value.
	if err := os.WriteFile(f, []byte("ANSI_COLOR=0;31\nBUG_REPORT_URL=https://example.com/bugs?a=1&b=2\n"), 0644); err != nil {
		t.Fatal(err)
	}
	m := parseKeyValueFile(f)
	if m["ansi_color"] != "0;31" {
		t.Errorf("ansi_color = %q, want %q", m["ansi_color"], "0;31")
	}
	if m["bug_report_url"] != "https://example.com/bugs?a=1&b=2" {
		t.Errorf("bug_report_url = %q, want %q", m["bug_report_url"], "https://example.com/bugs?a=1&b=2")
	}
}

func TestParseKeyValueFile_MissingFile(t *testing.T) {
	m := parseKeyValueFile("/nonexistent/path/os-release")
	if m != nil {
		t.Errorf("expected nil for missing file, got %v", m)
	}
}

func TestParseKeyValueFile_KeyLowercased(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "os-release")
	if err := os.WriteFile(f, []byte("ID=alpine\nID_LIKE=busybox\n"), 0644); err != nil {
		t.Fatal(err)
	}
	m := parseKeyValueFile(f)
	if _, ok := m["id"]; !ok {
		t.Error("key 'id' not found; expected lowercase")
	}
	if _, ok := m["id_like"]; !ok {
		t.Error("key 'id_like' not found; expected lowercase")
	}
}

func TestParseKeyValueFile_SkipsLineMissingEquals(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "os-release")
	if err := os.WriteFile(f, []byte("BADLINE\nNAME=good\n"), 0644); err != nil {
		t.Fatal(err)
	}
	m := parseKeyValueFile(f)
	if len(m) != 1 {
		t.Errorf("len = %d, want 1: %v", len(m), m)
	}
	if m["name"] != "good" {
		t.Errorf("name = %q, want %q", m["name"], "good")
	}
}

// ---------------------------------------------------------------------------
// collectReleaseFilesAt
// ---------------------------------------------------------------------------

func TestCollectReleaseFilesAt_FindsKnownFiles(t *testing.T) {
	root := t.TempDir()
	etcDir := filepath.Join(root, "etc")
	if err := os.MkdirAll(etcDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(etcDir, "alpine-release"), []byte("3.18.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(etcDir, "debian_version"), []byte("12.0\n"), 0644); err != nil {
		t.Fatal(err)
	}

	m := collectReleaseFilesAt(root)
	if m["alpine-release"] != "3.18.0" {
		t.Errorf("alpine-release = %q, want %q", m["alpine-release"], "3.18.0")
	}
	if m["debian_version"] != "12.0" {
		t.Errorf("debian_version = %q, want %q", m["debian_version"], "12.0")
	}
}

func TestCollectReleaseFilesAt_MissingFilesGraceful(t *testing.T) {
	root := t.TempDir()
	// No etc/ directory at all.
	m := collectReleaseFilesAt(root)
	if len(m) != 0 {
		t.Errorf("expected empty map for missing files, got %v", m)
	}
}

func TestCollectReleaseFilesAt_RedhatRelease(t *testing.T) {
	root := t.TempDir()
	etcDir := filepath.Join(root, "etc")
	if err := os.MkdirAll(etcDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(etcDir, "redhat-release"), []byte("Red Hat Enterprise Linux 9.2\n"), 0644); err != nil {
		t.Fatal(err)
	}

	m := collectReleaseFilesAt(root)
	if m["redhat-release"] != "Red Hat Enterprise Linux 9.2" {
		t.Errorf("redhat-release = %q, want %q", m["redhat-release"], "Red Hat Enterprise Linux 9.2")
	}
}

// ---------------------------------------------------------------------------
// CollectContainerFacts
// ---------------------------------------------------------------------------

func TestCollectContainerFacts_EmptyRootReturnsNil(t *testing.T) {
	facts := CollectContainerFacts("")
	if facts != nil {
		t.Errorf("expected nil for empty root, got %v", facts)
	}
}

func TestCollectContainerFacts_WithOsRelease(t *testing.T) {
	root := t.TempDir()
	etcDir := filepath.Join(root, "etc")
	if err := os.MkdirAll(etcDir, 0755); err != nil {
		t.Fatal(err)
	}
	osRelease := `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.18.0
PRETTY_NAME="Alpine Linux v3.18"
`
	if err := os.WriteFile(filepath.Join(etcDir, "os-release"), []byte(osRelease), 0644); err != nil {
		t.Fatal(err)
	}

	facts := CollectContainerFacts(root)
	if facts == nil {
		t.Fatal("expected non-nil facts")
	}
	osRel, ok := facts["os_release"].(map[string]any)
	if !ok {
		t.Fatalf("os_release not a map: %T %v", facts["os_release"], facts["os_release"])
	}
	if osRel["name"] != "Alpine Linux" {
		t.Errorf("os_release.name = %q, want %q", osRel["name"], "Alpine Linux")
	}
	if osRel["id"] != "alpine" {
		t.Errorf("os_release.id = %q, want %q", osRel["id"], "alpine")
	}
}

func TestCollectContainerFacts_WithLsbRelease(t *testing.T) {
	root := t.TempDir()
	etcDir := filepath.Join(root, "etc")
	if err := os.MkdirAll(etcDir, 0755); err != nil {
		t.Fatal(err)
	}
	lsbRelease := "DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=22.04\nDISTRIB_CODENAME=jammy\n"
	if err := os.WriteFile(filepath.Join(etcDir, "lsb-release"), []byte(lsbRelease), 0644); err != nil {
		t.Fatal(err)
	}

	facts := CollectContainerFacts(root)
	if facts == nil {
		t.Fatal("expected non-nil facts")
	}
	lsb, ok := facts["lsb_release"].(map[string]any)
	if !ok {
		t.Fatalf("lsb_release not a map: %T %v", facts["lsb_release"], facts["lsb_release"])
	}
	if lsb["distrib_id"] != "Ubuntu" {
		t.Errorf("lsb_release.distrib_id = %q, want %q", lsb["distrib_id"], "Ubuntu")
	}
}

func TestCollectContainerFacts_WithReleaseFiles(t *testing.T) {
	root := t.TempDir()
	etcDir := filepath.Join(root, "etc")
	if err := os.MkdirAll(etcDir, 0755); err != nil {
		t.Fatal(err)
	}
	// os-release provides the main identity; also drop an alpine-release
	osRelease := "NAME=Alpine\nVERSION_ID=3.18.0\n"
	if err := os.WriteFile(filepath.Join(etcDir, "os-release"), []byte(osRelease), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(etcDir, "alpine-release"), []byte("3.18.0\n"), 0644); err != nil {
		t.Fatal(err)
	}

	facts := CollectContainerFacts(root)
	if facts == nil {
		t.Fatal("expected non-nil facts")
	}
	rf, ok := facts["release_files"].(map[string]any)
	if !ok {
		t.Fatalf("release_files not a map: %T %v", facts["release_files"], facts["release_files"])
	}
	if rf["alpine-release"] != "3.18.0" {
		t.Errorf("release_files[alpine-release] = %q, want %q", rf["alpine-release"], "3.18.0")
	}
}

func TestCollectContainerFacts_NoFilesReturnsEmptyMap(t *testing.T) {
	root := t.TempDir()
	// No etc/ at all — all reads gracefully absent.
	facts := CollectContainerFacts(root)
	// All sections absent → map is empty (addIfNotEmpty skips them), but not nil.
	if facts == nil {
		t.Error("expected non-nil map (even if empty)")
	}
}

// ---------------------------------------------------------------------------
// addIfNotEmpty
// ---------------------------------------------------------------------------

func TestAddIfNotEmpty_NilVal(t *testing.T) {
	m := map[string]any{}
	addIfNotEmpty(m, "key", nil)
	if _, ok := m["key"]; ok {
		t.Error("expected key to be absent for nil value")
	}
}

func TestAddIfNotEmpty_EmptyMapVal(t *testing.T) {
	m := map[string]any{}
	addIfNotEmpty(m, "key", map[string]any{})
	if _, ok := m["key"]; ok {
		t.Error("expected key to be absent for empty map value")
	}
}

func TestAddIfNotEmpty_EmptySliceAny(t *testing.T) {
	m := map[string]any{}
	addIfNotEmpty(m, "key", []any{})
	if _, ok := m["key"]; ok {
		t.Error("expected key to be absent for empty []any")
	}
}

func TestAddIfNotEmpty_EmptySliceMapAny(t *testing.T) {
	m := map[string]any{}
	addIfNotEmpty(m, "key", []map[string]any{})
	if _, ok := m["key"]; ok {
		t.Error("expected key to be absent for empty []map[string]any")
	}
}

func TestAddIfNotEmpty_EmptyString(t *testing.T) {
	m := map[string]any{}
	addIfNotEmpty(m, "key", "")
	if _, ok := m["key"]; ok {
		t.Error("expected key to be absent for empty string")
	}
}

func TestAddIfNotEmpty_NonEmptyValues(t *testing.T) {
	tests := []struct {
		name string
		val  any
	}{
		{"non-empty string", "hello"},
		{"non-empty map", map[string]any{"a": 1}},
		{"non-empty []any", []any{"x"}},
		{"non-empty []map[string]any", []map[string]any{{"a": 1}}},
		{"int", 42},
	}
	for _, tc := range tests {
		m := map[string]any{}
		addIfNotEmpty(m, "key", tc.val)
		if _, ok := m["key"]; !ok {
			t.Errorf("[%s] expected key to be present, but it was absent", tc.name)
		}
	}
}

// ---------------------------------------------------------------------------
// readTrim
// ---------------------------------------------------------------------------

func TestReadTrim_ReturnsContent(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "testfile")
	if err := os.WriteFile(f, []byte("  hello world  \n"), 0644); err != nil {
		t.Fatal(err)
	}
	got := readTrim(f)
	if got != "hello world" {
		t.Errorf("readTrim = %q, want %q", got, "hello world")
	}
}

func TestReadTrim_MissingFileReturnsEmpty(t *testing.T) {
	got := readTrim("/nonexistent/path/file")
	if got != "" {
		t.Errorf("readTrim missing file = %q, want empty string", got)
	}
}

// ---------------------------------------------------------------------------
// CollectFacts (host-level — only smoke-test: no panic, non-nil map)
// ---------------------------------------------------------------------------

func TestCollectFacts_NoPanicReturnsNonNilMap(t *testing.T) {
	facts := CollectFacts()
	if facts == nil {
		t.Fatal("CollectFacts returned nil")
	}
	// "agent" section is always populated.
	agentSection, ok := facts["agent"]
	if !ok {
		t.Fatal("CollectFacts result missing 'agent' key")
	}
	agentMap, ok := agentSection.(map[string]any)
	if !ok {
		t.Fatalf("'agent' is not a map: %T", agentSection)
	}
	if agentMap["goos"] == nil {
		t.Error("agent.goos is nil")
	}
}
