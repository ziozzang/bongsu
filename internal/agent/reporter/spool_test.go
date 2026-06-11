package reporter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

func spoolTestReport(scanID string, ts time.Time) *models.ScanReport {
	return &models.ScanReport{
		Host:      models.Host{ID: "host-1"},
		ScanID:    scanID,
		ScanType:  "manual",
		Timestamp: ts,
	}
}

func TestSpoolReportWritesAtomicallyWithMode(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	path, err := SpoolReport(dir, spoolTestReport("scan-a", ts))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("spool file mode = %v, want 0600", info.Mode().Perm())
	}
	if filepath.Dir(path) != SpoolDir(dir) {
		t.Fatalf("spool file in %q, want under %q", filepath.Dir(path), SpoolDir(dir))
	}
	// No leftover temp files.
	entries, _ := os.ReadDir(SpoolDir(dir))
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("leftover temp file: %s", e.Name())
		}
	}
	// Round-trips back to the same scan id.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got models.ScanReport
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.ScanID != "scan-a" {
		t.Fatalf("round-tripped scan id = %q, want scan-a", got.ScanID)
	}
}

func TestListSpoolFilesOrdersOldestFirst(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	// Write out of order; list must return chronological order.
	if _, err := SpoolReport(dir, spoolTestReport("scan-mid", base.Add(time.Second))); err != nil {
		t.Fatal(err)
	}
	if _, err := SpoolReport(dir, spoolTestReport("scan-old", base)); err != nil {
		t.Fatal(err)
	}
	if _, err := SpoolReport(dir, spoolTestReport("scan-new", base.Add(2*time.Second))); err != nil {
		t.Fatal(err)
	}
	files, err := listSpoolFiles(SpoolDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("got %d files, want 3", len(files))
	}
	wantOrder := []string{"scan-old", "scan-mid", "scan-new"}
	for i, path := range files {
		data, _ := os.ReadFile(path)
		var r models.ScanReport
		_ = json.Unmarshal(data, &r)
		if r.ScanID != wantOrder[i] {
			t.Fatalf("file %d = %q, want %q", i, r.ScanID, wantOrder[i])
		}
	}
}

func TestReplaySpoolSuccessDeletesFiles(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	for i, id := range []string{"scan-a", "scan-b", "scan-c"} {
		if _, err := SpoolReport(dir, spoolTestReport(id, base.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatal(err)
		}
	}

	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rep models.ScanReport
		_ = json.NewDecoder(r.Body).Decode(&rep)
		seen = append(seen, rep.ScanID)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	rep := New(srv.URL, "api-key")
	rep.sleep = func(time.Duration) {}
	n := rep.ReplaySpool(dir)
	if n != 3 {
		t.Fatalf("replayed %d, want 3", n)
	}
	// Sent oldest first.
	want := []string{"scan-a", "scan-b", "scan-c"}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("send order[%d] = %q, want %q", i, seen[i], want[i])
		}
	}
	files, _ := listSpoolFiles(SpoolDir(dir))
	if len(files) != 0 {
		t.Fatalf("spool not drained: %d files remain", len(files))
	}
}

func TestReplaySpoolFailureKeepsAndStops(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	for i, id := range []string{"scan-a", "scan-b", "scan-c"} {
		if _, err := SpoolReport(dir, spoolTestReport(id, base.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("BONGSU_AGENT_RETRY_ATTEMPTS", "1")
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		// First report succeeds, second fails (server "goes down" again).
		if requests == 1 {
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	rep := New(srv.URL, "api-key")
	rep.sleep = func(time.Duration) {}
	n := rep.ReplaySpool(dir)
	if n != 1 {
		t.Fatalf("replayed %d, want 1 (stop after first failure)", n)
	}
	files, _ := listSpoolFiles(SpoolDir(dir))
	if len(files) != 2 {
		t.Fatalf("remaining files = %d, want 2 (failed one kept, third untouched)", len(files))
	}
	// The two remaining should be scan-b and scan-c, in order.
	wantRemain := []string{"scan-b", "scan-c"}
	for i, path := range files {
		data, _ := os.ReadFile(path)
		var rr models.ScanReport
		_ = json.Unmarshal(data, &rr)
		if rr.ScanID != wantRemain[i] {
			t.Fatalf("remaining[%d] = %q, want %q", i, rr.ScanID, wantRemain[i])
		}
	}
}

func TestSpoolReportCapEvictsOldest(t *testing.T) {
	t.Setenv("BONGSU_AGENT_SPOOL_MAX", "3")
	dir := t.TempDir()
	base := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	ids := []string{"scan-1", "scan-2", "scan-3", "scan-4", "scan-5"}
	for i, id := range ids {
		if _, err := SpoolReport(dir, spoolTestReport(id, base.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	files, _ := listSpoolFiles(SpoolDir(dir))
	if len(files) != 3 {
		t.Fatalf("spool size = %d, want capped at 3", len(files))
	}
	// Newest three survive: scan-3, scan-4, scan-5.
	wantKept := []string{"scan-3", "scan-4", "scan-5"}
	for i, path := range files {
		data, _ := os.ReadFile(path)
		var rr models.ScanReport
		_ = json.Unmarshal(data, &rr)
		if rr.ScanID != wantKept[i] {
			t.Fatalf("kept[%d] = %q, want %q", i, rr.ScanID, wantKept[i])
		}
	}
}

func TestReplaySpoolSkipsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	spoolDir := SpoolDir(dir)
	if err := os.MkdirAll(spoolDir, 0700); err != nil {
		t.Fatal(err)
	}
	// A corrupt file sorted oldest, then a good report.
	corrupt := filepath.Join(spoolDir, "00000000000000000001-corrupt.json")
	if err := os.WriteFile(corrupt, []byte("{not valid json"), 0600); err != nil {
		t.Fatal(err)
	}
	good := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	if _, err := SpoolReport(dir, spoolTestReport("scan-good", good)); err != nil {
		t.Fatal(err)
	}

	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rep models.ScanReport
		_ = json.NewDecoder(r.Body).Decode(&rep)
		seen = append(seen, rep.ScanID)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	rep := New(srv.URL, "api-key")
	rep.sleep = func(time.Duration) {}
	n := rep.ReplaySpool(dir)
	if n != 1 {
		t.Fatalf("replayed %d, want 1 (corrupt skipped, good sent)", n)
	}
	if len(seen) != 1 || seen[0] != "scan-good" {
		t.Fatalf("sent = %v, want [scan-good]", seen)
	}
	if _, err := os.Stat(corrupt); !os.IsNotExist(err) {
		t.Fatalf("corrupt file was not deleted: err=%v", err)
	}
	files, _ := listSpoolFiles(spoolDir)
	if len(files) != 0 {
		t.Fatalf("spool not drained: %d files remain", len(files))
	}
}

func TestReplaySpoolEmptyDirIsNoop(t *testing.T) {
	dir := t.TempDir()
	rep := New("http://localhost:0", "api-key")
	if n := rep.ReplaySpool(dir); n != 0 {
		t.Fatalf("replay of empty/missing spool = %d, want 0", n)
	}
}

func TestSpoolMaxFromEnv(t *testing.T) {
	if got := spoolMaxFromEnv(); got != defaultSpoolMax {
		t.Fatalf("default spool max = %d, want %d", got, defaultSpoolMax)
	}
	t.Setenv("BONGSU_AGENT_SPOOL_MAX", "7")
	if got := spoolMaxFromEnv(); got != 7 {
		t.Fatalf("custom spool max = %d, want 7", got)
	}
	for _, v := range []string{"0", "-2", "nope"} {
		t.Setenv("BONGSU_AGENT_SPOOL_MAX", v)
		if got := spoolMaxFromEnv(); got != defaultSpoolMax {
			t.Fatalf("BONGSU_AGENT_SPOOL_MAX=%q gave %d, want %d", v, got, defaultSpoolMax)
		}
	}
}
