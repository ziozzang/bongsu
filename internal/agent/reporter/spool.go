package reporter

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// defaultSpoolMax bounds the number of unsent scan reports retained on disk so
// a long server outage cannot grow the spool without limit. The newest reports
// are the most valuable, so once the cap is reached the oldest spooled file is
// evicted before a new one is written.
const defaultSpoolMax = 20

// spoolMaxFromEnv returns the configured spool cap, honoring
// BONGSU_AGENT_SPOOL_MAX and falling back to defaultSpoolMax for empty/invalid
// values.
func spoolMaxFromEnv() int {
	if v := os.Getenv("BONGSU_AGENT_SPOOL_MAX"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultSpoolMax
}

// SpoolDir returns the directory under workDir where unsent reports are spooled.
func SpoolDir(workDir string) string {
	return filepath.Join(workDir, "spool")
}

// spoolFileName builds a sortable file name for a spooled report. The timestamp
// prefix (UTC, nanosecond) makes lexical order match chronological order so the
// oldest file is replayed/evicted first.
func spoolFileName(t time.Time, scanID string) string {
	safe := sanitizeScanID(scanID)
	return fmt.Sprintf("%020d-%s.json", t.UTC().UnixNano(), safe)
}

func sanitizeScanID(scanID string) string {
	scanID = strings.TrimSpace(scanID)
	if scanID == "" {
		scanID = "noid"
	}
	var b strings.Builder
	for _, r := range scanID {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// listSpoolFiles returns absolute paths of spooled report files, oldest first.
func listSpoolFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		if strings.HasSuffix(name, ".tmp") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = filepath.Join(dir, n)
	}
	return out, nil
}

// SpoolReport writes the marshaled report JSON to the spool directory under
// workDir using an atomic temp+rename so a crash never leaves a half-written
// report. Before writing, the spool is capped: while at/over the configured
// limit the oldest spooled file is evicted (newest data wins).
func SpoolReport(workDir string, report *models.ScanReport) (string, error) {
	dir := SpoolDir(workDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create spool dir: %w", err)
	}

	data, err := json.Marshal(report)
	if err != nil {
		return "", fmt.Errorf("marshal report for spool: %w", err)
	}

	max := spoolMaxFromEnv()
	if err := evictForCapacity(dir, max); err != nil {
		// Eviction failure is non-fatal: still try to persist the new report.
		log.Printf("spool: failed to enforce capacity: %v", err)
	}

	name := spoolFileName(report.Timestamp, report.ScanID)
	finalPath := filepath.Join(dir, name)
	tmpPath := finalPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return "", fmt.Errorf("write spool temp file: %w", err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("rename spool file: %w", err)
	}
	return finalPath, nil
}

// evictForCapacity removes the oldest spooled files until there is room for one
// more (i.e. fewer than max files remain). max <= 0 means unbounded.
func evictForCapacity(dir string, max int) error {
	if max <= 0 {
		return nil
	}
	files, err := listSpoolFiles(dir)
	if err != nil {
		return err
	}
	// Leave room for the one about to be written: keep at most max-1.
	for len(files) >= max {
		oldest := files[0]
		if err := os.Remove(oldest); err != nil && !os.IsNotExist(err) {
			return err
		}
		log.Printf("spool: capacity %d reached, evicted oldest report %s", max, filepath.Base(oldest))
		files = files[1:]
	}
	return nil
}

// ReplaySpool attempts to resend previously spooled reports, oldest first.
// On the first send failure it stops (the server is likely still down, so
// burning through every file wastes the retry budget). Corrupt files that fail
// to parse are skipped and deleted. It returns the number of reports
// successfully resent. Replay never returns an error that should block a fresh
// scan; transient send failures are logged and tolerated.
func (r *Reporter) ReplaySpool(workDir string) int {
	dir := SpoolDir(workDir)
	files, err := listSpoolFiles(dir)
	if err != nil {
		log.Printf("spool: failed to list spool dir: %v", err)
		return 0
	}
	if len(files) == 0 {
		return 0
	}
	log.Printf("spool: replaying %d spooled report(s)", len(files))
	sent := 0
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("spool: failed to read %s: %v", filepath.Base(path), err)
			// Treat unreadable as corrupt: drop it so it cannot wedge replay.
			_ = os.Remove(path)
			continue
		}
		var report models.ScanReport
		if err := json.Unmarshal(data, &report); err != nil {
			log.Printf("spool: dropping corrupt spool file %s: %v", filepath.Base(path), err)
			_ = os.Remove(path)
			continue
		}
		if _, err := r.Send(&report); err != nil {
			log.Printf("spool: replay of %s failed, leaving for next run: %v", filepath.Base(path), err)
			// Server still unreachable; stop replaying to preserve retry budget.
			break
		}
		if err := os.Remove(path); err != nil {
			log.Printf("spool: replayed %s but failed to delete: %v", filepath.Base(path), err)
		} else {
			log.Printf("spool: replayed and removed %s", filepath.Base(path))
		}
		sent++
	}
	return sent
}
