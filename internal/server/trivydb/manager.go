package trivydb

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var ErrInvalidArchive = errors.New("invalid trivy db archive")

const maxStatusErrorBytes = 8192

type Manager struct {
	trivyPath  string
	cacheDir   string
	dbRepo     string
	interval   time.Duration
	mu         sync.RWMutex
	ready      bool
	lastUpdate time.Time
	lastStatus string
	lastError  string
	onUpdate   func(string)
}

func NewManager(trivyPath, cacheDir, dbRepo string, interval time.Duration) *Manager {
	return &Manager{
		trivyPath: trivyPath,
		cacheDir:  cacheDir,
		dbRepo:    dbRepo,
		interval:  interval,
	}
}

func (m *Manager) SetUpdateHook(fn func(string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onUpdate = fn
}

func (m *Manager) Start(ctx context.Context) {
	os.MkdirAll(m.cacheDir, 0755)

	// trivy-db is provided by init container or uploaded via API.
	// Just check if it exists in the cache directory.
	if m.checkExisting() {
		m.mu.Lock()
		m.ready = true
		m.lastUpdate = time.Now()
		m.lastStatus = "ok"
		m.lastError = ""
		m.mu.Unlock()
		log.Printf("trivy-db ready (loaded from cache)")
	} else {
		m.recordError("missing", fmt.Errorf("trivy-db not found in %s", filepath.Join(m.cacheDir, "db", "trivy.db")))
		log.Printf("WARNING: trivy-db not found, server-side CVE matching disabled")
		log.Printf("  To update: docker compose run --rm trivy-db && docker compose restart server")
	}

	if m.interval <= 0 {
		return
	}

	log.Printf("trivy-db periodic update enabled (interval: %s)", m.interval)
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.download(ctx); err != nil {
				m.recordError("failed", err)
				log.Printf("trivy-db periodic update failed: %v", err)
				continue
			}
			m.mu.Lock()
			m.ready = true
			m.lastUpdate = time.Now()
			m.lastStatus = "ok"
			m.lastError = ""
			onUpdate := m.onUpdate
			m.mu.Unlock()
			log.Printf("trivy-db updated")
			if onUpdate != nil {
				onUpdate("trivy-db periodic update")
			}
		}
	}
}

func (m *Manager) IsReady() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ready
}

func (m *Manager) LastUpdate() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastUpdate
}

func (m *Manager) Status() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]any{
		"ready":       m.ready,
		"last_update": m.lastUpdate,
		"status":      m.statusLocked(),
		"last_error":  m.lastError,
	}
}

func (m *Manager) PublicStatus() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]any{
		"ready":       m.ready,
		"last_update": m.lastUpdate,
		"status":      m.statusLocked(),
	}
}

func (m *Manager) UpdateNow(ctx context.Context) error {
	if err := m.download(ctx); err != nil {
		m.recordError("failed", err)
		return err
	}
	m.mu.Lock()
	m.ready = true
	m.lastUpdate = time.Now()
	m.lastStatus = "ok"
	m.lastError = ""
	m.mu.Unlock()
	log.Printf("trivy-db updated (on-demand)")
	return nil
}

func (m *Manager) checkExisting() bool {
	dbPath := filepath.Join(m.cacheDir, "db", "trivy.db")
	info, err := os.Stat(dbPath)
	if err != nil {
		return false
	}
	return info.Size() > 0
}

func (m *Manager) download(ctx context.Context) error {
	dlCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(dlCtx, m.trivyPath, m.downloadArgs()...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("trivy download-db: %s: %w", string(out), err)
	}
	return nil
}

func (m *Manager) downloadArgs() []string {
	args := []string{
		"image",
		"--download-db-only",
		"--cache-dir", m.cacheDir,
	}
	if m.dbRepo != "" {
		args = append(args, "--db-repository", m.dbRepo)
	}
	return args
}

func (m *Manager) LoadFromFile(path string) error {
	dbDir := filepath.Join(m.cacheDir, "db")
	_, stagedDB, cleanup, err := m.stageArchive(path)
	if err != nil {
		m.recordError("failed", err)
		return err
	}
	defer cleanup()

	backup := filepath.Join(m.cacheDir, fmt.Sprintf(".bongsu-trivy-db-backup-%d", time.Now().UnixNano()))
	hadExisting := false
	if _, err := os.Stat(dbDir); err == nil {
		hadExisting = true
		if err := os.Rename(dbDir, backup); err != nil {
			m.recordError("failed", fmt.Errorf("backup existing db: %w", err))
			return fmt.Errorf("backup existing db: %w", err)
		}
	}
	if err := os.Rename(stagedDB, dbDir); err != nil {
		if hadExisting {
			_ = os.Rename(backup, dbDir)
		}
		m.recordError("failed", fmt.Errorf("activate staged db: %w", err))
		return fmt.Errorf("activate staged db: %w", err)
	}
	if hadExisting {
		_ = os.RemoveAll(backup)
	}

	m.mu.Lock()
	m.ready = true
	m.lastUpdate = time.Now()
	m.lastStatus = "ok"
	m.lastError = ""
	m.mu.Unlock()
	log.Printf("trivy-db loaded from file")
	return nil
}

func (m *Manager) ValidateArchive(path string) error {
	_, _, cleanup, err := m.stageArchive(path)
	if cleanup != nil {
		defer cleanup()
	}
	return err
}

func (m *Manager) recordError(status string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastStatus = status
	if err == nil {
		m.lastError = ""
		return
	}
	m.lastError = boundedError(err.Error(), maxStatusErrorBytes)
}

func (m *Manager) statusLocked() string {
	if m.lastStatus != "" {
		return m.lastStatus
	}
	if m.ready {
		return "ok"
	}
	return "unknown"
}

func boundedError(s string, limit int) string {
	s = strings.TrimSpace(s)
	if len(s) <= limit {
		return s
	}
	s = s[:limit]
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return strings.TrimSpace(s) + "...(truncated)"
}

func (m *Manager) stageArchive(path string) (string, string, func(), error) {
	if err := os.MkdirAll(m.cacheDir, 0755); err != nil {
		return "", "", nil, fmt.Errorf("create cache dir: %w", err)
	}
	staging, err := os.MkdirTemp(m.cacheDir, ".bongsu-trivy-db-*")
	if err != nil {
		return "", "", nil, fmt.Errorf("create staging dir: %w", err)
	}
	cleanup := func() { os.RemoveAll(staging) }
	f, err := os.Open(path)
	if err != nil {
		cleanup()
		return "", "", nil, fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		cleanup()
		return "", "", nil, fmt.Errorf("%w: gzip reader: %v", ErrInvalidArchive, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			cleanup()
			return "", "", nil, fmt.Errorf("%w: tar read: %v", ErrInvalidArchive, err)
		}
		if !isSafePath(staging, hdr.Name) {
			cleanup()
			return "", "", nil, fmt.Errorf("%w: unsafe path in archive: %s", ErrInvalidArchive, hdr.Name)
		}
		target := filepath.Join(staging, hdr.Name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				cleanup()
				return "", "", nil, fmt.Errorf("create %s: %w", target, err)
			}
			continue
		case tar.TypeReg, tar.TypeRegA:
		default:
			cleanup()
			return "", "", nil, fmt.Errorf("%w: unsupported archive entry type %c for %s", ErrInvalidArchive, hdr.Typeflag, hdr.Name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			cleanup()
			return "", "", nil, fmt.Errorf("create %s: %w", filepath.Dir(target), err)
		}
		out, err := os.Create(target)
		if err != nil {
			cleanup()
			return "", "", nil, fmt.Errorf("create %s: %w", target, err)
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			cleanup()
			return "", "", nil, fmt.Errorf("write %s: %w", target, err)
		}
		out.Close()
	}
	stagedDB := filepath.Join(staging, "db")
	if info, err := os.Stat(filepath.Join(stagedDB, "trivy.db")); err != nil || info.Size() == 0 {
		cleanup()
		return "", "", nil, fmt.Errorf("%w: archive missing db/trivy.db", ErrInvalidArchive)
	}
	return staging, stagedDB, cleanup, nil
}

func (m *Manager) WriteArchive(w io.Writer) error {
	dbDir := filepath.Join(m.cacheDir, "db")
	if !m.checkExisting() {
		return fmt.Errorf("trivy-db not ready")
	}
	gz := gzip.NewWriter(w)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	return filepath.WalkDir(dbDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(m.cacheDir, path)
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
}

func (m *Manager) ArchiveBytes() ([]byte, error) {
	tmp, err := os.CreateTemp("", "bongsu-trivy-db-*.tar.gz")
	if err != nil {
		return nil, err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := m.WriteArchive(tmp); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	return os.ReadFile(name)
}

func isSafePath(base, name string) bool {
	if filepath.IsAbs(name) {
		return false
	}
	cleaned := filepath.Join(base, name)
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return false
	}
	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(baseAbs, abs)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}
