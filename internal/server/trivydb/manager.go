package trivydb

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

type Manager struct {
	trivyPath  string
	cacheDir   string
	dbRepo     string
	interval   time.Duration
	mu         sync.RWMutex
	ready      bool
	lastUpdate time.Time
}

func NewManager(trivyPath, cacheDir, dbRepo string, interval time.Duration) *Manager {
	return &Manager{
		trivyPath: trivyPath,
		cacheDir:  cacheDir,
		dbRepo:    dbRepo,
		interval:  interval,
	}
}

func (m *Manager) Start(ctx context.Context) {
	os.MkdirAll(m.cacheDir, 0755)

	// trivy-db is provided by init container or uploaded via API.
	// Just check if it exists in the cache directory.
	if m.checkExisting() {
		m.mu.Lock()
		m.ready = true
		m.lastUpdate = time.Now()
		m.mu.Unlock()
		log.Printf("trivy-db ready (loaded from cache)")
	} else {
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
				log.Printf("trivy-db periodic update failed: %v", err)
				continue
			}
			m.mu.Lock()
			m.lastUpdate = time.Now()
			m.mu.Unlock()
			log.Printf("trivy-db updated")
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

func (m *Manager) UpdateNow(ctx context.Context) error {
	if err := m.download(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	m.ready = true
	m.lastUpdate = time.Now()
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

	cmd := exec.CommandContext(dlCtx, m.trivyPath,
		"image",
		"--download-db-only",
		"--cache-dir", m.cacheDir,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("trivy download-db: %s: %w", string(out), err)
	}
	return nil
}

func (m *Manager) LoadFromFile(path string) error {
	dbDir := filepath.Join(m.cacheDir, "db")
	os.MkdirAll(dbDir, 0755)

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read: %w", err)
		}
		if !isSafePath(m.cacheDir, hdr.Name) {
			return fmt.Errorf("unsafe path in archive: %s", hdr.Name)
		}
		target := filepath.Join(m.cacheDir, hdr.Name)
		if hdr.Typeflag == tar.TypeDir {
			os.MkdirAll(target, 0755)
			continue
		}
		os.MkdirAll(filepath.Dir(target), 0755)
		out, err := os.Create(target)
		if err != nil {
			out.Close()
			return fmt.Errorf("create %s: %w", target, err)
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return fmt.Errorf("write %s: %w", target, err)
		}
		out.Close()
	}

	m.mu.Lock()
	m.ready = true
	m.lastUpdate = time.Now()
	m.mu.Unlock()
	log.Printf("trivy-db loaded from file")
	return nil
}

func isSafePath(base, name string) bool {
	cleaned := filepath.Join(base, name)
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return false
	}
	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return false
	}
	return len(abs) >= len(baseAbs) && abs[:len(baseAbs)] == baseAbs
}
