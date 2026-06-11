package api

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// secdbBundleCache holds a pre-built airgap export bundle per variant
// (with/without the Trivy DB) so downloads stream an existing file instead of
// building ~170MB on demand. The cache is rebuilt in the background whenever the
// security database changes, and each entry records the security DB revision it
// was built from so a stale bundle is never served after a sync/import.
type secdbBundleCache struct {
	dir string
	mu  sync.Mutex // serializes rebuilds; readers use per-entry snapshots
}

type secdbBundleMeta struct {
	Path          string    `json:"-"`
	Revision      string    `json:"revision"`
	IncludeTrivy  bool      `json:"include_trivy"`
	Size          int64     `json:"size"`
	CveRecords    int       `json:"cve_records"`
	TrivyIncluded bool      `json:"trivy_included"`
	BuiltAt       time.Time `json:"built_at"`
}

func newSecdbBundleCache() *secdbBundleCache {
	base := os.Getenv("BONGSU_TMPDIR")
	if base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "bongsu-secdb-bundle-cache")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Printf("secdb bundle cache: cannot create %s: %v", dir, err)
		return &secdbBundleCache{dir: ""}
	}
	return &secdbBundleCache{dir: dir}
}

func bundleVariantName(includeTrivy bool) string {
	if includeTrivy {
		return "with-trivy"
	}
	return "cve-only"
}

func (c *secdbBundleCache) paths(includeTrivy bool) (data, meta string) {
	name := bundleVariantName(includeTrivy)
	return filepath.Join(c.dir, "bundle-"+name+".tar.gz"), filepath.Join(c.dir, "bundle-"+name+".json")
}

// get returns a usable cached bundle for the variant only if it exists and was
// built from the current security DB revision; otherwise (nil, false).
func (c *secdbBundleCache) get(includeTrivy bool, currentRevision string) (*secdbBundleMeta, bool) {
	if c == nil || c.dir == "" {
		return nil, false
	}
	dataPath, metaPath := c.paths(includeTrivy)
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, false
	}
	var m secdbBundleMeta
	if json.Unmarshal(raw, &m) != nil {
		return nil, false
	}
	if currentRevision != "" && m.Revision != currentRevision {
		return nil, false
	}
	fi, err := os.Stat(dataPath)
	if err != nil || fi.Size() != m.Size {
		return nil, false
	}
	m.Path = dataPath
	return &m, true
}

// store atomically promotes a freshly built bundle file into the cache for the
// variant and writes its metadata sidecar. srcPath is consumed (renamed); on
// failure it is left for the caller's defer to remove.
func (c *secdbBundleCache) store(srcPath string, m secdbBundleMeta) error {
	if c == nil || c.dir == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	dataPath, metaPath := c.paths(m.IncludeTrivy)
	// Copy (not rename) so the caller's temp file and its os.Remove defer stay
	// valid; the cache owns its own copy. Rename within the cache dir keeps the
	// swap atomic for readers.
	tmp := dataPath + ".tmp"
	if err := copyFile(srcPath, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, dataPath); err != nil {
		os.Remove(tmp)
		return err
	}
	metaBytes, _ := json.Marshal(m)
	metaTmp := metaPath + ".tmp"
	if err := os.WriteFile(metaTmp, metaBytes, 0o600); err != nil {
		return err
	}
	return os.Rename(metaTmp, metaPath)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// rebuildSecdbBundleCache builds and caches the cve-only bundle (the common
// airgap transfer) so the next download streams instantly. Called in the
// background after the security DB changes. Best-effort: errors are logged, not
// fatal. Only the cve-only variant is pre-built; the with-trivy variant is
// cached lazily on first download (it is large and less commonly transferred).
func (s *Server) rebuildSecdbBundleCache(reason string) {
	if s.bundleCache == nil || s.bundleCache.dir == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	revision, err := s.db.GetSecurityDBRevision(ctx)
	if err != nil {
		log.Printf("secdb bundle cache: revision lookup failed: %v", err)
		return
	}
	if _, ok := s.bundleCache.get(false, revision); ok {
		return // already current
	}
	start := time.Now()
	path, cveCount, trivyIncluded, size, rev, err := s.buildSecurityDBBundleTemp(ctx, false)
	if err != nil {
		log.Printf("secdb bundle cache: build failed (%s): %v", reason, err)
		return
	}
	defer os.Remove(path)
	meta := secdbBundleMeta{
		Revision: rev, IncludeTrivy: false, Size: size, CveRecords: cveCount,
		TrivyIncluded: trivyIncluded, BuiltAt: time.Now().UTC(),
	}
	if err := s.bundleCache.store(path, meta); err != nil {
		log.Printf("secdb bundle cache: store failed: %v", err)
		return
	}
	log.Printf("secdb bundle cache: pre-built cve-only bundle rev %s (%d records, %d bytes) in %s",
		rev, cveCount, size, time.Since(start).Round(time.Millisecond))
}
