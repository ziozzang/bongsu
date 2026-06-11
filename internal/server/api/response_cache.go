package api

import (
	"sync"
	"time"
)

// responseCache is a tiny TTL cache for expensive, frequently-polled read
// endpoints (/api/stats, the admin /api/health operational block). The
// dashboard polls these every few seconds while the underlying aggregates
// change on scan/recalc cadence, so a short TTL trades a few seconds of
// staleness for removing 10+ aggregate queries from every poll. Entries are
// keyed by caller scope so RBAC-scoped responses never leak across subjects.
type responseCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]responseCacheEntry
}

type responseCacheEntry struct {
	value   any
	expires time.Time
}

func newResponseCache(ttlEnv string, defSeconds int) *responseCache {
	secs := envInt(ttlEnv, defSeconds)
	if secs <= 0 {
		// 0 disables caching entirely.
		return &responseCache{ttl: 0}
	}
	return &responseCache{ttl: time.Duration(secs) * time.Second, entries: map[string]responseCacheEntry{}}
}

func (c *responseCache) get(key string) (any, bool) {
	if c == nil || c.ttl <= 0 {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || time.Now().After(e.expires) {
		return nil, false
	}
	return e.value, true
}

func (c *responseCache) put(key string, value any) {
	if c == nil || c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Bound the map: these caches hold a handful of scope variants; a runaway
	// key space (e.g. per-request keys by mistake) must not grow unbounded.
	if len(c.entries) > 256 {
		c.entries = map[string]responseCacheEntry{}
	}
	c.entries[key] = responseCacheEntry{value: value, expires: time.Now().Add(c.ttl)}
}

// invalidate clears the cache, e.g. after a scan ingest or recalculation that
// changes the aggregates the cached responses summarize.
func (c *responseCache) invalidate() {
	if c == nil || c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[string]responseCacheEntry{}
}
