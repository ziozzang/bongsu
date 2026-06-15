package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ziozzang/bongsu/internal/server/db"
)

// apiTokenStore is an in-memory cache of the active DB-backed API tokens, keyed
// by the SHA-256 hash of the secret. Auth is therefore a map lookup on the hot
// path (no per-request DB query). The cache is refreshed periodically and
// immediately after any create/revoke so rotation/revocation take effect
// promptly. last-used is recorded asynchronously and throttled.
type apiTokenStore struct {
	db       *db.DB
	mu       sync.RWMutex
	byHash   map[string]apiTokenEntry
	lastSeen map[string]time.Time // tokenID -> last time we recorded use
}

type apiTokenEntry struct {
	ID        string
	Role      string
	Subject   string
	ExpiresAt *time.Time
}

func newAPITokenStore(database *db.DB) *apiTokenStore {
	return &apiTokenStore{
		db:       database,
		byHash:   map[string]apiTokenEntry{},
		lastSeen: map[string]time.Time{},
	}
}

func hashAPIToken(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// refresh reloads the active token set from the database.
func (s *apiTokenStore) refresh(ctx context.Context) error {
	if s == nil || s.db == nil {
		return nil
	}
	tokens, err := s.db.ActiveAPITokens(ctx)
	if err != nil {
		return err
	}
	next := make(map[string]apiTokenEntry, len(tokens))
	activeIDs := make(map[string]bool, len(tokens))
	for _, t := range tokens {
		next[t.TokenHash] = apiTokenEntry{ID: t.ID, Role: t.Role, Subject: t.Subject, ExpiresAt: t.ExpiresAt}
		activeIDs[t.ID] = true
	}
	s.mu.Lock()
	s.byHash = next
	// Prune last-used tracking for tokens that are no longer active so the map
	// can't grow unbounded across token churn over the process lifetime.
	for id := range s.lastSeen {
		if !activeIDs[id] {
			delete(s.lastSeen, id)
		}
	}
	s.mu.Unlock()
	return nil
}

// put adds/updates a single token in the cache (used right after creation so a
// new token works immediately even if the next periodic refresh is delayed).
func (s *apiTokenStore) put(hash string, e apiTokenEntry) {
	if s == nil || hash == "" {
		return
	}
	s.mu.Lock()
	s.byHash[hash] = e
	s.mu.Unlock()
}

// evict removes a token from the cache immediately (used on revoke so the
// revocation takes effect even if a subsequent full refresh fails).
func (s *apiTokenStore) evict(hash string) {
	if s == nil || hash == "" {
		return
	}
	s.mu.Lock()
	delete(s.byHash, hash)
	s.mu.Unlock()
}

// lookup resolves a presented secret to its token entry, or ok=false. Expiry is
// re-checked defensively even though refresh already filters expired tokens.
func (s *apiTokenStore) lookup(secret string) (apiTokenEntry, bool) {
	if s == nil || secret == "" {
		return apiTokenEntry{}, false
	}
	h := hashAPIToken(secret)
	s.mu.RLock()
	e, ok := s.byHash[h]
	s.mu.RUnlock()
	if !ok {
		return apiTokenEntry{}, false
	}
	if e.ExpiresAt != nil && !e.ExpiresAt.After(timeNow()) {
		return apiTokenEntry{}, false
	}
	return e, true
}

// markUsed records last-used at most once per minute per token, in the
// background, so the hot auth path never blocks on a DB write.
func (s *apiTokenStore) markUsed(id string) {
	if s == nil || s.db == nil || id == "" {
		return
	}
	now := timeNow()
	s.mu.Lock()
	if last, ok := s.lastSeen[id]; ok && now.Sub(last) < time.Minute {
		s.mu.Unlock()
		return
	}
	s.lastSeen[id] = now
	s.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.db.TouchAPIToken(ctx, id)
	}()
}

// timeNow is a thin indirection kept simple; tests can rely on real time.
func timeNow() time.Time { return time.Now() }

// startAPITokenStore initializes the token cache and a periodic refresher so
// runtime token creation/revocation converges even without an explicit refresh.
func (s *Server) startAPITokenStore() {
	if s.db == nil {
		return
	}
	s.apiTokens = newAPITokenStore(s.db)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_ = s.apiTokens.refresh(ctx)
	cancel()
	interval := time.Duration(envInt("BONGSU_API_TOKEN_REFRESH_SECONDS", 30)) * time.Second
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = s.apiTokens.refresh(ctx)
			cancel()
		}
	}()
}

// refreshAPITokens reloads the cache immediately (called after create/revoke).
func (s *Server) refreshAPITokens() {
	if s.apiTokens == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = s.apiTokens.refresh(ctx)
}

// apiTokenFromRequest resolves a DB-backed API token presented via X-API-Key or
// Authorization: Bearer, records its use, and returns the resolved entry.
func (s *Server) apiTokenFromRequest(r *http.Request) (apiTokenEntry, bool) {
	if s.apiTokens == nil {
		return apiTokenEntry{}, false
	}
	key := r.Header.Get("X-API-Key")
	if key == "" {
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			key = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		}
	}
	entry, ok := s.apiTokens.lookup(key)
	if ok {
		s.apiTokens.markUsed(entry.ID)
	}
	return entry, ok
}
