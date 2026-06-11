package api

import (
	"strings"
	"sync"
	"time"
)

// loginLimiter throttles password brute force: after maxFailures failed login
// attempts from one client IP (or against one username) within the window,
// further attempts are rejected until the window expires. Successful logins
// clear the counters. The map is bounded by lazy expiry plus a hard cap so a
// spray across many IPs/usernames cannot grow memory without limit.
type loginLimiter struct {
	mu          sync.Mutex
	maxFailures int
	window      time.Duration
	entries     map[string]*loginFailures
	now         func() time.Time
}

type loginFailures struct {
	count int
	first time.Time
}

const loginLimiterMaxEntries = 100000

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		maxFailures: envPositiveIntDefault("BONGSU_LOGIN_MAX_FAILURES", 5),
		window:      time.Duration(envPositiveIntDefault("BONGSU_LOGIN_LOCKOUT_MINUTES", 15)) * time.Minute,
		entries:     map[string]*loginFailures{},
		now:         time.Now,
	}
}

func envPositiveIntDefault(key string, def int) int {
	if v := envInt(key, def); v > 0 {
		return v
	}
	return def
}

// blocked reports whether this ip/username pair is currently locked out.
func (l *loginLimiter) blocked(ip, username string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for _, key := range loginLimiterKeys(ip, username) {
		if e, ok := l.entries[key]; ok {
			if now.Sub(e.first) > l.window {
				delete(l.entries, key)
				continue
			}
			if e.count >= l.maxFailures {
				return true
			}
		}
	}
	return false
}

// fail records a failed attempt for both the client IP and the username.
func (l *loginLimiter) fail(ip, username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.entries) >= loginLimiterMaxEntries {
		// Hard cap: drop expired entries; if still full, reset rather than grow
		// without bound (favors availability of memory over a perfect ledger).
		for k, e := range l.entries {
			if now.Sub(e.first) > l.window {
				delete(l.entries, k)
			}
		}
		if len(l.entries) >= loginLimiterMaxEntries {
			l.entries = map[string]*loginFailures{}
		}
	}
	for _, key := range loginLimiterKeys(ip, username) {
		e, ok := l.entries[key]
		if !ok || now.Sub(e.first) > l.window {
			l.entries[key] = &loginFailures{count: 1, first: now}
			continue
		}
		e.count++
	}
}

// success clears the counters for the pair after a valid login.
func (l *loginLimiter) success(ip, username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, key := range loginLimiterKeys(ip, username) {
		delete(l.entries, key)
	}
}

func loginLimiterKeys(ip, username string) []string {
	keys := make([]string, 0, 2)
	if ip = strings.TrimSpace(ip); ip != "" {
		keys = append(keys, "ip\x00"+ip)
	}
	if username = strings.ToLower(strings.TrimSpace(username)); username != "" {
		keys = append(keys, "user\x00"+username)
	}
	return keys
}
