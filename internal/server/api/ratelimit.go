package api

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type ipRateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitorBucket
	rps      float64
	burst    int
}

type visitorBucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newIPRateLimiter(rps float64, burst int) *ipRateLimiter {
	rl := &ipRateLimiter{
		visitors: make(map[string]*visitorBucket),
		rps:      rps,
		burst:    burst,
	}
	go rl.cleanupStaleVisitors()
	return rl
}

func (rl *ipRateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if v, exists := rl.visitors[ip]; exists {
		v.lastSeen = time.Now()
		return v.limiter
	}
	limiter := rate.NewLimiter(rate.Limit(rl.rps), rl.burst)
	rl.visitors[ip] = &visitorBucket{limiter: limiter, lastSeen: time.Now()}
	return limiter
}

func (rl *ipRateLimiter) cleanupStaleVisitors() {
	for {
		time.Sleep(3 * time.Minute)
		rl.mu.Lock()
		for ip, v := range rl.visitors {
			if time.Since(v.lastSeen) > 10*time.Minute {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isRateLimitExemptPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if s.authenticateAdmin(r) {
			next.ServeHTTP(w, r)
			return
		}
		ip := clientIP(r)
		var limiter *rate.Limiter
		if s.authenticateAgent(r) {
			limiter = s.agentRateLimiter.getLimiter(ip)
		} else {
			limiter = s.generalRateLimiter.getLimiter(ip)
		}
		if !limiter.Allow() {
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error": "rate limit exceeded",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isRateLimitExemptPath(path string) bool {
	return path == "/api/health" ||
		path == "/api/ready" ||
		path == "/api/live" ||
		path == "/api/docs/openapi.yaml"
}
