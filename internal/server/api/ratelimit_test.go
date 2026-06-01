package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func rateLimitServer(generalRPS float64, generalBurst int, agentRPS float64) *Server {
	s := &Server{
		apiKey:             "test-admin-key",
		agentKey:           "test-agent-key",
		generalRateLimiter: newIPRateLimiter(generalRPS, generalBurst),
		agentRateLimiter:   newIPRateLimiter(agentRPS, int(agentRPS)*2),
	}
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("GET /test", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	s.mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return s
}

func rateLimitHandler(s *Server) http.Handler {
	var h http.Handler = s.mux
	h = s.rateLimitMiddleware(h)
	return h
}

func TestRateLimitBurstEnforcement(t *testing.T) {
	s := rateLimitServer(1, 2, 100)
	handler := rateLimitHandler(s)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d should succeed, got %d", i+1, rec.Code)
		}
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd request should be rate limited, got %d", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After header = %q, want %q", got, "1")
	}
}

func TestRateLimitAdminExempt(t *testing.T) {
	s := rateLimitServer(1, 2, 100)
	handler := rateLimitHandler(s)

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-API-Key", "test-admin-key")
		req.RemoteAddr = "1.2.3.4:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("admin request %d should succeed, got %d", i+1, rec.Code)
		}
	}
}

func TestRateLimitAgentHigherLimits(t *testing.T) {
	s := rateLimitServer(1, 2, 100)
	handler := rateLimitHandler(s)

	// General: burst=2, 3rd should fail
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("general request %d should succeed, got %d", i+1, rec.Code)
		}
	}
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("general 3rd request should be limited, got %d", rec.Code)
	}

	// Agent: burst=200, many requests should succeed
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-API-Key", "test-agent-key")
		req.RemoteAddr = "10.0.0.2:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("agent request %d should succeed, got %d", i+1, rec.Code)
		}
	}
}

func TestRateLimitHealthPathExempt(t *testing.T) {
	s := rateLimitServer(1, 2, 100)
	handler := rateLimitHandler(s)

	for _, path := range []string{"/api/health"} {
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest("GET", path, nil)
			req.RemoteAddr = "1.2.3.4:1234"
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s request %d should succeed (exempt), got %d", path, i+1, rec.Code)
			}
		}
	}
}

func TestRateLimitPerIPIsolation(t *testing.T) {
	s := rateLimitServer(1, 2, 100)
	handler := rateLimitHandler(s)

	// IP A exhausts limit
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("IP A request %d should succeed", i+1)
		}
	}
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("IP A should be limited")
	}

	// IP B still works
	req = httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "5.6.7.8:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("IP B should still be allowed, got %d", rec.Code)
	}
}
