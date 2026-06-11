package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

const sessionTokenBytes = 32

// dummyBcryptHash is a valid bcrypt hash of an unguessable value, compared
// against when a login names an unknown user so the request costs the same
// as a wrong password for a real user (no username-existence timing oracle).
var dummyBcryptHash = []byte("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSONBody(w, r, &req, false); err != nil {
		writeJSONBodyError(w, err, "invalid request body")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and password are required"})
		return
	}

	ip := clientIP(r)
	if s.loginLimit != nil && s.loginLimit.blocked(ip, req.Username) {
		s.audit(r, "auth.login", "local_user", req.Username, "rate_limited", map[string]any{"username": req.Username})
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many failed login attempts; try again later"})
		return
	}

	ctx := r.Context()
	user, err := s.db.GetLocalUserByUsername(ctx, req.Username)
	if err != nil {
		// Burn a bcrypt comparison so unknown usernames cost the same as wrong
		// passwords — otherwise response timing reveals which usernames exist.
		_ = bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(req.Password))
		if s.loginLimit != nil {
			s.loginLimit.fail(ip, req.Username)
		}
		s.audit(r, "auth.login", "local_user", req.Username, "denied", map[string]any{"username": req.Username, "reason": "unknown_user"})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		if s.loginLimit != nil {
			s.loginLimit.fail(ip, req.Username)
		}
		s.audit(r, "auth.login", "local_user", user.ID, "denied", map[string]any{"username": req.Username})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	if s.loginLimit != nil {
		s.loginLimit.success(ip, req.Username)
	}

	token, tokenHash, err := generateSessionToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	maxAge := s.sessionMaxAge
	expiresAt := time.Now().Add(maxAge)
	ua := r.UserAgent()
	if len(ua) > 512 {
		ua = ua[:512]
	}

	_, err = s.db.CreateSession(ctx, user.ID, tokenHash, expiresAt, ip, ua)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "bongsu_session",
		Value:    token,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: true,
		Secure:   secureRequest(r),
		SameSite: http.SameSiteLaxMode,
	})

	s.audit(r, "auth.login", "local_user", user.ID, "ok", map[string]any{"username": req.Username})
	writeJSON(w, http.StatusOK, map[string]any{
		"token":   token,
		"user":    sanitizeUser(user),
		"expires": expiresAt.Format(time.RFC3339),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	session := s.sessionFromRequest(r)
	if session != nil {
		s.db.DeleteSession(r.Context(), session.ID)
		s.audit(r, "auth.logout", "local_user", session.UserID, "ok", nil)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "bongsu_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secureRequest(r),
		SameSite: http.SameSiteLaxMode,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	session := s.sessionFromRequest(r)
	if session == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
		return
	}
	user, err := s.db.GetLocalUserByID(r.Context(), session.UserID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": sanitizeUser(user)})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	session := s.sessionFromRequest(r)
	if session == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeJSONBody(w, r, &req, false); err != nil {
		writeJSONBodyError(w, err, "invalid request body")
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "current_password and new_password are required"})
		return
	}
	changeMinLen := 12
	if envBool("BONGSU_ALLOW_WEAK_SECRETS", false) {
		changeMinLen = 1
	}
	if len(req.NewPassword) < changeMinLen {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("new password must be at least %d characters", changeMinLen)})
		return
	}

	ctx := r.Context()
	user, err := s.db.GetLocalUserByID(ctx, session.UserID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "current password is incorrect"})
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := s.db.UpdateLocalUserPassword(ctx, user.ID, string(newHash)); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	s.audit(r, "auth.change_password", "local_user", user.ID, "ok", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "password_changed"})
}

func (s *Server) sessionFromRequest(r *http.Request) *models.Session {
	if s.db == nil {
		return nil
	}
	token := s.sessionToken(r)
	if token == "" {
		return nil
	}
	tokenHash := hashSessionToken(token)
	session, err := s.db.GetSessionByTokenHash(r.Context(), tokenHash)
	if err != nil {
		return nil
	}
	s.db.TouchSession(r.Context(), session.ID)
	return session
}

func (s *Server) sessionToken(r *http.Request) string {
	if c, err := r.Cookie("bongsu_session"); err == nil && c.Value != "" {
		return c.Value
	}
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	}
	return ""
}

func (s *Server) authenticateSession(r *http.Request) bool {
	return s.sessionFromRequest(r) != nil
}

func (s *Server) sessionUserRole(r *http.Request) string {
	session := s.sessionFromRequest(r)
	if session == nil {
		return ""
	}
	user, err := s.db.GetLocalUserByID(r.Context(), session.UserID)
	if err != nil {
		return ""
	}
	return user.Role
}

func (s *Server) sessionUser(r *http.Request) *models.LocalUser {
	session := s.sessionFromRequest(r)
	if session == nil {
		return nil
	}
	user, err := s.db.GetLocalUserByID(r.Context(), session.UserID)
	if err != nil {
		return nil
	}
	return user
}

func generateSessionToken() (token, tokenHash string, err error) {
	raw := make([]byte, sessionTokenBytes)
	if _, err = rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate session token: %w", err)
	}
	token = hex.EncodeToString(raw)
	h := sha256.Sum256([]byte(token))
	tokenHash = hex.EncodeToString(h[:])
	return token, tokenHash, nil
}

func hashSessionToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func sanitizeUser(u *models.LocalUser) map[string]any {
	return map[string]any{
		"id":       u.ID,
		"username": u.Username,
		"role":     u.Role,
	}
}

func (s *Server) startSessionCleanup() {
	go func() {
		for {
			time.Sleep(time.Hour)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			n, err := s.db.DeleteExpiredSessions(ctx)
			if err != nil {
				log.Printf("session cleanup error: %v", err)
			} else if n > 0 {
				log.Printf("cleaned up %d expired sessions", n)
			}
			// Bound notification_log growth on the same housekeeping cadence.
			if err := s.db.CleanupOldNotificationLogs(ctx); err != nil {
				log.Printf("notification log cleanup error: %v", err)
			}
			cancel()
		}
	}()
}

func (s *Server) bootstrapAdmin() {
	adminUser := strings.TrimSpace(os.Getenv("BONGSU_ADMIN_USERNAME"))
	adminPass := os.Getenv("BONGSU_ADMIN_PASSWORD")
	if adminUser == "" || adminPass == "" {
		return
	}
	minLen := 16
	if envBool("BONGSU_ALLOW_WEAK_SECRETS", false) {
		minLen = 1
	}
	if len(adminPass) < minLen {
		log.Printf("WARNING: BONGSU_ADMIN_PASSWORD too short (%d < %d), skipping admin bootstrap", len(adminPass), minLen)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	n, err := s.db.CountLocalUsers(ctx)
	if err != nil {
		log.Printf("admin bootstrap: count users: %v", err)
		return
	}
	if n > 0 {
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(adminPass), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("admin bootstrap: hash password: %v", err)
		return
	}
	user, err := s.db.CreateLocalUser(ctx, adminUser, string(hash), "admin")
	if err != nil {
		log.Printf("admin bootstrap: create user: %v", err)
		return
	}
	log.Printf("Bootstrapped initial admin user: %s (id: %s)", adminUser, user.ID)
}
