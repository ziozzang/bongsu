package api

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/ziozzang/bongsu/internal/server/db"
	"golang.org/x/crypto/bcrypt"
)

func minUserPasswordLen() int {
	if envBool("BONGSU_ALLOW_WEAK_SECRETS", false) {
		return 1
	}
	return 12
}

func validUserRole(role string) bool {
	return role == "admin" || role == "viewer"
}

// --- Local user management (admin only) ---

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	users, err := s.db.ListLocalUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users, "total": len(users)})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := decodeJSONBody(w, r, &req, false); err != nil {
		writeJSONBodyError(w, err, "invalid request body")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.Role = strings.TrimSpace(req.Role)
	if req.Username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}
	if !validUserRole(req.Role) {
		writeError(w, http.StatusBadRequest, "role must be admin or viewer")
		return
	}
	if len(req.Password) < minUserPasswordLen() {
		writeError(w, http.StatusBadRequest, "password too short")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	user, err := s.db.CreateLocalUser(r.Context(), req.Username, string(hash), req.Role)
	if err != nil {
		if db.IsUniqueViolation(err) {
			writeError(w, http.StatusConflict, "username already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	s.audit(r, "user.create", "local_user", user.ID, "ok", map[string]any{"username": user.Username, "role": user.Role})
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) handleUpdateUserRole(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	var req struct {
		Role string `json:"role"`
	}
	if err := decodeJSONBody(w, r, &req, false); err != nil {
		writeJSONBodyError(w, err, "invalid request body")
		return
	}
	if !validUserRole(req.Role) {
		writeError(w, http.StatusBadRequest, "role must be admin or viewer")
		return
	}
	ctx := r.Context()
	target, err := s.db.GetLocalUserByID(ctx, id)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	// The last-admin invariant is enforced atomically (tx + row locks) to avoid
	// a check-then-act race between concurrent demotions.
	switch res, err := s.db.UpdateLocalUserRoleGuarded(ctx, id, req.Role); {
	case err != nil:
		writeError(w, http.StatusInternalServerError, "db error")
		return
	case res == db.UserGuardNotFound:
		writeError(w, http.StatusNotFound, "user not found")
		return
	case res == db.UserGuardLastAdmin:
		writeError(w, http.StatusConflict, "cannot demote the last admin user")
		return
	}
	// A role change invalidates any cached scope on existing sessions.
	_, _ = s.db.DeleteUserSessions(ctx, id)
	s.audit(r, "user.update_role", "local_user", id, "ok", map[string]any{"username": target.Username, "from": target.Role, "to": req.Role})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "id": id, "role": req.Role})
}

func (s *Server) handleResetUserPassword(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	var req struct {
		Password string `json:"password"`
	}
	if err := decodeJSONBody(w, r, &req, false); err != nil {
		writeJSONBodyError(w, err, "invalid request body")
		return
	}
	if len(req.Password) < minUserPasswordLen() {
		writeError(w, http.StatusBadRequest, "password too short")
		return
	}
	ctx := r.Context()
	target, err := s.db.GetLocalUserByID(ctx, id)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.db.UpdateLocalUserPassword(ctx, id, string(hash)); err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	// Force re-login everywhere after an admin reset.
	revoked, _ := s.db.DeleteUserSessions(ctx, id)
	s.audit(r, "user.reset_password", "local_user", id, "ok", map[string]any{"username": target.Username, "sessions_revoked": revoked})
	writeJSON(w, http.StatusOK, map[string]any{"status": "password_reset", "sessions_revoked": revoked})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	ctx := r.Context()
	target, err := s.db.GetLocalUserByID(ctx, id)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	// Don't let an admin delete their own in-use account.
	if cur := s.sessionUser(r); cur != nil && cur.ID == id {
		writeError(w, http.StatusConflict, "cannot delete your own account")
		return
	}
	// The last-admin invariant is enforced atomically (tx + row locks).
	switch res, err := s.db.DeleteLocalUserGuarded(ctx, id); {
	case err != nil:
		writeError(w, http.StatusInternalServerError, "db error")
		return
	case res == db.UserGuardNotFound:
		writeError(w, http.StatusNotFound, "user not found")
		return
	case res == db.UserGuardLastAdmin:
		writeError(w, http.StatusConflict, "cannot delete the last admin user")
		return
	}
	s.audit(r, "user.delete", "local_user", id, "ok", map[string]any{"username": target.Username, "role": target.Role})
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "id": id})
}

// --- DB-backed API tokens (admin only) ---

func generateAPITokenSecret() (secret, prefix, hash string, err error) {
	buf := make([]byte, 24)
	if _, err = rand.Read(buf); err != nil {
		// Fail closed: never mint a credential from a failed CSPRNG.
		return "", "", "", err
	}
	secret = "bsk_" + hex.EncodeToString(buf)
	prefix = secret[:12] + "…"
	hash = hashAPIToken(secret)
	return secret, prefix, hash, nil
}

func (s *Server) handleListAPITokens(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	tokens, err := s.db.ListAPITokens(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens, "total": len(tokens)})
}

func (s *Server) handleCreateAPIToken(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		Name          string `json:"name"`
		Role          string `json:"role"`
		Subject       string `json:"subject"`
		ExpiresInDays int    `json:"expires_in_days"`
	}
	if err := decodeJSONBody(w, r, &req, false); err != nil {
		writeJSONBodyError(w, err, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Role = strings.TrimSpace(req.Role)
	req.Subject = strings.TrimSpace(req.Subject)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if !validUserRole(req.Role) {
		writeError(w, http.StatusBadRequest, "role must be admin or viewer")
		return
	}
	if req.Role == "viewer" && req.Subject == "" {
		writeError(w, http.StatusBadRequest, "viewer tokens require a subject (e.g. user:alice or group:platform)")
		return
	}
	var expiresAt *time.Time
	if req.ExpiresInDays > 0 {
		t := timeNow().Add(time.Duration(req.ExpiresInDays) * 24 * time.Hour)
		expiresAt = &t
	}
	secret, prefix, hash, err := generateAPITokenSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate token")
		return
	}
	token, err := s.db.CreateAPIToken(r.Context(), req.Name, hash, prefix, req.Role, req.Subject, s.actorID(r), expiresAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	// Make the new token usable immediately, even before the next refresh.
	if s.apiTokens != nil {
		s.apiTokens.put(hash, apiTokenEntry{ID: token.ID, Role: token.Role, Subject: token.Subject, ExpiresAt: token.ExpiresAt})
	}
	s.refreshAPITokens()
	s.audit(r, "api_token.create", "api_token", token.ID, "ok", map[string]any{"name": token.Name, "role": token.Role, "subject": token.Subject})
	// The plaintext secret is returned exactly once.
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "secret": secret})
}

func (s *Server) handleRevokeAPIToken(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	hash, err := s.db.RevokeAPIToken(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "token not found")
		return
	}
	// Evict immediately so revocation holds even if the refresh below fails.
	if s.apiTokens != nil {
		s.apiTokens.evict(hash)
	}
	s.refreshAPITokens()
	s.audit(r, "api_token.revoke", "api_token", id, "ok", nil)
	writeJSON(w, http.StatusOK, map[string]any{"status": "revoked", "id": id})
}
