package api

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type AuthResult struct {
	Username  string
	Role      string
	SubjectID string
}

type Authenticator interface {
	Authenticate(ctx context.Context, username, password string) (*AuthResult, error)
}

type LocalAuthenticator struct {
	server *Server
}

func (a *LocalAuthenticator) Authenticate(ctx context.Context, username, password string) (*AuthResult, error) {
	user, err := a.server.db.GetLocalUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}
	return &AuthResult{
		Username:  user.Username,
		Role:      user.Role,
		SubjectID: user.ID,
	}, nil
}

type OIDCAuthenticator struct {
	issuer   string
	clientID string
}

func newOIDCAuthenticator(issuer, clientID string) *OIDCAuthenticator {
	return &OIDCAuthenticator{issuer: issuer, clientID: clientID}
}

func (a *OIDCAuthenticator) Authenticate(_ context.Context, _, _ string) (*AuthResult, error) {
	return nil, fmt.Errorf("OIDC authentication not configured")
}

func (s *Server) initAuthenticator() Authenticator {
	oidcIssuer := strings.TrimSpace(envOr("BONGSU_OIDC_ISSUER", ""))
	if oidcIssuer != "" {
		log.Printf("WARNING: BONGSU_OIDC_ISSUER is set, but OIDC login is not implemented yet; using local authentication")
	}
	return &LocalAuthenticator{server: s}
}

func envOr(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}
