package api

import (
	"context"
	"fmt"
	"log"
	"os"

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

func (s *Server) initAuthenticator() Authenticator {
	if s.oidcAuth != nil {
		log.Printf("OIDC bearer authentication enabled for issuer %s; local password login remains enabled", s.oidcAuth.issuer)
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
